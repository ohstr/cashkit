// An Order connection on a FakeBank's node, for wallet tests (NIP-CO): its
// `cashorder1` answers `get_info` over NIP-47; `cash_order` and its lookups
// come over the node's private transport; `pay()` mints an order's bills the
// way §Minting says and publishes an order notice. Test support only.
import {
  decideLookup,
  encodeOrderConnection,
  finalizeEvent,
  getPublicKey,
  mintSplit,
  nip44,
  orderFee,
  signOrderConnection,
  toHex,
  verifyEvent,
  type NostrEvent,
  type Payment,
} from '../src/core/index.js'
import type { FakeBank, Identity } from './fakeBank.js'
import type { Answer, RequestInfo } from './fakeHub.js'
import { signedInvoice } from './helpers.js'

let seq = 0x3000
function nextKey(): Uint8Array {
  const k = new Uint8Array(32)
  new DataView(k.buffer).setUint32(28, ++seq)
  k[0] = 0x44
  return k
}

/** BIP-173's example mainnet address. */
export const ADDRESS = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'

export const TERMS = {
  lightning: { min_millis: 1000, max_millis: 1_000_000_000, fee_base: 1000, fee_ppm: 1000, window: 3600 },
  onchain: { min_millis: 10_000_000, max_millis: 1_000_000_000, fee_base: 21000, fee_ppm: 2000, window: 86400, confirmations: [{ up_to_millis: 100_000_000, n: 1 }, { up_to_millis: 1_000_000_000, n: 3 }, { n: 6 }] },
  bill: { redeem_fee_base: 0, redeem_fee_ppm: 5000, min_transfer_millis: 1000 },
}

interface FakeOrderRow {
  readonly rid: string
  readonly buyer: string
  readonly recipient: Identity
  readonly amount: bigint
  readonly payment: Payment
  readonly notify: string
  readonly fee: bigint
  readonly pay: bigint
  readonly payBy: number
  readonly relay: string
  state: 'open' | 'paid' | 'minted' | 'expired' | 'closed'
  readonly bills: { wallet_pubkey: string; cash_token: string | { status: 'spent'; reason: string }; amount_millis: bigint; paid_millis: bigint; outpoint?: string }[]
}

export class FakeOrder {
  readonly connKey = nextKey()
  readonly secret = nextKey()
  readonly pubkey = getPublicKey(this.connKey)
  readonly client = getPublicKey(this.secret)
  terms: Record<string, unknown> = TERMS
  /** The invoice an order reply carries: by default for `pay`, made now by the Hub's node and expiring at `payBy`. */
  invoiceFor: (pay: bigint, payBy: number) => string = (pay, payBy) => signedInvoice({ amountMillis: pay, nodeKey: this.bank.hub.nodeKey, timestamp: this.now, expiry: Math.max(1, payBy - this.now), hashByte: 0x77 })
  /** Applies the order but loses its reply. */
  loseReply = false
  readonly orders = new Map<string, FakeOrderRow>()
  readonly placed: RequestInfo[] = []
  readonly string: string

  constructor(readonly bank: FakeBank) {
    const hub = bank.hub
    hub.bills.set(this.pubkey, this.client)
    const prev = bank.override
    bank.override = (m, info) => (info.item.target === this.pubkey ? this.handle(m, info) : prev?.(m, info))
    hub.pool.subscribe(hub.relayUrls, { kinds: [23194], '#p': [this.pubkey] }, {
      onEvent: (e: NostrEvent, relay: string) => {
        if (!verifyEvent(e) || e.pubkey !== this.client) return
        const ck = nip44.getConversationKey(this.connKey, e.pubkey)
        const req = JSON.parse(nip44.decrypt(e.content, ck)) as { method: string }
        const a = req.method === 'get_info' ? { result: this.info() } : { error: { code: 'NOT_IMPLEMENTED', message: req.method } }
        const reply = finalizeEvent({ kind: 23195, created_at: e.created_at, tags: [['p', e.pubkey], ['e', e.id], ['encryption', 'nip44_v2']], content: nip44.encrypt(JSON.stringify({ result_type: req.method, ...a }), ck) }, this.connKey)
        void hub.pool.publish(relay, reply).catch(() => undefined)
      },
      onEose: () => {},
    })
    this.string = encodeOrderConnection(signOrderConnection({ walletPubkey: this.pubkey, secret: toHex(this.secret), relays: hub.relayUrls, label: 'Alice’s cash counter', hubIdentity: hub.node, chain: 'bitcoin' }, hub.nodeKey))
  }

  private get now(): number {
    return Math.floor(this.bank.hub.clock() / 1000)
  }

  info(): Record<string, unknown> {
    return { methods: ['get_info'], private_methods: ['cash_lookup', 'cash_order'], pubkey: this.bank.hub.node, network: 'mainnet', chain: 'bitcoin', cash_order: this.terms }
  }

  private handle(method: string, info: RequestInfo): Answer {
    if (method === 'cash_order') return this.order(info)
    if (method === 'cash_lookup') return this.lookup(info)
    return 'omit'
  }

  private order(info: RequestInfo): Answer {
    this.placed.push(info)
    const p = info.params as Record<string, unknown>
    const rid = p['request_id']
    if (typeof rid !== 'string') return { error: { code: 'BAD_REQUEST', message: 'request_id' } }
    if (this.bank.usedIds.has(rid)) return { error: { code: 'REQUEST_REUSED', message: 'used' } }
    if (info.signer === undefined) return { error: { code: 'BAD_REQUEST', message: 'proof required' } }
    this.bank.usedIds.add(rid)
    const payment = p['payment'] as Payment
    const k = (this.terms as Record<string, Record<string, unknown> | undefined>)[payment]
    if (k === undefined) return { error: { code: 'RESTRICTED', message: 'not sold' } }
    for (const bad of ['recipients', 'expiry', 'cash_secret']) if (bad in p) return { error: { code: 'BAD_REQUEST', message: bad } }
    const amount = BigInt(p['amount_millis'] as number)
    if (amount < BigInt(k['min_millis'] as number) || amount > BigInt(k['max_millis'] as number)) return { error: { code: 'RESTRICTED', message: 'amount' } }
    const r = p['recipient'] as { identity_type: string; identity_value: string }
    const { feeMillis, payMillis } = orderFee(payment, { minMillis: 0n, maxMillis: 0n, feeBase: BigInt(k['fee_base'] as number), feePpm: BigInt(k['fee_ppm'] as number), window: 0 }, amount)
    const row: FakeOrderRow = {
      rid,
      buyer: info.signer,
      recipient: { type: r.identity_type, value: r.identity_value } as Identity,
      amount,
      payment,
      notify: p['notify'] as string,
      fee: feeMillis,
      pay: payMillis,
      payBy: this.now + (k['window'] as number),
      relay: this.bank.hub.relayUrls[0]!,
      state: 'open',
      bills: [],
    }
    this.orders.set(rid, row)
    return this.loseReply ? 'omit' : { result: this.json(row) }
  }

  json(o: FakeOrderRow): Record<string, unknown> {
    return {
      state: o.state,
      payment: o.payment,
      amount_millis: o.amount,
      fee_millis: o.fee,
      pay_millis: o.pay,
      ...(o.payment === 'lightning' ? { invoice: this.invoiceFor(o.pay, o.payBy) } : { address: ADDRESS, confirmations: 1 }),
      pay_by: o.payBy,
      bills: o.bills,
    }
  }

  private lookup(info: RequestInfo): Answer {
    const p = info.params as Record<string, unknown>
    const rid = p['request_id']
    const deadline = p['deadline']
    if (typeof rid !== 'string' || typeof deadline !== 'number') return { error: { code: 'BAD_REQUEST', message: 'lookup' } }
    const o = this.orders.get(rid)
    if (o !== undefined) {
      if (info.signer !== o.buyer) return { error: { code: 'UNAUTHORIZED', message: 'not the buyer' } }
      return { result: { status: 'done', result: this.json(o) } }
    }
    const d = decideLookup({ now: this.now, deadline, horizon: this.bank.hub.maxRequestAge ?? 300, hasRecord: false })
    return { result: typeof d === 'string' ? { status: d } : { status: 'pending', retry_after: d.retryAfter } }
  }

  /** A payment of `received` millis arrives and is minted (§Minting), then a notice goes out. */
  async pay(o: FakeOrderRow, received: bigint): Promise<void> {
    const max = BigInt(((this.terms as Record<string, Record<string, unknown>>)[o.payment]!['max_millis'] as number) ?? 0)
    for (const amt of mintSplit(received, o.fee, max)) {
      const w = this.bank.mint(amt, o.recipient)
      o.bills.push({ wallet_pubkey: w.walletPubkey, cash_token: w.token, amount_millis: amt, paid_millis: received, ...(o.payment === 'onchain' && { outpoint: `${'ab'.repeat(32)}:${o.bills.length}` }) })
    }
    o.state = 'minted'
    await this.notice(o)
  }

  async notice(o: FakeOrderRow): Promise<void> {
    const ev = finalizeEvent({ kind: 23189, created_at: this.now, tags: [['p', o.notify]], content: '' }, nextKey())
    await this.bank.hub.pool.publish(o.relay, ev).catch(() => undefined)
  }

  only(): FakeOrderRow {
    return [...this.orders.values()][0]!
  }
}

