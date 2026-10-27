// A Circle Wallet Hub on a FakeBank's node, for wallet tests (NIP-CW): its
// `circlehub1` answers `get_info` over NIP-47; joins and their lookups come
// over the node's private transport (a join on the standard transport is
// NOT_IMPLEMENTED); every Circle Wallet it issues answers its member's key
// over NIP-47. Test support only.
import {
  decideLookup,
  encodeCircleHubConnection,
  finalizeEvent,
  getPublicKey,
  nip44,
  signCircleHubConnection,
  toHex,
  verifyEvent,
  type NostrEvent,
} from '../src/core/index.js'
import type { FakeBank } from './fakeBank.js'
import type { Answer, RequestInfo } from './fakeHub.js'

let seq = 0x2000
function nextKey(): Uint8Array {
  const k = new Uint8Array(32)
  new DataView(k.buffer).setUint32(28, ++seq)
  k[0] = 0x43
  return k
}

export interface IssuedWallet {
  readonly walletKey: Uint8Array
  readonly walletPubkey: string
  member: string
  connectionPubkey: string
  balance: bigint
  frozen: boolean
  deleted: boolean
  readonly details: Record<string, unknown>
  readonly seen: { method: string; params: Record<string, unknown> }[]
}

export interface CircleOptions {
  readonly label?: string
  /** Undefined: the Hub serves no rotation. */
  readonly rotationDelaySecs?: number
  readonly perWalletMax?: bigint
  readonly dust?: bigint
}

export class FakeCircle {
  readonly hubKey = nextKey()
  readonly hubSecret = nextKey()
  readonly hubPubkey = getPublicKey(this.hubKey)
  readonly client = getPublicKey(this.hubSecret)
  accepting = true
  /** Undefined: anyone may join. */
  members: Set<string> | undefined
  /** Applies the join but loses its reply. */
  loseJoinReply = false
  /** Answers every join with this code. */
  refuseWith: string | undefined
  /** How `get_info` reports the node identity (default the node's). */
  infoIdentity: string | undefined
  readonly wallets = new Map<string, IssuedWallet>()
  readonly joins: RequestInfo[] = []
  readonly usedProofs = new Set<string>()
  readonly records = new Map<string, { member: string; result: unknown }>()
  readonly string: string

  constructor(
    readonly bank: FakeBank,
    readonly o: CircleOptions = {},
  ) {
    const hub = bank.hub
    hub.bills.set(this.hubPubkey, this.client)
    const prev = bank.override
    bank.override = (m, info) => (info.item.target === this.hubPubkey ? this.handle(m, info) : prev?.(m, info))
    this.serve(this.hubKey, (e) => (e.pubkey === this.client ? this.hubAnswer : undefined))
    this.string = encodeCircleHubConnection(
      signCircleHubConnection({ walletPubkey: this.hubPubkey, secret: toHex(this.hubSecret), relays: hub.relayUrls, label: o.label ?? 'Ada’s Circle', hubIdentity: hub.node, chain: 'bitcoin' }, hub.nodeKey),
    )
  }

  private get now(): number {
    return Math.floor(this.bank.hub.clock() / 1000)
  }

  info(): Record<string, unknown> {
    return {
      methods: ['get_info'],
      private_methods: ['cash_lookup', 'create_circle_wallet'],
      network: 'mainnet',
      chain: 'bitcoin',
      circle_wallet: {
        available_millis: 1_000_000,
        max_exp_secs: 0,
        fees_ppm: 1000,
        fee_reserve: { ppm: 5000, min_millis: 10000 },
        dust_threshold_millis: Number(this.o.dust ?? 1000n),
        circle_policy: 'allowlist',
        identity: this.infoIdentity ?? this.bank.hub.node,
        ...(this.o.rotationDelaySecs !== undefined && { rotation_delay_secs: this.o.rotationDelaySecs }),
        ...(this.o.perWalletMax !== undefined && { per_wallet_max_millis: Number(this.o.perWalletMax) }),
        min_budget_renewal: 'daily',
        accepting: this.accepting,
      },
    }
  }

  private readonly hubAnswer = (method: string): Answer => (method === 'get_info' ? { result: this.info() } : { error: { code: 'NOT_IMPLEMENTED', message: `${method} goes over the private transport` } })

  /** Serves NIP-47 requests addressed to `key`'s pubkey; `route` picks the handler for a sender. */
  private serve(key: Uint8Array, route: (e: NostrEvent) => ((method: string, params: Record<string, unknown>) => Answer) | undefined): void {
    const pub = getPublicKey(key)
    this.bank.hub.pool.subscribe(this.bank.hub.relayUrls, { kinds: [23194], '#p': [pub] }, {
      onEvent: (e: NostrEvent, relay: string) => {
        if (!verifyEvent(e)) return
        const h = route(e)
        if (h === undefined) return
        const ck = nip44.getConversationKey(key, e.pubkey)
        const req = JSON.parse(nip44.decrypt(e.content, ck)) as { method: string; params?: Record<string, unknown> }
        const a = h(req.method, req.params ?? {})
        if (a === 'omit') return
        const body = JSON.stringify({ result_type: req.method, ...a }, (_k, v) => (typeof v === 'bigint' ? Number(v) : v))
        const reply = finalizeEvent({ kind: 23195, created_at: e.created_at, tags: [['p', e.pubkey], ['e', e.id], ['encryption', 'nip44_v2']], content: nip44.encrypt(body, ck) }, key)
        void this.bank.hub.pool.publish(relay, reply).catch(() => undefined)
      },
      onEose: () => {},
    })
  }

  private handle(method: string, info: RequestInfo): Answer {
    if (method === 'create_circle_wallet') return this.join(info)
    if (method === 'cash_lookup') return this.lookup(info)
    return { error: { code: 'NOT_IMPLEMENTED', message: method } }
  }

  private join(info: RequestInfo): Answer {
    this.joins.push(info)
    const p = info.params as Record<string, unknown>
    const pubkey = p['pubkey'] as string
    if (info.signer !== pubkey) return { error: { code: 'UNAUTHORIZED', message: 'the item proof is not the requester’s' } }
    let proof: NostrEvent
    try {
      proof = JSON.parse(p['identity_event'] as string) as NostrEvent
    } catch {
      return { error: { code: 'BAD_REQUEST', message: 'identity_event' } }
    }
    const tag = (k: string) => proof.tags.find((t) => t[0] === k)?.[1]
    const terms = `${p['max_amount']}:${p['max_receive']}:${p['expiry'] ?? 0}:${p['budget_renewal'] ?? 'never'}`
    if (!verifyEvent(proof) || proof.pubkey !== pubkey || tag('d') !== this.hubPubkey || tag('connection') !== p['connection_pubkey'] || tag('terms') !== terms || proof.tags.some((t) => t[0] === 'action')) {
      return { error: { code: 'UNAUTHORIZED', message: 'the identity proof does not verify' } }
    }
    if (this.usedProofs.has(proof.id)) return { error: { code: 'REQUEST_REUSED', message: 'proof already used' } }
    this.usedProofs.add(proof.id)
    if (!this.accepting) return { error: { code: 'RESTRICTED', message: 'not accepting joins' } }
    if (this.members !== undefined && !this.members.has(pubkey)) return { error: { code: 'RESTRICTED', message: 'not a member' } }
    if (this.refuseWith !== undefined) return { error: { code: this.refuseWith, message: 'refused' } }
    if ([...this.wallets.values()].some((w) => w.member === pubkey && !w.deleted)) return { error: { code: 'WALLET_EXISTS', message: 'already a member' } }
    const walletKey = nextKey()
    const details: Record<string, unknown> = {
      wallet_pubkey: getPublicKey(walletKey),
      connection_pubkey: p['connection_pubkey'],
      relays: this.bank.hub.relayUrls,
      max_amount: p['max_amount'],
      max_receive: p['max_receive'],
      expires_at: 0,
      fees_ppm: 1000,
      dust_threshold_millis: Number(this.o.dust ?? 1000n),
      ...(this.o.rotationDelaySecs !== undefined && { rotation_delay_secs: this.o.rotationDelaySecs }),
      budget_renewal: p['budget_renewal'] ?? 'never',
    }
    const w: IssuedWallet = { walletKey, walletPubkey: getPublicKey(walletKey), member: pubkey, connectionPubkey: p['connection_pubkey'] as string, balance: 0n, frozen: false, deleted: false, details, seen: [] }
    this.wallets.set(w.walletPubkey, w)
    this.serve(walletKey, (e) => (e.pubkey === w.connectionPubkey ? (m, params) => this.walletAnswer(w, m, params) : undefined))
    const result = { encrypted_details: nip44.encrypt(JSON.stringify(details), nip44.getConversationKey(this.hubKey, pubkey)) }
    this.records.set(`${pubkey}:${w.connectionPubkey}`, { member: pubkey, result })
    return this.loseJoinReply ? 'omit' : { result }
  }

  private lookup(info: RequestInfo): Answer {
    const p = info.params as Record<string, unknown>
    const conn = p['connection_pubkey']
    const deadline = p['deadline']
    if (typeof conn !== 'string' || typeof deadline !== 'number') return { error: { code: 'BAD_REQUEST', message: 'lookup needs connection_pubkey and deadline' } }
    if (info.signer === undefined) return { error: { code: 'UNAUTHORIZED', message: 'no item proof' } }
    const rec = this.records.get(`${info.signer}:${conn}`)
    if (rec !== undefined) return { result: { status: 'done', result: rec.result } }
    const d = decideLookup({ now: this.now, deadline: Math.min(deadline, this.now + 360), horizon: 360, hasRecord: false })
    return { result: typeof d === 'string' ? { status: d } : { status: 'pending', retry_after: d.retryAfter } }
  }

  private walletAnswer(w: IssuedWallet, method: string, params: Record<string, unknown>): Answer {
    w.seen.push({ method, params })
    if (w.deleted) return { error: { code: 'UNAUTHORIZED', message: 'deleted' } }
    if (w.frozen) return { error: { code: 'FROZEN', message: 'frozen' } }
    switch (method) {
      case 'get_info':
        return { result: { alias: 'circle wallet', network: 'mainnet', chain: 'bitcoin', methods: ['pay_invoice', 'pay_keysend', 'make_invoice', 'lookup_invoice', 'list_transactions', 'get_balance', 'get_budget', 'get_info', 'delete_circle_wallet'] } }
      case 'get_balance':
        return { result: { balance: Number(w.balance) } }
      case 'get_budget':
        return { result: { total_budget: w.details['max_amount'], used_budget: 0, renewal_period: w.details['budget_renewal'], total_receive_budget: w.details['max_receive'], used_receive_budget: 0 } }
      case 'make_invoice':
        if (!(Number(params['amount']) > 0)) return { error: { code: 'RESTRICTED', message: 'an invoice needs an amount' } }
        return { result: { invoice: `lnbc${params['amount']}fake`, amount: params['amount'] } }
      case 'delete_circle_wallet':
        if (w.balance > (this.o.dust ?? 1000n)) return { error: { code: 'RESTRICTED', message: 'holds more than dust' } }
        w.deleted = true
        return { result: {} }
      default:
        return { error: { code: 'RESTRICTED', message: method } }
    }
  }
}
