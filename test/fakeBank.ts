// A stateful Hub for wallet tests: it keeps every Cash Wallet it minted and
// applies cash_status, cash_transfer, cash_consolidate and cash_redeem the
// way NIP-CASH §Transferring and Splitting a Slice and §Consolidating
// describe. Test support only; it trusts the transport layer's proof checks
// (FakeHub) and adds the per-method identity checks on top.
import { sha256 } from '@noble/hashes/sha2.js'
import { decideLookup, encodeCashHubConnection, finalizeEvent, fromHex, getPublicKey, hubGroupFor, nip44, signCashHubConnection, toHex, verifyEvent, type NostrEvent } from '../src/core/index.js'
import { FakeHub, type Answer, type MemoryRelayPool, type RequestInfo } from './fakeHub.js'

export type Identity = { readonly type: 'pubkey' | 'connection_key'; readonly value: string } | { readonly type: 'cash'; readonly value: string }

export interface BankWallet {
  readonly walletKey: Uint8Array
  readonly walletPubkey: string
  readonly connSecret: Uint8Array
  readonly token: string
  identity: Identity
  amount: bigint
  /** Recipients this wallet has ever had (NIP-CASH's "lifetime-solo" rule). */
  history: number
  spent: boolean
  /** Claimed by a redeem whose payment has not finished. */
  claimed?: boolean
  expiresAt?: number
}

/** The cash commitment for a hex secret: hex(sha256(secret bytes)). */
export const commitment = (secretHex: string) => toHex(sha256(fromHex(secretHex, 'secret')))

let keySeq = 0x1000
function nextKey(): Uint8Array {
  const k = new Uint8Array(32)
  new DataView(k.buffer).setUint32(28, ++keySeq)
  k[0] = 0x42
  return k
}

export interface BankOptions {
  readonly seed?: number
  /** Redeem fee per bill; default 0. */
  fee?: (amount: bigint) => bigint
}

export class FakeBank {
  readonly hub: FakeHub
  readonly wallets = new Map<string, BankWallet>()
  readonly hubGroup: Uint8Array
  readonly redeemed: { walletPubkey: string; invoice: string; amount: bigint }[] = []
  fee: (amount: bigint) => bigint
  /** Answers for one method, checked before the bank's own; return undefined to fall through. */
  override: ((method: string, info: RequestInfo) => Answer | undefined) | undefined
  /** Applies the call but loses the answer: the "landed, reply lost" case. */
  loseReplyFor = new Set<string>()
  /** Every request_id ever used on this node (NIP-CASH §`request_id`): never dropped. */
  readonly usedIds = new Set<string>()
  /** The record of each committed call, by request_id. */
  readonly records = new Map<string, { readonly target: string; readonly authorizer: string; readonly result: unknown }>()
  /** Cash Hub connections served over NIP-47, by connection pubkey. */
  readonly cashHubs = new Map<string, { readonly walletKey: Uint8Array; readonly client: string }>()
  /** How the Cash Hub connections answer get_info. */
  cashHubInfo: { pubkey?: string; network?: string | null; chain?: string | null } = {}
  /** Mints but loses the reply. */
  loseMintReply = false
  /** The `withdraw` terms `cash_status` reports; undefined: withdrawals not offered. */
  withdrawTerms: Record<string, unknown> | undefined

  constructor(
    pool: MemoryRelayPool,
    relays: readonly string[],
    o: BankOptions = {},
  ) {
    this.hub = new FakeHub(pool, relays, o.seed ?? 0x0a)
    this.hubGroup = hubGroupFor(this.hub.inbox)
    this.fee = o.fee ?? (() => 0n)
    this.hub.handler = (method, info) => {
      const a = this.override?.(method, info) ?? this.handle(method, info)
      if (this.loseReplyFor.has(method)) return 'omit'
      return a
    }
  }

  start(): Promise<void> {
    return this.hub.start()
  }

  private now(): number {
    return Math.floor(this.hub.clock() / 1000)
  }

  /** Mints a live wallet for `to` and returns its token. */
  mint(amount: bigint, to: Identity, o: { expiresAt?: number } = {}): BankWallet {
    const walletKey = nextKey()
    const connSecret = nextKey()
    const token = this.hub.mintBill({ walletKey, connSecret, amount, hubGroup: this.hubGroup, identityRequired: to.type !== 'cash' })
    const w: BankWallet = {
      walletKey,
      walletPubkey: getPublicKey(walletKey),
      connSecret,
      token,
      identity: to,
      amount,
      history: 1,
      spent: false,
      ...(o.expiresAt !== undefined && { expiresAt: o.expiresAt }),
    }
    this.wallets.set(w.walletPubkey, w)
    return w
  }

  mintToPubkey(amount: bigint, pubkey: string, o: { expiresAt?: number } = {}): BankWallet {
    return this.mint(amount, { type: 'pubkey', value: pubkey }, o)
  }

  mintToCash(amount: bigint, secretHex: string, o: { expiresAt?: number } = {}): BankWallet {
    return this.mint(amount, { type: 'cash', value: commitment(secretHex) }, o)
  }

  wallet(token: string): BankWallet | undefined {
    for (const w of this.wallets.values()) if (w.token === token.toLowerCase() || w.token === token) return w
    return undefined
  }

  /** Live (unspent) value per identity value, for assertions. */
  balanceOf(identityValue: string): bigint {
    let s = 0n
    for (const w of this.wallets.values()) if (!w.spent && w.identity.value === identityValue) s += w.amount
    return s
  }

  // ---- methods

  private handle(method: string, info: RequestInfo): Answer {
    if (method === 'cash_lookup') return this.lookup(info)
    const w = this.wallets.get(info.item.target)
    if (w === undefined) return 'omit'
    if (w.spent && method === 'cash_status') return { result: { status: 'spent', reason: 'transferred' } }
    if (w.spent) return { error: { code: 'NOT_FOUND', message: 'this slice has already been claimed' } }
    if (w.expiresAt !== undefined && w.expiresAt <= this.now()) return { error: { code: 'EXPIRED', message: 'this cash wallet has expired' } }
    const idBearing = method === 'cash_transfer' || method === 'cash_consolidate'
    const rid = info.params['request_id']
    if (idBearing && (typeof rid !== 'string' || !/^(?:[0-9a-f]{2}){16,32}$/.test(rid))) return { error: { code: 'BAD_REQUEST', message: 'request_id is required' } }
    if (idBearing && this.usedIds.has(rid as string)) return { error: { code: 'REQUEST_REUSED', message: 'request_id already used' } }
    const denied = this.authenticate(w, info)
    if (denied !== undefined) return denied
    if (idBearing) this.usedIds.add(rid as string)
    const record = (a: Answer): Answer => {
      if (typeof a === 'object' && 'result' in a) {
        const secret = info.params['cash_secret']
        this.records.set(rid as string, { target: info.item.target, authorizer: info.signer ?? (typeof secret === 'string' ? commitment(secret) : ''), result: a.result })
      }
      return a
    }
    switch (method) {
      case 'cash_status':
        return { result: { recipients: [this.row(w)], ...(this.withdrawTerms !== undefined && { withdraw: this.withdrawTerms }) } }
      case 'cash_transfer':
        return record(this.transfer(w, info))
      case 'cash_consolidate':
        return record(this.consolidate(w, info))
      case 'cash_redeem':
        return this.redeem(w, info)
      default:
        return { error: { code: 'NOT_IMPLEMENTED' } }
    }
  }

  /**
   * Who is calling: the cash secret, or the slice proof's signer. The
   * refusals are lokihub's, word for word (nip47/private_dispatch.go at
   * 281790fa): the same answer for every method.
   */
  private authenticate(w: BankWallet, info: RequestInfo): Answer | undefined {
    const p = info.params
    if (w.identity.type === 'cash') {
      const secret = p['cash_secret']
      if (info.item.method === 'cash_status') {
        // Served on the bill proof alone; a secret here is refused.
        return secret === undefined ? undefined : { error: { code: 'BAD_REQUEST', message: 'a cash-mode status item carries no cash secret' } }
      }
      if (typeof secret !== 'string' || secret === '') return { error: { code: 'BAD_REQUEST', message: 'this item carries neither a slice proof nor a cash secret' } }
      if (commitment(secret) !== w.identity.value) return { error: { code: 'NOT_FOUND', message: 'no slice of this bill matches this cash secret' } }
      return undefined
    }
    if (info.signer !== w.identity.value) return { error: { code: 'NOT_FOUND', message: 'no slice of this bill is registered for the identity that signed this item' } }
    return undefined
  }

  private row(w: BankWallet) {
    const fee = this.fee(w.amount)
    return {
      identity_type: w.identity.type,
      identity_value: w.identity.value,
      amount_millis: w.amount,
      claimed: w.claimed === true,
      redeem_fee_millis: fee,
      net_redeemable_millis: w.amount - fee,
      min_transfer_millis: 0,
      ...(w.expiresAt !== undefined && { expires_at: w.expiresAt }),
    }
  }

  /** A token delivered to the caller: NIP-44 to a signing caller, plain to a cash one. */
  private deliver(newWallet: BankWallet, to: Identity): string {
    if (to.type === 'cash') return newWallet.token
    return nip44.encrypt(newWallet.token, nip44.getConversationKey(newWallet.walletKey, to.value))
  }

  private spinOff(amount: bigint, to: Identity, expiresAt: number | undefined): BankWallet {
    return this.mint(amount, to, expiresAt !== undefined ? { expiresAt } : {})
  }

  private transfer(w: BankWallet, info: RequestInfo): Answer {
    const p = info.params
    const ni = p['new_identity'] as { identity_type: string; identity_value?: string } | undefined
    if (ni === undefined || ni.identity_value === undefined) return { error: { code: 'BAD_REQUEST', message: 'new_identity is required' } }
    const to = { type: ni.identity_type, value: ni.identity_value } as Identity
    const caller = w.identity
    const split = p['amount_millis'] === undefined ? undefined : BigInt(p['amount_millis'] as number)
    if (split !== undefined && (split <= 0n || split > w.amount)) return { error: { code: 'BAD_REQUEST', message: 'amount_millis out of range' } }
    const partial = split !== undefined && split < w.amount
    const rc = p['remainder_commitment']
    if (partial && caller.type === 'cash') {
      if (typeof rc !== 'string' || !/^[0-9a-f]{64}$/.test(rc) || rc === caller.value) return { error: { code: 'BAD_REQUEST', message: 'a split of a cash slice needs a fresh remainder_commitment' } }
    } else if (rc !== undefined) return { error: { code: 'BAD_REQUEST', message: 'remainder_commitment is only for a split of a cash slice' } }
    if (split !== undefined && split < w.amount) {
      w.spent = true
      const carved = this.spinOff(split, to, w.expiresAt)
      const rest = this.spinOff(w.amount - split, caller.type === 'cash' ? { type: 'cash', value: rc as string } : caller, w.expiresAt)
      return {
        result: {
          amount_millis: split,
          identity_type: to.type,
          identity_value: to.value,
          remaining_amount_millis: w.amount - split,
          new_wallet_pubkey: carved.walletPubkey,
          new_wallet_token: this.deliver(carved, caller),
          remainder_wallet_pubkey: rest.walletPubkey,
          remainder_wallet_token: this.deliver(rest, caller),
        },
      }
    }
    if (to.type === 'cash' && w.history > 1) {
      w.spent = true
      const moved = this.spinOff(w.amount, to, w.expiresAt)
      return {
        result: {
          amount_millis: w.amount,
          identity_type: to.type,
          identity_value: to.value,
          new_wallet_pubkey: moved.walletPubkey,
          new_wallet_token: this.deliver(moved, caller),
        },
      }
    }
    // In place: same wallet and token, new identity.
    w.identity = to
    w.history++
    return { result: { amount_millis: w.amount, identity_type: to.type, identity_value: to.value } }
  }

  private consolidate(_dial: BankWallet, info: RequestInfo): Answer {
    const p = info.params
    const sources = p['sources'] as { wallet_pubkey: string; identity_type?: string; identity_value?: string; identity_event?: string; cash_secret?: string }[]
    const ni = p['new_identity'] as { identity_type: string; identity_value?: string }
    if (!Array.isArray(sources) || sources.length < 2) return { error: { code: 'BAD_REQUEST', message: 'cash_consolidate needs at least two sources' } }
    const ws: BankWallet[] = []
    for (const s of sources) {
      const w = this.wallets.get(s.wallet_pubkey)
      if (w === undefined) return { error: { code: 'BAD_REQUEST', message: 'every source must be a wallet on the same Cash Hub' } }
      if (w.spent) return { error: { code: 'NOT_FOUND', message: 'a source has already been claimed' } }
      if (w.identity.type === 'cash' || s.cash_secret !== undefined) return { error: { code: 'BAD_REQUEST', message: 'a cash-mode slice cannot be consolidated' } }
      let ev: NostrEvent
      try {
        ev = JSON.parse(s.identity_event ?? '') as NostrEvent
      } catch {
        return { error: { code: 'BAD_REQUEST', message: 'bad identity_event' } }
      }
      if (!verifyEvent(ev) || ev.pubkey !== w.identity.value || s.identity_value !== w.identity.value) {
        return { error: { code: 'NOT_FOUND', message: 'no unclaimed slice for this identity' } }
      }
      if (ws.includes(w)) return { error: { code: 'BAD_REQUEST', message: 'a source appears twice' } }
      ws.push(w)
    }
    let sum = 0n
    let expiresAt: number | undefined
    for (const w of ws) {
      w.spent = true
      sum += w.amount
      if (w.expiresAt !== undefined) expiresAt = expiresAt === undefined ? w.expiresAt : Math.min(expiresAt, w.expiresAt)
    }
    const to = { type: ni.identity_type, value: ni.identity_value ?? '' } as Identity
    const merged = this.spinOff(sum, to, expiresAt)
    const first = ws[0]!.identity
    return {
      result: {
        amount_millis: sum,
        new_wallet_pubkey: merged.walletPubkey,
        new_wallet_token: to.type === 'pubkey' ? this.deliver(merged, first) : merged.token,
        ...(expiresAt !== undefined && { expires_at: expiresAt }),
      },
    }
  }

  /**
   * cash_lookup (NIP-CASH §Looking Up a Call): served for any target this
   * node knows, destroyed bills included; a record is answered `done` to its
   * recorded authorizer and target only; without one the status follows the
   * deadline. Pure: it changes nothing.
   */
  private lookup(info: RequestInfo): Answer {
    const target = info.item.target
    if (!this.wallets.has(target) && !this.cashHubs.has(target)) return 'omit'
    const p = info.params
    const rid = p['request_id']
    const deadline = p['deadline']
    const secret = p['cash_secret']
    if (typeof rid !== 'string' || typeof deadline !== 'number') return { error: { code: 'BAD_REQUEST', message: 'lookup needs request_id and deadline' } }
    const rec = this.records.get(rid)
    if (rec !== undefined) {
      if (rec.target !== target) return { error: { code: 'UNAUTHORIZED', message: 'not this call' } }
      const by = info.signer ?? (typeof secret === 'string' ? commitment(secret) : undefined)
      if (by !== rec.authorizer) return { error: { code: 'UNAUTHORIZED', message: 'not this call' } }
      return { result: { status: 'done', result: rec.result } }
    }
    if (info.signer === undefined && typeof secret === 'string') {
      const w = this.wallets.get(target)
      if (w === undefined || w.identity.value !== commitment(secret)) return { error: { code: 'UNAUTHORIZED', message: 'secret does not match' } }
    }
    const d = decideLookup({ now: this.now(), deadline, horizon: this.hub.maxRequestAge ?? 300, hasRecord: false })
    return { result: typeof d === 'string' ? { status: d } : { status: 'pending', retry_after: d.retryAfter } }
  }

  /**
   * A Cash Hub connection served over NIP-47 (`get_info`, `mint_cash`), its
   * `cashhub1` signed by the node identity. Returns the string.
   */
  openCashHub(): string {
    const walletKey = nextKey()
    const clientSecret = nextKey()
    const wallet = getPublicKey(walletKey)
    const client = getPublicKey(clientSecret)
    this.cashHubs.set(wallet, { walletKey, client })
    this.hub.bills.set(wallet, client)
    this.hub.pool.subscribe(this.hub.relayUrls, { kinds: [23194], '#p': [wallet] }, {
      onEvent: (e: NostrEvent, relay: string) => void this.serveCashHub(e, relay, walletKey),
      onEose: () => {},
    })
    return encodeCashHubConnection(
      signCashHubConnection({ walletPubkey: wallet, secret: toHex(clientSecret), relays: this.hub.relayUrls, label: 'Fake Cash Hub', hubIdentity: this.hub.node, chain: 'bitcoin' }, this.hub.nodeKey),
    )
  }

  private async serveCashHub(e: NostrEvent, relay: string, walletKey: Uint8Array): Promise<void> {
    const wallet = getPublicKey(walletKey)
    const hubConn = this.cashHubs.get(wallet)!
    if (e.pubkey !== hubConn.client || !verifyEvent(e)) return
    const ck = nip44.getConversationKey(walletKey, e.pubkey)
    const req = JSON.parse(nip44.decrypt(e.content, ck)) as { method: string; params?: Record<string, unknown> }
    const answer = this.cashHubAnswer(req.method, req.params ?? {}, e)
    if (req.method === 'mint_cash' && this.loseMintReply) return
    const body = JSON.stringify({ result_type: req.method, ...answer }, (_k, v) => (typeof v === 'bigint' ? Number(v) : v))
    const reply = finalizeEvent({ kind: 23195, created_at: e.created_at, tags: [['p', e.pubkey], ['e', e.id], ['encryption', 'nip44_v2']], content: nip44.encrypt(body, ck) }, walletKey)
    await this.hub.pool.publish(relay, reply).catch(() => undefined)
  }

  private cashHubAnswer(method: string, p: Record<string, unknown>, e: NostrEvent): { result?: unknown; error?: { code: string; message: string } } {
    const i = this.cashHubInfo
    if (method === 'get_info') {
      return {
        result: {
          pubkey: i.pubkey ?? this.hub.node,
          ...(i.network !== null && { network: i.network ?? 'mainnet' }),
          ...(i.chain !== null && { chain: i.chain ?? 'bitcoin' }),
          methods: ['get_info', 'mint_cash'],
          private_methods: ['cash_lookup'],
        },
      }
    }
    if (method !== 'mint_cash') return { error: { code: 'NOT_IMPLEMENTED', message: method } }
    const rid = p['request_id']
    if (typeof rid !== 'string' || !/^(?:[0-9a-f]{2}){16,32}$/.test(rid)) return { error: { code: 'BAD_REQUEST', message: 'request_id is required' } }
    if (this.usedIds.has(rid)) return { error: { code: 'REQUEST_REUSED', message: 'request_id already used' } }
    this.usedIds.add(rid)
    const exp = Number(e.tags.find((t) => t[0] === 'expiration')?.[1] ?? NaN)
    if (!Number.isFinite(exp) || exp < this.now() || exp > this.now() + (this.hub.maxRequestAge ?? 0)) return { error: { code: 'BAD_REQUEST', message: 'expiration is missing or out of range' } }
    const r = (p['recipients'] as { identity_type: string; identity_value: string; amount_millis: number }[] | undefined)?.[0]
    if (r === undefined) return { error: { code: 'BAD_REQUEST', message: 'recipients' } }
    const w = this.mint(BigInt(r.amount_millis), { type: r.identity_type, value: r.identity_value } as Identity)
    const result = { wallet_pubkey: w.walletPubkey, cash_token: w.token, recipients: [{ identity_type: r.identity_type, identity_value: r.identity_value, amount_millis: r.amount_millis }] }
    this.records.set(rid, { target: getPublicKey(this.cashHubs.get(e.tags.find((t) => t[0] === 'p')![1]!)!.walletKey), authorizer: e.pubkey, result })
    return { result }
  }

  private redeem(w: BankWallet, info: RequestInfo): Answer {
    const invoice = info.params['invoice']
    if (typeof invoice !== 'string') return { error: { code: 'BAD_REQUEST', message: 'invoice is required' } }
    const fee = this.fee(w.amount)
    w.spent = true
    this.redeemed.push({ walletPubkey: w.walletPubkey, invoice, amount: w.amount })
    return { result: { preimage: '00'.repeat(32), fees_paid: fee } }
  }
}
