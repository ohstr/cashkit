// On-chain withdrawals on a FakeBank (NIP-CASH §Redeeming On-chain), for
// wallet tests: quotes and receipts signed by the node identity, the call,
// its lookups, a cancel request, and helpers that move a payout through its
// states (`broadcast`, `confirm`, `finalize`, `cancel` with its re-mint).
// Test support only.
import { sha256 } from '@noble/hashes/sha2.js'
import {
  decideLookup,
  decodeWitnessAddress,
  finalizeEvent,
  nip44,
  parseTx,
  requestHash,
  toHex,
  txid,
  verifyEvent,
  witnessScript,
  withdrawFee,
  type NostrEvent,
} from '../src/core/index.js'
import type { BankWallet, FakeBank, Identity } from './fakeBank.js'
import type { Answer, RequestInfo } from './fakeHub.js'

export const TERMS = { withdraw_fee_base: 500_000, withdraw_fee_ppm: 2000, min_millis: 1_000_000, max_millis: 10_000_000_000, script_types: [[0, 20], [0, 32], [1, 32]], final_depth: 6 }
/** BIP-173's example mainnet P2WPKH address. */
export const PAYTO = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
const commitment = (secretHex: string) => toHex(sha256(Uint8Array.from(secretHex.match(/../g)!.map((b) => parseInt(b, 16)))))

export interface FakePayout {
  readonly rid: string
  readonly w: BankWallet
  readonly authorizer: string
  readonly remintTo: Identity
  readonly address: string
  readonly amount: bigint
  readonly fee: bigint
  readonly payout: bigint
  readonly sentBy: number
  readonly notify: string
  readonly receipt: string
  readonly relay: string
  state: 'queued' | 'broadcast' | 'confirmed' | 'final' | 'cancelled'
  signed: boolean
  tx?: string
  txid?: string
  depth?: number
  newWallet?: { pubkey: string; token: string }
}

const u32le = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255]
const u64le = (v: bigint) => Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(8 * i)) & 255n))

/** A one-input, one-output transaction paying `sats` to `address`. */
export function payoutTx(address: string, sats: bigint): string {
  const w = decodeWitnessAddress(address, address.slice(0, address.lastIndexOf('1')))
  const script = witnessScript(w.version, w.program)
  return toHex(Uint8Array.from([...u32le(2), 1, ...Array.from({ length: 32 }, () => 7), ...u32le(0), 0, ...u32le(0xffffffff), 1, ...u64le(sats), script.length, ...script, ...u32le(0)]))
}

export class FakeWithdraw {
  readonly payouts = new Map<string, FakePayout>()
  networkFee = 1_200_000n
  /** Answer a quote with this refusal (code and detail). */
  refuseQuote: { code: string; detail?: string } | undefined

  constructor(readonly bank: FakeBank) {
    bank.withdrawTerms = TERMS
    const prev = bank.override
    bank.override = (m, info) => this.handle(m, info) ?? prev?.(m, info)
  }

  private get now(): number {
    return Math.floor(this.bank.hub.clock() / 1000)
  }

  private sign(kind: number, tags: string[][]): string {
    return JSON.stringify(finalizeEvent({ kind, created_at: this.now, tags, content: '' }, this.bank.hub.nodeKey))
  }

  private handle(method: string, info: RequestInfo): Answer | undefined {
    const p = info.params as Record<string, unknown>
    if (method === 'cash_lookup' && typeof p['request_id'] === 'string' && this.payouts.has(p['request_id'])) return this.lookup(info, this.payouts.get(p['request_id'])!)
    if (method !== 'cash_withdraw_quote' && method !== 'cash_withdraw') return undefined
    const w = this.bank.wallets.get(info.item.target)
    if (w === undefined) return 'omit'
    if (method === 'cash_withdraw' && p['cancel'] === true) return this.cancelRequest(info, w)
    if (w.spent) return { error: { code: 'RESTRICTED', message: 'claimed' } }
    // Who asks: the slice's signer, or for a cash slice the bill proof alone (quote) or its secret (call).
    if (w.identity.type === 'connection_key') {
      // A connection-key slice: the attestation by the recorded IA names the signer.
      let att: NostrEvent | undefined
      try {
        att = JSON.parse(p['attestation_event'] as string) as NostrEvent
      } catch {
        att = undefined
      }
      const tag = (n: string) => att?.tags.find((t) => t[0] === n)?.[1]
      if (att === undefined || !verifyEvent(att) || att.pubkey !== w.identity.ia || tag('d') !== w.identity.value || tag('p') !== info.signer || p['identity_value'] !== w.identity.value) {
        return { error: { code: 'NOT_FOUND', message: 'no slice for this signer' } }
      }
    } else if (w.identity.type !== 'cash' && info.signer !== w.identity.value) return { error: { code: 'NOT_FOUND', message: 'no slice for this signer' } }
    if (method === 'cash_withdraw_quote') return this.quote(w, p)
    return this.withdraw(info, w, p)
  }

  private quote(w: BankWallet, p: Record<string, unknown>): Answer {
    if ('cash_secret' in p || 'proof' in p) return { error: { code: 'BAD_REQUEST', message: 'a quote carries no secret' } }
    if (this.refuseQuote !== undefined) return { error: { code: this.refuseQuote.code, message: 'refused', ...(this.refuseQuote.detail !== undefined && { detail: this.refuseQuote.detail }) } }
    const address = p['address'] as string
    const { hubFee, fee, payout } = withdrawFee(w.amount, this.networkFee, BigInt(TERMS.withdraw_fee_base), BigInt(TERMS.withdraw_fee_ppm), this.bank.fee(w.amount))
    const sentBy = this.now + 3600
    const sendBefore = p['send_before']
    if (typeof sendBefore === 'number' && sendBefore < sentBy) return { error: { code: 'RESTRICTED', message: 'too slow', detail: 'too_slow' } }
    const fields = { amount_millis: w.amount, network_fee_millis: this.networkFee, hub_fee_millis: hubFee, payout_millis: payout, sent_by: sentBy, holds_until: 870413 }
    const i = w.identity.type === 'connection_key' ? ['i', w.identity.value, w.identity.ia] : ['i', w.identity.value]
    const quote = this.sign(23187, [['d', w.walletPubkey], i, ['address', address], ...Object.entries(fields).map(([k, v]) => [k, String(v)])])
    return { result: { quote, address, ...fields, fee_millis: fee } }
  }

  private withdraw(info: RequestInfo, w: BankWallet, p: Record<string, unknown>): Answer {
    const rid = p['request_id']
    if (typeof rid !== 'string') return { error: { code: 'BAD_REQUEST', message: 'request_id' } }
    if (this.bank.usedIds.has(rid)) return { error: { code: 'REQUEST_REUSED', message: 'used' } }
    let authorizer = w.identity.value
    if (w.identity.type === 'cash') {
      const s = p['cash_secret']
      if (typeof s !== 'string' || commitment(s) !== w.identity.value) return { error: { code: 'NOT_FOUND', message: 'no slice for this secret' } }
      if (typeof p['remint_commitment'] !== 'string' || p['remint_commitment'] === w.identity.value) return { error: { code: 'BAD_REQUEST', message: 'remint_commitment' } }
      authorizer = w.identity.value
    } else if ('remint_commitment' in p) return { error: { code: 'BAD_REQUEST', message: 'remint_commitment' } }
    else if (w.identity.type === 'connection_key') authorizer = info.signer ?? ''
    this.bank.usedIds.add(rid)
    let q: NostrEvent
    try {
      q = JSON.parse(p['quote'] as string) as NostrEvent
    } catch {
      return { error: { code: 'BAD_REQUEST', message: 'quote' } }
    }
    const tag = (k: string) => q.tags.find((t) => t[0] === k)?.[1] ?? ''
    if (!verifyEvent(q) || q.pubkey !== this.bank.hub.node || tag('d') !== w.walletPubkey) return { error: { code: 'RESTRICTED', message: 'quote', detail: 'quote_invalid' } }
    w.spent = true
    const payout = BigInt(tag('payout_millis'))
    const sentBy = Number(tag('sent_by'))
    const receipt = this.sign(23188, [['d', w.walletPubkey], ['q', q.id], ['request_hash', requestHash(rid)], ['address', tag('address')], ['payout_millis', String(payout)], ['sent_by', String(sentBy)]])
    const o: FakePayout = {
      rid,
      w,
      authorizer,
      remintTo: w.identity.type === 'cash' ? { type: 'cash', value: p['remint_commitment'] as string } : w.identity,
      address: tag('address'),
      amount: w.amount,
      fee: w.amount - payout,
      payout,
      sentBy,
      notify: p['notify'] as string,
      receipt,
      relay: this.bank.hub.relayUrls[0]!,
      state: 'queued',
      signed: false,
    }
    this.payouts.set(rid, o)
    return { result: this.json(o) }
  }

  json(o: FakePayout): Record<string, unknown> {
    const cancelled = o.state === 'cancelled'
    return {
      state: o.state,
      address: o.address,
      amount_millis: o.amount,
      fee_millis: o.fee,
      payout_millis: o.payout,
      sent_by: o.sentBy,
      final_depth: TERMS.final_depth,
      signed: o.signed,
      receipt: o.receipt,
      ...(!cancelled && o.tx !== undefined && { tx: o.tx }),
      ...(!cancelled && o.txid !== undefined && { txid: o.txid, vout: 0, depth: o.depth ?? 0 }),
      ...(cancelled && o.newWallet !== undefined && { new_wallet_pubkey: o.newWallet.pubkey, new_wallet_token: o.newWallet.token }),
    }
  }

  private authorized(info: RequestInfo, o: FakePayout): boolean {
    const secret = (info.params as Record<string, unknown>)['cash_secret']
    const by = info.signer ?? (typeof secret === 'string' ? commitment(secret) : undefined)
    return by === o.authorizer
  }

  private lookup(info: RequestInfo, o: FakePayout): Answer {
    if (!this.authorized(info, o)) return { error: { code: 'UNAUTHORIZED', message: 'not this call' } }
    return { result: { status: 'done', result: this.json(o) } }
  }

  private cancelRequest(info: RequestInfo, w: BankWallet): Answer {
    const o = this.payouts.get((info.params as Record<string, unknown>)['request_id'] as string)
    if (o === undefined || o.w !== w) return { error: { code: 'NOT_FOUND', message: 'no record' } }
    if (!this.authorized(info, o)) return { error: { code: 'UNAUTHORIZED', message: 'not this call' } }
    if (this.now < o.sentBy + 604800) return { error: { code: 'RESTRICTED', message: 'too early' } }
    this.cancel(o)
    return { result: this.json(o) }
  }

  only(): FakePayout {
    return [...this.payouts.values()][0]!
  }

  broadcast(o: FakePayout, tx = payoutTx(o.address, o.payout / 1000n)): void {
    o.signed = true
    o.tx = tx
    o.txid = txid(parseTx(tx))
    o.state = 'broadcast'
    o.depth = 0
  }

  confirm(o: FakePayout, depth: number): void {
    o.depth = depth
    o.state = depth >= TERMS.final_depth ? 'final' : 'confirmed'
  }

  /** Cancels and re-mints the whole amount for the slice's identity or the remint commitment. */
  cancel(o: FakePayout): void {
    const nw = this.bank.mint(o.amount, o.remintTo)
    const to = o.remintTo.type === 'connection_key' ? o.authorizer : o.remintTo.value
    const token = o.remintTo.type === 'cash' ? nw.token : nip44.encrypt(nw.token, nip44.getConversationKey(nw.walletKey, to))
    o.newWallet = { pubkey: nw.walletPubkey, token }
    o.state = 'cancelled'
    delete o.tx
    delete o.txid
    delete o.depth
  }

  async notice(o: FakePayout): Promise<void> {
    const ev = finalizeEvent({ kind: 23189, created_at: this.now, tags: [['p', o.notify]], content: '' }, crypto.getRandomValues(new Uint8Array(32)))
    await this.bank.hub.pool.publish(o.relay, ev).catch(() => undefined)
  }

  decideLookupFor(deadline: number): unknown {
    return decideLookup({ now: this.now, deadline, horizon: this.bank.hub.maxRequestAge ?? 300, hasRecord: false })
  }
}
