// On-chain withdrawals (NIP-CASH §Redeeming On-chain): the fee, the quote
// and its checks, the call, its receipt, the payout and a cancel request.
import { sha256 } from '@noble/hashes/sha2.js'
import { toHex } from './bytes.js'
import { buildProof, eventJSON } from './claim.js'
import { CoreError } from './errors.js'
import { MAX_FEE_PPM } from './fees.js'
import type { Credential } from './identity.js'
import { tokenOrTombstone } from './lookup.js'
import { getEventHash, verifyEvent, type NostrEvent } from './nip01.js'
import { isRequestId } from './requestId.js'
import type { Tombstone } from './results.js'

export { validateWithdrawTerms, type WithdrawTerms } from './withdrawTerms.js'

// ---- the calls (NIP-CASH §Quoting a Withdrawal … §Cancelling a Payout).
// Port of nmilat nipcash/withdraw_{quote,fee,request,receipt,payout,detail}.go.

export const METHOD_CASH_WITHDRAW_QUOTE = 'cash_withdraw_quote'
export const METHOD_CASH_WITHDRAW = 'cash_withdraw'
export const KIND_WITHDRAW_QUOTE = 23187
export const KIND_WITHDRAW_RECEIPT = 23188
/** A payout not broadcast by `sent_by` plus this is cancelled by the Hub. */
export const CANCEL_GRACE = 86400
/** A broadcast payout may be cancelled on request from `sent_by` plus this. */
export const CANCEL_REQUEST_AFTER = 604800

const HEX64 = /^[0-9a-f]{64}$/
const DEC = /^(0|[1-9][0-9]*)$/

/**
 * The fee (§The Withdraw Fee): `hub = base + ⌊ppm × amount / 10^6⌋`; `fee =
 * max(network + hub, redeemFee)`, capped at `amount`, raised so the payout
 * is whole base units; `payout = amount − fee`. Display and checks only.
 */
export function withdrawFee(amount: bigint, networkFee: bigint, base: bigint, ppm: bigint, redeemFee: bigint): { hubFee: bigint; fee: bigint; payout: bigint } {
  if (ppm > MAX_FEE_PPM || ppm < 0n) throw new CoreError('withdraw_fee_invalid', 'withdraw_fee_ppm must be from 0 to 1000000')
  const hubFee = base + (ppm * amount) / 1_000_000n
  let fee = networkFee + hubFee > redeemFee ? networkFee + hubFee : redeemFee
  if (fee > amount) fee = amount
  const rem = (amount - fee) % 1000n
  if (rem !== 0n) fee += rem
  return { hubFee, fee, payout: amount - fee }
}

/** The quote params: the address, an optional `send_before`, and a connection-key slice's identity. Never a proof or a secret. */
export function cashWithdrawQuoteRequest(p: { address: string; sendBefore?: number; connectionKey?: { identityValue: string; iaPubkey: string; attestationEvent: string } }): Record<string, unknown> {
  return {
    address: p.address,
    ...(p.sendBefore !== undefined && { send_before: p.sendBefore }),
    ...(p.connectionKey !== undefined && { identity_value: p.connectionKey.identityValue, ia_pubkey: p.connectionKey.iaPubkey, attestation_event: p.connectionKey.attestationEvent }),
  }
}

/** A kind-23187 quote event, its tags read. Structure only: see `verifyWithdrawQuote`. */
export interface WithdrawQuote {
  readonly event: NostrEvent
  readonly id: string
  readonly wallet: string
  readonly identityValue: string
  readonly iaPubkey?: string
  readonly address: string
  readonly amountMillis: bigint
  readonly networkFeeMillis: bigint
  readonly hubFeeMillis: bigint
  readonly payoutMillis: bigint
  readonly sentBy: number
  readonly holdsUntil: number
}

export const quoteFeeMillis = (q: Pick<WithdrawQuote, 'amountMillis' | 'payoutMillis'>): bigint => q.amountMillis - q.payoutMillis

const QUOTE_TAGS = ['d', 'i', 'address', 'amount_millis', 'network_fee_millis', 'hub_fee_millis', 'payout_millis', 'sent_by', 'holds_until'] as const
const RECEIPT_TAGS = ['d', 'q', 'request_hash', 'address', 'payout_millis', 'sent_by'] as const

function parseEventText(raw: string, code: 'quote_malformed' | 'receipt_invalid', what: string): NostrEvent {
  let e: unknown
  try {
    e = JSON.parse(raw)
  } catch {
    throw new CoreError(code, `${what} is not JSON`)
  }
  if (e === null || typeof e !== 'object' || Array.isArray(e)) throw new CoreError(code, `${what} is not an event`)
  const x = e as NostrEvent
  if (typeof x.id !== 'string' || typeof x.pubkey !== 'string' || typeof x.sig !== 'string' || typeof x.kind !== 'number' || typeof x.created_at !== 'number' || !Array.isArray(x.tags) || typeof x.content !== 'string') throw new CoreError(code, `${what} is not an event`)
  return x
}

function tagsOnce(e: NostrEvent, names: readonly string[], code: 'quote_malformed' | 'receipt_invalid', what: string): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  for (const t of e.tags) {
    if (!Array.isArray(t) || typeof t[0] !== 'string') throw new CoreError(code, `${what}: a malformed tag`)
    if (!names.includes(t[0])) throw new CoreError(code, `${what}: an unexpected tag ${t[0]}`)
    if (t[0] in out) throw new CoreError(code, `${what}: tag ${t[0]} repeated`)
    out[t[0]] = t
  }
  for (const n of names) if (!(n in out)) throw new CoreError(code, `${what}: missing tag ${n}`)
  return out
}

const decimal = (v: string | undefined, code: 'quote_malformed' | 'receipt_invalid', what: string): bigint => {
  if (v === undefined || !DEC.test(v)) throw new CoreError(code, `${what} is not an unsigned decimal`)
  return BigInt(v)
}

/** Reads a quote event's structure: kind 23187, the nine tags each once in any order, decimals without leading zeros, empty content. */
export function parseWithdrawQuote(raw: string): WithdrawQuote {
  const e = parseEventText(raw, 'quote_malformed', 'the quote')
  if (e.kind !== KIND_WITHDRAW_QUOTE) throw new CoreError('quote_malformed', 'the quote is not kind 23187')
  if (e.content !== '') throw new CoreError('quote_malformed', 'the quote carries content')
  const t = tagsOnce(e, QUOTE_TAGS, 'quote_malformed', 'the quote')
  const i = t['i']!
  if (t['d']!.length !== 2 || !HEX64.test(t['d']![1]!) || i.length < 2 || i.length > 3 || !HEX64.test(i[1]!) || (i.length === 3 && !HEX64.test(i[2]!))) throw new CoreError('quote_malformed', 'the quote names no valid bill or slice')
  const n = (k: string) => decimal(t[k]![1], 'quote_malformed', `the quote's ${k}`)
  return {
    event: e,
    id: e.id,
    wallet: t['d']![1]!,
    identityValue: i[1]!,
    ...(i.length === 3 && { iaPubkey: i[2]! }),
    address: t['address']![1] ?? '',
    amountMillis: n('amount_millis'),
    networkFeeMillis: n('network_fee_millis'),
    hubFeeMillis: n('hub_fee_millis'),
    payoutMillis: n('payout_millis'),
    sentBy: Number(n('sent_by')),
    holdsUntil: Number(n('holds_until')),
  }
}

/** The quote's id recomputed under NIP-01, its signature, and its author the Hub identity (x-only). */
export function verifyWithdrawQuote(q: WithdrawQuote, hubXOnly: string): void {
  if (getEventHash(q.event) !== q.event.id || !verifyEvent(q.event) || q.event.pubkey !== hubXOnly) throw new CoreError('quote_mismatch', 'the quote is not signed by this Hub')
}

/** The quote answer's fields. */
export interface CashWithdrawQuoteResult {
  readonly quote: WithdrawQuote
  readonly address: string
  readonly amountMillis: bigint
  readonly networkFeeMillis: bigint
  readonly hubFeeMillis: bigint
  readonly feeMillis: bigint
  readonly payoutMillis: bigint
  readonly sentBy: number
  readonly holdsUntil: number
}

export function parseCashWithdrawQuoteResult(v: unknown): CashWithdrawQuoteResult {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new CoreError('quote_malformed', 'the quote answer is not an object')
  const o = v as Record<string, unknown>
  if (typeof o['quote'] !== 'string') throw new CoreError('quote_malformed', 'the answer carries no quote')
  const n = (k: string) => {
    const x = o[k]
    if (typeof x === 'number' && Number.isSafeInteger(x) && x >= 0) return BigInt(x)
    if (typeof x === 'bigint' && x >= 0n) return x
    throw new CoreError('quote_malformed', `the answer's ${k} is not a non-negative integer`)
  }
  return {
    quote: parseWithdrawQuote(o['quote']),
    address: typeof o['address'] === 'string' ? o['address'] : '',
    amountMillis: n('amount_millis'),
    networkFeeMillis: n('network_fee_millis'),
    hubFeeMillis: n('hub_fee_millis'),
    feeMillis: n('fee_millis'),
    payoutMillis: n('payout_millis'),
    sentBy: Number(n('sent_by')),
    holdsUntil: Number(n('holds_until')),
  }
}

const fail = (f: string): never => {
  throw new CoreError('quote_mismatch', `the quote's ${f} does not check out`)
}

/**
 * The checks a client makes of a quote answer: signed by the Hub, its tags
 * equal to the answer's fields, naming the slice and the address asked
 * about, `sent_by` within `send_before`; then `fee = amount − payout`, the
 * payout whole base units, the amount the slice's committed amount, and the
 * fee at least the slice's redeem fee when known. Any failure is
 * `quote_mismatch` naming the field, never its value.
 */
export function verifyQuoteAnswer(
  r: CashWithdrawQuoteResult,
  x: { hubXOnly: string; wallet: string; identityValue: string; iaPubkey?: string; address: string; sendBefore?: number; amountMillis?: bigint; redeemFeeMillis?: bigint },
): void {
  verifyWithdrawQuote(r.quote, x.hubXOnly)
  const q = r.quote
  if (q.wallet !== x.wallet) fail('bill')
  if (q.identityValue !== x.identityValue || q.iaPubkey !== x.iaPubkey) fail('slice')
  if (q.address !== x.address || r.address !== x.address) fail('address')
  if (q.amountMillis !== r.amountMillis || q.networkFeeMillis !== r.networkFeeMillis || q.hubFeeMillis !== r.hubFeeMillis || q.payoutMillis !== r.payoutMillis || q.sentBy !== r.sentBy || q.holdsUntil !== r.holdsUntil) fail('fields')
  if (x.sendBefore !== undefined && q.sentBy > x.sendBefore) fail('sent_by')
  if (r.feeMillis !== r.amountMillis - r.payoutMillis || r.payoutMillis > r.amountMillis) fail('fee')
  if (r.payoutMillis % 1000n !== 0n) fail('payout')
  if (x.amountMillis !== undefined && r.amountMillis !== x.amountMillis) fail('amount')
  if (x.redeemFeeMillis !== undefined && r.feeMillis < x.redeemFeeMillis) fail('fee')
}

/** Whether a quote still holds at a chain tip height (the Hub's call; the wallet knows no tip). */
export const quoteValidAt = (holdsUntil: number, tip: number): boolean => tip <= holdsUntil

/** The lowercase hex SHA-256 of the ASCII bytes of `request_id`, as a receipt binds it. */
export const requestHash = (requestId: string): string => toHex(sha256(new TextEncoder().encode(requestId)))

/** The `cash_withdraw` params: the quote, request id, notify, a cash slice's remint commitment, and the proof fields (`m`, `q`). */
export async function cashWithdrawRequest(p: { walletPubkey: string; quote: WithdrawQuote; credential: Credential; requestId: string; notify: string; remintCommitment?: string; sliceCommitment?: string; now?: number }): Promise<Record<string, unknown>> {
  if (!isRequestId(p.requestId)) throw new CoreError('invalid_request', 'request_id must be 16 to 32 bytes of lowercase hex')
  if (!HEX64.test(p.notify)) throw new CoreError('invalid_request', 'notify is 64 lowercase hex')
  const isCash = p.credential.kind === 'secret'
  if (isCash !== (p.remintCommitment !== undefined)) throw new CoreError('invalid_request', 'a cash-mode slice needs a remint commitment, and no other slice takes one')
  if (p.remintCommitment !== undefined && (!HEX64.test(p.remintCommitment) || p.remintCommitment === p.sliceCommitment)) throw new CoreError('invalid_request', 'the remint commitment must be fresh')
  const proof = await buildProof(p.credential, { method: 'cash_withdraw', walletPubkey: p.walletPubkey, quoteId: p.quote.id }, p.now)
  return { quote: eventJSON(p.quote.event), request_id: p.requestId, notify: p.notify, ...(p.remintCommitment !== undefined && { remint_commitment: p.remintCommitment }), ...proof }
}

/** A cancel request: exactly `cancel`, the original `request_id`, and a cash call's secret. */
export const cashWithdrawCancelRequest = (p: { requestId: string; cashSecret?: string }): Record<string, unknown> => ({ cancel: true, request_id: p.requestId, ...(p.cashSecret !== undefined && { cash_secret: p.cashSecret }) })

/**
 * Checks a receipt: kind 23188, its id and signature, author the Hub, and
 * every tag against the call as written ahead (`quoteId` `''` skips only the
 * `q` comparison, for a recovered call). Throws `receipt_invalid`.
 */
export function verifyWithdrawReceipt(raw: string, x: { hubXOnly: string; target: string; quoteId: string; requestId: string; address: string; payoutMillis: bigint; sentBy: number }): void {
  const e = parseEventText(raw, 'receipt_invalid', 'the receipt')
  if (e.kind !== KIND_WITHDRAW_RECEIPT) throw new CoreError('receipt_invalid', 'the receipt is not kind 23188')
  if (getEventHash(e) !== e.id || !verifyEvent(e) || e.pubkey !== x.hubXOnly) throw new CoreError('receipt_invalid', 'the receipt is not signed by this Hub')
  if (e.content !== '') throw new CoreError('receipt_invalid', 'the receipt carries content')
  const t = tagsOnce(e, RECEIPT_TAGS, 'receipt_invalid', 'the receipt')
  const v = (k: string) => t[k]![1]
  if (v('d') !== x.target) throw new CoreError('receipt_invalid', 'the receipt names another bill')
  if (x.quoteId !== '' && v('q') !== x.quoteId) throw new CoreError('receipt_invalid', 'the receipt names another quote')
  if (v('request_hash') !== requestHash(x.requestId)) throw new CoreError('receipt_invalid', 'the receipt names another request')
  if (v('address') !== x.address) throw new CoreError('receipt_invalid', 'the receipt names another address')
  if (decimal(v('payout_millis'), 'receipt_invalid', 'payout_millis') !== x.payoutMillis || Number(decimal(v('sent_by'), 'receipt_invalid', 'sent_by')) !== x.sentBy) throw new CoreError('receipt_invalid', 'the receipt names other amounts')
}

/** The receipt's `q`, for a recovered call. */
export function receiptQuoteId(raw: string): string {
  const e = parseEventText(raw, 'receipt_invalid', 'the receipt')
  return e.tags.find((t) => t[0] === 'q')?.[1] ?? ''
}

export const PAYOUT_STATES = ['queued', 'broadcast', 'confirmed', 'final', 'cancelled'] as const
export type PayoutState = (typeof PAYOUT_STATES)[number]

export interface Payout {
  readonly state: PayoutState
  readonly address: string
  readonly amountMillis: bigint
  readonly feeMillis: bigint
  readonly payoutMillis: bigint
  readonly sentBy: number
  readonly finalDepth: number
  readonly signed: boolean
  readonly receipt: string
  readonly tx?: string
  readonly txid?: string
  readonly vout?: number
  readonly depth?: number
  readonly newWalletPubkey?: string
  readonly newWalletToken?: string | Tombstone
}

const badPayout = (m: string) => new CoreError('invalid_payload', `cash_withdraw: ${m}`)

/** Reads a payout (§Response): an unknown state, a missing receipt, broadcast fields under `cancelled`, or re-mint fields elsewhere are malformed, never a state. */
export function parsePayout(v: unknown): Payout {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw badPayout('the payout is not an object')
  const o = v as Record<string, unknown>
  const state = o['state']
  if (!(PAYOUT_STATES as readonly unknown[]).includes(state)) throw badPayout(`unknown state ${String(state)}`)
  const n = (k: string): bigint => {
    const x = o[k]
    if (typeof x === 'number' && Number.isSafeInteger(x) && x >= 0) return BigInt(x)
    if (typeof x === 'bigint' && x >= 0n) return x
    throw badPayout(`${k} is not a non-negative integer`)
  }
  if (typeof o['receipt'] !== 'string' || o['receipt'] === '') throw badPayout('no receipt')
  if (typeof o['signed'] !== 'boolean') throw badPayout('signed is not a boolean')
  const cancelled = state === 'cancelled'
  if (cancelled && ('tx' in o || 'txid' in o || 'vout' in o || 'depth' in o)) throw badPayout('a cancelled payout carries broadcast fields')
  if (!cancelled && ('new_wallet_pubkey' in o || 'new_wallet_token' in o)) throw badPayout('re-mint fields outside cancelled')
  if (state !== 'queued' && !cancelled && typeof o['txid'] !== 'string') throw badPayout('a broadcast payout names its txid')
  let token: string | Tombstone | undefined
  if (cancelled && 'new_wallet_token' in o) {
    try {
      token = tokenOrTombstone(o['new_wallet_token'])
    } catch {
      throw badPayout('new_wallet_token is neither a token nor a tombstone')
    }
  }
  return {
    state: state as PayoutState,
    address: typeof o['address'] === 'string' ? o['address'] : '',
    amountMillis: n('amount_millis'),
    feeMillis: n('fee_millis'),
    payoutMillis: n('payout_millis'),
    sentBy: Number(n('sent_by')),
    finalDepth: Number(n('final_depth')),
    signed: o['signed'],
    receipt: o['receipt'],
    ...(typeof o['tx'] === 'string' && { tx: o['tx'] }),
    ...(typeof o['txid'] === 'string' && { txid: o['txid'] }),
    ...(o['vout'] !== undefined && { vout: Number(n('vout')) }),
    ...(o['depth'] !== undefined && { depth: Number(n('depth')) }),
    ...(typeof o['new_wallet_pubkey'] === 'string' && { newWalletPubkey: o['new_wallet_pubkey'] }),
    ...(token !== undefined && { newWalletToken: token }),
  }
}

export const payoutFinished = (p: Pick<Payout, 'state'>): boolean => p.state === 'final' || p.state === 'cancelled'

/** A refusal's `detail` (§Errors): one of the known values, else undefined. */
export const DETAILS = ['network', 'script_type', 'below_min', 'too_slow', 'quote_invalid', 'quote_expired', 'unfinal', 'own_address'] as const
export type Detail = (typeof DETAILS)[number]
export const parseDetail = (s: unknown): Detail | undefined => ((DETAILS as readonly unknown[]).includes(s) ? (s as Detail) : undefined)
