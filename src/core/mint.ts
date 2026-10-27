// mint_cash (NIP-CASH §Minting Cash): the request a Cash Hub's owner sends
// over its Cash Hub connection, and its result. Port of nmilat
// nipcash/mint_cash.go MintCashParams.Request and ParseResult.
import { CoreError } from './errors.js'
import { isCommitment } from './identity.js'
import { isRequestId } from './requestId.js'

const HEX64 = /^[0-9a-f]{64}$/
const MAX_U64 = (1n << 64n) - 1n
const badRequest = (msg: string) => new CoreError('invalid_request', `mint_cash: ${msg}`)
const badResult = (msg: string) => new CoreError('invalid_payload', `mint_cash result: ${msg}`)

export interface MintRecipient {
  readonly identityType: 'pubkey' | 'connection_key' | 'cash'
  /** A pubkey, connection key, or for `cash` the commitment of a secret the caller generated (and wrote ahead). */
  readonly identityValue: string
  /** `connection_key` only. */
  readonly iaPubkey?: string
  readonly amountMillis: bigint
}

export interface MintCashRequest {
  recipients: { identity_type: string; identity_value: string; ia_pubkey?: string; amount_millis: bigint }[]
  expiry?: number
  request_id: string
}

/**
 * The `mint_cash` params. At least one recipient; a `cash` recipient only
 * alone; no duplicate (type, value, ia); amounts positive and their sum
 * within uint64. `expirySeconds` undefined or 0 sends no `expiry` (the
 * Hub's ceiling). The request also needs a NIP-47 `expiration`, set by the
 * caller on the event.
 */
export function mintCashRequest(p: { recipients: readonly MintRecipient[]; expirySeconds?: number; requestId: string }): MintCashRequest {
  if (!isRequestId(p.requestId)) throw badRequest('request_id must be 16 to 32 bytes of lowercase hex')
  if (p.recipients.length === 0) throw badRequest('at least one recipient')
  const hasCash = p.recipients.some((r) => r.identityType === 'cash')
  if (hasCash && p.recipients.length !== 1) throw badRequest('a cash recipient must be the only recipient')
  const seen = new Set<string>()
  let sum = 0n
  const out: MintCashRequest['recipients'] = []
  for (const r of p.recipients) {
    const raw = r as unknown as Record<string, unknown>
    if ('cashSecret' in raw || 'cash_secret' in raw) throw badRequest('a recipient never carries a cash secret')
    if (typeof r.amountMillis !== 'bigint' || r.amountMillis <= 0n) throw badRequest('amount_millis must be positive')
    sum += r.amountMillis
    if (sum > MAX_U64) throw badRequest('the recipients add up to more than a uint64')
    switch (r.identityType) {
      case 'pubkey':
        if (!HEX64.test(r.identityValue)) throw badRequest('a pubkey recipient is 64 lowercase hex')
        if (r.iaPubkey !== undefined) throw badRequest('a pubkey recipient carries no ia_pubkey')
        break
      case 'connection_key':
        if (!HEX64.test(r.identityValue)) throw badRequest('a connection_key recipient is 64 lowercase hex')
        if (r.iaPubkey === undefined || !HEX64.test(r.iaPubkey)) throw badRequest('a connection_key recipient needs its ia_pubkey')
        break
      case 'cash':
        if (!isCommitment(r.identityValue)) throw badRequest('a cash recipient is a commitment of 64 lowercase hex')
        if (r.iaPubkey !== undefined) throw badRequest('a cash recipient carries no ia_pubkey')
        break
      default:
        throw badRequest(`unknown identity type ${String((r as MintRecipient).identityType)}`)
    }
    const key = `${r.identityType}\0${r.identityValue}\0${r.iaPubkey ?? ''}`
    if (seen.has(key)) throw badRequest('the same recipient twice')
    seen.add(key)
    out.push({ identity_type: r.identityType, identity_value: r.identityValue, ...(r.iaPubkey !== undefined && { ia_pubkey: r.iaPubkey }), amount_millis: r.amountMillis })
  }
  const e = p.expirySeconds
  if (e !== undefined && (typeof e !== 'number' || !Number.isSafeInteger(e) || e < 0)) throw badRequest('expiry must be a whole number of seconds')
  return { recipients: out, ...(e !== undefined && e > 0 && { expiry: e }), request_id: p.requestId }
}

export interface MintCashResult {
  readonly walletPubkey: string
  /** The new bill's credential. Never empty. */
  readonly cashToken: string
  /** Absent when the wallet never expires (0 and null read the same). */
  readonly expiresAt?: number
  readonly recipients: readonly { readonly identityType: string; readonly identityValue: string; readonly iaPubkey?: string; readonly amountMillis: bigint }[]
}

const amount = (v: unknown): bigint | undefined => {
  if (typeof v === 'bigint' && v >= 0n && v <= MAX_U64) return v
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v)
  return undefined
}

/**
 * Parses a `mint_cash` result against the request sent: the token alone is
 * the credential (any other field, a pairing URI included, is ignored); the
 * echoed recipients must match what was asked, and none may carry a secret.
 */
export function parseMintCashResult(result: unknown, sent: MintCashRequest): MintCashResult {
  if (result === null || typeof result !== 'object' || Array.isArray(result)) throw badResult('expected an object')
  const o = result as Record<string, unknown>
  const token = o['cash_token']
  if (typeof token !== 'string' || token === '') throw badResult('cash_token is empty')
  const wallet = o['wallet_pubkey']
  if (typeof wallet !== 'string' || !HEX64.test(wallet)) throw badResult('wallet_pubkey must be 64 lowercase hex')
  let expiresAt: number | undefined
  // A lookup's result is read with integers as bigints; a reply's as numbers.
  const raw0 = o['expires_at']
  const e = typeof raw0 === 'bigint' && raw0 >= 0n && raw0 <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(raw0) : raw0
  if (e !== undefined && e !== null) {
    if (typeof e !== 'number' || !Number.isSafeInteger(e) || e < 0) throw badResult('expires_at must be unix seconds')
    expiresAt = e === 0 ? undefined : e
  }
  const raw = o['recipients']
  if (!Array.isArray(raw)) throw badResult('recipients must be an array')
  if (raw.length !== sent.recipients.length) throw badResult('recipients do not echo the request')
  const recipients = raw.map((r, i) => {
    if (r === null || typeof r !== 'object' || Array.isArray(r)) throw badResult('a recipient must be an object')
    const x = r as Record<string, unknown>
    if ('cash_secret' in x) throw badResult('a recipient carries a cash secret')
    const want = sent.recipients[i]!
    const amt = amount(x['amount_millis'])
    if (x['identity_type'] !== want.identity_type || x['identity_value'] !== want.identity_value || (x['ia_pubkey'] ?? undefined) !== want.ia_pubkey || amt !== want.amount_millis) {
      throw badResult('recipients do not echo the request')
    }
    return { identityType: want.identity_type, identityValue: want.identity_value, ...(want.ia_pubkey !== undefined && { iaPubkey: want.ia_pubkey }), amountMillis: amt }
  })
  return { walletPubkey: wallet, cashToken: token, ...(expiresAt !== undefined && { expiresAt }), recipients }
}
