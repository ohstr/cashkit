// Results of cash_redeem, cash_transfer, cash_consolidate and cash_status.
// Port of nmilat nipcash's ParseResult methods. Input is the already-parsed
// JSON `result`; uint64 amounts may arrive as safe-integer numbers or as
// bigints from a precision-preserving parser, and are returned as bigint.
import type { ConsolidateSource, RecipientStatus } from './claim.js'
import { CoreError } from './errors.js'
import { decryptDelivery, type Credential, type Target } from './identity.js'

type Obj = Record<string, unknown>

const bad = (msg: string) => new CoreError('invalid_payload', msg)

function asObject(v: unknown, what: string): Obj {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw bad(`${what}: expected an object`)
  return v as Obj
}

/** A uint64 field; absent or null reads as 0, as Go's zero value. */
function u64(o: Obj, key: string, what: string): bigint {
  const v = o[key]
  if (v === undefined || v === null) return 0n
  if (typeof v === 'bigint' && v >= 0n && v < 1n << 64n) return v
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v)
  throw bad(`${what}: ${key} must be a non-negative integer`)
}

function optU64(o: Obj, key: string, what: string): bigint | undefined {
  return o[key] === undefined || o[key] === null ? undefined : u64(o, key, what)
}

function optInt(o: Obj, key: string, what: string): number | undefined {
  const v = o[key]
  if (v === undefined || v === null) return undefined
  if (typeof v === 'number' && Number.isSafeInteger(v)) return v
  if (typeof v === 'bigint' && v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(v)
  throw bad(`${what}: ${key} must be an integer`)
}

function str(o: Obj, key: string, what: string): string {
  const v = o[key]
  if (v === undefined || v === null) return ''
  if (typeof v !== 'string') throw bad(`${what}: ${key} must be a string`)
  return v
}

function bool(o: Obj, key: string, what: string): boolean {
  const v = o[key]
  if (v === undefined || v === null) return false
  if (typeof v !== 'boolean') throw bad(`${what}: ${key} must be a boolean`)
  return v
}

export interface CashRedeemResult {
  readonly preimage: string
  /** The recipient's own redeem fee, never the routing cost. */
  readonly feesPaid: bigint
}

export function parseCashRedeemResult(result: unknown): CashRedeemResult {
  const o = asObject(result, 'cash_redeem result')
  return { preimage: str(o, 'preimage', 'cash_redeem'), feesPaid: u64(o, 'fees_paid', 'cash_redeem') }
}

export interface CashTransferResult {
  readonly amountMillis: bigint
  readonly identityType: string
  readonly identityValue: string
  readonly remainingAmountMillis?: bigint
  readonly newWalletPubkey: string
  /** Decrypted; secret-bearing. "" when the bill moved in place. */
  readonly newWalletToken: string
  readonly remainderWalletPubkey: string
  /** Decrypted; secret-bearing. */
  readonly remainderWalletToken: string
}

/** Parses a cash_transfer result, decrypting delivered tokens with `credential`. */
export async function parseCashTransferResult(result: unknown, credential: Credential): Promise<CashTransferResult> {
  const o = asObject(result, 'cash_transfer result')
  const w = 'cash_transfer'
  const newWalletPubkey = str(o, 'new_wallet_pubkey', w)
  const remainderWalletPubkey = str(o, 'remainder_wallet_pubkey', w)
  const newToken = str(o, 'new_wallet_token', w)
  const remainderToken = str(o, 'remainder_wallet_token', w)
  const remaining = optU64(o, 'remaining_amount_millis', w)
  return {
    amountMillis: u64(o, 'amount_millis', w),
    identityType: str(o, 'identity_type', w),
    identityValue: str(o, 'identity_value', w),
    ...(remaining !== undefined && { remainingAmountMillis: remaining }),
    newWalletPubkey,
    newWalletToken: newToken === '' ? '' : await decryptDelivery(credential, newWalletPubkey, newToken),
    remainderWalletPubkey,
    remainderWalletToken: remainderToken === '' ? '' : await decryptDelivery(credential, remainderWalletPubkey, remainderToken),
  }
}

/**
 * The token the recipient now holds: the spun-off bill when there is one,
 * otherwise the original, which moved in place.
 */
export function recipientToken(r: Pick<CashTransferResult, 'newWalletToken'>, originalToken: string): string {
  return r.newWalletToken !== '' ? r.newWalletToken : originalToken
}

export interface CashConsolidateResult {
  readonly amountMillis: bigint
  readonly newWalletPubkey: string
  /** Decrypted for a pubkey target; as delivered otherwise. Secret-bearing. */
  readonly newWalletToken: string
  readonly expiresAt?: number
}

/**
 * Parses a cash_consolidate result. For a pubkey target the token is
 * decrypted with the first source's credential, as nmilat does; for a cash
 * or connection-key target it is passed through.
 */
export async function parseCashConsolidateResult(
  result: unknown,
  p: { readonly sources: readonly ConsolidateSource[]; readonly to: Target },
): Promise<CashConsolidateResult> {
  const o = asObject(result, 'cash_consolidate result')
  const w = 'cash_consolidate'
  const newWalletPubkey = str(o, 'new_wallet_pubkey', w)
  const token = str(o, 'new_wallet_token', w)
  const expiresAt = optInt(o, 'expires_at', w)
  const first = p.sources[0]
  let newWalletToken = token
  if (token !== '' && first !== undefined && p.to.identityType === 'pubkey') {
    try {
      newWalletToken = await decryptDelivery(first.credential, newWalletPubkey, token)
    } catch {
      throw bad("cash_consolidate: could not decrypt the consolidated wallet's token")
    }
  }
  return {
    amountMillis: u64(o, 'amount_millis', w),
    newWalletPubkey,
    newWalletToken,
    ...(expiresAt !== undefined && { expiresAt }),
  }
}

/** A full cash_status roster row. */
export interface RecipientStatusRow extends RecipientStatus {
  readonly claimed_at?: number
  readonly redeem_fee_millis: bigint
  readonly net_redeemable_millis: bigint
  readonly min_transfer_millis: bigint
  readonly expires_at?: number
}

export interface CashStatusResult {
  readonly recipients: readonly RecipientStatusRow[]
  /** "spent" when the bill's value has moved on. */
  readonly error: string
  readonly retainedUntil?: number
}

export const STATUS_SPENT = 'spent'

export function parseCashStatusResult(result: unknown): CashStatusResult {
  const o = asObject(result, 'cash_status result')
  const w = 'cash_status'
  const raw = o['recipients'] ?? []
  if (!Array.isArray(raw)) throw bad('cash_status: recipients must be an array')
  const recipients = raw.map((r): RecipientStatusRow => {
    const row = asObject(r, 'cash_status recipient')
    const claimedAt = optInt(row, 'claimed_at', w)
    const expiresAt = optInt(row, 'expires_at', w)
    const value = str(row, 'identity_value', w)
    return {
      identity_type: str(row, 'identity_type', w),
      ...(value !== '' && { identity_value: value }),
      amount_millis: u64(row, 'amount_millis', w),
      claimed: bool(row, 'claimed', w),
      ...(claimedAt !== undefined && { claimed_at: claimedAt }),
      redeem_fee_millis: u64(row, 'redeem_fee_millis', w),
      net_redeemable_millis: u64(row, 'net_redeemable_millis', w),
      min_transfer_millis: u64(row, 'min_transfer_millis', w),
      ...(expiresAt !== undefined && { expires_at: expiresAt }),
    }
  })
  const retainedUntil = optInt(o, 'retained_until', w)
  return { recipients, error: str(o, 'error', w), ...(retainedUntil !== undefined && { retainedUntil }) }
}

export const isSpent = (r: Pick<CashStatusResult, 'error'>): boolean => r.error === STATUS_SPENT
