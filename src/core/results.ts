// Results of cash_redeem, cash_transfer, cash_consolidate and cash_status.
// Port of nmilat nipcash's ParseResult methods. Input is the already-parsed
// JSON `result`; uint64 amounts may arrive as safe-integer numbers or as
// bigints from a precision-preserving parser, and are returned as bigint.
import type { ConsolidateSource } from './claim.js'
import { isRequestId } from './requestId.js'
import { validateWithdrawTerms, type WithdrawTerms } from './withdraw.js'
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

/** An expiry: omitted, null and 0 all mean "never expires" (undefined), never "expired at epoch 0". */
function optExpiry(o: Obj, key: string, what: string): number | undefined {
  const v = optInt(o, key, what)
  if (v !== undefined && v < 0) throw bad(`${what}: ${key} must not be negative`)
  return v === 0 ? undefined : v
}

/** The reasons a bill can end on; any other value, or none, reads as spent with no reason. */
export type TombstoneReason = 'redeemed' | 'transferred' | 'consolidated' | 'expired' | 'reclaimed'
const REASONS: ReadonlySet<string> = new Set(['redeemed', 'transferred', 'consolidated', 'expired', 'reclaimed'])

/**
 * A destroyed bill (NIP-CASH §Answering About a Destroyed Bill): the
 * definite answer that it is gone, the item's result for every bill method.
 */
export interface Tombstone {
  readonly status: 'spent'
  /** Absent for a written-off bill, or when the Hub sent a value this client does not know. */
  readonly reason?: TombstoneReason
  readonly retainedUntil?: number
  /** Only trusted by a caller whose own item proof the answer was to. */
  readonly withdrawRequestId?: string
}

/** The tombstone a result is, or undefined when it is not one. Never throws. */
export function parseTombstone(result: unknown): Tombstone | undefined {
  if (result === null || typeof result !== 'object' || Array.isArray(result)) return undefined
  const o = result as Obj
  if (o['status'] !== 'spent') return undefined
  const reason = typeof o['reason'] === 'string' && REASONS.has(o['reason']) ? (o['reason'] as TombstoneReason) : undefined
  let retainedUntil: number | undefined
  try {
    retainedUntil = optInt(o, 'retained_until', 'tombstone')
  } catch {
    retainedUntil = undefined
  }
  const wid = isRequestId(o['withdraw_request_id']) ? o['withdraw_request_id'] : undefined
  return { status: 'spent', ...(reason !== undefined && { reason }), ...(retainedUntil !== undefined && { retainedUntil }), ...(wid !== undefined && { withdrawRequestId: wid }) }
}

export type BillMethod = 'cash_status' | 'cash_redeem' | 'cash_transfer' | 'cash_consolidate'

/** A bill method's result: its parsed value, or the tombstone in its place. */
export type BillResult<R> = { readonly kind: 'result'; readonly value: R } | { readonly kind: 'tombstone'; readonly tombstone: Tombstone }

export interface CashRedeemResult {
  /** 64 lowercase hex. */
  readonly preimage: string
  /** The recipient's own redeem fee, never the routing cost; 0 for a same-node redeem. */
  readonly feesPaid: bigint
}

export function parseCashRedeemResult(result: unknown): CashRedeemResult {
  const o = asObject(result, 'cash_redeem result')
  const preimage = o['preimage']
  if (typeof preimage !== 'string' || !/^[0-9a-f]{64}$/.test(preimage)) throw bad('cash_redeem: preimage must be 64 lowercase hex')
  if (o['fees_paid'] === undefined || o['fees_paid'] === null) throw bad('cash_redeem: fees_paid is required')
  return { preimage, feesPaid: u64(o, 'fees_paid', 'cash_redeem') }
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
  /** A zap transfer's bill: its signed `issued_at`. Absent on any other transfer. */
  readonly issuedAt?: number
  /** A zap bill's signed `expires_at`, 0 when it never expires (unlike every other expiry). */
  readonly zapExpiresAt?: number
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
  const issuedAt = optInt(o, 'issued_at', w)
  const zapExpiresAt = issuedAt !== undefined ? (optInt(o, 'expires_at', w) ?? 0) : undefined
  if (issuedAt !== undefined && (issuedAt < 0 || zapExpiresAt! < 0)) throw bad('cash_transfer: issued_at and expires_at must not be negative')
  return {
    amountMillis: u64(o, 'amount_millis', w),
    identityType: str(o, 'identity_type', w),
    identityValue: str(o, 'identity_value', w),
    ...(remaining !== undefined && { remainingAmountMillis: remaining }),
    newWalletPubkey,
    newWalletToken: newToken === '' ? '' : await decryptDelivery(credential, newWalletPubkey, newToken),
    remainderWalletPubkey,
    remainderWalletToken: remainderToken === '' ? '' : await decryptDelivery(credential, remainderWalletPubkey, remainderToken),
    ...(issuedAt !== undefined && { issuedAt, zapExpiresAt: zapExpiresAt! }),
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
  const expiresAt = optExpiry(o, 'expires_at', w)
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

/** One recipient row of a cash_status roster. */
export interface RecipientStatus {
  readonly identity_type: string
  readonly identity_value?: string
  /** A `connection_key` row's Identity Authority. */
  readonly ia_pubkey?: string
  readonly amount_millis: bigint
  readonly claimed: boolean
  readonly claimed_at?: number
  readonly redeem_fee_millis: bigint
  readonly net_redeemable_millis: bigint
  readonly min_transfer_millis: bigint
  /** Absent for a wallet that never expires (0 and null read the same). */
  readonly expires_at?: number
  /** Only trusted by a caller whose own item proof the answer was to. */
  readonly withdraw_request_id?: string
}

export interface CashStatusResult {
  readonly recipients: readonly RecipientStatus[]
  /** Set when the bill is gone; `recipients` is then empty. */
  readonly tombstone?: Tombstone
  /** The Hub's on-chain withdrawal terms, when it offers them and they are valid. */
  readonly withdraw?: WithdrawTerms
}

export function parseCashStatusResult(result: unknown): CashStatusResult {
  const tombstone = parseTombstone(result)
  if (tombstone !== undefined) return { recipients: [], tombstone }
  const o = asObject(result, 'cash_status result')
  const w = 'cash_status'
  const raw = o['recipients'] ?? []
  if (!Array.isArray(raw)) throw bad('cash_status: recipients must be an array')
  const recipients = raw.map((r): RecipientStatus => {
    const row = asObject(r, 'cash_status recipient')
    const claimedAt = optInt(row, 'claimed_at', w)
    const expiresAt = optExpiry(row, 'expires_at', w)
    const value = str(row, 'identity_value', w)
    const ia = str(row, 'ia_pubkey', w)
    const wid = isRequestId(row['withdraw_request_id']) ? row['withdraw_request_id'] : undefined
    return {
      identity_type: str(row, 'identity_type', w),
      ...(value !== '' && { identity_value: value }),
      ...(ia !== '' && { ia_pubkey: ia }),
      amount_millis: u64(row, 'amount_millis', w),
      claimed: bool(row, 'claimed', w),
      ...(claimedAt !== undefined && { claimed_at: claimedAt }),
      redeem_fee_millis: u64(row, 'redeem_fee_millis', w),
      net_redeemable_millis: u64(row, 'net_redeemable_millis', w),
      min_transfer_millis: u64(row, 'min_transfer_millis', w),
      ...(expiresAt !== undefined && { expires_at: expiresAt }),
      ...(wid !== undefined && { withdraw_request_id: wid }),
    }
  })
  const withdraw = validateWithdrawTerms(o['withdraw'])
  return { recipients, ...(withdraw !== undefined && { withdraw }) }
}

export const isSpent = (r: Pick<CashStatusResult, 'tombstone'>): boolean => r.tombstone !== undefined

/** A bill method's result or its tombstone; `parse` reads the method's own shape. */
export async function parseBillResult<R>(result: unknown, parse: (v: unknown) => R | Promise<R>): Promise<BillResult<R>> {
  const tombstone = parseTombstone(result)
  if (tombstone !== undefined) return { kind: 'tombstone', tombstone }
  return { kind: 'result', value: await parse(result) }
}
