// cash_lookup (NIP-CASH §Looking Up a Call): asks a Hub what became of a
// call by its request_id, without moving anything. Port of nmilat
// nipcash/cash_lookup.go (CashLookupRequest, ParseCashLookupResult,
// DecideLookup, TokenOrTombstone).
import { CoreError } from './errors.js'
import { isCashSecret } from './identity.js'
import { isRequestId } from './requestId.js'
import { parseTombstone, type Tombstone } from './results.js'

const HEX64 = /^[0-9a-f]{64}$/
const badParams = (msg: string) => new CoreError('invalid_request', `cash_lookup: ${msg}`)
const badResult = (msg: string) => new CoreError('invalid_payload', `cash_lookup result: ${msg}`)

export interface CashLookupParams {
  request_id?: string
  connection_pubkey?: string
  deadline: number
  cash_secret?: string
}

/**
 * The lookup's params: by `requestId`, or for a NIP-CW join by
 * `connectionPubkey` (exactly one); `deadline` is the original call's as
 * sent. A bearer lookup sends `cashSecret` only after one without it was
 * refused `UNAUTHORIZED`.
 */
export function cashLookupParams(by: { readonly requestId: string } | { readonly connectionPubkey: string }, deadline: number, cashSecret?: string): CashLookupParams {
  const id = 'requestId' in by ? by.requestId : undefined
  const cp = 'connectionPubkey' in by ? by.connectionPubkey : undefined
  if ((id === undefined) === (cp === undefined)) throw badParams('exactly one of request_id and connection_pubkey')
  if (id !== undefined && !isRequestId(id)) throw badParams('request_id must be 16 to 32 bytes of lowercase hex')
  if (cp !== undefined && !HEX64.test(cp)) throw badParams('connection_pubkey must be 64 lowercase hex')
  if (!Number.isSafeInteger(deadline) || deadline < 0) throw badParams('deadline must be unix seconds')
  if (cashSecret !== undefined && !isCashSecret(cashSecret)) throw badParams('cash_secret must be 64 lowercase hex')
  return { ...(id !== undefined && { request_id: id }), ...(cp !== undefined && { connection_pubkey: cp }), deadline, ...(cashSecret !== undefined && { cash_secret: cashSecret }) }
}

export type CashLookupResult =
  | { readonly status: 'done'; readonly result: unknown }
  | { readonly status: 'pending'; readonly retryAfter: number }
  | { readonly status: 'unknown' }
  | { readonly status: 'expired' }

export function parseCashLookupResult(v: unknown): CashLookupResult {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw badResult('expected an object')
  const o = v as Record<string, unknown>
  switch (o['status']) {
    case 'done':
      if (o['result'] === undefined || o['result'] === null || typeof o['result'] !== 'object') throw badResult('done carries the original result')
      return { status: 'done', result: o['result'] }
    case 'pending': {
      const r = o['retry_after']
      if (typeof r !== 'number' || !Number.isSafeInteger(r) || r < 0) throw badResult('pending carries retry_after')
      return { status: 'pending', retryAfter: r }
    }
    case 'unknown':
      return { status: 'unknown' }
    case 'expired':
      return { status: 'expired' }
    default:
      throw badResult('unknown status')
  }
}

/** A created bill's token field in a `done` result: its token, or the tombstone in its place. */
export function tokenOrTombstone(v: unknown): string | Tombstone | undefined {
  if (v === undefined || v === null) return undefined
  if (typeof v === 'string') return v
  const t = parseTombstone(v)
  if (t === undefined) throw new CoreError('invalid_payload', 'cash_lookup result: a token field is neither a token nor a tombstone')
  return t
}

const TOKEN_FIELDS = ['cash_token', 'new_wallet_token', 'remainder_wallet_token'] as const

/**
 * Splits a `done` result into the original response (a destroyed bill's
 * token field emptied) and the tombstones found in its token fields, so the
 * method's own parser and credential decode the rest. Nothing here reads a
 * pairing URI.
 */
export function decodeLookupDone(result: unknown): { readonly result: Record<string, unknown>; readonly tombstones: Partial<Record<(typeof TOKEN_FIELDS)[number], Tombstone>> } {
  if (result === null || typeof result !== 'object' || Array.isArray(result)) throw new CoreError('invalid_payload', 'cash_lookup result: done carries the original result')
  const out: Record<string, unknown> = { ...(result as Record<string, unknown>) }
  const tombstones: Partial<Record<(typeof TOKEN_FIELDS)[number], Tombstone>> = {}
  for (const f of TOKEN_FIELDS) {
    const t = tokenOrTombstone(out[f])
    if (t !== undefined && typeof t !== 'string') {
      tombstones[f] = t
      out[f] = ''
    }
  }
  return { result: out, tombstones }
}

/**
 * The status a Hub answers on its clock (`now`), for a lookup with
 * `deadline`: `pending` up to the deadline, then `unknown` up to deadline +
 * `horizon` (H; 360 for a join lookup by connection_pubkey), then
 * `expired`; `done` whenever a record is held. The deadline is clamped to
 * now + horizon.
 */
export function decideLookup(p: { readonly now: number; readonly deadline: number; readonly horizon: number; readonly hasRecord: boolean }): CashLookupResult['status'] | { readonly status: 'pending'; readonly retryAfter: number } {
  if (p.hasRecord) return 'done'
  const deadline = Math.min(p.deadline, p.now + p.horizon)
  if (p.now <= deadline) return { status: 'pending', retryAfter: deadline + 1 }
  if (p.now <= deadline + p.horizon) return 'unknown'
  return 'expired'
}
