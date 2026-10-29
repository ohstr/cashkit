// One outcome per batched item. Port of nmilat nipcash/client/batch_outcome.go
// and bill_state.go.
import type { Credential, Tombstone } from '../core/index.js'
import type { ResponseEnvelope, ResultError } from '../transport/index.js'
import { ClientError, NotServedError, WalletError } from './errors.js'

/**
 * - `not_served`: a complete reply left the item out, the Hub's final word.
 *   Information-free by design, and possibly applied: never read it as a
 *   failure or as "spent".
 * - `unanswered`: the reply was incomplete (or never came) and nothing that
 *   arrived mentions the item: ask again. Possibly applied, as above.
 * - `result`: served and succeeded.
 * - `error`: served and refused, with the Hub's reason.
 * - `conflicted`: answered more than once; no decided outcome, possibly applied.
 * - `tombstone`: the bill is gone (NIP-CASH §Answering About a Destroyed
 *   Bill), so the call never ran.
 */
export type OutcomeState = 'not_served' | 'unanswered' | 'result' | 'error' | 'conflicted' | 'tombstone'

export interface ItemOutcome {
  readonly id: string
  readonly state: OutcomeState
  /** The method's result as JSON text, when `state` is `result`. */
  readonly result?: string
  /** The Hub's reason, when `state` is `error`. */
  readonly error?: ResultError
  /** The Hub answered with a success this client could not decode: it ran. */
  readonly undecodable: boolean
  /** Which envelope carried it, from 0, for a batch split across several. */
  readonly envelope: number
}

/**
 * Whether resending cannot double-spend: only an explicit refusal. An
 * omission is NOT safe, since it looks exactly like an item that ran and
 * whose reply was lost; ask with cash_status first.
 */
export const safeToResend = (o: Pick<ItemOutcome, 'state' | 'undecodable'>): boolean => o.state === 'error' && !o.undecodable

export const succeeded = (o: Pick<ItemOutcome, 'state'>): boolean => o.state === 'result'

/**
 * Pairs a response with the ids sent, so every requested item gets exactly
 * one outcome. An envelope-level error applies to every item in it.
 */
export function joinOutcomes(requestedIds: readonly string[], resp: Pick<ResponseEnvelope, 'results' | 'error'> | undefined, envelope: number, conflicted: ReadonlySet<string> = new Set(), complete = true): ItemOutcome[] {
  const byId = new Map((resp?.results ?? []).map((r) => [r.id, r]))
  return requestedIds.map((id): ItemOutcome => {
    if (conflicted.has(id)) return { id, state: 'conflicted', undecodable: false, envelope }
    const r = byId.get(id)
    if (r?.error) return { id, state: 'error', error: r.error, undecodable: false, envelope }
    if (r) return { id, state: 'result', ...(r.result !== undefined && { result: r.result }), undecodable: false, envelope }
    if (resp?.error) return { id, state: 'error', error: resp.error, undecodable: false, envelope }
    // Only a complete reply's omission is final; a missing chunk may still have held it.
    return { id, state: complete ? 'not_served' : 'unanswered', undecodable: false, envelope }
  })
}

/** Every item left out by a complete reply. */
export const notServedOutcomes = (ids: readonly string[], envelope: number): ItemOutcome[] =>
  ids.map((id) => ({ id, state: 'not_served', undecodable: false, envelope }))

/** Every item of an envelope that got no reply at all (or could not be published): ask again. */
export const unansweredOutcomes = (ids: readonly string[], envelope: number): ItemOutcome[] =>
  ids.map((id) => ({ id, state: 'unanswered', undecodable: false, envelope }))

const isTombstone = (x: unknown): x is Tombstone => typeof x === 'object' && x !== null && (x as { status?: unknown }).status === 'spent'

/**
 * A single-item batch as a single call's answer: nothing for a result, the
 * Hub's refusal, the send error, or NotServedError. A decided outcome wins
 * over a send error that arrived with it.
 */
export function oneItemError(o: (Pick<ItemOutcome, 'state' | 'error'> & { readonly undecodable?: boolean; readonly tombstone?: unknown }) | undefined, sendError: unknown, method: string): Error | undefined {
  if (o?.state === 'tombstone' || (o?.state === 'result' && o.tombstone !== undefined)) return new ClientError('spent', `the hub says this bill is gone, so the ${method} did not run`, isTombstone(o.tombstone) ? { tombstone: o.tombstone } : undefined)
  if (o?.state === 'result') return undefined
  // It ran: a success whose body did not decode is never a refusal.
  if (o?.undecodable) return new ClientError('undecodable_result', `the hub applied this ${method}, but its answer could not be read`)
  if (o?.state === 'error' && o.error) return new WalletError(method, o.error.code, o.error.message ?? '')
  if (sendError !== undefined) return sendError instanceof Error ? sendError : new Error(String(sendError))
  return new NotServedError(method)
}

/**
 * - `indeterminate` (the default): no answer. A timeout is never `spent`.
 * - `available`: the roster came back.
 * - `spent`: the Hub said so explicitly.
 * - `unreadable`: a connection-key holder asked, and the Hub answered
 *   `NOT_FOUND`, as NIP-CASH §Scoping the Roster requires of a spec Hub
 *   (it finds "mine" from the item-proof signer, never a ConnectionKey).
 *   It says nothing about the bill: neither that it is gone nor that the
 *   slice is not this holder's.
 */
export type BillState = 'indeterminate' | 'available' | 'spent' | 'unreadable'

/**
 * A `cash_status` refusal that only means the status cannot be read: the
 * caller holds a `connection_key` slice and the Hub answered `NOT_FOUND`.
 * NIP-CASH §Scoping the Roster has a Hub decide "mine" from the item proof's
 * signer and answer `NOT_FOUND` to a signer holding no slice, for `scope:
 * all` too, and a connection-key holder's signer is its attested key, never
 * the ConnectionKey. So that answer is neither "spent" nor "not yours".
 * `err` is a refusal as `statusMany` reports it, or the `WalletError` the
 * one-item calls throw.
 */
export function statusUnreadable(credential: Pick<Credential, 'kind'>, err: unknown): boolean {
  if (credential.kind !== 'connection_key') return false
  if (err instanceof WalletError) return err.walletCode === 'NOT_FOUND'
  return (err as Partial<ResultError> | undefined)?.code === 'NOT_FOUND'
}

/**
 * What a call's outcome means for its pending record (NIP-CASH §Methods,
 * §Lost Replies):
 * - `applied`: it ran and its result is known.
 * - `final_not_applied`: refused `BAD_REQUEST`, item- or envelope-level; it
 *   never ran and never will.
 * - `tombstone`: the bill is gone; the call never ran.
 * - `not_sent`: refused locally before anything went out.
 * - `open`: anything else (another Hub code, an omission, a timeout, an
 *   incomplete or conflicted reply, an undecodable success): it may have
 *   run, so it stays pending and is looked up, never resent.
 */
export type CallClass =
  | { readonly kind: 'applied' }
  | { readonly kind: 'final_not_applied'; readonly code: string; readonly detail?: string }
  | { readonly kind: 'tombstone' }
  | { readonly kind: 'not_sent' }
  | { readonly kind: 'open'; readonly reason: 'refused' | 'not_served' | 'unanswered' | 'conflicted' | 'undecodable'; readonly code?: string; readonly detail?: string }

export function classifyCall(o: Pick<ItemOutcome, 'state' | 'error' | 'undecodable'> & { readonly tombstone?: unknown }): CallClass {
  if (o.state === 'tombstone' || (o.state === 'result' && o.tombstone !== undefined)) return { kind: 'tombstone' }
  if (o.undecodable) return { kind: 'open', reason: 'undecodable' }
  if (o.state === 'result') return { kind: 'applied' }
  if (o.state === 'conflicted') return { kind: 'open', reason: 'conflicted' }
  if (o.state === 'error' && o.error !== undefined) {
    const detail = o.error.detail !== undefined ? { detail: o.error.detail } : {}
    if (o.error.code === 'NOT_SENT') return { kind: 'not_sent' }
    if (o.error.code === 'BAD_REQUEST') return { kind: 'final_not_applied', code: o.error.code, ...detail }
    return { kind: 'open', reason: 'refused', code: o.error.code, ...detail }
  }
  return { kind: 'open', reason: o.state === 'unanswered' ? 'unanswered' : 'not_served' }
}
