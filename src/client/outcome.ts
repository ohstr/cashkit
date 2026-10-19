// One outcome per batched item. Port of nmilat nipcash/client/batch_outcome.go
// and bill_state.go.
import type { ResponseEnvelope, ResultError } from '../transport/index.js'
import { ClientError, NotServedError, WalletError } from './errors.js'

/**
 * - `not_served` (the default): no answer. Information-free by design, and
 *   possibly applied: never read it as a failure or as "spent".
 * - `result`: served and succeeded.
 * - `error`: served and refused, with the Hub's reason.
 */
export type OutcomeState = 'not_served' | 'result' | 'error'

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
export function joinOutcomes(requestedIds: readonly string[], resp: Pick<ResponseEnvelope, 'results' | 'error'> | undefined, envelope: number): ItemOutcome[] {
  const byId = new Map((resp?.results ?? []).map((r) => [r.id, r]))
  return requestedIds.map((id): ItemOutcome => {
    const r = byId.get(id)
    if (r?.error) return { id, state: 'error', error: r.error, undecodable: false, envelope }
    if (r) return { id, state: 'result', ...(r.result !== undefined && { result: r.result }), undecodable: false, envelope }
    if (resp?.error) return { id, state: 'error', error: resp.error, undecodable: false, envelope }
    return { id, state: 'not_served', undecodable: false, envelope }
  })
}

export const notServedOutcomes = (ids: readonly string[], envelope: number): ItemOutcome[] =>
  ids.map((id) => ({ id, state: 'not_served', undecodable: false, envelope }))

/**
 * A single-item batch as a single call's answer: nothing for a result, the
 * Hub's refusal, the send error, or NotServedError. A decided outcome wins
 * over a send error that arrived with it.
 */
export function oneItemError(o: (Pick<ItemOutcome, 'state' | 'error'> & { readonly undecodable?: boolean }) | undefined, sendError: unknown, method: string): Error | undefined {
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
 */
export type BillState = 'indeterminate' | 'available' | 'spent'
