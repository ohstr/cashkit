// NIP-CP §Balance's result to state table on the wallet's holdings: one
// mapping (core `stateForResult`) for every method that answers about a held
// bill: cash_status, cash_redeem, cash_transfer, cash_consolidate and a
// lookup `done`.
import { stateForResult, type BillAnswer, type Credential, type PocketState, type Tombstone } from '../core/index.js'
import { WalletError } from '../client/index.js'
import type { ResultError } from '../transport/index.js'
import { CashkitError } from './errors.js'
import { appendActivity, updateHolding } from './ledger.js'
import type { Ctx } from './context.js'
import type { Holding, HoldingStatus } from './model.js'
import type { StorageTx } from './ports.js'

/** How a bill the Hub says is gone ends: the final holding status (and Pocket state) of a definitive answer. */
export type GoneStatus = 'spent' | 'expired' | 'reclaimed'

/** The final status a definitive answer sets; undefined for one that is not definitive. */
export function goneStatus(a: BillAnswer): GoneStatus | undefined {
  const r = stateForResult(a)
  return r.definitive ? (r.state as GoneStatus) : undefined
}

/** A tombstone's final status (its `reason`: expired, reclaimed, anything else spent). */
export const tombstoneStatus = (t: Pick<Tombstone, 'reason'> | undefined): GoneStatus => goneStatus({ result: 'tombstone', ...(t?.reason !== undefined && { reason: t.reason }) })!

/**
 * Whether a refusal is `NOT_FOUND` for an item proof signed by the holding's
 * identity key, or made with its cash secret: the slice was removed, so the
 * bill is `reclaimed`. A connection-key holder's `NOT_FOUND` says nothing
 * (`statusUnreadable`) and is not this.
 */
export function notFoundByEntryKey(credential: Pick<Credential, 'kind'>, err: unknown): boolean {
  if (credential.kind !== 'signing' && credential.kind !== 'secret') return false
  if (err instanceof WalletError) return err.walletCode === 'NOT_FOUND'
  return (err as Partial<ResultError> | undefined)?.code === 'NOT_FOUND'
}

/** The kind of credential a holding's item proofs use. */
export const credentialKindOf = (h: Pick<Holding, 'mode'>): Credential['kind'] => (h.mode === 'cash' ? 'secret' : h.mode === 'connection_key' ? 'connection_key' : 'signing')

/** The Pocket state a holding no longer held is written with. */
export function pocketStateOf(h: Pick<Holding, 'status'>): PocketState {
  return h.status === 'expired' || h.status === 'reclaimed' ? h.status : 'spent'
}

/** The error a bill the Hub says is gone reports. */
export function goneError(ends: GoneStatus, input?: string): CashkitError {
  const o = { reason: ends, ...(input !== undefined && { input }) }
  if (ends === 'reclaimed') return new CashkitError('spent', 'the sender removed your share of this bill (reclaimed): it is no longer yours', o)
  if (ends === 'expired') return new CashkitError('spent', 'the Hub says this bill expired: it is gone', o)
  return new CashkitError('spent', 'the Hub says this bill is spent: its value has already moved and the bill is gone', o)
}

/** Ends a holding in `tx` (only one in `from`), with its `spent` activity. */
export async function endHolding(t: StorageTx, now: number, id: string, ends: GoneStatus, from: readonly HoldingStatus[] = ['held']): Promise<boolean> {
  const h = await t.get('holdings', id)
  if (h === undefined || !from.includes(h.status)) return false
  await updateHolding(t, id, (x) => ({ ...x, status: ends }))
  await appendActivity(t, now, { action: 'spent', holdingId: id })
  return true
}

/** Ends a held holding in its own commit. */
export async function markGone(ctx: Ctx, id: string, ends: GoneStatus): Promise<void> {
  await ctx.commit((t) => endHolding(t, ctx.now(), id, ends))
}
