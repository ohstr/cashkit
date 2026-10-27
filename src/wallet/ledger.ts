// Holding rows inside one storage transaction. Port of cashctl
// internal/ledger/ledger.go (Add, FindByToken, Held, SetStatus, AddHandoff),
// with the per-row version as the OCC check (§5.4).
import { toHex } from '../core/index.js'
import { CashkitError } from './errors.js'
import type { Activity, ActivityDetail, Handoff, HandoffKind, Holding, HoldingStatus, Sealed } from './model.js'
import { ConcurrentUpdateError, type StorageTx } from './ports.js'

/** A holding before it is stored: no id, status or version yet. */
export type NewHolding = Omit<Holding, 'id' | 'status' | 'version' | 'addedAt' | 'token'> & { readonly token: string }

export function newId(prefix: string, random: (n: number) => Uint8Array): string {
  return `${prefix}-${toHex(random(4))}`
}

export async function findByToken(t: StorageTx, token: string): Promise<Holding | undefined> {
  const lower = token.toLowerCase()
  return (await t.list('holdings')).find((h) => h.token.toLowerCase() === lower)
}

export async function heldHoldings(t: StorageTx): Promise<Holding[]> {
  return (await t.list('holdings')).filter((h) => h.status === 'held')
}

/**
 * Adds a holding (`ledger.Add`): the token is lowercased; a token already
 * held is a conflict; a token held before and since let go reactivates the
 * same row, keeping its id, with every other field replaced.
 */
export async function addHolding(t: StorageTx, h: NewHolding, o: { now: number; random: (n: number) => Uint8Array }): Promise<Holding> {
  const token = h.token.toLowerCase()
  const existing = await findByToken(t, token)
  if (existing?.status === 'held' || existing?.status === 'redeeming') throw new CashkitError('conflict', 'this token is already in your wallet', { input: existing.id })
  let id = existing?.id
  if (id === undefined) {
    do id = newId('h', o.random)
    while ((await t.get('holdings', id)) !== undefined)
  }
  const row: Holding = { ...h, token, id, status: 'held', addedAt: o.now, version: (existing?.version ?? 0) + 1 }
  await t.put('holdings', row, existing?.version ?? 0)
  return row
}

/**
 * Writes `next` over the row read as `prev`; fails with `conflict` if the
 * stored row moved on since. Returns the stored row.
 */
export async function saveHolding(t: StorageTx, prev: Pick<Holding, 'version'>, next: Holding): Promise<Holding> {
  const row: Holding = { ...next, version: prev.version + 1 }
  try {
    await t.put('holdings', row, prev.version)
  } catch (err) {
    if (err instanceof ConcurrentUpdateError) throw conflict(err)
    throw err
  }
  return row
}

/** Re-reads a holding by id and applies `change`, OCC-checked against `expectVersion` when given. */
export async function updateHolding(
  t: StorageTx,
  id: string,
  change: (h: Holding) => Holding,
  expectVersion?: number,
): Promise<Holding> {
  const cur = await t.get('holdings', id)
  if (cur === undefined) throw new CashkitError('not_found', `no holding ${id}`, { input: id })
  if (expectVersion !== undefined && cur.version !== expectVersion) throw conflict(new ConcurrentUpdateError('holdings', id))
  return saveHolding(t, cur, change(cur))
}

export const setStatus = (t: StorageTx, id: string, status: HoldingStatus) => updateHolding(t, id, (h) => ({ ...h, status }))

export async function appendActivity(t: StorageTx, at: number, detail: ActivityDetail): Promise<Activity> {
  const id = await t.insert('activity', { ...detail, at })
  return { ...detail, id, at } as Activity
}

/**
 * Records a handoff (`AddHandoff`): a cash note starts `unclaimed`, a gift
 * `sent`.
 */
export async function addHandoff(
  t: StorageTx,
  h: { kind: HandoffKind; handoff: Sealed; amount: bigint; target: string; walletPubkey: string; expiresAt?: number },
  o: { now: number; random: (n: number) => Uint8Array },
): Promise<Handoff> {
  let id: string
  do id = newId('o', o.random)
  while ((await t.get('handoffs', id)) !== undefined)
  const row: Handoff = { ...h, id, at: o.now, status: h.kind === 'gift' ? 'sent' : 'unclaimed', version: 1 }
  await t.put('handoffs', row, 0)
  return row
}

export function conflict(err: ConcurrentUpdateError): CashkitError {
  return new CashkitError('conflict', 'your wallet changed while this was in progress; nothing was sent, so reload and try again', { cause: err })
}

/** How a no-longer-held status reads (`spentStatusDescription`). */
export function statusDescription(s: HoldingStatus): string {
  switch (s) {
    case 'redeemed':
      return 'redeemed'
    case 'transferred':
      return 'transferred'
    case 'consolidated':
      return 'consolidated into another token'
    case 'spent':
      return 'reported spent by its Hub'
    default:
      return ''
  }
}

/** cashctl `alreadySpentError`: value gone is `spent`, given away is `not_found`. */
export function notHeldError(h: Pick<Holding, 'id' | 'status'>): CashkitError {
  const desc = statusDescription(h.status)
  if (h.status === 'transferred') {
    return new CashkitError('not_found', `token ${h.id} was already ${desc}, so it is no longer yours`, { input: h.id })
  }
  return new CashkitError('spent', `token ${h.id} was already ${desc}, so it is spent: its value has already moved`, { input: h.id })
}
