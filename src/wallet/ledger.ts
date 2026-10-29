// Holding rows inside one storage transaction. Port of cashctl
// internal/ledger/ledger.go (Add, FindByToken, Held, SetStatus, AddHandoff),
// with the per-row version as the OCC check (§5.4).
import { canonicalToken, decodeToken, toHex } from '../core/index.js'
import { CashkitError } from './errors.js'
import type { Activity, ActivityDetail, Handoff, HandoffKind, Holding, HoldingStatus, Sealed } from './model.js'
import { ConcurrentUpdateError, type StorageTx } from './ports.js'

/** A holding before it is stored: no id, status or version yet. */
export type NewHolding = Omit<Holding, 'id' | 'status' | 'version' | 'addedAt' | 'token'> & { readonly token: string }

export function newId(prefix: string, random: (n: number) => Uint8Array): string {
  return `${prefix}-${toHex(random(4))}`
}

/**
 * The holding of a bill, found by its wallet pubkey (TLV 0): a bill has many
 * spellings, all one bill. A held (or redeeming) row wins over one let go.
 */
export async function findByWallet(t: StorageTx, walletPubkey: string): Promise<Holding | undefined> {
  const rows = (await t.list('holdings')).filter((h) => h.walletPubkey === walletPubkey)
  return rows.find((h) => h.status === 'held' || h.status === 'redeeming') ?? rows[0]
}

/** The holding of the bill `token` spells, however it is spelled. */
export async function findByToken(t: StorageTx, token: string): Promise<Holding | undefined> {
  return findByWallet(t, decodeToken(token).walletPubkey)
}

export async function heldHoldings(t: StorageTx): Promise<Holding[]> {
  return (await t.list('holdings')).filter((h) => h.status === 'held')
}

/**
 * Adds a holding (`ledger.Add`), keyed by the bill's wallet pubkey and stored
 * in its canonical spelling (`canonicalToken`): a bill already held is a
 * conflict however it is spelled; a bill held before and since let go
 * reactivates the same row, keeping its id, with every other field replaced.
 */
export async function addHolding(t: StorageTx, h: NewHolding, o: { now: number; random: (n: number) => Uint8Array }): Promise<Holding> {
  const token = canonicalToken(h.token)
  const walletPubkey = decodeToken(token).walletPubkey
  if (h.walletPubkey !== walletPubkey) throw new CashkitError('internal', `a holding's wallet pubkey ${h.walletPubkey} is not its token's ${walletPubkey}`)
  const existing = await findByWallet(t, walletPubkey)
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

/** Whether `normalizeHoldings` has anything to do: a token not in its canonical spelling, or a bill held twice. */
export async function holdingsNeedNormalizing(t: StorageTx): Promise<boolean> {
  const live = new Set<string>()
  for (const h of await t.list('holdings')) {
    try {
      if (canonicalToken(h.token) !== h.token) return true
    } catch {
      // not a bill string this decoder reads
    }
    if (h.status !== 'held' && h.status !== 'redeeming') continue
    if (live.has(h.walletPubkey)) return true
    live.add(h.walletPubkey)
  }
  return false
}

/** Whether `d` holds nothing `keep` lacks: the same identity, no secret or key of its own. */
const sameSlice = (keep: Holding, d: Holding): boolean =>
  d.mode === keep.mode && d.mode !== 'cash' && d.throwawayKey === undefined && keep.throwawayKey === undefined && (d.mode !== 'connection_key' || (d.connectionKey?.key !== undefined && d.connectionKey.key === keep.connectionKey?.key))

/**
 * Brings stored holdings to one row per bill (run at open): each token is
 * rewritten in its canonical spelling, and where an older version stored
 * one bill twice as held under two spellings, the first row added is kept
 * and a later one is removed when it is the same slice under the same
 * identity and no open call names it. A cash-mode or differently bound
 * copy keeps its row: its secret or binding is never dropped. Returns the
 * ids removed.
 */
export async function normalizeHoldings(t: StorageTx, openCallSources: ReadonlySet<string>): Promise<string[]> {
  for (const h of await t.list('holdings')) {
    let token: string
    try {
      token = canonicalToken(h.token)
    } catch {
      continue // not a bill string this decoder reads: left as stored
    }
    if (token !== h.token) await saveHolding(t, h, { ...h, token })
  }
  const byWallet = new Map<string, Holding[]>()
  for (const h of await t.list('holdings')) {
    if (h.status === 'held' || h.status === 'redeeming') byWallet.set(h.walletPubkey, [...(byWallet.get(h.walletPubkey) ?? []), h])
  }
  const removed: string[] = []
  for (const group of byWallet.values()) {
    if (group.length < 2 || group.some((h) => openCallSources.has(h.id))) continue
    // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
    const [keep, ...rest] = [...group].sort((a, b) => a.addedAt - b.addedAt || (a.id < b.id ? -1 : 1))
    for (const d of rest) {
      if (!sameSlice(keep!, d)) continue
      await t.delete('holdings', d.id)
      removed.push(d.id)
    }
  }
  return removed
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
    case 'expired':
      return 'reported expired by its Hub'
    case 'reclaimed':
      return 'removed by its sender (reclaimed)'
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
