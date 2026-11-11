// The materialized Cash Pocket cache: a LOCAL_ONLY relational projection of the
// resolved pocket (one winner per `w`), so `pocket.balance`/`entries` read
// locally with zero latency instead of re-fetching and re-decrypting every wrap
// on every call (the old readPocket-per-read path). It is derived and
// rebuildable from the wraps, never authoritative, never synced or served.
//
// A full sync materializes the whole resolved set (pocket.ts); a background
// delta (`refreshPocket`) pulls only wraps newer than the cursor minus the
// NIP-59 2-day back-dating window and folds them in pairwise. The fold mirrors
// core `resolveEntries` exactly (verified against the shared golden
// `resolution.json` and nmilat.Resolve): higher rev wins; at equal rev a final
// state, then latest created_at, then lowest id; a distinct rumor at the winning
// rev flags a conflict.
import { FINAL_STATES, type PocketEntry } from '../core/index.js'
import type { Ctx } from './context.js'
import type { PocketCacheRow } from './model.js'

/** The NIP-59 back-dating window: a wrap published now may carry a created_at up to 2 days in the past (risk 13), so a delta pull starts this far before the cursor. */
export const POCKET_SYNC_OVERLAP_SECONDS = 2 * 86400

const isFinal = (s: string) => (FINAL_STATES as readonly string[]).includes(s)

/** The comparator fields NIP-CP resolution orders on. */
interface Cmp {
  readonly rev: number
  readonly isFinal: boolean
  readonly createdAt: number
  readonly id: string
}

/** Orders two entries known to share a `w` and `rev` (core resolveEntries' `beats`). */
function beatsSameRev(a: Cmp, b: Cmp): boolean {
  if (a.isFinal !== b.isFinal) return a.isFinal
  if (a.createdAt !== b.createdAt) return a.createdAt > b.createdAt
  return a.id < b.id
}

/** One decoded entry + its winning-rumor meta, as the fold consumes it. */
export interface FoldInput {
  readonly entry: PocketEntry
  readonly rumor: { readonly id: string; readonly created_at: number }
}

function rowFrom(inp: FoldInput, conflict: boolean, version: number): PocketCacheRow {
  const e = inp.entry
  return {
    id: e.w,
    rev: e.rev,
    state: e.state,
    isFinal: isFinal(e.state),
    createdAt: inp.rumor.created_at,
    rumorId: inp.rumor.id,
    amountMillis: e.amountMillis,
    chain: e.chain,
    ...(e.identity !== undefined && { identityType: e.identity.type }),
    ...(e.identity !== undefined && 'value' in e.identity && { identityValue: e.identity.value }),
    ...(e.identity !== undefined && 'ia' in e.identity && { identityIa: e.identity.ia }),
    ...(e.expiresAt !== undefined && { expiresAt: e.expiresAt }),
    conflict,
    version,
  }
}

const cmpOf = (r: PocketCacheRow): Cmp => ({ rev: r.rev, isFinal: r.isFinal, createdAt: r.createdAt, id: r.rumorId })
const cmpIn = (inp: FoldInput): Cmp => ({ rev: inp.entry.rev, isFinal: isFinal(inp.entry.state), createdAt: inp.rumor.created_at, id: inp.rumor.id })

/**
 * Pairwise-fold one incoming entry against the stored winner (none = first):
 * returns the new row to store, or undefined when nothing changes. Idempotent
 * and order-independent because resolution is a total order, so re-applying an
 * event or applying deltas in any order converges on the same winner.
 */
export function foldOne(prev: PocketCacheRow | undefined, inp: FoldInput): PocketCacheRow | undefined {
  if (prev === undefined) return rowFrom(inp, false, 1)
  const a = cmpIn(inp)
  const b = cmpOf(prev)
  if (a.rev > b.rev) return rowFrom(inp, false, prev.version + 1) // new highest rev: sole winner, conflict resets
  if (a.rev === b.rev) {
    const conflict = prev.conflict || inp.rumor.id !== prev.rumorId
    if (beatsSameRev(a, b)) return { ...rowFrom(inp, conflict, prev.version + 1) }
    if (conflict !== prev.conflict) return { ...prev, conflict, version: prev.version + 1 }
    return undefined
  }
  return undefined // lower rev: loses
}

/** The cache's balance per chain: the sum over live rows (index-only, no decrypt, no relay). */
export async function cacheBalance(ctx: Ctx): Promise<Map<string, bigint>> {
  const rows = await ctx.read((t) => t.list('pocketCache'))
  const out = new Map<string, bigint>()
  for (const r of rows) if (r.state === 'live') out.set(r.chain, (out.get(r.chain) ?? 0n) + r.amountMillis)
  return out
}

/** The cache's resolved entries, without any secret, plus the w's flagged for a cash_status re-check. */
export async function cacheEntries(ctx: Ctx): Promise<{ entries: { w: string; state: string; amountMillis: bigint; chain: string; pending: boolean }[]; conflicts: string[] }> {
  const rows = await ctx.read((t) => t.list('pocketCache'))
  return {
    entries: rows.map((r) => ({ w: r.id, state: r.state, amountMillis: r.amountMillis, chain: r.chain, pending: r.state === 'pending' })),
    conflicts: rows.filter((r) => r.conflict).map((r) => r.id),
  }
}

/** The cursor (newest folded wrap created_at); 0 when the cache was never populated or is empty. */
export async function cursorAt(ctx: Ctx): Promise<number> {
  return (await ctx.read((t) => t.get('pocketCursor', 'self')))?.at ?? 0
}

/** Whether the cache has ever been materialized (the cursor row exists, even at 0 for an empty pocket) — so reads needn't fall back to a relay fetch. */
export async function materialized(ctx: Ctx): Promise<boolean> {
  return (await ctx.read((t) => t.get('pocketCursor', 'self'))) !== undefined
}

/** Records the cursor at max(current, at), creating the row on first call (even at 0, marking the cache materialized). */
async function advanceCursor(ctx: Ctx, at: number): Promise<void> {
  await ctx.commit(async (t) => {
    const cur = await t.get('pocketCursor', 'self')
    const next = Math.max(cur?.at ?? 0, Math.max(0, at))
    if (cur !== undefined && cur.at === next) return
    await t.put('pocketCursor', { id: 'self', at: next, version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
  })
}

/** Fold a batch of delta inputs into the cache (upsert-only — never deletes a w not in the batch), then advance the cursor to the newest created_at seen. */
export async function foldDelta(ctx: Ctx, inputs: readonly FoldInput[]): Promise<void> {
  let maxAt = 0
  for (const inp of inputs) {
    maxAt = Math.max(maxAt, inp.rumor.created_at)
    await ctx.commit(async (t) => {
      const prev = await t.get('pocketCache', inp.entry.w)
      const next = foldOne(prev, inp)
      if (next === undefined) return
      await t.put('pocketCache', next, prev?.version ?? 0)
    })
  }
  await advanceCursor(ctx, maxAt)
}

/**
 * Replace the cache with a complete resolved set (a full sync). Upserts every
 * winner, flags the resolver's conflicts, and deletes rows for a `w` no longer
 * present (pruned/removed). The cursor advances to the newest winner created_at
 * — a safe lower bound (≤ the newest wrap), the 2-day overlap covers the rest.
 */
export async function materializeFull(
  ctx: Ctx,
  entries: ReadonlyMap<string, PocketEntry>,
  winners: ReadonlyMap<string, { created_at: number; id: string }>,
  conflicts: readonly string[],
): Promise<void> {
  const conflictSet = new Set(conflicts)
  let maxAt = 0
  await ctx.commit(async (t) => {
    const existing = await t.list('pocketCache')
    const keep = new Set<string>()
    for (const [w, e] of entries) {
      const meta = winners.get(w) ?? { created_at: 0, id: '' }
      maxAt = Math.max(maxAt, meta.created_at)
      keep.add(w)
      const prev = await t.get('pocketCache', w)
      const row = rowFrom({ entry: e, rumor: meta }, conflictSet.has(w), (prev?.version ?? 0) + 1)
      await t.put('pocketCache', row, prev?.version ?? 0)
    }
    for (const r of existing) if (!keep.has(r.id)) await t.delete('pocketCache', r.id)
  })
  await advanceCursor(ctx, maxAt)
}
