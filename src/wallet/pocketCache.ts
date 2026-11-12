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

/** The NIP-59 back-dating window: a wrap published now may carry a created_at up to 2 days in the past (risk 13), so a delta pull starts this far before the cursor. The adapter (sync-pocket) owns the single subtraction of this window; `refreshPocket` passes the raw cursor. */
export const POCKET_SYNC_OVERLAP_SECONDS = 2 * 86400

/**
 * The cache-schema version (mirrors cashctl's `cacheSchemaVersion`): bumped
 * whenever the decoded-cache row shape or fold semantics change. It is stamped
 * on the `pocketCursor` row; a mismatch (or absence, for a cache written before
 * the field existed) makes `materialized` report the cache stale, so the next
 * read forces a one-time true rebuild (`rebuildPocketCache`). The cache is
 * derived and rebuildable from the wraps, so a bump is always safe.
 */
export const CACHE_SCHEMA_VERSION = 1

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

/**
 * Flag the given w's as conflicted in the cache (idempotent). A sync accumulates
 * runtime re-check conflicts after its initial materialize; this applies them to
 * the already-materialized cache without re-materializing.
 */
export async function flagConflicts(ctx: Ctx, conflicts: readonly string[]): Promise<void> {
  for (const w of conflicts) {
    await ctx.commit(async (t) => {
      const cur = await t.get('pocketCache', w)
      if (cur === undefined || cur.conflict) return
      await t.put('pocketCache', { ...cur, conflict: true, version: cur.version + 1 }, cur.version)
    })
  }
}

/** The cursor (newest folded wrap created_at); 0 when the cache was never populated or is empty. */
export async function cursorAt(ctx: Ctx): Promise<number> {
  return (await ctx.read((t) => t.get('pocketCursor', 'self')))?.at ?? 0
}

/**
 * Whether the cache is materialized AND current (the cursor row exists — even at
 * 0 for an empty pocket — and carries the current schema). A cursor written
 * under an older schema, or before the field existed, reports not-materialized,
 * so the next read rebuilds it once. Keeps reads off the relay once fresh.
 */
export async function materialized(ctx: Ctx): Promise<boolean> {
  const cur = await ctx.read((t) => t.get('pocketCursor', 'self'))
  return cur !== undefined && cur.schema === CACHE_SCHEMA_VERSION
}

/** Records the cursor at max(current, at), creating the row on first call (even at 0, marking the cache materialized), and stamps the current schema. */
async function advanceCursor(ctx: Ctx, at: number): Promise<void> {
  await ctx.commit(async (t) => {
    const cur = await t.get('pocketCursor', 'self')
    const next = Math.max(cur?.at ?? 0, Math.max(0, at))
    if (cur !== undefined && cur.at === next && cur.schema === CACHE_SCHEMA_VERSION) return
    await t.put('pocketCursor', { id: 'self', at: next, schema: CACHE_SCHEMA_VERSION, version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
  })
}

/**
 * A TRUE reset of the cache: delete every `pocketCache` row AND the
 * `pocketCursor` row, so a following `materializeFull` re-folds every `w` from
 * `prev === undefined` (the authoritative winner is written fresh) instead of
 * merging onto a stored higher-rev row. Used by the recovery/rebuild path only;
 * the normal delta/sync merge (foldOne, rev-monotonic) is left untouched.
 */
export async function clearPocketCache(ctx: Ctx): Promise<void> {
  await ctx.commit(async (t) => {
    for (const r of await t.list('pocketCache')) await t.delete('pocketCache', r.id)
    if ((await t.get('pocketCursor', 'self')) !== undefined) await t.delete('pocketCursor', 'self')
  })
}

/**
 * Clears the cache only when its stored schema is stale (an older version, or no
 * field at all), so the following `materializeFull` becomes a fresh rebuild
 * rather than a merge onto rows written by an older schema. A no-op on a fresh
 * cache (no cursor yet) or a current-schema cache — the normal path is unchanged.
 */
export async function clearStaleCache(ctx: Ctx): Promise<void> {
  const cur = await ctx.read((t) => t.get('pocketCursor', 'self'))
  if (cur !== undefined && cur.schema !== CACHE_SCHEMA_VERSION) await clearPocketCache(ctx)
}

/**
 * Fold one locally-written entry into the cache, in the same flow as the write
 * (writeEntry), so cached reads stay fresh between syncs without re-fetching.
 * No-op until the cache has been materialized (the first read rebuilds it fully,
 * so a partial cache is never served). Does NOT advance the cursor — the cursor
 * tracks only relay-pulled wraps; a local write is covered by the next delta's
 * 2-day overlap. Monotonic: a lower/stale rev loses (foldOne).
 */
export async function foldLocal(ctx: Ctx, inp: FoldInput): Promise<void> {
  if (!(await materialized(ctx))) return
  await ctx.commit(async (t) => {
    const prev = await t.get('pocketCache', inp.entry.w)
    const next = foldOne(prev, inp)
    if (next === undefined) return
    await t.put('pocketCache', next, prev?.version ?? 0)
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
      // Merge, not clobber: a newer local write (higher rev, folded in by foldLocal
      // during this very sync) must not be regressed to this sync's pre-write
      // snapshot. foldOne keeps the winner (rev is monotonic); the resolver's
      // conflict is OR'd in. When prev already wins (folded undefined) only a
      // newly-flagged conflict is written.
      const folded = foldOne(prev, { entry: e, rumor: meta })
      if (folded !== undefined) {
        await t.put('pocketCache', { ...folded, conflict: folded.conflict || conflictSet.has(w) }, prev?.version ?? 0)
      } else if (prev !== undefined && conflictSet.has(w) && !prev.conflict) {
        await t.put('pocketCache', { ...prev, conflict: true, version: prev.version + 1 }, prev.version)
      }
    }
    for (const r of existing) if (!keep.has(r.id)) await t.delete('pocketCache', r.id)
  })
  await advanceCursor(ctx, maxAt)
}
