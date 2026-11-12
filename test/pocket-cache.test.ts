// The materialized pocket cache: the pairwise fold must agree, winner-for-winner
// and conflict-for-conflict, with core resolveEntries AND with the shared
// cross-impl golden corpus (cash-e2e/glue/vectors/pocket/resolution.json) that
// cashctl tests against too — so the two clients resolve a pocket identically.
// Plus fold idempotence / order-independence and the cursor's 2-day window.
import { existsSync, readFileSync } from 'node:fs'
import { describe, expect, test } from 'vitest'
import { resolveEntries, type PocketEntry, type PocketState } from '../src/core/index.js'
import { CACHE_SCHEMA_VERSION, cacheBalance, cacheEntries, cursorAt, foldDelta, foldLocal, foldOne, materialized, materializeFull, POCKET_SYNC_OVERLAP_SECONDS, type FoldInput } from '../src/wallet/pocketCache.js'
import { cachedBalanceOf, cachedEntriesOf } from '../src/wallet/pocket.js'
import type { Ctx } from '../src/wallet/context.js'
import type { Wallet } from '../src/wallet/index.js'
import { harness } from './walletHarness.js'

const ctxOf = (w: Wallet) => (w as unknown as { ctx: Ctx }).ctx

const VECTORS = new URL('../../cash-e2e/glue/vectors/pocket/resolution.json', import.meta.url)

interface VInput {
  w: string
  rev: number
  state: PocketState
  created_at: number
  id: string
}
interface VCase {
  name: string
  input: VInput[]
  winners: Record<string, VInput>
  conflicts: string[]
}

const mkEntry = (i: VInput): PocketEntry => ({ w: i.w, rev: i.rev, state: i.state, checkedAt: 1, wrapKey: '', amountMillis: 1n, chain: 'bitcoin' })
const foldInput = (i: VInput): FoldInput => ({ entry: mkEntry(i), rumor: { id: i.id, created_at: i.created_at } })
const rumorInput = (i: VInput) => ({ rumor: { id: i.id, created_at: i.created_at }, entry: { ...mkEntry(i), recognised: true } })
const vin = (w: string, rev: number, state: PocketState, id: string, created_at = 100): VInput => ({ w, rev, state, id, created_at })
const bill = (w: string, amount: bigint, state: PocketState = 'live'): PocketEntry => ({ w, rev: 1, state, checkedAt: 1, wrapKey: 'bb'.repeat(32), amountMillis: amount, chain: 'bitcoin', cash: 'satscash1x', identity: { type: 'pubkey', value: 'cc'.repeat(32) } })
const cachedInput = (w: string, amount: bigint, id: string, created_at: number, state: PocketState = 'live'): FoldInput => ({ entry: bill(w, amount, state), rumor: { id, created_at } })

/** Apply the pairwise fold over `inputs` in order, returning the winner + conflict per w. */
function foldAll(inputs: readonly VInput[]): { winners: Map<string, { rev: number; state: string; id: string }>; conflicts: Set<string> } {
  const rows = new Map<string, ReturnType<typeof foldOne> & object>()
  for (const i of inputs) {
    const next = foldOne(rows.get(i.w), foldInput(i))
    if (next !== undefined) rows.set(i.w, next)
  }
  const winners = new Map<string, { rev: number; state: string; id: string }>()
  const conflicts = new Set<string>()
  for (const [w, r] of rows) {
    winners.set(w, { rev: r.rev, state: r.state, id: r.rumorId })
    if (r.conflict) conflicts.add(w)
  }
  return { winners, conflicts }
}

function* permutations<T>(xs: readonly T[]): Generator<T[]> {
  if (xs.length <= 1) {
    yield [...xs]
    return
  }
  for (let i = 0; i < xs.length; i++) {
    const rest = [...xs.slice(0, i), ...xs.slice(i + 1)]
    for (const p of permutations(rest)) yield [xs[i]!, ...p]
  }
}

const cases: VCase[] | undefined = existsSync(VECTORS) ? (JSON.parse(readFileSync(VECTORS, 'utf8')) as VCase[]) : undefined

describe('pocket cache fold — golden-vector cross-impl parity', () => {
  if (cases === undefined) {
    test.skip('resolution.json not found (cash-e2e not checked out alongside) — skipped', () => {})
    return
  }
  for (const c of cases) {
    test(`resolveEntries matches vector: ${c.name}`, () => {
      const { entries, conflicts } = resolveEntries(c.input.map(rumorInput))
      for (const [w, win] of Object.entries(c.winners)) {
        const e = entries.get(w)
        expect(e?.rev, w).toBe(win.rev)
        expect(e?.state, w).toBe(win.state)
      }
      expect(new Set(conflicts)).toEqual(new Set(c.conflicts))
    })

    test(`pairwise fold matches vector in EVERY order: ${c.name}`, () => {
      const expectWinners = new Map(Object.entries(c.winners).map(([w, win]) => [w, { rev: win.rev, state: win.state as string, id: win.id }]))
      const expectConflicts = new Set(c.conflicts)
      // every permutation + a re-applied (idempotent) run converge on the same result
      for (const order of permutations(c.input)) {
        const got = foldAll([...order, ...order]) // doubled: also proves idempotence
        expect(got.winners, `${c.name} / ${order.map((i) => i.id).join(',')}`).toEqual(expectWinners)
        expect(got.conflicts).toEqual(expectConflicts)
      }
    })
  }
})

describe('pocket cache fold — units', () => {
  const i = vin

  test('first entry wins, re-applying it is a no-op (idempotent)', () => {
    const a = foldInput(i('a'.repeat(64), 1, 'live', '01'))
    const first = foldOne(undefined, a)
    expect(first?.rev).toBe(1)
    expect(foldOne(first, a)).toBeUndefined()
  })

  test('higher rev supersedes and resets conflict', () => {
    const w = 'b'.repeat(64)
    const row0 = foldOne(undefined, foldInput(i(w, 1, 'live', '01')))!
    const row = foldOne(row0, foldInput(i(w, 1, 'live', '02'))) ?? row0 // tie → conflict
    expect(row.conflict).toBe(true)
    const up = foldOne(row, foldInput(i(w, 2, 'spent', '03')))
    expect(up?.rev).toBe(2)
    expect(up?.conflict).toBe(false)
  })

  test('lower rev loses (no change)', () => {
    const w = 'c'.repeat(64)
    const row = foldOne(undefined, foldInput(i(w, 5, 'live', '09')))
    expect(foldOne(row, foldInput(i(w, 3, 'spent', '01')))).toBeUndefined()
  })

  test('the 2-day cursor overlap guards NIP-59 back-dating (risk 13)', () => {
    expect(POCKET_SYNC_OVERLAP_SECONDS).toBe(2 * 86400)
  })
})

describe('cached reads are served locally (no relay)', () => {
  const inp = cachedInput
  const W1 = 'a'.repeat(64)
  const W2 = 'b'.repeat(64)

  test('cachedBalance/cachedEntries read the materialized cache with NO pocket configured', async () => {
    const h = await harness() // a wallet with NO `pocket` dep: any relay touch would throw requirePocket
    const ctx = ctxOf(h.wallet)
    await foldDelta(ctx, [inp(W1, 500n, '01', 1000), inp(W2, 700n, '02', 1100), inp(W2, 700n, '03', 1200)])
    // W2 folded twice at the same rev with different ids → a conflict; balance counts it once.
    expect(await cachedBalanceOf(ctx)).toEqual(new Map([['bitcoin', 1200n]]))
    const { entries, conflicts } = await cachedEntriesOf(ctx)
    expect(new Set(entries.map((e) => e.w))).toEqual(new Set([W1, W2]))
    expect(conflicts).toEqual([W2])
    // the cursor advanced to the newest folded created_at
    expect(await cursorAt(ctx)).toBe(1200)
  })

  test('a spent fold drops the bill from the cached balance', async () => {
    const h = await harness()
    const ctx = ctxOf(h.wallet)
    await foldDelta(ctx, [inp(W1, 500n, '01', 1000)])
    expect(await cachedBalanceOf(ctx)).toEqual(new Map([['bitcoin', 500n]]))
    await foldDelta(ctx, [inp(W1, 500n, '09', 2000, 'spent')]) // rev 1, final beats non-final at equal rev
    expect(await cachedBalanceOf(ctx)).toEqual(new Map())
  })
})

/** A PocketEntry at a chosen rev/state/amount (the fold's winner input). */
const entryRev = (w: string, rev: number, amount: bigint, state: PocketState = 'live'): PocketEntry => ({ w, rev, state, checkedAt: 1, wrapKey: 'bb'.repeat(32), amountMillis: amount, chain: 'bitcoin', cash: 'satscash1x', identity: { type: 'pubkey', value: 'cc'.repeat(32) } })

describe('the cache-schema version marks a stale cache (FIX 6)', () => {
  const W = 'a'.repeat(64)

  test('materialized is true only for a cursor stamped with the current schema', async () => {
    const h = await harness()
    const ctx = ctxOf(h.wallet)
    // A fold stamps the current schema on the cursor → materialized.
    await foldDelta(ctx, [cachedInput(W, 100n, '01', 1000)])
    const cur = await ctx.read((t) => t.get('pocketCursor', 'self'))
    expect(cur?.schema).toBe(CACHE_SCHEMA_VERSION)
    expect(await materialized(ctx)).toBe(true)
    // A cursor from an older version (no `schema` field) reads as stale.
    await ctx.commit((t) => t.put('pocketCursor', { id: 'self', at: cur!.at, version: cur!.version + 1 }, cur!.version))
    expect(await materialized(ctx)).toBe(false)
    // An explicitly older schema number is stale too.
    const bare = await ctx.read((t) => t.get('pocketCursor', 'self'))
    await ctx.commit((t) => t.put('pocketCursor', { id: 'self', at: bare!.at, schema: CACHE_SCHEMA_VERSION - 1, version: bare!.version + 1 }, bare!.version))
    expect(await materialized(ctx)).toBe(false)
  })
})

describe('the normal materializeFull merge stays intact (positive control)', () => {
  const W = 'd'.repeat(64)

  test('a delta materializeFull does NOT regress a legitimately newer local write', async () => {
    const h = await harness()
    const ctx = ctxOf(h.wallet)
    // A sync materializes the pre-write snapshot: W live@rev1.
    await materializeFull(ctx, new Map([[W, entryRev(W, 1, 500n, 'live')]]), new Map([[W, { created_at: 1000, id: '01' }]]), [])
    expect(await cacheBalance(ctx)).toEqual(new Map([['bitcoin', 500n]]))
    // Mid-sync, this device writes W spent at the next rev (folded in by foldLocal).
    await foldLocal(ctx, { entry: entryRev(W, 2, 500n, 'spent'), rumor: { id: '02', created_at: 1100 } })
    expect(await cacheBalance(ctx)).toEqual(new Map())
    // The same sync now merges its pre-write snapshot (W live@rev1) — it MUST NOT
    // clobber the newer local spent@rev2 (rev-monotonic merge keeps the winner).
    await materializeFull(ctx, new Map([[W, entryRev(W, 1, 500n, 'live')]]), new Map([[W, { created_at: 1000, id: '01' }]]), [])
    const { entries } = await cacheEntries(ctx)
    expect(entries.find((e) => e.w === W)?.state).toBe('spent')
    expect(await cacheBalance(ctx)).toEqual(new Map())
  })
})
