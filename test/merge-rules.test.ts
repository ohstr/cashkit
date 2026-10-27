// Which bills the wallet merges: by hub group, ordered bills apart, by the
// last-read min_transfer, never a bill kept out of merges or past its expiry.
import { describe, expect, test } from 'vitest'
import { splitCashString } from '../src/core/index.js'
import { CashkitError } from '../src/wallet/index.js'
import type { Holding } from '../src/wallet/model.js'
import { harness, type Harness } from './walletHarness.js'

const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )

async function bills(h: Harness, amounts: readonly bigint[]): Promise<string[]> {
  const ids: string[] = []
  for (const a of amounts) {
    const r = await h.wallet.receive(h.bank.mintToPubkey(a, h.me).token)
    if (r.received) ids.push(r.holding.id)
  }
  return ids
}

async function patch(h: Harness, id: string, f: (x: Holding) => Holding): Promise<void> {
  await h.storage.tx('rw', async (t) => {
    const row = (await t.get('holdings', id))!
    await t.put('holdings', { ...f(row), version: row.version + 1 }, row.version)
  })
}

/** A sorted copy. */
function sorted<T>(xs: readonly T[]): T[] {
  const c = [...xs]
  // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
  c.sort()
  return c
}

const calls = (h: Harness) => h.storage.tx('r', (t) => t.list('pendingCalls'))

describe('merge grouping', () => {
  test('ordered bills merge apart from the rest; each merge discloses common ownership', async () => {
    const h = await harness()
    const [a, b, c, d] = await bills(h, [1000n, 2000n, 3000n, 4000n])
    for (const id of [c!, d!]) await patch(h, id, (x) => ({ ...x, ordered: true }))
    const r = await h.wallet.consolidate()
    const merged = r.outcomes.flatMap((o) => (o.ok ? [sorted(o.from)] : []))
    expect(merged).toHaveLength(2)
    expect(merged).toContainEqual(sorted([a!, b!]))
    expect(merged).toContainEqual(sorted([c!, d!]))
    expect(r.outcomes.every((o) => o.ok && o.disclosesCommonOwnership)).toBe(true)
    const held = await h.wallet.holdings()
    expect(held.map((x) => [x.amount, x.ordered])).toEqual(expect.arrayContaining([[3000n, false], [7000n, true]]))
  })
  test('a different last-read min_transfer keeps bills apart', async () => {
    const h = await harness()
    const [a, b, c] = await bills(h, [1000n, 2000n, 3000n])
    await patch(h, c!, (x) => ({ ...x, minTransfer: 500n }))
    const r = await h.wallet.consolidate()
    expect(r.outcomes.flatMap((o) => (o.ok ? [sorted(o.from)] : []))).toEqual([sorted([a!, b!])])
    expect(r.aloneOnTheirHub).toEqual([c])
  })
  test('naming ordered and other bills together is mixed_ordered, before anything is written', async () => {
    const h = await harness()
    const [a, b] = await bills(h, [1000n, 2000n])
    await patch(h, a!, (x) => ({ ...x, ordered: true }))
    expect(await failure(h.wallet.consolidate({ holdings: [a!, b!] }))).toMatchObject({ code: 'invalid_input', reason: 'mixed_ordered' })
    expect(await calls(h)).toEqual([])
  })
  test('a send naming ordered and other bills together is mixed_ordered, before anything is written', async () => {
    const h = await harness()
    const [a, b] = await bills(h, [1000n, 2000n])
    await patch(h, a!, (x) => ({ ...x, ordered: true }))
    expect(await failure(h.wallet.planSend({ holdings: [a!, b!] }))).toMatchObject({ code: 'invalid_input', reason: 'mixed_ordered' })
    expect(await failure(h.wallet.send({ holdings: [a!, b!], amount: 2500n }))).toMatchObject({ code: 'invalid_input', reason: 'mixed_ordered' })
    expect(await calls(h)).toEqual([])
  })
  test('an expired bill is never auto-merged', async () => {
    const h = await harness()
    const [a, b, c] = await bills(h, [1000n, 2000n, 3000n])
    await patch(h, c!, (x) => ({ ...x, expiresAt: 1 }))
    const r = await h.wallet.consolidate()
    expect(r.outcomes.flatMap((o) => (o.ok ? [sorted(o.from)] : []))).toEqual([sorted([a!, b!])])
  })
})

describe('excludeFromMerge', () => {
  test('a bill kept out of merges is skipped by consolidate and shown as such', async () => {
    const h = await harness()
    const [a, b, c] = await bills(h, [1000n, 2000n, 3000n])
    expect((await h.wallet.holdings.setExcludeFromMerge(c!, true)).excludeFromMerge).toBe(true)
    const r = await h.wallet.consolidate()
    expect(r.outcomes.flatMap((o) => (o.ok ? [sorted(o.from)] : []))).toEqual([sorted([a!, b!])])
    expect((await h.wallet.holdings()).find((x) => x.id === c)?.excludeFromMerge).toBe(true)
  })
  test('a send that could only be covered by merging it is excluded_from_merge; a single bill still pays', async () => {
    const h = await harness()
    const [, b] = await bills(h, [1000n, 2000n])
    await h.wallet.holdings.setExcludeFromMerge(b!, true)
    expect(await failure(h.wallet.planSend({ amount: 2500n }))).toMatchObject({ code: 'invalid_input', reason: 'excluded_from_merge' })
    expect((await h.wallet.planSend({ amount: 1500n })).sources.map((s) => s.holdingId)).toEqual([b])
    await h.wallet.holdings.setExcludeFromMerge(b!, false)
    const plan = await h.wallet.planSend({ amount: 2500n })
    expect(plan).toMatchObject({ consolidateFirst: true, disclosesCommonOwnership: true })
  })
})

describe('cash note status', () => {
  test('is read with the bearer credential and no secret: unclaimed, then claimed once received', async () => {
    const h = await harness()
    await bills(h, [5000n])
    const r = await h.wallet.send({ amount: 1000n })
    const before = h.bank.hub.requests.length
    expect((await h.wallet.handoffs({ refresh: true })).map((x) => x.status)).toEqual(['unclaimed'])
    const reads = h.bank.hub.requests.slice(before).filter((x) => x.item.method === 'cash_status')
    expect(reads.length).toBeGreaterThan(0)
    expect(reads.every((x) => x.params['cash_secret'] === undefined)).toBe(true)
    const bob = await harness({ pool: h.pool, bank: h.bank })
    await bob.wallet.receive(r.cashNote!)
    expect(splitCashString(r.cashNote!).cashSecret).toMatch(/^[0-9a-f]{64}$/)
    expect((await h.wallet.handoffs({ refresh: true })).map((x) => x.status)).toEqual(['claimed'])
  })
})
