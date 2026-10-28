// The Storage port's contract (design §3), run against every adapter. Cases
// follow cashctl internal/ledger/ledger_test.go and
// auditD_cli_occ_crossprocess_test.go where they cover the same behaviour.
import { describe, expect, test } from 'vitest'
import { ConcurrentUpdateError, type Storage } from '../src/wallet/index.js'
import { COLLECTIONS } from '../src/wallet/model.js'

export interface StorageFactory {
  readonly name: string
  /** A new store at `location` (a fresh one when omitted). */
  open(location?: string): Promise<Storage>
  /** A fresh location, for adapters that persist; undefined for memory. */
  location?(): string
  close?(s: Storage): Promise<void>
}

// A row shape every collection accepts in practice; the contract does not care about fields.
type AnyRow = { id: string; version: number; [k: string]: unknown }
const row = (id: string, version: number, extra: Record<string, unknown> = {}): AnyRow => ({ id, version, ...extra })
const put = (s: Storage, r: AnyRow, expectVersion?: number) => s.tx('rw', (t) => t.put('holdings', r as never, expectVersion))
const get = (s: Storage, id: string) => s.tx('r', (t) => t.get('holdings', id)) as Promise<AnyRow | undefined>
const list = (s: Storage) => s.tx('r', (t) => t.list('holdings')) as unknown as Promise<AnyRow[]>

export function storageContract(f: StorageFactory): void {
  describe(`Storage contract: ${f.name}`, () => {
    test('every collection of the schema keeps its own rows (T-516)', async () => {
      const s = await f.open()
      for (const c of COLLECTIONS) {
        if (c === 'activity') continue
        await s.tx('rw', (t) => t.put(c, { id: 'same', version: 1, coll: c, amount: 1n } as never, 0))
      }
      for (const c of COLLECTIONS) {
        if (c === 'activity') continue
        const rows = (await s.tx('r', (t) => t.list(c))) as unknown as { coll: string; amount: bigint }[]
        expect(rows).toEqual([{ id: 'same', version: 1, coll: c, amount: 1n }])
      }
      await f.close?.(s)
    })
    test('put then get round-trips bigint, nested objects, arrays and sealed values', async () => {
      const s = await f.open()
      const r = row('h-1', 1, { amount: 9007199254740993n, sealed: { alg: 'none', data: 'ab' }, relayUrls: ['wss://a', 'wss://b'], nested: { at: 1, flag: true, none: null } })
      await put(s, r, 0)
      expect(await get(s, 'h-1')).toEqual(r)
      await f.close?.(s)
    })
    test('rows are copies: mutating a read changes nothing', async () => {
      const s = await f.open()
      await put(s, row('h-1', 1, { relayUrls: ['wss://a'] }), 0)
      const a = (await get(s, 'h-1'))!
      ;(a['relayUrls'] as string[]).push('wss://evil')
      expect((await get(s, 'h-1'))!['relayUrls']).toEqual(['wss://a'])
      await f.close?.(s)
    })
    test('a stale expectVersion throws ConcurrentUpdateError and rolls back the whole tx (TestSave_ConcurrentDisjointWritesDoNotClobber)', async () => {
      const s = await f.open()
      await put(s, row('h-1', 1), 0)
      const err = await s
        .tx('rw', async (t) => {
          await t.put('holdings', row('h-2', 1) as never, 0)
          await t.put('holdings', row('h-1', 9) as never, 5)
        })
        .catch((e: unknown) => e)
      expect(err).toBeInstanceOf(ConcurrentUpdateError)
      expect((await list(s)).map((r) => r.id)).toEqual(['h-1'])
      await f.close?.(s)
    })
    test('expectVersion 0 means "no row yet"', async () => {
      const s = await f.open()
      await put(s, row('h-1', 1), 0)
      await expect(put(s, row('h-1', 1), 0)).rejects.toBeInstanceOf(ConcurrentUpdateError)
      await put(s, row('h-1', 2), 1)
      expect((await get(s, 'h-1'))!.version).toBe(2)
      await f.close?.(s)
    })
    test('a throw inside a tx rolls everything back', async () => {
      const s = await f.open()
      await expect(
        s.tx('rw', async (t) => {
          await t.put('holdings', row('h-1', 1) as never, 0)
          throw new Error('boom')
        }),
      ).rejects.toThrow('boom')
      expect(await list(s)).toEqual([])
      await f.close?.(s)
    })
    test('a read-only tx cannot write', async () => {
      const s = await f.open()
      await expect(s.tx('r', (t) => t.delete('holdings', 'x'))).rejects.toThrow(/read-only/)
      await f.close?.(s)
    })
    test('list keeps insertion order, filters with where, and sees the tx own writes', async () => {
      const s = await f.open()
      await s.tx('rw', async (t) => {
        for (const [id, mode] of [['h-c', 'cash'], ['h-a', 'pubkey'], ['h-b', 'cash']] as const) await t.put('holdings', row(id, 1, { mode }) as never, 0)
        expect((await t.list('holdings', { where: { mode: 'cash' } } as never)).map((r) => (r as unknown as AnyRow).id)).toEqual(['h-c', 'h-b'])
      })
      expect((await list(s)).map((r) => r.id)).toEqual(['h-c', 'h-a', 'h-b'])
      await f.close?.(s)
    })
    test('an updated row keeps its place in the order', async () => {
      const s = await f.open()
      await put(s, row('h-1', 1), 0)
      await put(s, row('h-2', 1), 0)
      await put(s, row('h-1', 2), 1)
      expect((await list(s)).map((r) => r.id)).toEqual(['h-1', 'h-2'])
      await f.close?.(s)
    })
    test('delete removes the row', async () => {
      const s = await f.open()
      await put(s, row('h-1', 1), 0)
      await s.tx('rw', (t) => t.delete('holdings', 'h-1'))
      expect(await get(s, 'h-1')).toBeUndefined()
      await f.close?.(s)
    })
    test('insert gives increasing keys and keeps order (TestAppendHistory)', async () => {
      const s = await f.open()
      const ids = await s.tx('rw', async (t) => [await t.insert('activity', { at: 1, action: 'spent', holdingId: 'h' } as never), await t.insert('activity', { at: 2, action: 'protect', holdingId: 'h' } as never)])
      expect(ids[0]! < ids[1]!).toBe(true)
      const rows = (await s.tx('r', (t) => t.list('activity'))) as unknown as AnyRow[]
      expect(rows.map((r) => r.id)).toEqual(ids)
      expect(rows.map((r) => r['action'])).toEqual(['spent', 'protect'])
      await f.close?.(s)
    })
    test('collections are separate', async () => {
      const s = await f.open()
      await s.tx('rw', async (t) => {
        await t.put('holdings', row('x', 1) as never, 0)
        await t.put('connections', row('x', 1, { kind: 'nwc' }) as never, 0)
      })
      expect(await s.tx('r', (t) => t.get('connections', 'x'))).toMatchObject({ kind: 'nwc' })
      expect(await s.tx('r', (t) => t.list('handoffs'))).toEqual([])
      await f.close?.(s)
    })
    test('concurrent rw transactions are serialised, so both increments land', async () => {
      const s = await f.open()
      await put(s, row('n', 1, { n: 0 }), 0)
      const bump = () =>
        s.tx('rw', async (t) => {
          const cur = (await t.get('holdings', 'n')) as unknown as AnyRow
          await t.put('holdings', { ...cur, n: (cur['n'] as number) + 1, version: cur.version + 1 } as never, cur.version)
        })
      await Promise.all([bump(), bump(), bump()])
      expect((await get(s, 'n'))!['n']).toBe(3)
      await f.close?.(s)
    })
    test('concurrent receives of one key keep one row (TestSave_ConcurrentSameTokenReceiveDoesNotDuplicate)', async () => {
      const s = await f.open()
      const results = await Promise.allSettled([1, 2, 3].map(() => put(s, row('same', 1), 0)))
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
      expect(await list(s)).toHaveLength(1)
      await f.close?.(s)
    })

    if (f.location !== undefined) {
      const where = f.location
      test('data survives closing and reopening', async () => {
        const loc = where()
        const a = await f.open(loc)
        await put(a, row('h-1', 1, { amount: 5n }), 0)
        await f.close?.(a)
        const b = await f.open(loc)
        expect(await get(b, 'h-1')).toEqual(row('h-1', 1, { amount: 5n }))
        await f.close?.(b)
      })
      test('two instances on one store: a stale write conflicts, disjoint rows both land (auditD_cli_occ_crossprocess)', async () => {
        const loc = where()
        const a = await f.open(loc)
        const b = await f.open(loc)
        await put(a, row('h-1', 1), 0)
        await put(a, row('h-2', 1), 0)
        await put(b, row('h-1', 2), 1)
        await expect(put(a, row('h-1', 2), 1)).rejects.toBeInstanceOf(ConcurrentUpdateError)
        await Promise.all([put(a, row('h-2', 2), 1), put(b, row('h-3', 1), 0)])
        expect((await list(a)).map((r) => [r.id, r.version])).toEqual([['h-1', 2], ['h-2', 2], ['h-3', 1]])
        await f.close?.(a)
        await f.close?.(b)
      })
    }
  })
}
