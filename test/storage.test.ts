// Every Storage adapter against the one contract (test/storageContract.ts),
// plus what is specific to each.
import { mkdtempSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { describe, expect, test } from 'vitest'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { SQLITE_SCHEMA_VERSION, SqliteStorage } from '../src/adapters/storage-sqlite.js'
import { IndexedDbStorage } from '../src/adapters/storage-indexeddb.js'
import { indexedDB } from 'fake-indexeddb'
import { decodeRow, encodeRow } from '../src/wallet/codec.js'
import { storageContract } from './storageContract.js'
import { harness } from './walletHarness.js'

const dir = mkdtempSync(join(tmpdir(), 'cashkit-storage-'))
let n = 0
const fresh = () => join(dir, `w${++n}.db`)

storageContract({ name: 'memory', open: async () => new MemoryStorage() })

storageContract({
  name: 'sqlite (node:sqlite)',
  open: async (loc) => SqliteStorage.open({ path: loc ?? fresh() }),
  location: fresh,
  close: (s) => (s as SqliteStorage).close(),
})

let idb = 0
storageContract({
  name: 'indexeddb (fake-indexeddb)',
  open: async (loc) => IndexedDbStorage.open({ name: loc ?? `w${++idb}`, indexedDB }),
  location: () => `loc${++idb}`,
  close: async (s) => (s as IndexedDbStorage).close(),
})

describe('IndexedDbStorage', () => {
  test('a callback that awaits something else loses its transaction (§3: never await off-tx)', async () => {
    const s = await IndexedDbStorage.open({ name: `w${++idb}`, indexedDB })
    const err = await s
      .tx('rw', async (t) => {
        await t.put('holdings', { id: 'a', version: 1 } as never, 0)
        await new Promise((r) => setTimeout(r, 5))
        await t.put('holdings', { id: 'b', version: 1 } as never, 0)
      })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(Error)
    s.close()
  })
})

describe('SqliteStorage', () => {
  test('creates the file 0600, in WAL mode, at the current schema (cashctl internal/store)', async () => {
    const path = fresh()
    const s = await SqliteStorage.open({ path })
    await s.tx('rw', (t) => t.put('meta', { id: 'meta', schemaVersion: 1, walletId: 'w', version: 1 }, 0))
    await s.close()
    if (process.platform !== 'win32') expect(statSync(path).mode & 0o777).toBe(0o600)
    const db = new DatabaseSync(path)
    expect((db.prepare('PRAGMA journal_mode').get() as { journal_mode: string }).journal_mode).toBe('wal')
    expect((db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version).toBe(SQLITE_SCHEMA_VERSION)
    db.close()
  })
  test('refuses a database from a newer schema', async () => {
    const path = fresh()
    const db = new DatabaseSync(path)
    db.exec('PRAGMA user_version = 99')
    db.close()
    await expect(SqliteStorage.open({ path })).rejects.toThrow(/newer cashkit/)
  })
  test('migrating twice is a no-op', async () => {
    const path = fresh()
    await (await SqliteStorage.open({ path })).close()
    const s = await SqliteStorage.open({ path })
    await s.tx('rw', (t) => t.put('holdings', { id: 'h', version: 1 } as never, 0))
    await s.close()
  })
  test('a closed store refuses new transactions', async () => {
    const s = await SqliteStorage.open({ path: fresh() })
    await s.close()
    await expect(s.tx('r', (t) => t.list('holdings'))).rejects.toThrow(/closed/)
  })
  test('a read never sees a write that has not committed', async () => {
    const s = await SqliteStorage.open({ path: fresh() })
    let seen: unknown = 'unset'
    await s.tx('rw', async (t) => {
      await t.put('holdings', { id: 'h', version: 1 } as never, 0)
      seen = await s.tx('r', (r) => r.get('holdings', 'h'))
    })
    expect(seen).toBeUndefined()
    expect(await s.tx('r', (r) => r.get('holdings', 'h'))).toMatchObject({ id: 'h' })
    await s.close()
  })
})

test('a wallet on SQLite receives, sends, and reopens with everything intact', async () => {
  const path = fresh()
  const storage = await SqliteStorage.open({ path })
  const h = await harness({ storage })
  await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
  const sent = await h.wallet.send({ amount: 2000n })
  await storage.close()
  const again = await SqliteStorage.open({ path })
  const w = await h.reopen({ storage: again })
  expect((await w.holdings()).map((x) => x.amount)).toEqual([3000n])
  const [note] = await w.handoffs({ includeSecrets: true })
  expect(note!.handoff).toBe(sent.cashNote)
  expect((await w.identity.get())?.pubkey).toBe(h.me)
  await again.close()
})

test('a wallet on IndexedDB runs receive, protect, a merging send and consolidate: no commit awaits off its tx', async () => {
  const name = `wallet${++idb}`
  const storage = await IndexedDbStorage.open({ name, indexedDB })
  const h = await harness({ storage })
  const t = (await import('../src/core/index.js')).newCashTarget()
  const r = await h.wallet.receive(`${h.bank.mintToCash(3000n, t.secret).token}#${t.secret}`)
  expect(r.received && r.secured.status).toBe('rekeyed')
  await h.wallet.receive(h.bank.mintToPubkey(3000n, h.me).token)
  await h.wallet.receive(h.bank.mintToPubkey(1000n, h.me).token)
  const sent = await h.wallet.send({ amount: 5000n })
  expect(sent.consolidatedFirst).toBe(true)
  await h.wallet.status()
  storage.close()
  const again = await IndexedDbStorage.open({ name, indexedDB })
  const w = await h.reopen({ storage: again })
  expect((await w.holdings()).reduce((a, x) => a + (x.amount ?? 0n), 0n)).toBe(2000n)
  again.close()
})

test('codec round-trips bigint exactly, and leaves look-alike objects alone', () => {
  const v = { a: 2n ** 70n, b: [1n, { c: -5n }], d: { $bigint: 1 }, e: 'x' }
  expect(decodeRow(encodeRow(v))).toEqual(v)
  expect(encodeRow({ x: undefined, y: 1n })).toBe('{"y":{"$bigint":"1"}}')
})
