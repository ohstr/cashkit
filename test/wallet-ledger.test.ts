// Holding rows, OCC and the memory adapters. Ported from cashctl
// internal/ledger/ledger_test.go and auditD_cli_occ_crossprocess_test.go
// (test names in comments).
import { describe, expect, test } from 'vitest'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { NoneVault } from '../src/adapters/vault-none.js'
import { MemoryLock } from '../src/adapters/lock-memory.js'
import { CashkitError } from '../src/wallet/errors.js'
import { addHandoff, addHolding, appendActivity, findByToken, heldHoldings, notHeldError, setStatus, updateHolding, type NewHolding } from '../src/wallet/ledger.js'
import { ConcurrentUpdateError } from '../src/wallet/ports.js'

let n = 0
const random = (k: number) => Uint8Array.from({ length: k }, () => ++n & 0xff)
const o = () => ({ now: 1_700_000_000_000, random })

const nh = (token: string, extra: Partial<NewHolding> = {}): NewHolding => ({
  token,
  walletPubkey: 'ab'.repeat(32),
  hubGroup: '',
  relayUrls: ['wss://r'],
  verified: false,
  mode: 'pubkey',
  protection: 'none',
  ...extra,
})

const rw = <T>(s: MemoryStorage, fn: Parameters<MemoryStorage['tx']>[1]) => s.tx('rw', fn) as Promise<T>

describe('addHolding', () => {
  test('generates an id and sets held, version 1 (TestAdd_GeneratesIDAndSetsDefaults)', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh('lokicash1aaa'), o()))
    expect(row.id).toMatch(/^h-[0-9a-f]{8}$/)
    expect(row).toMatchObject({ status: 'held', version: 1, addedAt: o().now })
  })
  test('rejects a token already held, even differing only in case (TestAdd_RejectsDuplicateToken, …DifferingOnlyInCase)', async () => {
    const s = new MemoryStorage()
    await s.tx('rw', (t) => addHolding(t, nh('lokicash1aaa'), o()))
    for (const tok of ['lokicash1aaa', 'LOKICASH1AAA']) {
      const err = await s.tx('rw', (t) => addHolding(t, nh(tok), o())).catch((e: unknown) => e)
      expect(err).toBeInstanceOf(CashkitError)
      expect((err as CashkitError).code).toBe('conflict')
    }
  })
  test('stores the token lowercase and finds it case-insensitively (TestAdd_StoresTokenLowercase, TestFindByToken_IsCaseInsensitive…)', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh('LokiCash1AbC'), o()))
    expect(row.token).toBe('lokicash1abc')
    expect((await s.tx('r', (t) => findByToken(t, 'LOKICASH1ABC')))?.id).toBe(row.id)
  })
  test('reactivates a no-longer-held token with the same id and fresh fields (TestAdd_ReactivatesANoLongerHeldToken)', async () => {
    const s = new MemoryStorage()
    const first = await s.tx('rw', (t) => addHolding(t, nh('lokicash1aaa', { amount: 5n }), o()))
    await s.tx('rw', (t) => setStatus(t, first.id, 'transferred'))
    const again = await s.tx('rw', (t) => addHolding(t, nh('lokicash1aaa', { amount: 9n, mode: 'cash' }), o()))
    expect(again.id).toBe(first.id)
    expect(again).toMatchObject({ status: 'held', amount: 9n, mode: 'cash', version: 3 })
    expect(await s.tx('r', (t) => t.list('holdings'))).toHaveLength(1)
  })
  test('heldHoldings excludes every non-held status (TestHeld_ExcludesNonHeldStatuses)', async () => {
    const s = new MemoryStorage()
    const statuses = ['held', 'redeemed', 'transferred', 'consolidated', 'spent'] as const
    await s.tx('rw', async (t) => {
      for (const [i, st] of statuses.entries()) {
        const row = await addHolding(t, nh(`lokicash1t${i}`), o())
        if (st !== 'held') await setStatus(t, row.id, st)
      }
    })
    expect((await s.tx('r', heldHoldings)).map((h) => h.token)).toEqual(['lokicash1t0'])
  })
  test('setStatus on an unknown id is not_found (TestSetStatus_UnknownIDErrors)', async () => {
    const s = new MemoryStorage()
    await expect(s.tx('rw', (t) => setStatus(t, 'h-nope', 'spent'))).rejects.toMatchObject({ code: 'not_found' })
  })
  test('generated ids do not collide (TestNewID_NoCollisions)', async () => {
    const s = new MemoryStorage()
    // A random source that repeats its first draw must still yield distinct ids.
    let calls = 0
    const repeating = (k: number) => (calls++ < 2 ? new Uint8Array([1, 2, 3, 4]) : random(k))
    const a = await s.tx('rw', (t) => addHolding(t, nh('lokicash1x0'), { now: 1, random: repeating }))
    const b = await s.tx('rw', (t) => addHolding(t, nh('lokicash1x1'), { now: 1, random: repeating }))
    expect(a.id).toBe('h-01020304')
    expect(b.id).not.toBe(a.id)
    expect(calls).toBe(3)
  })
})

describe('OCC (auditD_cli_occ_crossprocess)', () => {
  test('two writers on the same row: the second conflicts', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh('lokicash1aaa'), o()))
    await s.tx('rw', (t) => updateHolding(t, row.id, (h) => ({ ...h, verified: true }), row.version))
    await expect(s.tx('rw', (t) => updateHolding(t, row.id, (h) => ({ ...h, amount: 1n }), row.version))).rejects.toMatchObject({ code: 'conflict', retryable: true })
  })
  test('writers on different rows both succeed (TestSave_ConcurrentDisjointWritesDoNotClobber)', async () => {
    const s = new MemoryStorage()
    const [a, b] = await s.tx('rw', async (t) => [await addHolding(t, nh('lokicash1a'), o()), await addHolding(t, nh('lokicash1b'), o())])
    await Promise.all([
      s.tx('rw', (t) => updateHolding(t, a!.id, (h) => ({ ...h, amount: 1n }), a!.version)),
      s.tx('rw', (t) => updateHolding(t, b!.id, (h) => ({ ...h, amount: 2n }), b!.version)),
    ])
    const rows = await s.tx('r', (t) => t.list('holdings'))
    expect(rows.map((r) => r.amount)).toEqual([1n, 2n])
  })
  test('concurrent receives of one token keep one row (TestSave_ConcurrentSameTokenReceiveDoesNotDuplicate)', async () => {
    const s = new MemoryStorage()
    const results = await Promise.allSettled([1, 2, 3].map(() => s.tx('rw', (t) => addHolding(t, nh('lokicash1same'), o()))))
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect(await s.tx('r', (t) => t.list('holdings'))).toHaveLength(1)
  })
  test('put with a stale expectVersion throws ConcurrentUpdateError and rolls back the whole tx', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh('lokicash1aaa'), o()))
    const err = await s
      .tx('rw', async (t) => {
        await addHolding(t, nh('lokicash1bbb'), o())
        await t.put('holdings', { ...row, version: 9 }, 5)
      })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ConcurrentUpdateError)
    expect(await s.tx('r', (t) => t.list('holdings'))).toHaveLength(1)
  })
})

describe('MemoryStorage', () => {
  test('a read-only tx cannot write', async () => {
    const s = new MemoryStorage()
    await expect(s.tx('r', (t) => t.delete('holdings', 'x'))).rejects.toThrow(/read-only/)
  })
  test('rows are copies: mutating a read does not change the store', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh('lokicash1aaa'), o()))
    ;(row.relayUrls as string[]).push('wss://evil')
    expect((await s.tx('r', (t) => t.get('holdings', row.id)))?.relayUrls).toEqual(['wss://r'])
  })
  test('list filters with where, in insertion order, and sees staged writes', async () => {
    const s = new MemoryStorage()
    await rw(s, async (t) => {
      await addHolding(t, nh('lokicash1a', { mode: 'cash' }), o())
      await addHolding(t, nh('lokicash1b'), o())
      await addHolding(t, nh('lokicash1c', { mode: 'cash' }), o())
      expect((await t.list('holdings', { where: { mode: 'cash' } })).map((h) => h.token)).toEqual(['lokicash1a', 'lokicash1c'])
    })
  })
  test('activity is append-only with increasing keys (TestAppendHistory)', async () => {
    const s = new MemoryStorage()
    await s.tx('rw', async (t) => {
      await appendActivity(t, 1, { action: 'spent', holdingId: 'h-1' })
      await appendActivity(t, 2, { action: 'protect', holdingId: 'h-1' })
    })
    const rows = await s.tx('r', (t) => t.list('activity'))
    expect(rows.map((r) => r.action)).toEqual(['spent', 'protect'])
    expect(rows[0]!.id < rows[1]!.id).toBe(true)
  })
})

test('handoffs: a cash note starts unclaimed, a gift sent (TestHandoffs_PersistAndOnlyStatusChanges)', async () => {
  const s = new MemoryStorage()
  const v = new NoneVault()
  const sealed = await v.seal(new Uint8Array([1]))
  const [note, gift] = await s.tx('rw', async (t) => [
    await addHandoff(t, { kind: 'cash_note', handoff: sealed, amount: 5n, target: 'cash', walletPubkey: 'w' }, o()),
    await addHandoff(t, { kind: 'gift', handoff: sealed, amount: 5n, target: 'npub1x', walletPubkey: 'w' }, o()),
  ])
  expect(note!.status).toBe('unclaimed')
  expect(gift!.status).toBe('sent')
})

test('notHeldError: value gone is spent, given away is not_found (cmd/spent.go alreadySpentError)', () => {
  for (const st of ['redeemed', 'consolidated', 'spent'] as const) expect(notHeldError({ id: 'h', status: st }).code).toBe('spent')
  expect(notHeldError({ id: 'h', status: 'transferred' }).code).toBe('not_found')
})

describe('vault-none and lock-memory', () => {
  test('vault-none round-trips and refuses foreign seals', async () => {
    const v = new NoneVault()
    const s = await v.seal(new Uint8Array([0xde, 0xad]))
    expect(await v.open(s)).toEqual(new Uint8Array([0xde, 0xad]))
    expect(v.locked()).toBe(false)
    await expect(v.open({ alg: 'xchacha', data: '00' })).rejects.toThrow(/vault-none/)
  })
  test('lock-memory runs holders of one name one at a time, in order, across failures', async () => {
    const lock = new MemoryLock()
    const order: string[] = []
    const step = (name: string, id: string, fail = false) =>
      lock.withLock(name, async () => {
        order.push(`${id}:in`)
        await new Promise((r) => setTimeout(r, 5))
        order.push(`${id}:out`)
        if (fail) throw new Error('x')
      })
    await Promise.allSettled([step('a', '1', true), step('a', '2'), step('b', '3')])
    expect(order.indexOf('1:out')).toBeLessThan(order.indexOf('2:in'))
    expect(order.indexOf('3:in')).toBeLessThan(order.indexOf('1:out'))
  })
})
