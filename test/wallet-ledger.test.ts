// Holding rows, OCC and the memory adapters. Ported from cashctl
// internal/ledger/ledger_test.go and auditD_cli_occ_crossprocess_test.go
// (test names in comments).
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import { decodeToken, encodeToken, MINT_SIGNATURE_LEN, toHex, utf8 } from '../src/core/index.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { NoneVault } from '../src/adapters/vault-none.js'
import { MemoryLock } from '../src/adapters/lock-memory.js'
import { CashkitError } from '../src/wallet/errors.js'
import { addHandoff, addHolding, appendActivity, findByToken, heldHoldings, normalizeHoldings, notHeldError, setStatus, updateHolding, type NewHolding } from '../src/wallet/ledger.js'
import { bech32Decode, bech32Encode, fromWords, toWords } from '../src/core/bech32.js'
import { readTLVs, writeTLVs } from '../src/core/tlv.js'
import { canonicalToken, verifyProvenance } from '../src/core/index.js'
import { readFileSync } from 'node:fs'
import { harness } from './walletHarness.js'
import { ConcurrentUpdateError } from '../src/wallet/ports.js'

let n = 0
const random = (k: number) => Uint8Array.from({ length: k }, () => ++n & 0xff)
const o = () => ({ now: 1_700_000_000_000, random })

/** A real bill string whose wallet pubkey is derived from `name`. */
const tok = (name: string): string =>
  encodeToken({
    hrp: 'satscash',
    walletPubkey: toHex(sha256(utf8(`wallet ${name}`))),
    secret: toHex(sha256(utf8(`secret ${name}`))),
    relays: ['wss://r.test'],
    scheme: 'mint_v1',
    mintSignature: new Uint8Array(MINT_SIGNATURE_LEN).fill(1),
    attestedAmountMillis: 1000n,
  })

const nh = (token: string, extra: Partial<NewHolding> = {}): NewHolding => ({
  token,
  walletPubkey: decodeToken(token).walletPubkey,
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
    const row = await s.tx('rw', (t) => addHolding(t, nh(tok('aaa')), o()))
    expect(row.id).toMatch(/^h-[0-9a-f]{8}$/)
    expect(row).toMatchObject({ status: 'held', version: 1, addedAt: o().now })
  })
  test('rejects a token already held, even differing only in case (TestAdd_RejectsDuplicateToken, …DifferingOnlyInCase)', async () => {
    const s = new MemoryStorage()
    await s.tx('rw', (t) => addHolding(t, nh(tok('aaa')), o()))
    for (const spelling of [tok('aaa'), tok('aaa').toUpperCase()]) {
      const err = await s.tx('rw', (t) => addHolding(t, nh(spelling), o())).catch((e: unknown) => e)
      expect(err).toBeInstanceOf(CashkitError)
      expect((err as CashkitError).code).toBe('conflict')
    }
  })
  test('stores the token lowercase and finds it case-insensitively (TestAdd_StoresTokenLowercase, TestFindByToken_IsCaseInsensitive…)', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh(tok('abc').toUpperCase()), o()))
    expect(row.token).toBe(tok('abc'))
    expect((await s.tx('r', (t) => findByToken(t, tok('abc').toUpperCase())))?.id).toBe(row.id)
  })
  test('reactivates a no-longer-held token with the same id and fresh fields (TestAdd_ReactivatesANoLongerHeldToken)', async () => {
    const s = new MemoryStorage()
    const first = await s.tx('rw', (t) => addHolding(t, nh(tok('aaa'), { amount: 5n }), o()))
    await s.tx('rw', (t) => setStatus(t, first.id, 'transferred'))
    const again = await s.tx('rw', (t) => addHolding(t, nh(tok('aaa'), { amount: 9n, mode: 'cash' }), o()))
    expect(again.id).toBe(first.id)
    expect(again).toMatchObject({ status: 'held', amount: 9n, mode: 'cash', version: 3 })
    expect(await s.tx('r', (t) => t.list('holdings'))).toHaveLength(1)
  })
  test('heldHoldings excludes every non-held status (TestHeld_ExcludesNonHeldStatuses)', async () => {
    const s = new MemoryStorage()
    const statuses = ['held', 'redeemed', 'transferred', 'consolidated', 'spent'] as const
    await s.tx('rw', async (t) => {
      for (const [i, st] of statuses.entries()) {
        const row = await addHolding(t, nh(tok(`t${i}`)), o())
        if (st !== 'held') await setStatus(t, row.id, st)
      }
    })
    expect((await s.tx('r', heldHoldings)).map((h) => h.token)).toEqual([tok('t0')])
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
    const a = await s.tx('rw', (t) => addHolding(t, nh(tok('x0')), { now: 1, random: repeating }))
    const b = await s.tx('rw', (t) => addHolding(t, nh(tok('x1')), { now: 1, random: repeating }))
    expect(a.id).toBe('h-01020304')
    expect(b.id).not.toBe(a.id)
    expect(calls).toBe(3)
  })
})

describe('OCC (auditD_cli_occ_crossprocess)', () => {
  test('two writers on the same row: the second conflicts', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh(tok('aaa')), o()))
    await s.tx('rw', (t) => updateHolding(t, row.id, (h) => ({ ...h, verified: true }), row.version))
    await expect(s.tx('rw', (t) => updateHolding(t, row.id, (h) => ({ ...h, amount: 1n }), row.version))).rejects.toMatchObject({ code: 'conflict', retryable: true })
  })
  test('writers on different rows both succeed (TestSave_ConcurrentDisjointWritesDoNotClobber)', async () => {
    const s = new MemoryStorage()
    const [a, b] = await s.tx('rw', async (t) => [await addHolding(t, nh(tok('a')), o()), await addHolding(t, nh(tok('b')), o())])
    await Promise.all([
      s.tx('rw', (t) => updateHolding(t, a!.id, (h) => ({ ...h, amount: 1n }), a!.version)),
      s.tx('rw', (t) => updateHolding(t, b!.id, (h) => ({ ...h, amount: 2n }), b!.version)),
    ])
    const rows = await s.tx('r', (t) => t.list('holdings'))
    expect(rows.map((r) => r.amount)).toEqual([1n, 2n])
  })
  test('concurrent receives of one token keep one row (TestSave_ConcurrentSameTokenReceiveDoesNotDuplicate)', async () => {
    const s = new MemoryStorage()
    const results = await Promise.allSettled([1, 2, 3].map(() => s.tx('rw', (t) => addHolding(t, nh(tok('same')), o()))))
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect(await s.tx('r', (t) => t.list('holdings'))).toHaveLength(1)
  })
  test('put with a stale expectVersion throws ConcurrentUpdateError and rolls back the whole tx', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh(tok('aaa')), o()))
    const err = await s
      .tx('rw', async (t) => {
        await addHolding(t, nh(tok('bbb')), o())
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
    const row = await s.tx('rw', (t) => addHolding(t, nh(tok('aaa')), o()))
    ;(row.relayUrls as string[]).push('wss://evil')
    expect((await s.tx('r', (t) => t.get('holdings', row.id)))?.relayUrls).toEqual(['wss://r'])
  })
  test('list filters with where, in insertion order, and sees staged writes', async () => {
    const s = new MemoryStorage()
    await rw(s, async (t) => {
      await addHolding(t, nh(tok('a'), { mode: 'cash' }), o())
      await addHolding(t, nh(tok('b')), o())
      await addHolding(t, nh(tok('c'), { mode: 'cash' }), o())
      expect((await t.list('holdings', { where: { mode: 'cash' } })).map((h) => h.token)).toEqual([tok('a'), tok('c')])
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

const specToken = (JSON.parse(readFileSync(new URL('../vectors/provenance.json', import.meta.url), 'utf8')) as { specToken: { token: string } }).specToken.token
/** `s` with its TLV entries rewritten by `f`, under the same HRP. */
const respell = (s: string, f: (e: { type: number; value: Uint8Array }[]) => { type: number; value: Uint8Array }[]) => {
  const { hrp, words } = bech32Decode(s)
  return bech32Encode(hrp, toWords(writeTLVs(f(readTLVs(fromWords(words))))))
}
const withUnknown = (s: string) => respell(s, (e) => [...e, { type: 9, value: Uint8Array.of(0) }])
const reversed = (s: string) => respell(s, (e) => e.map((_, i) => e[e.length - 1 - i]!))

describe('one holding per bill, however it is spelled (NIP-CASH §Wire Format)', () => {
  test('canonicalToken drops unknown types, orders entries by type and lowercases', () => {
    const c = canonicalToken(specToken)
    expect(canonicalToken(withUnknown(specToken))).toBe(c)
    expect(canonicalToken(withUnknown(specToken).toUpperCase())).toBe(c)
    expect(canonicalToken(c)).toBe(c)
    // Reordering keeps TLV 1 in its own order, so one with two relays reversed is another spelling of other bytes.
    expect(decodeToken(canonicalToken(reversed(specToken))).walletPubkey).toBe(decodeToken(c).walletPubkey)
  })
  test('the canonical spelling keeps provenance and every relay entry, a blank one included', () => {
    expect(verifyProvenance(decodeToken(canonicalToken(withUnknown(specToken))))).toEqual(verifyProvenance(decodeToken(specToken)))
    const blank = respell(specToken, (e) => [...e, { type: 1, value: Uint8Array.of(0x20) }])
    expect(decodeToken(canonicalToken(blank)).relayBytes).toEqual(decodeToken(blank).relayBytes)
  })
  test('canonicalToken refuses what the decoder refuses', () => {
    expect(() => canonicalToken(respell(specToken, (e) => e.filter((x) => x.type !== 0)))).toThrow()
  })
  test('a bill re-spelled with an unknown TLV, or with its entries reordered, is not a second holding', async () => {
    const s = new MemoryStorage()
    await s.tx('rw', (t) => addHolding(t, nh(specToken), o()))
    for (const variant of [withUnknown(specToken), reversed(specToken)]) {
      expect(variant).not.toBe(specToken)
      const err = await s.tx('rw', (t) => addHolding(t, nh(variant), o())).catch((e: unknown) => e)
      expect(err).toMatchObject({ code: 'conflict' })
    }
    expect(await s.tx('r', heldHoldings)).toHaveLength(1)
    expect((await s.tx('r', (t) => findByToken(t, withUnknown(specToken))))?.token).toBe(canonicalToken(specToken))
  })
  test('a holding is stored in its canonical spelling, and a let-go bill re-spelled reactivates its row', async () => {
    const s = new MemoryStorage()
    const first = await s.tx('rw', (t) => addHolding(t, nh(withUnknown(specToken)), o()))
    expect(first.token).toBe(canonicalToken(specToken))
    await s.tx('rw', (t) => setStatus(t, first.id, 'transferred'))
    const again = await s.tx('rw', (t) => addHolding(t, nh(reversed(specToken)), o()))
    expect(again.id).toBe(first.id)
    expect(await s.tx('r', (t) => t.list('holdings'))).toHaveLength(1)
  })
})

/** Writes a row as an older version did: the token as given, no wallet-key check. */
const legacy = (s: MemoryStorage, id: string, token: string, extra: Partial<NewHolding> & { addedAt?: number } = {}) =>
  s.tx('rw', (t) => t.put('holdings', { ...nh(token), status: 'held', addedAt: 1, version: 1, ...extra, id, token: token.toLowerCase() }, 0))

const rows = (s: MemoryStorage) => s.tx('r', (t) => t.list('holdings'))

describe('normalizeHoldings (stores written before one holding per bill)', () => {
  test('rewrites tokens canonically; the second held copy becomes duplicate, its secret kept', async () => {
    const s = new MemoryStorage()
    await legacy(s, 'h-1', specToken, { addedAt: 1 })
    await legacy(s, 'h-2', withUnknown(specToken), { addedAt: 2, cashSecret: 'sealed-secret' as never })
    expect(await s.tx('rw', (t) => normalizeHoldings(t, new Set()))).toEqual(['h-2'])
    expect((await rows(s)).map((h) => [h.id, h.status, h.token])).toEqual([
      ['h-1', 'held', canonicalToken(specToken)],
      ['h-2', 'duplicate', canonicalToken(specToken)],
    ])
    expect((await rows(s))[1]!.cashSecret).toBe('sealed-secret')
  })
  test('every second copy is a duplicate, a cash note or another binding included', async () => {
    const s = new MemoryStorage()
    await legacy(s, 'h-1', specToken, { addedAt: 1 })
    await legacy(s, 'h-2', withUnknown(specToken), { addedAt: 2, mode: 'cash', protection: 'shared' })
    await legacy(s, 'h-3', reversed(specToken), { addedAt: 3, mode: 'connection_key' })
    expect(await s.tx('rw', (t) => normalizeHoldings(t, new Set()))).toEqual(['h-2', 'h-3'])
    expect((await rows(s)).filter((h) => h.status === 'held').map((h) => h.id)).toEqual(['h-1'])
  })
  test('the copy an open call names stays live, then a redeeming one, else the first received', async () => {
    const s = new MemoryStorage()
    await legacy(s, 'h-1', specToken, { addedAt: 1 })
    await legacy(s, 'h-2', withUnknown(specToken), { addedAt: 2 })
    expect(await s.tx('rw', (t) => normalizeHoldings(t, new Set(['h-2'])))).toEqual(['h-1'])
    const r = new MemoryStorage()
    await legacy(r, 'h-1', specToken, { addedAt: 1 })
    await legacy(r, 'h-2', withUnknown(specToken), { addedAt: 2, status: 'redeeming' } as Partial<NewHolding>)
    expect(await r.tx('rw', (t) => normalizeHoldings(t, new Set()))).toEqual(['h-1'])
  })
  test('Wallet.open: the bill counts once, the duplicate is not spendable, and a third spelling is the same holding', async () => {
    const s = new MemoryStorage()
    await legacy(s, 'h-1', specToken, { addedAt: 1, amount: 5n })
    await legacy(s, 'h-2', withUnknown(specToken), { addedAt: 2, amount: 5n })
    const h = await harness({ storage: s, deps: {} })
    expect((await h.wallet.holdings()).map((x) => x.id)).toEqual(['h-1'])
    expect(h.wallet.state.balance).toMatchObject({ held: 5n, count: 1 })
    expect((await h.wallet.holdings({ includeSpent: true })).find((x) => x.id === 'h-2')?.status).toBe('duplicate')
    await expect(h.wallet.planRedeem({ holdings: ['h-2'] })).rejects.toBeInstanceOf(CashkitError)
    // The duplicate's secret stays exportable for recovery.
    expect(await h.wallet.exportHolding('h-2')).toBe(canonicalToken(specToken))
    const third = await s.tx('rw', (t) => addHolding(t, nh(reversed(specToken)), o())).catch((e: unknown) => e)
    expect(third).toMatchObject({ code: 'conflict', input: 'h-1' })
  })
  test('a store with no duplicate is unchanged by Wallet.open', async () => {
    const s = new MemoryStorage()
    const row = await s.tx('rw', (t) => addHolding(t, nh(specToken), o()))
    await s.tx('rw', (t) => addHolding(t, nh(tok('other')), o()))
    const before = await rows(s)
    await harness({ storage: s, deps: {} })
    const after = await rows(s)
    expect(after.map((h) => [h.id, h.status, h.token, h.version])).toEqual(before.map((h) => [h.id, h.status, h.token, h.version]))
    expect(after[0]!.id).toBe(row.id)
  })
  test('leaves a let-go copy and other bills alone', async () => {
    const s = new MemoryStorage()
    await legacy(s, 'h-1', specToken, { addedAt: 1, status: 'transferred' } as Partial<NewHolding>)
    await legacy(s, 'h-2', withUnknown(specToken), { addedAt: 2 })
    await legacy(s, 'h-3', tok('other'), { addedAt: 3 })
    expect(await s.tx('rw', (t) => normalizeHoldings(t, new Set()))).toEqual([])
    expect((await s.tx('r', (t) => t.list('holdings'))).map((h) => h.id)).toEqual(['h-1', 'h-2', 'h-3'])
  })
})
