// Wallet schema 2: no migration from schema 1, pending calls written ahead
// and read back, the device id, derived-id and Hub records, and backup v2.
// T-511..T-516.
import { describe, expect, test } from 'vitest'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { NoneVault } from '../src/adapters/vault-none.js'
import { newCashTarget, toHex, utf8 } from '../src/core/index.js'
import { Wallet, type Sealed, type SecretVault, type WalletDeps } from '../src/wallet/index.js'
import { finishCall, isOwnCall, markSent, noteHub, openCallsFor, prepareCall, recordDerivedId, type CallSpec } from '../src/wallet/calls.js'
import { LOCAL_ONLY, SCHEMA_VERSION } from '../src/wallet/model.js'
import type { Ctx } from '../src/wallet/context.js'
import { MemoryRelayPool } from './fakeHub.js'

const deps = (o: Partial<WalletDeps> = {}): WalletDeps => ({ storage: new MemoryStorage(), vault: new NoneVault(), relays: new MemoryRelayPool(), ...o })
const ctxOf = (w: Wallet) => (w as unknown as { ctx: Ctx }).ctx
const spec = (o: Partial<CallSpec> = {}): CallSpec => ({
  kind: 'transfer',
  requestId: '00112233445566778899aabbccddeeff',
  method: 'cash_transfer',
  target: 'aa'.repeat(32),
  node: 'bb'.repeat(32),
  relays: ['wss://r'],
  deadline: 1_760_000_060,
  hAtSend: 300,
  amount: 5000n,
  sources: ['h-1'],
  authorizer: { kind: 'throwaway', key: 'cd'.repeat(32) },
  outputs: [{ role: 'new', destination: { kind: 'cash', secret: newCashTarget().secret } }, { role: 'remainder', destination: { kind: 'pubkey', pubkey: 'ee'.repeat(32) } }],
  ...o,
})

/** A vault that seals with a random nonce each time, so a sealed value never repeats. */
class NoisyVault implements SecretVault {
  async seal(p: Uint8Array): Promise<Sealed> {
    return { alg: 'noisy', data: toHex(crypto.getRandomValues(new Uint8Array(4))) + toHex(p) }
  }
  async open(s: Sealed): Promise<Uint8Array> {
    return Uint8Array.from(s.data.slice(8).match(/../g)!.map((b) => parseInt(b, 16)))
  }
  locked() {
    return false
  }
}

describe('T-511 schema 2', () => {
  test('a new store is schema 2 and has every collection', async () => {
    const d = deps()
    await Wallet.open(d)
    const meta = await d.storage.tx('r', (t) => t.get('meta', 'meta'))
    expect(meta?.schemaVersion).toBe(SCHEMA_VERSION)
    expect(SCHEMA_VERSION).toBe(2)
    expect(await d.storage.tx('r', (t) => t.get('device', 'self'))).toBeDefined()
  })
  test('a schema-1 store is refused before anything is written', async () => {
    const storage = new MemoryStorage()
    await storage.tx('rw', (t) => t.put('meta', { id: 'meta', schemaVersion: 1, walletId: 'old', version: 1 }, 0))
    await expect(Wallet.open(deps({ storage }))).rejects.toMatchObject({ code: 'internal', message: expect.stringMatching(/schema 1/) })
    expect(await storage.tx('r', (t) => t.get('device', 'self'))).toBeUndefined()
    expect(await storage.tx('r', (t) => t.get('settings', 'settings'))).toBeUndefined()
  })
  test('a newer schema is usage', async () => {
    const storage = new MemoryStorage()
    await storage.tx('rw', (t) => t.put('meta', { id: 'meta', schemaVersion: 3, walletId: 'new', version: 1 }, 0))
    await expect(Wallet.open(deps({ storage }))).rejects.toMatchObject({ code: 'usage' })
  })
  test('the device, derived ids, Hub records, Cash Pocket wraps and what discover keeps are local only', () => {
    expect(LOCAL_ONLY).toEqual(['device', 'derivedIds', 'hubs', 'pocket', 'discoverBook', 'discoverEvents', 'discoverOutbox'])
  })
})

describe('T-512 write-ahead with read-back', () => {
  test('a call is written prepared, its secrets sealed, and read back', async () => {
    const w = await Wallet.open(deps({ vault: new NoisyVault() }))
    const c = await prepareCall(ctxOf(w), spec())
    expect(c).toMatchObject({ state: 'prepared', requestId: spec().requestId, deadline: 1_760_000_060, attempts: 1 })
    expect(c.authorizer.kind).toBe('throwaway')
    expect(JSON.stringify(c, (_k, v) => (typeof v === 'bigint' ? String(v) : v))).not.toContain('cd'.repeat(32))
    const sent = await markSent(ctxOf(w), c)
    expect(sent.state).toBe('sent')
  })
  test('a read-back mismatch deletes the row and refuses (nothing sent)', async () => {
    class LyingVault extends NoisyVault {
      override async open(s: Sealed): Promise<Uint8Array> {
        const p = await super.open(s)
        return p.length > 0 ? utf8('ff'.repeat(32)) : p
      }
    }
    const d = deps({ vault: new LyingVault() })
    const w = await Wallet.open(d)
    await expect(prepareCall(ctxOf(w), spec())).rejects.toMatchObject({ code: 'internal', message: expect.stringMatching(/not placed/) })
    expect(await d.storage.tx('r', (t) => t.list('pendingCalls'))).toEqual([])
  })
  test('finishCall closes it in the result transaction; openCallsFor finds the locked holdings', async () => {
    const d = deps()
    const w = await Wallet.open(d)
    const ctx = ctxOf(w)
    const c = await prepareCall(ctx, spec({ authorizer: { kind: 'cash', holdingId: 'h-9' } }))
    expect((await openCallsFor(ctx, 'h-1')).map((x) => x.id)).toEqual([c.id])
    expect((await openCallsFor(ctx, 'h-9')).map((x) => x.id)).toEqual([c.id])
    await ctx.commit((t) => finishCall(t, c.id, 'applied'))
    expect(await openCallsFor(ctx, 'h-1')).toEqual([])
    const done = await d.storage.tx('r', (t) => t.get('pendingCalls', c.id))
    expect(done).toMatchObject({ state: 'done', outcome: 'applied' })
  })
})

describe('T-513 device id', () => {
  test('created once, kept on reopen; a call records it and is own', async () => {
    const d = deps()
    const a = await Wallet.open(d)
    const b = await Wallet.open(d)
    expect(ctxOf(a).deviceId).toMatch(/^[0-9a-f]{32}$/)
    expect(ctxOf(b).deviceId).toBe(ctxOf(a).deviceId)
    const c = await prepareCall(ctxOf(a), spec())
    expect(c.device).toBe(ctxOf(a).deviceId)
    expect(isOwnCall(ctxOf(b), c)).toBe(true)
  })
  test('a store whose meta names another fingerprint gets a new device id', async () => {
    const d = deps()
    const a = await Wallet.open(d)
    await d.storage.tx('rw', async (t) => {
      const m = (await t.get('meta', 'meta'))!
      await t.put('meta', { ...m, storeFingerprint: 'ff'.repeat(16), version: m.version + 1 }, m.version)
    })
    const b = await Wallet.open(d)
    expect(ctxOf(b).deviceId).not.toBe(ctxOf(a).deviceId)
  })
})

describe('T-514 derived-id and Hub records', () => {
  test('a derived id is kept until deadline + H; H only grows', async () => {
    const d = deps()
    const w = await Wallet.open(d)
    const ctx = ctxOf(w)
    const row = await ctx.commit((t) => recordDerivedId(t, { derivedId: 'ab'.repeat(32), parentCallId: 'pc-1', deadline: 1000, hMax: 300 }))
    expect(row.keepUntil).toBe(1300)
    await ctx.commit((t) => noteHub(t, 'bb'.repeat(32), 600))
    await ctx.commit((t) => noteHub(t, 'bb'.repeat(32), 120))
    expect((await d.storage.tx('r', (t) => t.get('hubs', 'bb'.repeat(32))))?.hMax).toBe(600)
  })
})

describe('T-515 backup v2', () => {
  test('pending-call secrets are sealed; local collections are neither exported nor imported; a restored call is foreign', async () => {
    const d = deps()
    const w = await Wallet.open(d)
    const ctx = ctxOf(w)
    const s = spec()
    const secret = (s.outputs[0]!.destination as { secret: string }).secret
    await prepareCall(ctx, s)
    await ctx.commit((t) => recordDerivedId(t, { derivedId: 'ab'.repeat(32), parentCallId: 'pc-1', deadline: 1, hMax: 1 }))
    const text = await w.exportBackup('pw', { logN: 4 })
    expect(text).not.toContain(secret)
    expect(text).not.toContain('cd'.repeat(32))
    const file = JSON.parse(text) as { version: number; collections: Record<string, unknown> }
    expect(file.version).toBe(2)
    for (const c of LOCAL_ONLY) expect(file.collections).not.toHaveProperty(c)
    const d2 = deps()
    const fresh = await Wallet.open(d2)
    await fresh.importBackup(text, 'pw')
    const calls = await d2.storage.tx('r', (t) => t.list('pendingCalls'))
    expect(calls).toHaveLength(1)
    expect(isOwnCall(ctxOf(fresh), calls[0]!)).toBe(false)
    const out = calls[0]!.outputs[0]!.destination as { secret: Sealed }
    expect(new TextDecoder().decode(await d2.vault.open(out.secret))).toBe(secret)
    expect(await d2.storage.tx('r', (t) => t.list('derivedIds'))).toEqual([])
  })
  test('a version-1 backup is refused', async () => {
    const w = await Wallet.open(deps())
    const text = (await w.exportBackup('pw', { logN: 4 })).replace('"version":2', '"version":1')
    const fresh = await Wallet.open(deps())
    await expect(fresh.importBackup(text, 'pw')).rejects.toMatchObject({ code: 'usage', message: expect.stringMatching(/older/) })
  })
})
