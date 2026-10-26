// In a real Chromium: the browser adapters, openWallet's defaults, and the
// multi-tab scenario (design §11.2).
import { describe, expect, inject, test } from 'vitest'
import { finalizeEvent, newCashTarget } from '../../src/core/index.js'
import { openWallet } from '../../src/index.js'
import { WebLocksLock } from '../../src/adapters/lock-weblocks.js'
import { RelayWs } from '../../src/adapters/relay-ws.js'
import { IndexedDbStorage } from '../../src/adapters/storage-indexeddb.js'
import { BroadcastSync } from '../../src/adapters/sync-broadcast.js'
import { DeviceVault } from '../../src/adapters/vault-device.js'
import { CashkitError, Wallet } from '../../src/wallet/index.js'
import { FakeBank } from '../fakeBank.js'
import { MemoryRelayPool } from '../fakeHub.js'
import { fill } from '../helpers.js'
import { storageContract } from '../storageContract.js'

let n = 0
const name = () => `browser-${Date.now()}-${++n}`
const tick = (ms = 50) => new Promise((r) => setTimeout(r, ms))

test('this is a real Chromium, not Node', () => {
  expect(typeof window).toBe('object')
  expect(navigator.userAgent).toMatch(/Chrome/)
  expect(typeof (globalThis as { process?: unknown }).process === 'undefined' || typeof document === 'object').toBe(true)
})

storageContract({
  name: 'indexeddb (Chromium)',
  open: (loc) => IndexedDbStorage.open({ name: loc ?? name() }),
  location: name,
  close: async (s) => (s as IndexedDbStorage).close(),
})

describe('DeviceVault in Chromium', () => {
  test('seals with a non-extractable key kept in IndexedDB, found again on reopen', async () => {
    const db = name()
    const a = await DeviceVault.open({ name: db })
    const s = await a.seal(new TextEncoder().encode('secret'))
    const b = await DeviceVault.open({ name: db })
    expect(new TextDecoder().decode(await b.open(s))).toBe('secret')
    expect(JSON.stringify(s)).not.toContain('secret')
  })
})

describe('relay-ws on the browser WebSocket', () => {
  test('publishes, then reads it back with EOSE', async () => {
    const url = inject('relayUrl')
    const pool = new RelayWs()
    const e = finalizeEvent({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: `browser ${Date.now()}` }, fill(0x21, 32))
    expect(await pool.publish(url, e)).toMatchObject({ ok: true })
    const got: string[] = []
    await new Promise<void>((r) => {
      const stop = pool.subscribe([url], { ids: [e.id] }, { onEvent: (x) => got.push(x.id), onEose: () => (stop(), r()) })
    })
    expect(got).toEqual([e.id])
  })
})

async function bank() {
  const pool = new MemoryRelayPool()
  const b = new FakeBank(pool, ['wss://bank.test'])
  await b.start()
  return { pool, bank: b }
}

describe('openWallet with the browser defaults', () => {
  test('IndexedDB, Web Locks, BroadcastChannel and storage.persist are wired in; money moves', async () => {
    const { pool, bank: b } = await bank()
    const w = await openWallet({ name: name(), vault: await DeviceVault.open({ name: name() }), relays: pool, replyWaitMs: 5000 })
    expect(typeof w.state.storagePersisted).toBe('boolean')
    const me = (await w.identity.generate()).pubkey
    const t = newCashTarget()
    const r = await w.receive(`${b.mintToCash(3000n, t.secret).token}#${t.secret}`)
    expect(r.received && r.secured.status).toBe('rekeyed')
    await w.receive(b.mintToPubkey(4000n, me).token)
    const sent = await w.send({ amount: 5000n })
    expect(sent.consolidatedFirst).toBe(true)
    expect(w.state.balance.held).toBe(2000n)
    expect(w.state.backupStale).toBe(true)
    const text = await w.exportBackup('pw', { logN: 4 })
    expect(text).not.toContain(t.secret)
    w.close()
  })
  test('outside a browser it would need storage; here it needs a vault', async () => {
    await expect(openWallet({} as never)).rejects.toBeInstanceOf(Error)
  })
})

describe('two tabs on one wallet (multi-tab scenario)', () => {
  test('separate IndexedDB connections, one Web Lock, BroadcastChannel refresh: one bill is spent once', async () => {
    const { pool, bank: b } = await bank()
    const db = name()
    const vaultDb = name()
    const tab = async () =>
      Wallet.open({
        storage: await IndexedDbStorage.open({ name: db }),
        vault: await DeviceVault.open({ name: vaultDb }),
        relays: pool,
        lock: new WebLocksLock(),
        sync: new BroadcastSync(`cashkit:${db}`),
        replyWaitMs: 5000,
      })
    const a = await tab()
    const me = (await a.identity.generate()).pubkey
    const bTab = await tab()
    await a.receive(b.mintToPubkey(5000n, me).token)
    await tick()
    // Tab B never touched the bill, but sees it through BroadcastChannel.
    expect(bTab.state.holdings.map((h) => h.amount)).toEqual([5000n])
    // Both tabs try to spend it at once: Web Locks serialise, OCC refuses the stale plan.
    const results = await Promise.allSettled([a.send({ amount: 2000n }), bTab.send({ amount: 3000n })])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    const failed = results.find((r): r is PromiseRejectedResult => r.status === 'rejected')!
    expect(failed.reason).toBeInstanceOf(CashkitError)
    expect((failed.reason as CashkitError).code).toBe('conflict')
    await tick()
    expect(a.state.balance.held).toBe(bTab.state.balance.held)
    a.close()
    bTab.close()
  })
})
