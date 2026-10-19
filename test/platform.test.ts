// Cross-tab pieces (design §5.4, §10): Web Locks, BroadcastChannel sync,
// storage persistence, and openWallet's defaults. Node has Web Locks and
// BroadcastChannel, so "two tabs" here are two wallets over one store.
import { describe, expect, test } from 'vitest'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { NoneVault } from '../src/adapters/vault-none.js'
import { WebLocksLock, type LockManagerLike } from '../src/adapters/lock-weblocks.js'
import { BroadcastSync } from '../src/adapters/sync-broadcast.js'
import { openWallet } from '../src/index.js'
import { CashkitError, type WalletState } from '../src/wallet/index.js'
import { harness } from './walletHarness.js'

const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms))
let chan = 0

describe('WebLocksLock', () => {
  test('one holder per name at a time, on the real navigator.locks', async () => {
    const lock = new WebLocksLock()
    const order: string[] = []
    const hold = (id: string) =>
      lock.withLock('cashkit:test', async () => {
        order.push(`${id}:in`)
        await tick(5)
        order.push(`${id}:out`)
      })
    await Promise.all([hold('a'), hold('b')])
    expect(order).toEqual(['a:in', 'a:out', 'b:in', 'b:out'])
  })
  test('uses the lock manager it is given, and returns the result', async () => {
    const calls: string[] = []
    const fake: LockManagerLike = { request: (name, _o, cb) => (calls.push(name), cb()) }
    expect(await new WebLocksLock(fake).withLock('n', async () => 42)).toBe(42)
    expect(calls).toEqual(['n'])
  })
  test('refuses to run where there is no navigator.locks', () => {
    const nav = Object.getOwnPropertyDescriptor(globalThis, 'navigator')
    Object.defineProperty(globalThis, 'navigator', { value: {}, configurable: true })
    try {
      expect(WebLocksLock.available()).toBe(false)
      expect(() => new WebLocksLock()).toThrow(/navigator.locks/)
    } finally {
      if (nav) Object.defineProperty(globalThis, 'navigator', nav)
    }
  })
})

describe('two tabs on one wallet', () => {
  test("a commit in one tab refreshes the other's state, through BroadcastChannel", async () => {
    const name = `t${++chan}`
    const storage = new MemoryStorage()
    const a = await harness({ storage, deps: { sync: new BroadcastSync(name) } })
    const b = await a.reopen({ sync: new BroadcastSync(name) })
    const seen: WalletState[] = []
    b.subscribe((s) => seen.push(s))
    await a.wallet.receive(a.bank.mintToPubkey(5000n, a.me).token)
    await tick()
    expect(b.state.holdings).toHaveLength(1)
    expect(seen.at(-1)?.balance.held).toBe(5000n)
    b.close()
  })
  test("another wallet's notices are ignored", async () => {
    const name = `t${++chan}`
    const a = await harness({ deps: { sync: new BroadcastSync(name) } })
    const other = await harness({ deps: { sync: new BroadcastSync(name) } })
    let refreshed = 0
    other.wallet.subscribe(() => refreshed++)
    await a.wallet.receive(a.bank.mintToPubkey(5000n, a.me).token)
    await tick()
    expect(refreshed).toBe(0)
  })
  test('two tabs spending one bill at once: exactly one send lands (Web Locks + OCC)', async () => {
    const storage = new MemoryStorage()
    const lock = new WebLocksLock()
    const a = await harness({ storage, deps: { lock } })
    const b = await a.reopen({ lock })
    await a.wallet.receive(a.bank.mintToPubkey(5000n, a.me).token)
    const results = await Promise.allSettled([a.wallet.send({ amount: 2000n }), b.send({ amount: 3000n })])
    const ok = results.filter((r) => r.status === 'fulfilled')
    const failed = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected')
    expect(ok).toHaveLength(1)
    expect(failed).toHaveLength(1)
    expect((failed[0]!.reason as CashkitError).code).toBe('conflict')
    expect((await a.wallet.holdings()).map((h) => h.status)).toEqual(['held'])
  })
})

describe('storage persistence (§10)', () => {
  test('the answer from persist() is state.storagePersisted', async () => {
    expect((await harness({ deps: { persist: async () => true } })).wallet.state.storagePersisted).toBe(true)
    expect((await harness({ deps: { persist: async () => false } })).wallet.state.storagePersisted).toBe(false)
    expect((await harness({ deps: { persist: () => Promise.reject(new Error('no')) } })).wallet.state.storagePersisted).toBe(false)
    expect((await harness()).wallet.state.storagePersisted).toBeUndefined()
  })
})

describe('openWallet defaults (design §3)', () => {
  test('outside a browser, storage is required', async () => {
    const e = await openWallet({ vault: new NoneVault() }).catch((x: unknown) => x)
    expect(e).toBeInstanceOf(CashkitError)
    expect((e as CashkitError).code).toBe('usage')
  })
  test('with storage given, it opens with the platform defaults', async () => {
    const h = await harness()
    const w = await openWallet({ vault: new NoneVault(), storage: new MemoryStorage(), relays: h.pool })
    expect(w.walletId).toMatch(/^[0-9a-f]+$/)
    expect(await w.holdings()).toEqual([])
  })
})
