// NIP-CASH §State Notice: no notice marks `confirmed` or `final`; a client
// reads the payout on each notice and polls it until `final`, never relying
// on notices. The cadence is XQ-31: the milestones, every 60 s while watched
// until broadcast and every 10 min after, at most hourly from autoSettle.
import { afterEach, describe, expect, test, vi } from 'vitest'
import { withdrawReadDue } from '../src/wallet/withdraw.js'
import type { PendingCall } from '../src/wallet/model.js'
import { FakeWithdraw, PAYTO } from './fakeWithdraw.js'
import { harness } from './walletHarness.js'

const yes = () => Promise.resolve(true)

async function sent() {
  const h = await harness()
  const hub = new FakeWithdraw(h.bank)
  const r = await h.wallet.receive(h.bank.mintToPubkey(21_000_000n, h.me).token)
  const id = r.received ? r.holding.id : ''
  const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
  const lookups = () => h.bank.hub.requests.filter((x) => x.item.method === 'cash_lookup').length
  const call = () => h.storage.tx('r', (x) => x.get('pendingCalls', v.id))
  return { h, hub, v, lookups, call }
}

afterEach(() => {
  vi.useRealTimers()
})

const callAt = (checkedAt: number, state: PendingCall['state'] = 'open_withdraw') =>
  ({ state, deadline: 1000, lookup: { omissions: 0, checkedAt }, withdrawal: { sentBy: 5000, checkedAt: 0 } }) as unknown as PendingCall

describe('withdrawReadDue', () => {
  test('a milestone not yet read after is due at the milestone', () => {
    // deadline + 1 = 1001; read at 1000, one second before it.
    expect(withdrawReadDue(callAt(1000), 3600)).toBe(1001)
    expect(withdrawReadDue(callAt(4999), 3600)).toBe(5000)
    expect(withdrawReadDue(callAt(5000 + 86400 + 59), 3600)).toBe(5000 + 86400 + 60)
  })
  test('once read after a milestone, the next read is the gap later or the next milestone', () => {
    expect(withdrawReadDue(callAt(1001), 3600)).toBe(4601)
    expect(withdrawReadDue(callAt(1001), 60)).toBe(1061)
    expect(withdrawReadDue(callAt(5000), 3600)).toBe(8600)
    expect(withdrawReadDue(callAt(5000 + 604800), 3600)).toBe(5000 + 604800 + 3600)
  })
  test('a call no longer open is never due', () => {
    expect(withdrawReadDue(callAt(0, 'done'), 3600)).toBeUndefined()
    expect(withdrawReadDue(callAt(0, 'sent'), 3600)).toBeUndefined()
  })
})

describe('settle() reads open payouts', () => {
  test('a payout that reached final with no notice is closed by settle()', async () => {
    const { h, hub, v, call } = await sent()
    const p = hub.only()
    hub.broadcast(p)
    hub.confirm(p, 6)
    const r = await h.wallet.settle()
    expect((await call())!.state).toBe('done')
    expect(r.withdrawals).toEqual({ checked: [v.id], ended: [v.id] })
  })
  test('a lost cancel notice: settle() still imports the re-minted bill', async () => {
    const { h, hub, v } = await sent()
    hub.cancel(hub.only())
    await h.wallet.settle()
    const after = await h.wallet.withdraw.get(v.id)
    expect(after.phase).toBe('cancelled')
    expect((await h.wallet.holdings()).map((x) => x.id)).toContain(after.remintHoldingId)
  })
  test('a payout still on its way stays open after settle()', async () => {
    const { h, hub, v, call } = await sent()
    hub.broadcast(hub.only())
    const r = await h.wallet.settle()
    expect((await call())!.state).toBe('open_withdraw')
    expect(r.withdrawals).toEqual({ checked: [v.id], ended: [] })
    expect((await h.wallet.withdraw.get(v.id)).phase).toBe('broadcast')
  })
})

describe('watch() polls', () => {
  test('the payout reaches final with no notice sent', async () => {
    const { h, hub, v } = await sent()
    const p = hub.only()
    hub.broadcast(p)
    hub.confirm(p, 6)
    const seen: string[] = []
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const stop = await h.wallet.withdraw.watch(v.id, { onUpdate: (u) => seen.push(u.phase) })
    await vi.advanceTimersByTimeAsync(11 * 60 * 1000)
    stop()
    expect(seen).toContain('final')
  })
  test('every 60 s before broadcast, then every 10 min, and stops at final', async () => {
    const { h, hub, v, lookups } = await sent()
    const p = hub.only()
    vi.useFakeTimers({ shouldAdvanceTime: false, toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    const stop = await h.wallet.withdraw.watch(v.id)
    const base = lookups()
    await vi.advanceTimersByTimeAsync(59_000)
    expect(lookups()).toBe(base)
    await vi.advanceTimersByTimeAsync(2_000)
    expect(lookups()).toBe(base + 1)
    hub.broadcast(p)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lookups()).toBe(base + 2)
    // Broadcast now: no read for the next 9 minutes, one at 10.
    await vi.advanceTimersByTimeAsync(9 * 60_000)
    expect(lookups()).toBe(base + 2)
    hub.confirm(p, 6)
    await vi.advanceTimersByTimeAsync(61_000)
    expect(lookups()).toBe(base + 3)
    expect((await h.wallet.withdraw.get(v.id)).phase).toBe('final')
    await vi.advanceTimersByTimeAsync(60 * 60_000)
    expect(lookups()).toBe(base + 3)
    stop()
  })
  test('a burst of notices makes one read, and a notice marks nothing itself', async () => {
    const { h, hub, v, lookups } = await sent()
    const p = hub.only()
    hub.broadcast(p)
    vi.useFakeTimers({ shouldAdvanceTime: false, toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    const stop = await h.wallet.withdraw.watch(v.id)
    const base = lookups()
    await hub.notice(p)
    await hub.notice(p)
    await hub.notice(p)
    await vi.advanceTimersByTimeAsync(2_500)
    expect(lookups()).toBe(base + 1)
    expect((await h.wallet.withdraw.get(v.id)).phase).toBe('broadcast')
    stop()
  })
})

describe('autoSettle reads an open payout without a watcher', () => {
  test('reads at each milestone, then hourly: a lost cancel notice still brings the re-minted bill in', async () => {
    const { h, hub, v, lookups } = await sent()
    vi.useFakeTimers({ shouldAdvanceTime: false, toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    const stop = h.wallet.autoSettle()
    const base = lookups()
    // deadline + 1 (the deadline is send + 60 s).
    await vi.advanceTimersByTimeAsync(55_000)
    expect(lookups()).toBe(base)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(lookups()).toBe(base + 1)
    // sent_by (the fake Hub's is quote time + 3600), before the hourly gap from the last read.
    await vi.advanceTimersByTimeAsync(3500_000)
    expect(lookups()).toBe(base + 1)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lookups()).toBe(base + 2)
    // Cancelled with no notice: no read before the hour, one just after it.
    hub.cancel(hub.only())
    const lastRead = (await h.storage.tx('r', (x) => x.get('pendingCalls', v.id)))!.lookup!.checkedAt!
    await vi.advanceTimersByTimeAsync((lastRead + 3600 - 5) * 1000 - Date.now())
    expect(lookups()).toBe(base + 2)
    expect((await h.wallet.withdraw.get(v.id)).phase).not.toBe('cancelled')
    await vi.advanceTimersByTimeAsync(10_000)
    expect(lookups()).toBe(base + 3)
    const after = await h.wallet.withdraw.get(v.id)
    expect(after.phase).toBe('cancelled')
    expect((await h.wallet.holdings()).map((x) => x.id)).toContain(after.remintHoldingId)
    stop()
  })
})
