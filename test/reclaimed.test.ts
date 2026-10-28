// NIP-CP §Balance on the wallet: one result to state table for every method
// that answers about a held bill. NOT_FOUND to the holding's identity key or
// cash secret is `reclaimed` (the sender removed the slice); a tombstone ends
// it by its reason; neither counts in any balance.
import { beforeEach, describe, expect, expectTypeOf, test } from 'vitest'
import type { HoldingStatus } from '../src/index.js'
import type { CashkitError } from '../src/wallet/index.js'
import { invoice } from './helpers.js'
import { harness, type Harness } from './walletHarness.js'

const err = (p: Promise<unknown>) => p.then(() => undefined, (e: unknown) => e as CashkitError)

let h: Harness
beforeEach(async () => {
  h = await harness()
})

async function receivePubkey(amount: bigint) {
  const w = h.bank.mintToPubkey(amount, h.me)
  const r = await h.wallet.receive(w.token)
  if (!r.received) throw new Error('not received')
  return { w, holding: r.holding }
}
const statusOf = async (id: string) => (await h.wallet.holdings({ includeSpent: true })).find((x) => x.id === id)?.status

describe('a slice its sender removed', () => {
  test('status() marks the holding reclaimed; it leaves the balance', async () => {
    const { w, holding } = await receivePubkey(5000n)
    await receivePubkey(1000n)
    expect((await h.wallet.balance()).holdings.held).toBe(6000n)
    w.removed = true
    const rep = await h.wallet.status()
    expect(rep.outcomes.find((o) => o.ok && o.holdingId === holding.id)).toMatchObject({ ok: true, state: 'spent', ends: 'reclaimed' })
    expect(await statusOf(holding.id)).toBe('reclaimed')
    expect((await h.wallet.balance()).holdings).toMatchObject({ held: 1000n, count: 1 })
  })
  test('a cash bill whose secret no longer finds a slice is reclaimed', async () => {
    const secret = '33'.repeat(32)
    const w = h.bank.mintToCash(4000n, secret)
    const r = await h.wallet.receive(`${w.token}#${secret}`)
    if (!r.received) throw new Error('not received')
    w.removed = true
    await h.wallet.status()
    expect(await statusOf(r.holding.id)).toBe('reclaimed')
    expect((await h.wallet.balance()).holdings.held).toBe(0n)
  })
  test('a redeem answered NOT_FOUND ends the holding reclaimed, not left pending', async () => {
    const { holding } = await receivePubkey(5000n)
    h.bank.override = (m) => (m === 'cash_redeem' ? { error: { code: 'NOT_FOUND', message: 'no slice' } } : undefined)
    const rep = await h.wallet.redeem({ holdings: [holding.id], invoice: invoice(5000n) })
    expect(rep.outcomes[0]).toMatchObject({ ok: false, error: { code: 'spent', reason: 'reclaimed' } })
    expect(await statusOf(holding.id)).toBe('reclaimed')
  })
  test('a transfer answered NOT_FOUND ends the source reclaimed and closes the call', async () => {
    const { holding } = await receivePubkey(5000n)
    h.bank.override = (m) => (m === 'cash_transfer' ? { error: { code: 'NOT_FOUND', message: 'no slice' } } : undefined)
    expect(await err(h.wallet.send({ amount: 2000n }))).toMatchObject({ code: 'spent', reason: 'reclaimed' })
    expect(await statusOf(holding.id)).toBe('reclaimed')
    expect((await h.wallet.pendingCalls.list()).filter((c) => c.state !== 'done')).toEqual([])
  })
})

describe('a tombstone ends a holding by its reason', () => {
  test.each([
    ['expired', 'expired'],
    ['reclaimed', 'reclaimed'],
    ['redeemed', 'spent'],
    [null, 'spent'],
  ] as const)('reason %s ⇒ %s', async (reason, want) => {
    const { w, holding } = await receivePubkey(5000n)
    w.spent = true
    w.spentReason = reason
    const rep = await h.wallet.status({ holdings: [holding.id] })
    expect(rep.outcomes[0]).toMatchObject({ ok: true, state: 'spent', ends: want })
    expect(await statusOf(holding.id)).toBe(want)
    expect((await h.wallet.balance()).holdings.held).toBe(0n)
  })
  test('receiving a reclaimed bill is refused as gone, with the reason', async () => {
    const w = h.bank.mintToPubkey(5000n, h.me)
    w.spent = true
    w.spentReason = 'reclaimed'
    expect(await err(h.wallet.receive(w.token))).toMatchObject({ code: 'spent', reason: 'reclaimed' })
    expect(await h.wallet.holdings({ includeSpent: true })).toEqual([])
  })
})

test('the exported HoldingStatus includes expired and reclaimed', () => {
  expectTypeOf<'reclaimed'>().toMatchTypeOf<HoldingStatus>()
  expectTypeOf<'expired'>().toMatchTypeOf<HoldingStatus>()
})
