// Confirmation requests (wallet.on('confirm', …)): every question is answered
// no without a handler, a handler's true goes ahead, notices are only shown.
import { describe, expect, test } from 'vitest'
import { Confirmations } from '../src/wallet/confirm.js'
import { CashkitError, isNotice, type ConfirmRequest } from '../src/wallet/index.js'
import { FakeCircle } from './fakeCircle.js'
import { FakeWithdraw, PAYTO } from './fakeWithdraw.js'
import { harness, type Harness } from './walletHarness.js'

const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )

/** Records every request and answers questions with `answer`. */
function recorder(h: Harness, answer: boolean): ConfirmRequest[] {
  const seen: ConfirmRequest[] = []
  h.wallet.on('confirm', (r) => {
    seen.push(r)
    return answer
  })
  return seen
}

describe('Confirmations', () => {
  test('no handler: every question is no and a notice goes nowhere', async () => {
    const c = new Confirmations()
    expect(await c.ask({ type: 'confirmDelete', name: 'x', dust: 1n })).toBe(false)
    expect(() => c.notify({ type: 'walletFrozen', name: 'x' })).not.toThrow()
  })
  test('the handler added last answers; only exactly true is yes; a throwing handler is no', async () => {
    const c = new Confirmations()
    const q = { type: 'confirmDelete', name: 'x', dust: 1n } as const
    const offA = c.add(() => true)
    const offB = c.add(() => 'yes' as unknown as boolean)
    expect(await c.ask(q)).toBe(false)
    offB()
    expect(await c.ask(q)).toBe(true)
    c.add(() => {
      throw new Error('boom')
    })
    expect(await c.ask(q)).toBe(false)
    offA()
  })
  test('notices and questions are told apart', () => {
    expect(isNotice({ type: 'lookupExpired', call: {} as never })).toBe(true)
    expect(isNotice({ type: 'confirmWithdraw', quote: {} as never })).toBe(false)
  })
})

async function withdrawSetup() {
  const h = await harness()
  const hub = new FakeWithdraw(h.bank)
  const r = await h.wallet.receive(h.bank.mintToPubkey(21_000_000n, h.me).token)
  return { h, hub, id: r.received ? r.holding.id : '' }
}

const terms = { maxAmount: 50_000n, maxReceive: 80_000n, budgetRenewal: 'monthly' as const }
async function circleSetup(o: ConstructorParameters<typeof FakeCircle>[1] = { rotationDelaySecs: 432000 }) {
  const h = await harness({ deps: { nwcTimeoutMs: 2000 } })
  return { h, circle: new FakeCircle(h.bank, o) }
}

describe('withdrawals', () => {
  test('no handler: nothing is sent', async () => {
    const { h, id } = await withdrawSetup()
    const q = await h.wallet.withdraw.quote(id, PAYTO)
    expect(await failure(h.wallet.withdraw.send(q))).toMatchObject({ reason: 'not_confirmed' })
    expect(await h.storage.tx('r', (t) => t.list('pendingCalls'))).toEqual([])
  })
  test('a handler saying no sends nothing; confirmWithdraw carries every figure, deliberate and irreversible', async () => {
    const { h, id } = await withdrawSetup()
    const seen = recorder(h, false)
    const q = await h.wallet.withdraw.quote(id, PAYTO)
    expect(await failure(h.wallet.withdraw.send(q))).toMatchObject({ reason: 'not_confirmed' })
    expect(seen).toHaveLength(1)
    expect(seen[0]).toMatchObject({
      type: 'confirmWithdraw',
      quote: { address: PAYTO, amountMillis: 21_000_000n, payoutMillis: 19_258_000n, feeMillis: 1_742_000n, irreversible: true, deliberate: true, highFee: false },
    })
    const d = (seen[0] as Extract<ConfirmRequest, { type: 'confirmWithdraw' }>).quote
    expect(d.addressGroups.join('')).toBe(PAYTO)
    expect(d.networkFeeMillis + d.hubFeeMillis).toBe(d.feeMillis)
    expect(typeof d.sentBy).toBe('number')
  })
  test('a handler saying yes sends it; a cancelled payout raises withdrawCancelled once', async () => {
    const { h, hub, id } = await withdrawSetup()
    const seen = recorder(h, true)
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO))
    expect(v.phase).toBe('accepted')
    hub.cancel(hub.only())
    const after = await h.wallet.withdraw.refresh(v.id)
    await h.wallet.withdraw.refresh(v.id)
    const cancelled = seen.filter((r) => r.type === 'withdrawCancelled')
    expect(cancelled).toEqual([{ type: 'withdrawCancelled', id: v.id, amountMillis: 21_000_000n, remintHoldingId: after.remintHoldingId }])
  })
})

describe('circles', () => {
  test('a Hub that cannot rotate: confirmNoRecovery with the Hub view; no handler refuses, yes joins', async () => {
    const { h, circle } = await circleSetup({})
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ reason: 'no_recovery_unconfirmed' })
    const seen = recorder(h, true)
    const r = await h.wallet.circles.join(circle.string, terms)
    expect(r.name).toBeTruthy()
    expect(seen[0]).toMatchObject({ type: 'confirmNoRecovery', view: { kind: 'circlehub', online: 'pass' } })
  })
  test('notices: an unexpected rotation and a freeze; delete asks with the dust', async () => {
    const { h, circle } = await circleSetup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const seen = recorder(h, false)
    await h.wallet.circles.notify(r.name, { notification_type: 'rotation_pending', notification: { connection_pubkey: 'ab'.repeat(32), completes_at: 99 } })
    await h.wallet.circles.notify(r.name, { notification_type: 'wallet_frozen', notification: {} })
    expect(seen).toEqual([
      { type: 'rotationAlert', name: r.name },
      { type: 'walletFrozen', name: r.name },
    ])
    ;[...circle.wallets.values()][0]!.balance = 10n
    expect(await failure(h.wallet.circles.delete(r.name))).toMatchObject({ reason: 'not_confirmed' })
    expect(seen.at(-1)).toEqual({ type: 'confirmDelete', name: r.name, dust: 10n })
  })
})

describe('zaps', () => {
  test('an untrusted minter: approveMinter is asked; yes approves it and the zap is claimed', async () => {
    const alice = await harness()
    const bob = await harness({ pool: alice.pool, bank: alice.bank })
    await alice.wallet.receive(alice.bank.mintToPubkey(50_000n, alice.me).token)
    await alice.wallet.zaps.send({ to: bob.me, amountMillis: 21_000n, target: { e: 'cd'.repeat(32) }, relays: ['wss://social.test'] })
    const ev = alice.pool.published.find((p) => p.event.kind === 9522)!.event
    expect(await failure(bob.wallet.zaps.claim(ev))).toMatchObject({ reason: 'minter_untrusted' })
    const seen = recorder(bob, true)
    const held = await bob.wallet.zaps.claim(ev)
    expect(held).toMatchObject({ amount: 21_000n })
    expect(seen[0]).toMatchObject({ type: 'approveMinter', networkUnverifiable: true })
    expect((await bob.wallet.settings.get()).trustedMinters).toHaveLength(1)
  })
})
