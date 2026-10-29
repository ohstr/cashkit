// NIP-CASH §Looking Up a Call: in a `done`, a created bill since destroyed
// appears as its tombstone object in place of its token. Such a bill is
// neither held nor handed off, a spin-off is never read as a move in place,
// and the call still closes applied.
import { describe, expect, test } from 'vitest'
import { newCashTarget } from '../src/core/index.js'
import { CashkitError } from '../src/wallet/index.js'
import { harness, type Harness } from './walletHarness.js'

const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )
const openCalls = (h: Harness) => h.storage.tx('r', async (t) => (await t.list('pendingCalls')).filter((c) => c.state !== 'done'))
const TOMBSTONE = { status: 'spent', reason: 'redeemed' }

/** Rewrites the Hub's record of the call `requestId` so its `field` reads as a destroyed bill. */
function destroy(h: Harness, requestId: string, field: string) {
  const rec = h.bank.records.get(requestId)!
  h.bank.records.set(requestId, { ...rec, result: { ...(rec.result as Record<string, unknown>), [field]: TOMBSTONE } })
}

async function lostSend(h: Harness, amount: bigint) {
  h.bank.loseReplyFor.add('cash_transfer')
  const e = await failure(h.wallet.send({ amount }))
  expect(e.code).toBe('indeterminate')
  h.bank.loseReplyFor.clear()
  const [call] = await openCalls(h)
  return call!
}

describe('a lookup done whose created bill is a tombstone', () => {
  test('a cash note already spent by its recipient: the source is transferred, no note is kept, the call closes', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const call = await lostSend(h, 5000n)
    destroy(h, call.requestId, 'new_wallet_token')
    const rep = await h.wallet.settle()
    expect(rep.applied).toEqual([call.id])
    expect(await openCalls(h)).toEqual([])
    expect(await h.wallet.handoffs()).toEqual([])
    expect((await h.storage.tx('r', (t) => t.get('holdings', call.sources[0]!)))?.status).toBe('transferred')
  })
  test('the same send with the note still there keeps the note', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const call = await lostSend(h, 5000n)
    expect((await h.wallet.settle()).applied).toEqual([call.id])
    expect(await h.wallet.handoffs()).toHaveLength(1)
  })
  test('a split whose remainder is already destroyed adds no remainder; its note is kept', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const call = await lostSend(h, 2000n)
    destroy(h, call.requestId, 'remainder_wallet_token')
    expect((await h.wallet.settle()).applied).toEqual([call.id])
    expect(await h.wallet.holdings()).toEqual([])
    expect(await h.wallet.handoffs()).toHaveLength(1)
  })
  test('a protect whose new bill is already destroyed ends the holding, never keeping the old token as moved', async () => {
    const h = await harness()
    const t = newCashTarget()
    const r = await h.wallet.receive(`${h.bank.mintToCash(5000n, t.secret).token}#${t.secret}`, { protect: false })
    if (!r.received) throw new Error('not received')
    const before = (await h.storage.tx('r', (x) => x.get('holdings', r.holding.id)))!.token
    h.bank.loseReplyFor.add('cash_transfer')
    await h.wallet.protect({ holdings: [r.holding.id] }).catch(() => undefined)
    h.bank.loseReplyFor.clear()
    const [call] = await openCalls(h)
    destroy(h, call!.requestId, 'new_wallet_token')
    expect((await h.wallet.settle()).applied).toEqual([call!.id])
    const row = (await h.storage.tx('r', (x) => x.get('holdings', r.holding.id)))!
    expect(row.status).toBe('spent')
    expect(row.token).toBe(before)
    expect(await h.wallet.holdings()).toEqual([])
  })
})

describe('a mint whose bill a lookup shows destroyed', () => {
  test('closes applied with nothing held, instead of being looked up for ever', async () => {
    const h = await harness({ deps: { nwcTimeoutMs: 300 } })
    await h.wallet.connections.add('hub', h.bank.openCashHub())
    h.bank.loseMintReply = true
    const e = await failure(h.wallet.mint({ hub: 'hub', amount: 3000n, to: 'self' }))
    h.bank.loseMintReply = false
    const call = (await openCalls(h)).find((c) => c.id === e.pendingCallId)!
    destroy(h, call.requestId, 'cash_token')
    expect((await h.wallet.settle()).applied).toEqual([call.id])
    expect(await openCalls(h)).toEqual([])
    expect(await h.wallet.holdings()).toEqual([])
  }, 20_000)
})
