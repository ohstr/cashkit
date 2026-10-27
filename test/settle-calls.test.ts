// Settling pending calls by cash_lookup (NIP-CASH §Lost Replies, §Looking
// Up a Call): a reply applies; a lost reply is found `done`; `pending`
// waits; `unknown` re-places under the derived id on the owning device, or
// closes a coded refusal, or asks the user; `expired` surfaces; omissions
// never read as `unknown`. A test call kind transfers a bill to Bob through
// the fake bank, whose clock the wallet shares. T-521..T-528.
import { beforeEach, describe, expect, test } from 'vitest'
import { bySigning, decodeToken, derivedRequestId, newCashTarget, newRequestId, pubkeyTarget } from '../src/core/index.js'
import { billFor, CashClient, deadlineFor, transferMany } from '../src/client/index.js'
import { toJSON, type PendingCall, type Wallet } from '../src/wallet/index.js'
import { executeCall, registerCallKind, type CallKind } from '../src/wallet/runner.js'
import { prepareCall } from '../src/wallet/calls.js'
import type { Ctx } from '../src/wallet/context.js'
import { updateHolding } from '../src/wallet/ledger.js'
import { harness, type Harness } from './walletHarness.js'

const BOB = 'ee'.repeat(32)
let skew = 0
const clock = () => Date.now() + skew
const ctxOf = (w: Wallet) => (w as unknown as { ctx: Ctx }).ctx
let finished: { id: string; from: string }[] = []

function testKind(autoReplace: boolean): CallKind {
  return {
    autoReplace,
    ...(!autoReplace && { replaceRequest: 'confirmMintReplace' as const }),
    async place(ctx, call, beforePublish) {
      const h = (await ctx.read((t) => t.get('holdings', call.sources[0]!)))!
      const c = new CashClient(ctx.clientDeps, h.token)
      const r = await transferMany(
        await c.session(),
        [{ id: '1', bill: c.bill, credential: bySigning(await ctx.requireSigner()), to: pubkeyTarget(BOB), currentAmount: BigInt(call.params!['current']!), requestId: call.requestId }],
        () => ctx.nowSeconds(),
        { notAfter: call.deadline, beforePublish },
      )
      return { outcome: r.outcomes[0], ...(r.error !== undefined && { error: r.error }) }
    },
    async finish(_ctx, call, _result, from) {
      return async (t) => {
        finished.push({ id: call.id, from })
        await updateHolding(t, call.sources[0]!, (x) => ({ ...x, status: 'transferred' }))
      }
    },
    async lookupTarget(ctx, call) {
      const h = (await ctx.read((t) => t.get('holdings', call.sources[0]!)))!
      return { bill: billFor(decodeToken(h.token)), authorizer: { kind: 'signer', signer: await ctx.requireSigner() } }
    },
  }
}
registerCallKind('test-transfer', testKind(true))
registerCallKind('test-mint', testKind(false))

let h: Harness
beforeEach(async () => {
  skew = 0
  finished = []
  h = await harness({ deps: { clock } })
  h.bank.hub.clock = clock
})

async function prepared(kind = 'test-transfer', o: Partial<PendingCall> = {}) {
  const w = h.bank.mintToPubkey(5000n, h.me)
  const r = await h.wallet.receive(w.token)
  if (!r.received) throw new Error('not received')
  const ctx = ctxOf(h.wallet)
  const session = await new CashClient(ctx.clientDeps, w.token).session()
  const call = await prepareCall(ctx, {
    kind,
    requestId: newRequestId(),
    method: 'cash_transfer',
    target: w.walletPubkey,
    node: session.hub,
    relays: session.relays,
    deadline: deadlineFor(session.maxRequestAge, ctx.nowSeconds()),
    hAtSend: session.maxRequestAge!,
    amount: 5000n,
    sources: [r.holding.id],
    authorizer: { kind: 'identity' },
    outputs: [{ role: 'new', destination: { kind: 'cash', secret: newCashTarget().secret } }],
    params: { current: '5000' },
    ...o,
  } as never)
  return { ctx, call, w, holdingId: r.holding.id }
}
const row = (id: string) => ctxOf(h.wallet).read((t) => t.get('pendingCalls', id))
const calls = () => ctxOf(h.wallet).read((t) => t.list('pendingCalls'))
const failure = (p: Promise<unknown>) => p.then(() => undefined, (e: unknown) => e as { code: string; pendingCallId?: string })

describe('T-521 a call and its answer', () => {
  test('an applied reply finishes the call in the transaction that closes it', async () => {
    const { ctx, call, holdingId } = await prepared()
    await executeCall(ctx, call)
    expect(await row(call.id)).toMatchObject({ state: 'done', outcome: 'applied' })
    expect(finished).toEqual([{ id: call.id, from: 'reply' }])
    expect((await ctx.read((t) => t.get('holdings', holdingId)))?.status).toBe('transferred')
  })
  test('a lost reply leaves the call sent (indeterminate, with its id); settle finds it done', async () => {
    const { ctx, call } = await prepared()
    h.bank.loseReplyFor.add('cash_transfer')
    const e = await failure(executeCall(ctx, call))
    h.bank.loseReplyFor.clear()
    expect(e).toMatchObject({ code: 'indeterminate', pendingCallId: call.id })
    expect((await row(call.id))?.state).toBe('sent')
    const events: string[] = []
    h.wallet.on('operation', (ev) => events.push(ev.phase))
    const rep = await h.wallet.settle()
    expect(rep.applied).toEqual([call.id])
    expect(finished).toEqual([{ id: call.id, from: 'lookup' }])
    expect(events).toContain('recovered')
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer')).toHaveLength(1)
  })
  test('a call never marked sent is closed not_sent', async () => {
    const { call } = await prepared()
    const rep = await h.wallet.settle()
    expect(rep.closed).toEqual([call.id])
    expect(await row(call.id)).toMatchObject({ state: 'done', outcome: 'not_sent' })
  })
  test('BAD_REQUEST closes it not applied (invalid_input)', async () => {
    const { ctx, call } = await prepared()
    h.bank.override = (m) => (m === 'cash_transfer' ? { error: { code: 'BAD_REQUEST', message: 'x' } } : undefined)
    expect(await failure(executeCall(ctx, call))).toMatchObject({ code: 'invalid_input' })
    expect(await row(call.id)).toMatchObject({ state: 'done', outcome: 'not_applied', lastCode: 'BAD_REQUEST' })
  })
  test('a tombstone answer marks the source spent and closes the call', async () => {
    const { ctx, call, holdingId } = await prepared()
    h.bank.override = (m) => (m === 'cash_transfer' ? { result: { status: 'spent', reason: 'redeemed' } } : undefined)
    expect(await failure(executeCall(ctx, call))).toMatchObject({ code: 'spent' })
    expect((await ctx.read((t) => t.get('holdings', holdingId)))?.status).toBe('spent')
    expect((await row(call.id))?.outcome).toBe('not_applied')
  })
})

describe('T-524 pending', () => {
  test('a sent call with no record before its deadline is pending until deadline + 1', async () => {
    const { ctx, call } = await prepared()
    const { markSent } = await import('../src/wallet/calls.js')
    await markSent(ctx, call)
    await h.wallet.settle()
    const r = await row(call.id)
    expect(r?.lookup).toMatchObject({ status: 'pending', retryAfter: call.deadline + 1 })
    await h.wallet.reload()
    expect(h.wallet.state.nextSettleAt).toBe(call.deadline + 1)
  })
})

async function lostThenUnknown(kind = 'test-transfer') {
  const { ctx, call } = await prepared(kind)
  const { markSent } = await import('../src/wallet/calls.js')
  await markSent(ctx, call) // sent, but never reached the Hub
  skew = (call.deadline + 2) * 1000 - Date.now()
  return { ctx, call }
}

describe('T-522 unknown and re-placement', () => {
  test('the owning device places it again under the derived id; the old call closes replaced', async () => {
    const { call } = await lostThenUnknown()
    const rep = await h.wallet.settle()
    expect(rep.replaced).toEqual([call.id])
    const all = await calls()
    const next = all.find((c) => c.derivedFrom === call.id)!
    expect(next).toMatchObject({ requestId: derivedRequestId(call.requestId), attempts: 2, state: 'done', outcome: 'applied' })
    expect(await row(call.id)).toMatchObject({ outcome: 'replaced' })
    expect(await ctxOf(h.wallet).read((t) => t.get('derivedIds', next.requestId))).toMatchObject({ parentCallId: call.id })
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer').map((r) => r.params['request_id'])).toEqual([next.requestId])
  })
  test('a derived id already recorded only closes the old call', async () => {
    const { ctx, call } = await lostThenUnknown()
    const { recordDerivedId } = await import('../src/wallet/calls.js')
    await ctx.commit((t) => recordDerivedId(t, { derivedId: derivedRequestId(call.requestId), parentCallId: call.id, deadline: 1, hMax: 1 }))
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ outcome: 'replaced' })
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer')).toHaveLength(0)
  })
  test('a coded refusal is never placed again: closed refused with its code', async () => {
    const { ctx, call } = await prepared()
    h.bank.override = (m) => (m === 'cash_transfer' ? { error: { code: 'RESTRICTED', message: 'x' } } : undefined)
    expect(await failure(executeCall(ctx, call))).toMatchObject({ code: 'auth', pendingCallId: call.id })
    h.bank.override = undefined
    skew = (call.deadline + 2) * 1000 - Date.now()
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ state: 'done', outcome: 'not_applied', needsUser: 'refused', lastCode: 'RESTRICTED' })
    expect((await calls()).some((c) => c.derivedFrom === call.id)).toBe(false)
  })
  test('a kind that needs the user waits for confirmReplace', async () => {
    const { call } = await lostThenUnknown('test-mint')
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ state: 'sent', needsUser: 'confirm_replace' })
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer')).toHaveLength(0)
    await h.wallet.pendingCalls.confirmReplace(call.id)
    expect(await row(call.id)).toMatchObject({ outcome: 'replaced' })
    expect((await calls()).find((c) => c.derivedFrom === call.id)?.outcome).toBe('applied')
  })
  test('with a handler, the kind asks its replace request; yes places it again', async () => {
    const seen: string[] = []
    h.wallet.on('confirm', (r) => (seen.push(r.type), r.type === 'confirmMintReplace'))
    const { call } = await lostThenUnknown('test-mint')
    await h.wallet.settle()
    for (let i = 0; i < 50 && (await row(call.id))?.outcome !== 'replaced'; i++) await new Promise((r) => setTimeout(r, 20))
    expect(seen).toContain('confirmMintReplace')
    expect(await row(call.id)).toMatchObject({ outcome: 'replaced' })
  })
  test('the third attempt is the last: replace_cap', async () => {
    const { call } = await lostThenUnknown()
    await ctxOf(h.wallet).commit(async (t) => {
      const c = (await t.get('pendingCalls', call.id))!
      await t.put('pendingCalls', { ...c, attempts: 3, version: c.version + 1 }, c.version)
    })
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ outcome: 'not_applied', needsUser: 'replace_cap' })
  })
  test('another device’s call is never placed again from here', async () => {
    const { call } = await lostThenUnknown()
    await ctxOf(h.wallet).commit(async (t) => {
      const c = (await t.get('pendingCalls', call.id))!
      await t.put('pendingCalls', { ...c, device: 'ff'.repeat(16), version: c.version + 1 }, c.version)
    })
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ state: 'sent', needsUser: 'foreign_device' })
    await expect(h.wallet.pendingCalls.confirmReplace(call.id)).rejects.toMatchObject({ code: 'usage' })
  })
})

describe('T-523 / T-526 expired, unanswered, closed by the user', () => {
  test('expired: closed lookup_expired, its written-ahead secret kept as unreconciled', async () => {
    const { ctx, call } = await prepared()
    const { markSent } = await import('../src/wallet/calls.js')
    await markSent(ctx, call)
    skew = (call.deadline + call.hAtSend + 5) * 1000 - Date.now()
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ outcome: 'lookup_expired', needsUser: 'lookup_expired' })
    await h.wallet.reload()
    expect(h.wallet.state.unreconciled).toBe(1)
    const s = await h.wallet.unreconciledSecrets({ includeSecrets: true })
    expect(s).toEqual([{ pendingCallId: call.id, role: 'new', cashSecret: expect.stringMatching(/^[0-9a-f]{64}$/) }])
    expect(await h.wallet.unreconciledSecrets()).toEqual([{ pendingCallId: call.id, role: 'new' }])
  })
  test('expired: the lookupExpired notice carries the closed call, never a secret', async () => {
    const seen: unknown[] = []
    h.wallet.on('confirm', (r) => (seen.push(r), false))
    const { ctx, call } = await prepared()
    const { markSent } = await import('../src/wallet/calls.js')
    await markSent(ctx, call)
    skew = (call.deadline + call.hAtSend + 5) * 1000 - Date.now()
    await h.wallet.settle()
    expect(seen).toEqual([{ type: 'lookupExpired', call: expect.objectContaining({ id: call.id, outcome: 'lookup_expired', needsUser: 'lookup_expired' }) }])
    expect(toJSON(seen)).not.toMatch(/[0-9a-f]{64}/)
  })
  test('omissions are never unknown; only past deadline + H they ask the user', async () => {
    const { ctx, call } = await prepared()
    const { markSent } = await import('../src/wallet/calls.js')
    await markSent(ctx, call)
    h.bank.override = (m) => (m === 'cash_lookup' ? 'omit' : undefined)
    skew = (call.deadline + 2) * 1000 - Date.now()
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ state: 'sent', lookup: { omissions: 1 } })
    expect((await row(call.id))?.needsUser).toBeUndefined()
    skew = (call.deadline + call.hAtSend + 5) * 1000 - Date.now()
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ state: 'sent', needsUser: 'lookup_unanswered' })
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer')).toHaveLength(0)
  })
  test('REQUEST_REUSED answering the lookup counts as no answer', async () => {
    const { ctx, call } = await prepared()
    const { markSent } = await import('../src/wallet/calls.js')
    await markSent(ctx, call)
    h.bank.override = (m) => (m === 'cash_lookup' ? { error: { code: 'REQUEST_REUSED', message: 'x' } } : undefined)
    skew = (call.deadline + 2) * 1000 - Date.now()
    await h.wallet.settle()
    expect(await row(call.id)).toMatchObject({ state: 'sent', lookup: { omissions: 1 } })
  })
  test('the user closes a call; views carry no request id or secret', async () => {
    const { call } = await prepared()
    const { markSent } = await import('../src/wallet/calls.js')
    await markSent(ctxOf(h.wallet), call)
    const list = await h.wallet.pendingCalls.list()
    expect(list).toEqual([expect.objectContaining({ id: call.id, op: 'test-transfer', state: 'sent', ownedHere: true, amount: 5000n })])
    expect(toJSON(list)).not.toContain(call.requestId)
    await h.wallet.pendingCalls.close(call.id)
    expect(await row(call.id)).toMatchObject({ outcome: 'user_closed' })
  })
})

describe('T-524 autoSettle', () => {
  test('schedules settle at the next retry time, and stops', async () => {
    const { ctx, call } = await prepared()
    const { markSent } = await import('../src/wallet/calls.js')
    await markSent(ctx, call)
    await h.wallet.settle()
    await h.wallet.reload()
    const timers: number[] = []
    let cleared = 0
    const stop = h.wallet.autoSettle({ setTimeout: (_fn, ms) => (timers.push(ms), timers.length), clearTimeout: () => void cleared++ })
    expect(timers).toHaveLength(1)
    expect(Math.abs(timers[0]! - ((call.deadline + 1) * 1000 - clock()))).toBeLessThan(1500)
    stop()
    expect(cleared).toBe(1)
  })
})
