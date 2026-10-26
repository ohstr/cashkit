// The batch session on the final rules: relay order, deadlines from the
// Hub's max_request_age, the write-ahead hook, the chunk collector of
// NIP-CASH §Chunked Replies, and the call classification. Cases follow
// nmilat nipcash/client {batch_session,batch_send,batch_outcome}_test.go and
// the NIP's tables (§Chunked Replies, §Deadlines, §Methods/Errors).
import { beforeEach, describe, expect, test } from 'vitest'
import { bySigning, decodeToken, localSigner, pubkeyTarget } from '../src/core/index.js'
import { BatchSession, billFor, CashClient, classifyCall, ClientError, deadlineFor, MIN_PUBLISH_MARGIN, statusMany, type ItemOutcome } from '../src/client/index.js'
import { FakeHub, MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const R1 = 'wss://a.test'
const R2 = 'wss://b.test'
const R3 = 'wss://c.test'
const holder = localSigner(fill(2, 32))
const now = () => Math.floor(Date.now() / 1000)

let pool: MemoryRelayPool
let hub: FakeHub
beforeEach(async () => {
  pool = new MemoryRelayPool()
  hub = new FakeHub(pool, [R1, R2, R3])
  await hub.start()
})
const bill = (i: number, relays: readonly string[] = [R1, R2]) => hub.mintBill({ walletKey: fill(0x40 + i, 32), connSecret: fill(0x60 + i, 32), amount: 21000n, relays })
const deps = () => ({ relays: pool, replyWaitMs: 1500 })
const statusItems = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `s${i}`, bill: billFor(decodeToken(bill(i))), credential: bySigning(holder) }))

describe('T-401 / T-402 relay order and failover', () => {
  test('announced relays first, then the token hints in order, each once', async () => {
    await hub.announce({ relays: [R3, R2], createdAt: now() + 1 })
    const s = await BatchSession.open(deps(), hub.node, [R1, R2, ' ', R1])
    expect(s.relays).toEqual([R3, R2, R1])
  })
  test('the announcement is fetched from the hints only', async () => {
    pool.relay(R1).stored = []
    pool.relay(R2).stored = []
    await expect(BatchSession.open(deps(), hub.node, [R1, R2])).rejects.toMatchObject({ code: 'no_announcement' })
  })
  test('a down relay is skipped; the request goes to the next and the reply is found there', async () => {
    await hub.announce({ relays: [R3, R2], createdAt: now() + 1 })
    pool.relay(R3).down = true
    const r = await new CashClient(deps(), bill(1)).statusMany(statusItems(1))
    expect(r.outcomes[0]!.state).toBe('result')
    expect(r.acceptedRelays).toEqual([R2])
    expect(pool.published.filter((p) => p.event.kind === 23190).map((p) => p.relay)).toEqual([R2])
  })
})

describe('T-405 deadlines', () => {
  test.each([
    [300, 60],
    [120, 60],
    [60, 30],
    [86401, 60],
    [undefined, 30],
  ])('H %s ⇒ now + %i', (h, w) => {
    expect(deadlineFor(h, 1000)).toBe(1000 + w)
  })
  test('the envelope carries exactly the deadline the write-ahead saw', async () => {
    const seen: number[] = []
    const s = await new CashClient(deps(), bill(1)).session()
    const t0 = now()
    await s.send(statusBuilders(s, 1), { beforePublish: async (p) => void seen.push(p.notAfter) })
    expect(seen).toHaveLength(1)
    expect(seen[0]! - t0).toBeGreaterThanOrEqual(59)
    expect(seen[0]! - t0).toBeLessThanOrEqual(61)
  })
  test('a given deadline is used as is', async () => {
    const s = await new CashClient(deps(), bill(1)).session()
    const seen: number[] = []
    await s.send(statusBuilders(s, 1), { notAfter: now() + 45, beforePublish: async (p) => void seen.push(p.notAfter) })
    expect(seen[0]).toBe(now() + 45)
  })
  test('less than 20 s left after the write-ahead: nothing is sent', async () => {
    const s = await new CashClient(deps(), bill(1)).session()
    const before = pool.published.length
    await expect(s.send(statusBuilders(s, 1), { notAfter: now() + MIN_PUBLISH_MARGIN - 1, beforePublish: async () => {} })).rejects.toMatchObject({ code: 'deadline_too_close' })
    expect(pool.published.length).toBe(before)
  })
  test('a failing write-ahead sends nothing', async () => {
    const s = await new CashClient(deps(), bill(1)).session()
    const before = pool.published.length
    await expect(s.send(statusBuilders(s, 1), { beforePublish: () => Promise.reject(new Error('disk full')) })).rejects.toThrow('disk full')
    expect(pool.published.length).toBe(before)
  })
  test('single envelope required: a batch that would split is refused before anything is sent', async () => {
    hub.limits = { ...hub.limits, maxItems: 2 }
    await hub.announce({ relays: [R1, R2], createdAt: now() + 1, limits: hub.limits })
    const s = await new CashClient(deps(), bill(1)).session()
    await expect(s.send(statusBuilders(s, 3), { singleEnvelope: true })).rejects.toMatchObject({ code: 'single_envelope_required' })
  })
  test('a Hub announcing no usable max_request_age takes reads but no bill-creating call', async () => {
    await hub.announce({ relays: [R1, R2], createdAt: now() + 1, maxRequestAge: 59 })
    const c = new CashClient(deps(), bill(1))
    await expect(c.statusMany(statusItems(1))).resolves.toBeDefined()
    const before = pool.published.filter((p) => p.event.kind === 23190).length
    await expect(c.cashTransfer({ credential: bySigning(holder), to: pubkeyTarget(holder.pubkey), currentAmount: 21000n })).rejects.toMatchObject({ code: 'hub_unusable' })
    expect(pool.published.filter((p) => p.event.kind === 23190).length).toBe(before)
  })
})

function statusBuilders(s: BatchSession, n: number) {
  return statusItems(n).map((it) => ({
    id: it.id,
    method: 'cash_status',
    build: async (id: string, b: Parameters<Parameters<BatchSession['send']>[0][number]['build']>[1]) => {
      const { buildItem } = await import('../src/client/index.js')
      return buildItem(id, it.bill, 'cash_status', {}, it.credential, b, now())
    },
  }))
}

const run = async () => statusMany(await new CashClient(deps(), bill(0)).session(), statusItems(3), now)

describe('T-403 the chunk collector (§Chunked Replies)', () => {
  test('all chunks, some items omitted: complete; each omission final', async () => {
    hub.faults = { chunks: 2, omit: new Set(['s1']) }
    const r = await run()
    expect(r.error).toBeUndefined()
    expect(r.outcomes.map((o) => o.state)).toEqual(['result', 'not_served', 'result'])
  })
  test('fewer chunks than total: incomplete, decided outcomes kept', async () => {
    hub.faults = { chunks: 3, sendChunks: 2 }
    const r = await run()
    expect(r.error).toMatchObject({ code: 'incomplete_reply' })
    expect(r.outcomes.filter((o) => o.state === 'result')).toHaveLength(2)
  }, 10_000)
  test('chunks disagreeing about total: incomplete, decided outcomes kept', async () => {
    hub.faults = { chunks: 2, chunkTotals: [2, 3] }
    const r = await run()
    expect(r.error).toMatchObject({ code: 'incomplete_reply' })
    expect(r.outcomes.filter((o) => o.state === 'result')).toHaveLength(3)
  }, 10_000)
  test('two events with one seq: incomplete, decided outcomes kept', async () => {
    hub.faults = { chunks: 2, repeatFirstChunk: true }
    const r = await run()
    expect(r.error).toMatchObject({ code: 'incomplete_reply' })
    expect(r.outcomes.filter((o) => o.state === 'result').length).toBeGreaterThanOrEqual(1)
  }, 10_000)
  test('an item answered twice is conflicted; the others keep theirs', async () => {
    hub.faults = { chunks: 2, answerTwice: 's0' }
    const r = await run()
    expect(r.outcomes.find((o) => o.id === 's0')!.state).toBe('conflicted')
    expect(r.outcomes.filter((o) => o.state === 'result')).toHaveLength(2)
  })
  test('the same event from two relays is one chunk', async () => {
    hub.faults = { chunks: 1, replyOnAllRelays: true }
    const r = await run()
    expect(r.error).toBeUndefined()
    expect(r.outcomes.every((o) => o.state === 'result')).toBe(true)
  })
  test('an inflated total is bounded by the items asked', async () => {
    hub.faults = { declaredTotal: 9 }
    const r = await run()
    expect(r.error).toBeUndefined()
  })
  test('an envelope-level error is the outcome of every item', async () => {
    hub.faults = { envelopeError: { code: 'QUOTA_EXCEEDED' } }
    const r = await run()
    expect(r.outcomes.every((o) => o.state === 'error' && o.error?.code === 'QUOTA_EXCEEDED')).toBe(true)
  })
  test('no reply: a timeout, every item not served, the wait bounded', async () => {
    hub.faults = { drop: true }
    const t = Date.now()
    const r = await run()
    expect(r.error).toMatchObject({ code: 'timeout' })
    expect(r.outcomes.every((o) => o.state === 'not_served')).toBe(true)
    expect(Date.now() - t).toBeLessThan(5000)
  }, 10_000)
})

const out = (o: Partial<ItemOutcome>): ItemOutcome => ({ id: '1', state: 'not_served', undecodable: false, envelope: 0, ...o })

describe('T-404 / T-415 classifyCall', () => {
  test('BAD_REQUEST is final, item- or envelope-level, with its detail', () => {
    expect(classifyCall(out({ state: 'error', error: { code: 'BAD_REQUEST', detail: 'quote_expired' } }))).toEqual({ kind: 'final_not_applied', code: 'BAD_REQUEST', detail: 'quote_expired' })
  })
  test.each(['REQUEST_REUSED', 'INTERNAL', 'INSUFFICIENT_BALANCE', 'RATE_LIMITED', 'UNAUTHORIZED', 'RESTRICTED', 'QUOTA_EXCEEDED', 'NOT_FOUND', 'PAYMENT_FAILED'])('%s is open', (code) => {
    expect(classifyCall(out({ state: 'error', error: { code, detail: 'x' } }))).toEqual({ kind: 'open', reason: 'refused', code, detail: 'x' })
  })
  test('omission, conflict and an undecodable success are open; a result is applied', () => {
    expect(classifyCall(out({}))).toEqual({ kind: 'open', reason: 'not_served' })
    expect(classifyCall(out({ state: 'conflicted' }))).toEqual({ kind: 'open', reason: 'conflicted' })
    expect(classifyCall(out({ state: 'error', undecodable: true, error: { code: 'INTERNAL' } }))).toEqual({ kind: 'open', reason: 'undecodable' })
    expect(classifyCall(out({ state: 'result', result: '{}' }))).toEqual({ kind: 'applied' })
  })
  test('a tombstone means the call never ran; a local refusal is not sent', () => {
    expect(classifyCall({ ...out({ state: 'tombstone' }), tombstone: { status: 'spent' } })).toEqual({ kind: 'tombstone' })
    expect(classifyCall(out({ state: 'error', error: { code: 'NOT_SENT' } }))).toEqual({ kind: 'not_sent' })
  })
  test('a ClientError for a local refusal is never a Hub code', () => {
    expect(new ClientError('deadline_too_close', 'x').code).toBe('deadline_too_close')
  })
})
