// Proof of work in the batch session (NIP-CASH §Proof of Work): the
// relays' NIP-11 minimum decides the difficulty; a `pow:` refusal re-mines
// the same event and publishes it again; mining runs after the write-ahead
// and before the 20 s check; NIP-47 calls never mine. Cases follow nmilat
// nipcash/client pow_test.go and the fake PoW relay (K-POW-4's rule).
import { beforeEach, describe, expect, test } from 'vitest'
import { bySigning, decodeToken, localSigner, newRequestId, powDifficulty } from '../src/core/index.js'
import { billFor, CashClient, CashHubClient, classifyCall, statusMany } from '../src/client/index.js'
import { FakeBank } from './fakeBank.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const R1 = 'wss://one.test'
const R2 = 'wss://two.test'
const holder = localSigner(fill(2, 32))
const now = () => Math.floor(Date.now() / 1000)

let pool: MemoryRelayPool
let bank: FakeBank
beforeEach(async () => {
  pool = new MemoryRelayPool()
  bank = new FakeBank(pool, [R1, R2])
  await bank.start()
})
const deps = (o: object = {}) => ({ relays: pool, replyWaitMs: 1500, ...o })
const requests = () => pool.attempts.filter((a) => a.event.kind === 23190)
async function status(o: object = {}) {
  const w = bank.mintToPubkey(1000n, holder.pubkey)
  const c = new CashClient(deps(o), w.token)
  return statusMany(await c.session(), [{ id: 'a', bill: billFor(decodeToken(w.token)), credential: bySigning(holder) }], now)
}

describe('T-413 mining before the first publish', () => {
  test('all minimums 0: a plain event, neither nonce nor expiration', async () => {
    const r = await status()
    expect(r.outcomes[0]!.state).toBe('result')
    expect(requests()[0]!.event.tags).toEqual([['p', bank.hub.inbox]])
  })
  test('minimums 0 and 12: the one event is mined to 12, with expiration = not_after', async () => {
    pool.relay(R2).powMinimum = 12
    const r = await status()
    expect(r.outcomes[0]!.state).toBe('result')
    const e = requests()[0]!.event
    expect(powDifficulty(e.id)).toBeGreaterThanOrEqual(12)
    expect(e.tags.map((t) => t[0])).toEqual(['p', 'nonce', 'expiration'])
    expect(e.tags[1]![2]).toBe('12')
    expect(Number(e.tags[2]![1])).toBe(bank.hub.requests[0]!.notAfter)
  })
  test('order: write-ahead, then mine, then publish', async () => {
    pool.relay(R1).powMinimum = 10
    const w = bank.mintToPubkey(1000n, holder.pubkey)
    const s = await new CashClient(deps(), w.token).session()
    const { buildItem } = await import('../src/client/index.js')
    const seen: number[] = []
    await s.send([{ id: 'a', method: 'cash_status', build: (id, b) => buildItem(id, billFor(decodeToken(w.token)), 'cash_status', {}, bySigning(holder), b, now()) }], {
      beforePublish: async () => void seen.push(requests().length),
    })
    expect(seen).toEqual([0])
    expect(powDifficulty(requests()[0]!.event.id)).toBeGreaterThanOrEqual(10)
  })
  test('over the mining budget: pow_too_hard, nothing published', async () => {
    pool.relay(R1).powMinimum = 16
    await expect(status({ powBudget: { maxDifficulty: 8 } })).rejects.toMatchObject({ code: 'pow_too_hard' })
    expect(requests()).toHaveLength(0)
  })
  test('a mint over NIP-47 is never mined', async () => {
    pool.relay(R1).powMinimum = 12
    pool.relay(R2).powMinimum = 12
    const hub = new CashHubClient(deps({ nwcTimeoutMs: 1500 }), bank.openCashHub())
    await hub.mint([{ identityType: 'pubkey', identityValue: holder.pubkey, amountMillis: 1000n }], { requestId: newRequestId() })
    const mint = pool.attempts.filter((a) => a.event.kind === 23194).map((a) => a.event)
    expect(mint.length).toBeGreaterThan(0)
    expect(mint.every((e) => !e.tags.some((t) => t[0] === 'nonce'))).toBe(true)
  })
})

describe('T-414 a pow: refusal', () => {
  test('re-mined to the stated difficulty and published again; the Hub runs it once', async () => {
    pool.relay(R1).powRequired = 12
    const r = await status()
    expect(r.outcomes[0]!.state).toBe('result')
    const tries = requests().filter((a) => a.relay === R1)
    expect(tries.map((t) => t.ok)).toEqual([false, true])
    expect(tries[0]!.message).toBe('pow: difficulty 12 required')
    const [a, b] = tries.map((t) => t.event)
    expect([b!.pubkey, b!.content, b!.created_at]).toEqual([a!.pubkey, a!.content, a!.created_at])
    expect(powDifficulty(b!.id)).toBeGreaterThanOrEqual(12)
    expect(bank.hub.requests.filter((q) => q.item.method === 'cash_status')).toHaveLength(1)
  })
  test('NIP-11 unreachable: a plain event first, re-mined after the refusal', async () => {
    pool.relay(R1).noInfo = true
    pool.relay(R1).powRequired = 10
    const r = await status()
    expect(r.outcomes[0]!.state).toBe('result')
    expect(requests().map((t) => t.ok)).toEqual([false, true])
  })
  test('every relay refusing: the call is sent (looked up later), never a Hub code', async () => {
    pool.relay(R1).refuse = true
    pool.relay(R2).refuse = true
    const r = await status()
    expect(r.outcomes[0]!.state).toBe('not_served')
    expect(classifyCall(r.outcomes[0]!)).toEqual({ kind: 'open', reason: 'not_served' })
  })
  test('a repeat of an accepted event is dropped by the PoW relay until it expires', async () => {
    pool.relay(R1).powMinimum = 8
    await status()
    const e = requests()[0]!.event
    const again = await pool.publish(R1, e)
    expect(again.message).toMatch(/duplicate/)
    expect(bank.hub.requests).toHaveLength(1)
  })
})
