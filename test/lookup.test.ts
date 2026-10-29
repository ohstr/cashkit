// cash_lookup and the Cash Hub client (NIP-CASH §Looking Up a Call,
// §Connection Signatures, §Minting Cash). Cases follow nmilat
// nipcash/client {lookup,cash_hub}_test.go; the fake bank keeps request
// records and serves a cashhub1 connection over NIP-47.
import { beforeEach, describe, expect, test } from 'vitest'
import { bySecret, bySigning, decodeToken, localSigner, newCashTarget, newRequestId, pubkeyTarget, toHex } from '../src/core/index.js'
import { billFor, CashClient, CashHubClient, ClientError, lookupMany, lookupOne, type BatchLookup } from '../src/client/index.js'
import { FakeBank } from './fakeBank.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const R1 = 'wss://hub.test'
const alice = localSigner(fill(3, 32))
const bob = localSigner(fill(4, 32))
const now = () => Math.floor(Date.now() / 1000)

let pool: MemoryRelayPool
let bank: FakeBank
beforeEach(async () => {
  pool = new MemoryRelayPool()
  bank = new FakeBank(pool, [R1])
  await bank.start()
})
const deps = () => ({ relays: pool, replyWaitMs: 1500, nwcTimeoutMs: 1500 })

async function transferLostReply(cred = bySigning(alice), w = bank.mintToPubkey(5000n, alice.pubkey)) {
  const c = new CashClient(deps(), w.token)
  const requestId = newRequestId()
  let deadline = 0
  bank.loseReplyFor.add('cash_transfer')
  const s = await c.session()
  const { transferMany } = await import('../src/client/index.js')
  const r = await transferMany(s, [{ id: 't', bill: c.bill, credential: cred, to: pubkeyTarget(bob.pubkey), currentAmount: w.amount, requestId }], now)
  void r
  bank.loseReplyFor.clear()
  deadline = bank.hub.requests.at(-1)!.notAfter
  return { c, s, requestId, deadline, w }
}

describe('T-406 / T-407 lookup items and statuses', () => {
  test('a lost transfer is found done, signed by its recorded authorizer', async () => {
    const { c, s, requestId, deadline } = await transferLostReply()
    const o = await lookupOne(s, { bill: c.bill, by: { requestId }, deadline, authorizer: { kind: 'signer', signer: alice } }, now)
    expect(o.state).toBe('result')
    expect(o.value).toMatchObject({ status: 'done', result: { amount_millis: 5000n } })
  })
  test('another signer, or another target, is refused UNAUTHORIZED', async () => {
    const { c, s, requestId, deadline } = await transferLostReply()
    const other = await lookupOne(s, { bill: c.bill, by: { requestId }, deadline, authorizer: { kind: 'signer', signer: bob } }, now)
    expect(other).toMatchObject({ state: 'error', error: { code: 'UNAUTHORIZED' } })
    const elsewhere = bank.mintToPubkey(1n, alice.pubkey)
    const wrongTarget = await lookupOne(s, { bill: billFor(decodeToken(elsewhere.token)), by: { requestId }, deadline, authorizer: { kind: 'signer', signer: alice } }, now)
    expect(wrongTarget).toMatchObject({ state: 'error', error: { code: 'UNAUTHORIZED' } })
  })
  test('the lookup of a destroyed bill is still answered', async () => {
    const { c, s, requestId, deadline, w } = await transferLostReply()
    expect(w.spent || bank.wallets.get(w.walletPubkey)!.identity.value === bob.pubkey).toBe(true)
    const o = await lookupOne(s, { bill: c.bill, by: { requestId }, deadline, authorizer: { kind: 'signer', signer: alice } }, now)
    expect(o.value?.status).toBe('done')
  })
  test('no record: pending until the deadline (retry deadline + 1), then unknown', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    const c = new CashClient(deps(), w.token)
    const s = await c.session()
    const item: BatchLookup = { bill: c.bill, by: { requestId: newRequestId() }, deadline: now() + 30, authorizer: { kind: 'signer', signer: alice } }
    const pending = await lookupOne(s, item, now)
    expect(pending.value).toEqual({ status: 'pending', retryAfter: now() + 31 })
    expect((await lookupOne(s, { ...item, deadline: now() - 5 }, now)).value).toEqual({ status: 'unknown' })
    expect((await lookupOne(s, { ...item, deadline: now() - 400 }, now)).value).toEqual({ status: 'expired' })
  })
  test('bearer two-step: without the secret first; with it only after UNAUTHORIZED', async () => {
    const t = newCashTarget()
    const w = bank.mintToCash(3000n, t.secret)
    const { c, s, requestId, deadline } = await transferLostReply(bySecret(t.secret), w)
    const o = await lookupOne(s, { bill: c.bill, by: { requestId }, deadline, authorizer: { kind: 'bearer', cashSecret: t.secret, stage: 'without' } }, now)
    expect(o.value?.status).toBe('done')
    const looks = bank.hub.requests.filter((r) => r.item.method === 'cash_lookup')
    expect(looks.map((r) => r.params['cash_secret'] !== undefined)).toEqual([false, true])
    expect(looks[1]!.params['cash_secret']).toBe(t.secret)
  })
  test('a bearer lookup with no record is answered by deadline without the secret', async () => {
    const t = newCashTarget()
    const w = bank.mintToCash(3000n, t.secret)
    const c = new CashClient(deps(), w.token)
    const s = await c.session()
    const o = await lookupOne(s, { bill: c.bill, by: { requestId: newRequestId() }, deadline: now() - 5, authorizer: { kind: 'bearer', cashSecret: t.secret, stage: 'without' } }, now)
    expect(o.value).toEqual({ status: 'unknown' })
    expect(bank.hub.requests.filter((r) => r.item.method === 'cash_lookup')).toHaveLength(1)
  })
  test('a lookup answered REQUEST_REUSED is routed as unanswered, never unknown', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    const c = new CashClient(deps(), w.token)
    const s = await c.session()
    bank.override = (m) => (m === 'cash_lookup' ? { error: { code: 'REQUEST_REUSED', message: 'x' } } : undefined)
    const r = await lookupMany(s, [{ bill: c.bill, by: { requestId: newRequestId() }, deadline: now(), authorizer: { kind: 'signer', signer: alice } }], now)
    expect(r.outcomes[0]!.state).toBe('unanswered')
  })
  test('an omitted lookup is not served, never unknown', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    const c = new CashClient(deps(), w.token)
    const s = await c.session()
    bank.override = (m) => (m === 'cash_lookup' ? 'omit' : undefined)
    const r = await lookupMany(s, [{ bill: c.bill, by: { requestId: newRequestId() }, deadline: now(), authorizer: { kind: 'signer', signer: alice } }], now)
    expect(r.outcomes[0]!.state).toBe('not_served')
  })
})

describe('T-408 / T-1205 the Cash Hub client', () => {
  test('a cashhub1 decodes and verifies; get_info passes the online check; node() is TLV 4', async () => {
    const hub = new CashHubClient(deps(), bank.openCashHub())
    expect(hub.verdict).toEqual({ verified: true })
    await hub.getInfo()
    expect(hub.node()).toBe(bank.hub.node)
    expect(hub.view()).toMatchObject({ kind: 'cashhub', verified: true, online: 'pass', network: 'mainnet', testNetwork: false, chain: 'bitcoin', label: 'Fake Cash Hub' })
    expect(hub.view().hubFingerprint.split(' ')).toHaveLength(16)
  })
  test.each<[string, Partial<FakeBank['cashHubInfo']>]>([
    ['another identity', { pubkey: toHex(fill(0x55, 32)) }],
    ['another chain', { chain: 'bitcoin-x' }],
    ['no chain', { chain: null }],
  ])('get_info with %s fails connection_mismatch', async (_, info) => {
    const hub = new CashHubClient(deps(), bank.openCashHub())
    bank.cashHubInfo = info
    await expect(hub.getInfo()).rejects.toMatchObject({ code: 'connection_mismatch' })
    expect(hub.view().online).toBe('fail')
  })
  test('a compressed pubkey in get_info passes', async () => {
    const hub = new CashHubClient(deps(), bank.openCashHub())
    bank.cashHubInfo = { pubkey: `02${bank.hub.node}` }
    await expect(hub.getInfo()).resolves.toBeDefined()
  })
  test('a test network is flagged, never blocked', async () => {
    const hub = new CashHubClient(deps(), bank.openCashHub())
    bank.cashHubInfo = { network: 'regtest' }
    await hub.getInfo()
    expect(hub.view()).toMatchObject({ network: 'regtest', testNetwork: true })
  })
  test('a URI, a token or a malformed string is refused before anything is dialled (T-1209)', () => {
    const before = pool.published.length
    for (const bad of ['nostr+walletconnect://abc?relay=wss://r&secret=x', bank.mintToPubkey(1n, alice.pubkey).token, 'cashhub1qqqq']) {
      expect(() => new CashHubClient(deps(), bad)).toThrow(expect.objectContaining({ code: 'connection_invalid' }))
    }
    expect(pool.published.length).toBe(before)
  })
  test('mint sends request_id and an expiration within H, and returns the bill', async () => {
    const hub = new CashHubClient(deps(), bank.openCashHub())
    const requestId = newRequestId()
    const seen: number[] = []
    const r = await hub.mint([{ identityType: 'pubkey', identityValue: alice.pubkey, amountMillis: 21000n }], { requestId, beforePublish: async ({ deadline }) => void seen.push(deadline) })
    expect(bank.wallet(r.cashToken)?.amount).toBe(21000n)
    const ev = pool.published.filter((p) => p.event.kind === 23194).at(-1)!.event
    expect(ev.tags.find((t) => t[0] === 'expiration')?.[1]).toBe(String(seen[0]))
    expect(seen[0]! - now()).toBeLessThanOrEqual(61)
  })
  test('a lost mint reply is found by lookupMint, signed by the connection itself', async () => {
    const hub = new CashHubClient(deps(), bank.openCashHub())
    const requestId = newRequestId()
    let deadline = 0
    bank.loseMintReply = true
    await expect(
      hub.mint([{ identityType: 'pubkey', identityValue: alice.pubkey, amountMillis: 7000n }], { requestId, beforePublish: async (x) => void (deadline = x.deadline) }),
    ).rejects.toBeInstanceOf(ClientError)
    bank.loseMintReply = false
    const o = await hub.lookupMint(requestId, deadline)
    expect(o.value).toMatchObject({ status: 'done', result: { cash_token: expect.stringMatching(/^lokicash1/) } })
  }, 20_000)
  test('a hub with no usable max_request_age takes no mint', async () => {
    bank.hub.maxRequestAge = undefined
    await bank.hub.announce({ relays: [R1], createdAt: now() + 1 })
    const hub = new CashHubClient(deps(), bank.openCashHub())
    await expect(hub.mint([{ identityType: 'pubkey', identityValue: alice.pubkey, amountMillis: 1n }], { requestId: newRequestId() })).rejects.toMatchObject({ code: 'hub_unusable' })
    expect(pool.published.filter((p) => p.event.kind === 23194 && p.event.tags.some((t) => t[0] === 'expiration'))).toHaveLength(0)
  })
  test('an unverified string needs the online check, then a confirmation', async () => {
    const good = bank.openCashHub()
    const { decodeCashHubConnection, encodeCashHubConnection } = await import('../src/core/index.js')
    const c = decodeCashHubConnection(good)
    const tampered = encodeCashHubConnection({ ...c, label: 'Not Alice', labelBytes: new TextEncoder().encode('Not Alice') })
    const refused = new CashHubClient(deps(), tampered)
    expect(refused.verdict).toEqual({ verified: false, reason: 'signer_mismatch' })
    await expect(refused.ensureUsable()).rejects.toMatchObject({ code: 'connection_unverified' })
    let asked = 0
    const confirmed = new CashHubClient(deps(), tampered, { confirmUnverified: async (v) => (asked++, v.online === 'pass' && !v.verified) })
    await confirmed.ensureUsable()
    await confirmed.ensureUsable()
    expect(asked).toBe(1)
  })
})
