// NIP-CW, the member's side: the join request and proof, its details, the
// Hub's terms, budget periods, member requests, the join item on the private
// transport, and connecting through a circlehub1. Cases follow nmilat
// nipcw/{terms,join_proof,create_circle_wallet,budget_period,member_request,
// private_join}_test.go and nipcw/client/client_test.go.
import { beforeEach, describe, expect, test } from 'vitest'
import {
  budgetPeriodStart,
  buildMemberRequest,
  connectionKeyFromSecret,
  CoreError,
  createCircleWalletRequest,
  preparedJoinUsed,
  currentPeriod,
  getPublicKey,
  KIND_CIRCLE_IDENTITY_PROOF,
  localSigner,
  maxPaymentCost,
  nip44,
  parseCircleWalletInfo,
  parseCreateCircleWalletResult,
  renewalAtLeast,
  termsTag,
  toHex,
  validateJoinTerms,
  verifyEvent,
  type NostrEvent,
} from '../src/core/index.js'
import { billFromParts, CircleWalletClient, connectCircle, createCircleWalletItem, createCircleWalletMany, openBatchSession } from '../src/client/index.js'
import { newNonce, paramsHash, verifyBillProof, verifyItemProof } from '../src/transport/index.js'
import { FakeBank } from './fakeBank.js'
import { FakeCircle } from './fakeCircle.js'
import { FakeHub, MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const R1 = 'wss://r1.test'
const now = () => Math.floor(Date.now() / 1000)
const priv = (n: number) => {
  const k = new Uint8Array(32)
  k[31] = n
  return k
}
const member = localSigner(fill(0x24, 32))
const hubKey = fill(0x26, 32)
const HUB = getPublicKey(hubKey)
const hubSecret = fill(0x27, 32)
const hubConn = () => billFromParts(HUB, toHex(hubSecret))
const key = (b: number) => connectionKeyFromSecret(toHex(fill(b, 32)))
/** Details sealed as the Hub does: from its connection key to the member. */
const seal = (d: Record<string, unknown>, from = hubKey) => ({ encrypted_details: nip44.encrypt(JSON.stringify(d), nip44.getConversationKey(from, member.pubkey)) })
const at = (s: string) => Math.floor(Date.parse(s) / 1000)
const terms = { maxAmount: 100000n, maxReceive: 200000n, budgetRenewal: 'monthly' as const }

describe('terms and the join proof (terms_test.go, join_proof_test.go)', () => {
  test('the terms tag: unsigned decimals, an omitted expiry as 0 and renewal as never', () => {
    expect(termsTag(terms)).toBe('100000:200000:0:monthly')
    expect(termsTag({ maxAmount: 0n, maxReceive: 0n })).toBe('0:0:0:never')
    expect(() => termsTag({ maxAmount: 1n << 63n, maxReceive: 0n })).toThrow(CoreError)
    expect(() => termsTag({ maxAmount: 1n, maxReceive: 1n, budgetRenewal: 'Monthly' as never })).toThrow(CoreError)
  })
  test('the spec example: keys 1 (member), 3 (Hub) and 2 (connection) give the published event id', async () => {
    const signer = localSigner(priv(1))
    const j = await createCircleWalletRequest({ signer, connectionPubkey: getPublicKey(priv(2)), hubPubkey: getPublicKey(priv(3)), terms, now: 1720000000 })
    expect(j.proofId).toBe('f796fb3c192db23c1ea2636c580408c6e574e290c6193e7694d170abedbc65b8')
    expect(j.deadline).toBe(1720000300)
    const proof = JSON.parse(j.request.identity_event) as NostrEvent
    expect(verifyEvent(proof)).toBe(true)
    expect(proof.tags).toEqual([['d', getPublicKey(priv(3))], ['connection', getPublicKey(priv(2))], ['terms', '100000:200000:0:monthly']])
    expect(j.request).toMatchObject({ pubkey: signer.pubkey, max_amount: 100000n, max_receive: 200000n, expiry: 0, budget_renewal: 'monthly' })
    expect(proof.tags.some((t) => t[0] === 'action')).toBe(false)
  })
  test('refuses a missing connection key or one equal to the member key', async () => {
    await expect(createCircleWalletRequest({ signer: member, connectionPubkey: '', hubPubkey: HUB, terms, now: 1 })).rejects.toThrow(CoreError)
    await expect(createCircleWalletRequest({ signer: member, connectionPubkey: member.pubkey, hubPubkey: HUB, terms, now: 1 })).rejects.toThrow(/differ/)
  })
  test('renewal floors', () => {
    expect(renewalAtLeast('monthly', 'monthly')).toBe(true)
    expect(renewalAtLeast(undefined, 'yearly')).toBe(true)
    expect(renewalAtLeast('weekly', 'monthly')).toBe(false)
  })
})

describe('join details (create_circle_wallet_test.go)', () => {
  const conn = key(0x31)
  const full = { wallet_pubkey: '9a'.repeat(32), connection_pubkey: conn.pubkey, relays: [' ', 'wss://w'], max_amount: 5, max_receive: 7, expires_at: 9, fees_ppm: 2500, dust_threshold_millis: 1000, rotation_delay_secs: 432000, budget_renewal: 'weekly' }
  test('decrypts from the Hub connection key and reads every term; no URI is built', async () => {
    const d = await parseCreateCircleWalletResult(seal(full), { signer: member, hubPubkey: HUB, connectionPubkey: conn.pubkey, requested: { maxAmount: 5n, maxReceive: 7n } })
    expect(d).toEqual({
      walletPubkey: '9a'.repeat(32),
      connectionPubkey: conn.pubkey,
      relays: ['wss://w'],
      maxAmount: 5n,
      maxReceive: 7n,
      expiresAt: 9,
      feesPpm: 2500,
      dustThresholdMillis: 1000n,
      rotationDelaySecs: 432000,
      budgetRenewal: 'weekly',
      missingTerms: [],
      leakedFields: [],
      capsRaised: false,
    })
  })
  test('another connection_pubkey (an old reply) is refused; missing terms, leaks and raised caps are reported', async () => {
    await expect(parseCreateCircleWalletResult(seal({ ...full, connection_pubkey: key(0x32).pubkey }), { signer: member, hubPubkey: HUB, connectionPubkey: conn.pubkey })).rejects.toThrow(/connection_pubkey/)
    const { fees_ppm: _f, ...noFees } = full
    const d = await parseCreateCircleWalletResult({ ...seal({ ...noFees, secret: 'x' }), uri: 'y' }, { signer: member, hubPubkey: HUB, connectionPubkey: conn.pubkey, requested: { maxAmount: 1n, maxReceive: 7n } })
    expect(d).toMatchObject({ missingTerms: ['fees_ppm'], leakedFields: ['secret', 'uri'], capsRaised: true })
  })
  test.each([
    ['the inbox key', fill(8, 32)],
    ['the member’s own key', fill(0x24, 32)],
  ] as const)('details sealed by %s do not decrypt', async (_, from) => {
    await expect(parseCreateCircleWalletResult(seal(full, from), { signer: member, hubPubkey: HUB, connectionPubkey: conn.pubkey })).rejects.toThrow(/decrypt/)
  })
})

describe('get_info circle_wallet', () => {
  const ID = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  test('decodes every field; a missing accepting reads as false; a compressed identity in x-only form', () => {
    const block = { available_millis: 1000, max_exp_secs: 60, fees_ppm: 5, fee_reserve: { ppm: 5000, min_millis: 10000 }, dust_threshold_millis: 1000, circle_policy: 'allowlist', identity: `02${ID}`, rotation_delay_secs: 432000, per_wallet_max_millis: 500, per_wallet_max_receive_millis: 600, min_budget_renewal: 'monthly', accepting: true }
    expect(parseCircleWalletInfo({ circle_wallet: block })).toEqual({
      available_millis: 1000n,
      max_exp_secs: 60,
      fees_ppm: 5,
      fee_reserve: { ppm: 5000, min_millis: 10000n },
      dust_threshold_millis: 1000n,
      circle_policy: 'allowlist',
      identity: ID,
      rotation_delay_secs: 432000,
      per_wallet_max_millis: 500n,
      per_wallet_max_receive_millis: 600n,
      min_budget_renewal: 'monthly',
      accepting: true,
    })
    expect(parseCircleWalletInfo({ circle_wallet: { identity: ID } })?.accepting).toBe(false)
    expect(parseCircleWalletInfo({ alias: 'x' })).toBeUndefined()
    expect(() => parseCircleWalletInfo({ circle_wallet: { identity: 7 } })).toThrow(CoreError)
  })
  test('validateJoinTerms names the field over a limit', () => {
    const info = parseCircleWalletInfo({ circle_wallet: { per_wallet_max_millis: 100, per_wallet_max_receive_millis: 100, min_budget_renewal: 'monthly', max_exp_secs: 60, accepting: true } })!
    expect(validateJoinTerms(info, { maxAmount: 101n, maxReceive: 1n })).toBe('max_amount')
    expect(validateJoinTerms(info, { maxAmount: 1n, maxReceive: 101n })).toBe('max_receive')
    expect(validateJoinTerms(info, { maxAmount: 1n, maxReceive: 1n, budgetRenewal: 'daily' })).toBe('budget_renewal')
    expect(validateJoinTerms(info, { maxAmount: 1n, maxReceive: 1n, expiry: 61 })).toBe('expiry')
    expect(validateJoinTerms(info, { maxAmount: 1n, maxReceive: 1n })).toBeUndefined()
  })
})

describe('budget periods (budget_period_test.go)', () => {
  test('monthly periods stay anchored to the creation day, clamped to the month’s end', () => {
    const c = at('2024-01-31T10:00:00Z')
    expect([1, 2, 3].map((k) => new Date(budgetPeriodStart(c, 'monthly', k)! * 1000).toISOString())).toEqual(['2024-02-29T10:00:00.000Z', '2024-03-31T10:00:00.000Z', '2024-04-30T10:00:00.000Z'])
  })
  test('yearly from Feb 29', () => {
    const c = at('2024-02-29T00:00:00Z')
    expect([1, 2, 3, 4].map((k) => new Date(budgetPeriodStart(c, 'yearly', k)! * 1000).toISOString().slice(0, 10))).toEqual(['2025-02-28', '2026-02-28', '2027-02-28', '2028-02-29'])
  })
  test('the current period: start inclusive, next start exclusive; never is one period', () => {
    const c = at('2024-01-31T10:00:00Z')
    expect(currentPeriod(c, 'monthly', at('2024-02-29T10:00:00Z'))).toEqual({ start: at('2024-02-29T10:00:00Z'), end: at('2024-03-31T10:00:00Z') })
    expect(currentPeriod(c, 'monthly', at('2024-02-29T09:59:59Z'))).toEqual({ start: c, end: at('2024-02-29T10:00:00Z') })
    expect(currentPeriod(c, 'daily', c + 86400 * 3 + 5)).toEqual({ start: c + 86400 * 3, end: c + 86400 * 4 })
    expect(currentPeriod(c, 'never', c + 1e8)).toEqual({ start: c })
  })
})

describe('member requests and the payment preview (member_request_test.go, fees_test.go)', () => {
  test('a rotate names the new key; freeze and unfreeze name none; never terms', async () => {
    const e = await buildMemberRequest(member, { hubPubkey: HUB, action: 'rotate', walletPubkey: '9a'.repeat(32), newConnectionPubkey: key(0x33).pubkey, now: 5 })
    expect(e.kind).toBe(KIND_CIRCLE_IDENTITY_PROOF)
    expect(e.tags).toEqual([['d', HUB], ['action', 'rotate'], ['wallet', '9a'.repeat(32)], ['connection', key(0x33).pubkey]])
    expect((await buildMemberRequest(member, { hubPubkey: HUB, action: 'freeze', walletPubkey: '9a'.repeat(32), now: 5 })).tags).toEqual([['d', HUB], ['action', 'freeze'], ['wallet', '9a'.repeat(32)]])
    await expect(buildMemberRequest(member, { hubPubkey: HUB, action: 'freeze', walletPubkey: '9a'.repeat(32), newConnectionPubkey: key(0x33).pubkey, now: 5 })).rejects.toThrow(CoreError)
  })
  test('the worst case of a Lightning payment, rounded down; advisory against balance and send room', () => {
    expect(maxPaymentCost(1_000_000n, 1000, { ppm: 5000, min_millis: 10000n })).toBe(1_000_000n + 1000n + 10000n)
    expect(maxPaymentCost(999n, 1000, { ppm: 5000, min_millis: 0n })).toBe(999n + 0n + 4n)
    const p = CircleWalletClient.previewPayment(1000n, { feesPpm: 0, feeReserve: { ppm: 0, min_millis: 100n }, balance: 1050n, active: true, budget: { totalBudget: 2000n, usedBudget: 1000n, totalReceiveBudget: 0n, usedReceiveBudget: 0n } })
    expect(p).toEqual({ maxCost: 1100n, withinBalance: false, withinSendRoom: false })
  })
})

describe('the join item (private_join_test.go)', () => {
  const node = getPublicKey(fill(0x28, 32))
  const binding = { hub: node, nonce: newNonce(), notAfter: now() + 60 }
  test('targets the Hub; the item proof is the requester’s, the bill proof the Hub connection secret’s', async () => {
    const j = await createCircleWalletRequest({ signer: member, connectionPubkey: key(0x31).pubkey, hubPubkey: HUB, terms, now: now() })
    const item = await createCircleWalletItem('join', hubConn(), member, j, binding, now())
    expect([item.target, item.method]).toEqual([HUB, 'create_circle_wallet'])
    const want = { target: HUB, hub: node, method: 'create_circle_wallet', paramsHash: paramsHash(item.params!), nonce: binding.nonce, notAfter: binding.notAfter }
    expect(verifyItemProof(item.proof!, want, now())).toBe(member.pubkey)
    expect(verifyBillProof(item.billProof!, want, now())).toBe(getPublicKey(hubSecret))
  })
  test('a prepared join builds one item only', async () => {
    const j = await createCircleWalletRequest({ signer: member, connectionPubkey: key(0x31).pubkey, hubPubkey: HUB, terms, now: now() })
    expect(preparedJoinUsed(j)).toBe(false)
    await createCircleWalletItem('join', hubConn(), member, j, binding, now())
    expect(preparedJoinUsed(j)).toBe(true)
    await expect(createCircleWalletItem('again', hubConn(), member, j, binding, now())).rejects.toThrow(/already used/)
  })
  test('details sealed by the inbox key are undecodable', async () => {
    const pool = new MemoryRelayPool()
    const hub = new FakeHub(pool, [R1])
    hub.bills.set(HUB, getPublicKey(hubSecret))
    await hub.start()
    const conn = key(0x31)
    hub.handler = () => ({ result: { encrypted_details: nip44.encrypt(JSON.stringify({ wallet_pubkey: 'ab'.repeat(32), connection_pubkey: conn.pubkey, relays: ['wss://w'] }), nip44.getConversationKey(hub.inboxKey, member.pubkey)) } })
    const s = await openBatchSession({ relays: pool }, hub.node, [R1])
    const j = await createCircleWalletRequest({ signer: member, connectionPubkey: conn.pubkey, hubPubkey: HUB, terms, now: now() })
    const r = await createCircleWalletMany(s, [{ hub: hubConn(), signer: member, join: j }], now)
    expect(r.outcomes[0]).toMatchObject({ state: 'error', undecodable: true })
  })
})

describe('connectCircle (nipcw/client/client_test.go)', () => {
  let pool: MemoryRelayPool
  let bank: FakeBank
  let circle: FakeCircle
  beforeEach(async () => {
    pool = new MemoryRelayPool()
    bank = new FakeBank(pool, [R1])
    await bank.start()
    circle = new FakeCircle(bank)
  })
  const deps = () => ({ relays: pool, replyWaitMs: 1500, nwcTimeoutMs: 1500 })
  test('decodes, verifies, checks get_info and opens the private transport', async () => {
    const c = await connectCircle(deps(), circle.string)
    expect(c.connection.walletPubkey).toBe(circle.hubPubkey)
    expect(c.circle).toMatchObject({ identity: bank.hub.node, accepting: true })
    expect(c.session.hub).toBe(bank.hub.node)
  })
  test('a URI or another string is connection_invalid; nothing is dialled', async () => {
    await expect(connectCircle(deps(), 'nostr+walletconnect://ab?relay=wss://x&secret=cd')).rejects.toMatchObject({ code: 'connection_invalid' })
  })
  test('a get_info naming another identity is connection_mismatch', async () => {
    circle.infoIdentity = getPublicKey(fill(0x55, 32))
    await expect(connectCircle(deps(), circle.string)).rejects.toMatchObject({ code: 'connection_mismatch' })
  })
  test('a closed circle refuses joins but still serves lookups', async () => {
    circle.accepting = false
    await expect(connectCircle(deps(), circle.string)).rejects.toMatchObject({ code: 'not_accepting' })
    await expect(connectCircle(deps(), circle.string, { purpose: 'lookup' })).resolves.toBeDefined()
  })
  test('no verified announcement: join_unavailable, nothing sent', async () => {
    const other = new MemoryRelayPool()
    const b2 = new FakeBank(other, [R1])
    const c2 = new FakeCircle(b2)
    // the Hub answers get_info, but its node never announced
    await expect(connectCircle({ relays: other, replyWaitMs: 500, nwcTimeoutMs: 1500 }, c2.string)).rejects.toMatchObject({ code: 'join_unavailable' })
    expect(other.published.filter((x) => x.event.kind === 23190)).toHaveLength(0)
  })
})
