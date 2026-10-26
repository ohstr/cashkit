// Circle joins over the private transport. Cases follow nmilat
// nipcw/private_join_test.go and nipcash/client/batch_circle_join_test.go.
import { beforeEach, describe, expect, test } from 'vitest'
import {
  connectionKeyFromSecret,
  CoreError,
  getPublicKey,
  KIND_CIRCLE_IDENTITY_PROOF,
  localSigner,
  nip44,
  toHex,
  verifyEvent,
  type NostrEvent,
} from '../src/core/index.js'
import {
  billFromParts,
  CircleClient,
  ClientError,
  fallbackReasonOf,
  createCircleWalletItem,
  createCircleWalletMany,
  openBatchSession,
  PrivateJoinUnavailableError,
  WalletError,
} from '../src/client/index.js'
import { newNonce, paramsHash, validateEnvelope, verifyBillProof, verifyItemProof } from '../src/transport/index.js'
import { FakeHub, MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'
import { FakeNwcWallet } from './walletHarness.js'

const R1 = 'wss://r1.test'
const now = () => Math.floor(Date.now() / 1000)
const member = localSigner(fill(0x24, 32))
const stranger = localSigner(fill(0x25, 32))
const hubKey = fill(0x26, 32)
const HUB = getPublicKey(hubKey)
const hubSecret = fill(0x27, 32)
const hubConn = () => billFromParts(HUB, toHex(hubSecret))
const key = (b: number) => connectionKeyFromSecret(toHex(fill(b, 32)))
const joinDetails = (w: string) => JSON.stringify({ wallet_pubkey: w.repeat(32), relays: ['wss://w'], expires_at: 1, fees_ppm: 0, budget_renewal: 'never' })
/** Details as the Hub seals them: from its connection key. */
const sealed = (w: string, to: string) => ({ encrypted_details: nip44.encrypt(joinDetails(w), nip44.getConversationKey(hubKey, to)) })
const params = (signer = member, connection = key(0x31)) => ({ signer, connection, maxAmountMillis: 1000n, expirySeconds: 0 })

describe('createCircleWalletItem (private_join_test.go)', () => {
  const node = getPublicKey(fill(0x28, 32))
  const binding = { hub: node, nonce: newNonce(), notAfter: now() + 60 }

  // TestCreateCircleWalletParams_Item.
  test('targets the Hub; the item proof is the requester’s, the bill proof the Hub connection secret’s', async () => {
    const item = await createCircleWalletItem('join', hubConn(), params(), binding, now())
    expect([item.target, item.method]).toEqual([HUB, 'create_circle_wallet'])
    const req = JSON.parse(item.params!) as Record<string, unknown>
    expect(req['pubkey']).toBe(member.pubkey)
    const identity = JSON.parse(req['identity_event'] as string) as NostrEvent
    expect(verifyEvent(identity)).toBe(true)
    expect(identity.kind).toBe(KIND_CIRCLE_IDENTITY_PROOF)
    expect(identity.tags).toEqual([['d', HUB], ['connection', key(0x31).pubkey]])

    const want = { target: HUB, hub: node, method: 'create_circle_wallet', paramsHash: paramsHash(item.params!), nonce: binding.nonce, notAfter: binding.notAfter }
    expect(verifyItemProof(item.proof!, want, now())).toBe(member.pubkey)
    expect(verifyBillProof(item.billProof!, want, now())).toBe(getPublicKey(hubSecret))
    const tags = (JSON.parse(item.proof!) as NostrEvent).tags
    expect(tags.filter((t) => t[0] === 'd' || t[0] === 'h')).toEqual([['d', HUB], ['h', node]])
    expect(() => validateEnvelope({ notAfter: binding.notAfter, nonce: binding.nonce, replyTo: newNonce(), items: [item] }, node, now())).not.toThrow()
  })
  // TestCreateCircleWalletParams_Item_NeedsHubSecret.
  test('a join without the Hub connection secret has no bill proof and is refused', () => {
    expect(() => billFromParts(HUB, '')).toThrow(ClientError)
  })
  test('a join without a member connection key is refused', async () => {
    await expect(createCircleWalletItem('join', hubConn(), { signer: member, maxAmountMillis: 1n, expirySeconds: 0 }, binding, now())).rejects.toThrow(CoreError)
  })
})

describe('createCircleWalletMany (batch_circle_join_test.go)', () => {
  let pool: MemoryRelayPool
  let hub: FakeHub
  const details = `{"wallet_pubkey":"${'ab'.repeat(32)}","relays":["wss://w"],"expires_at":1,"fees_ppm":0,"budget_renewal":"never"}`
  const sealFrom = (from: Uint8Array, to: string) => ({ encrypted_details: nip44.encrypt(details, nip44.getConversationKey(from, to)) })

  beforeEach(async () => {
    pool = new MemoryRelayPool()
    hub = new FakeHub(pool, [R1])
    hub.bills.set(HUB, getPublicKey(hubSecret)) // the bill proof must come from the Hub connection secret
    await hub.start()
  })

  // TestCreateCircleWalletMany_EndToEnd: the Hub checks both proofs as
  // §Private Join says, admits one join and refuses the other.
  test('two joins in one envelope: one admitted and decrypted, one refused with its code', async () => {
    hub.handler = (_m, info) => {
      if (info.item.target !== HUB || info.signer !== info.params['pubkey']) return 'omit'
      if (info.params['pubkey'] !== member.pubkey) return { error: { code: 'RESTRICTED' } }
      return { result: sealFrom(hubKey, member.pubkey) }
    }
    const s = await openBatchSession({ relays: pool }, hub.node, [R1])
    const r = await createCircleWalletMany(s, [{ id: 'member', hub: hubConn(), params: params() }, { id: 'stranger', hub: hubConn(), params: params(stranger, key(0x32)) }], now)
    expect(r.error).toBeUndefined()
    expect(r.outcomes.map((o) => o.state)).toEqual(['result', 'error'])
    expect(r.outcomes[0]!.value?.walletPubkey).toBe('ab'.repeat(32))
    expect(r.outcomes[1]!.error?.code).toBe('RESTRICTED')
    expect(pool.published.filter((x) => x.event.kind === 23190)).toHaveLength(1)
  })
  test('details sealed by the inbox key, not the Hub connection key, are undecodable', async () => {
    hub.handler = () => ({ result: sealFrom(hub.inboxKey, member.pubkey) })
    const s = await openBatchSession({ relays: pool }, hub.node, [R1])
    const r = await createCircleWalletMany(s, [{ hub: hubConn(), params: params() }], now)
    expect(r.outcomes[0]).toMatchObject({ id: '#0', state: 'error', undecodable: true })
  })
  test('a join bound to another node than the session’s is refused before sending', async () => {
    const s = await openBatchSession({ relays: pool }, hub.node, [R1])
    const elsewhere = { ...hubConn(), node: getPublicKey(fill(0x29, 32)) }
    await expect(createCircleWalletMany(s, [{ hub: elsewhere, params: params() }], now)).rejects.toThrow(/another node/)
    expect(pool.published.filter((x) => x.event.kind === 23190)).toHaveLength(0)
  })
})

describe('CircleClient.join (nipcw/client/join_test.go)', () => {
  let pool: MemoryRelayPool
  let hub: FakeHub
  let nwc: FakeNwcWallet
  let circle: Record<string, unknown> | undefined
  const privateRequests = () => pool.published.filter((x) => x.event.kind === 23190).length
  const standardJoins = () => nwc.seen.filter((x) => x.method === 'create_circle_wallet').length
  const client = (o: { notAfterSeconds?: number } = {}) => new CircleClient({ relays: pool, ...o }, nwc.uri)

  beforeEach(async () => {
    pool = new MemoryRelayPool()
    hub = new FakeHub(pool, [R1])
    hub.bills.set(HUB, getPublicKey(hubSecret))
    hub.handler = (_m, info) => (info.signer === info.params['pubkey'] ? { result: sealed('aa', info.params['pubkey'] as string) } : 'omit')
    await hub.start()
    nwc = new FakeNwcWallet(pool, 0x26, R1) // its key is hubKey, its app secret hubSecret
    circle = { available_millis: 1000, max_exp_secs: 0, fees_ppm: 0, circle_policy: 'follow_set', identity: hub.node }
    nwc.handler = (method, p) => {
      if (method === 'get_info') return { result: circle === undefined ? { alias: 'plain' } : { circle_wallet: circle } }
      if (method === 'create_circle_wallet') return { result: sealed('bb', p['pubkey'] as string) }
      return { error: { code: 'NOT_IMPLEMENTED', message: method } }
    }
  })

  // TestJoin_NoIdentityUsesStandard.
  test.each([
    ['no circle_wallet block', undefined],
    ['a block without identity', { circle_policy: 'allowlist' }],
  ])('%s: the standard transport, with no fallbackReason', async (_, block) => {
    circle = block
    const r = await client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 })
    expect([r.private, r.fallbackReason, r.wallet.walletPubkey]).toEqual([false, undefined, 'bb'.repeat(32)])
    expect([privateRequests(), standardJoins()]).toEqual([0, 1])
  })
  // nmilat Join: a get_info error fails the join before anything is sent.
  test('a Hub that refuses get_info fails the join, and nothing is sent', async () => {
    nwc.handler = (method, p) => (method === 'create_circle_wallet' ? { result: sealed('bb', p['pubkey'] as string) } : { error: { code: 'NOT_IMPLEMENTED', message: method } })
    await expect(client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 })).rejects.toMatchObject({ walletCode: 'NOT_IMPLEMENTED' })
    expect([privateRequests(), standardJoins()]).toEqual([0, 0])
  })
  test('a get_info with no answer fails the join before anything is sent', async () => {
    nwc.handler = () => 'silent'
    await expect(new CircleClient({ relays: pool, nwcTimeoutMs: 50 }, nwc.uri).join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 })).rejects.toMatchObject({ code: 'timeout' })
    expect([privateRequests(), standardJoins()]).toEqual([0, 0])
  })
  // TestJoin_IdentityJoinsPrivately.
  test('an identity in get_info: the private transport, without asking', async () => {
    const r = await client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 })
    expect([r.private, r.fallbackReason, r.wallet.walletPubkey]).toEqual([true, undefined, 'aa'.repeat(32)])
    expect([privateRequests(), standardJoins()]).toEqual([1, 0])
    expect(r.wallet.pairingUri).toContain(r.connection.secret)
    // Proofs bound d = the Hub connection pubkey and h = get_info's identity.
    expect(hub.requests[0]).toMatchObject({ item: { target: HUB }, signer: member.pubkey, billSigner: getPublicKey(hubSecret) })
  })
  // TestJoin_NoAnnouncementFallsBackAndSaysSo.
  test.each([
    ['no announcement', () => void (circle!['identity'] = getPublicKey(fill(0x55, 32)))],
    ['an announcement that does not verify', () => {
      const id = getPublicKey(fill(0x55, 32))
      circle!['identity'] = id
      const ev = hub.announcementEvent({ relays: [R1], createdAt: now() })
      pool.store(R1, { ...ev, pubkey: id })
    }],
    ['an identity that is not x-only hex', () => void (circle!['identity'] = '02' + hub.node)],
  ])('%s: the standard transport, and a fallbackReason', async (_, setup) => {
    setup()
    const r = await client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 })
    expect(r.private).toBe(false)
    expect(r.fallbackReason).toBeInstanceOf(Error)
    expect([privateRequests(), standardJoins()]).toEqual([0, 1])
  })
  test('a private join that fails before sending falls back, and says so', async () => {
    // A signer that will not sign the kind-23192 item proof: the item is never packed.
    const picky = { ...member, signEvent: (t: Parameters<typeof member.signEvent>[0]) => (t.kind === 23192 ? Promise.reject(new Error('no')) : member.signEvent(t)) }
    const r = await client().join({ signer: picky, maxAmountMillis: 1n, expirySeconds: 0 })
    expect([r.private, r.fallbackReason?.message]).toEqual([false, 'no'])
    expect([privateRequests(), standardJoins()]).toEqual([0, 1])
  })
  // TestJoin_FailedFallbackKeepsReason: the standard refusal keeps its class and code, and carries the reason.
  test('a fallback that is refused surfaces the standard refusal with the fallback reason', async () => {
    circle!['identity'] = getPublicKey(fill(0x55, 32))
    nwc.handler = (method) => (method === 'get_info' ? { result: { circle_wallet: circle } } : { error: { code: 'RESTRICTED', message: 'not a member' } })
    const e = await client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 }).catch((x: unknown) => x)
    expect(e).toBeInstanceOf(WalletError)
    expect((e as WalletError).walletCode).toBe('RESTRICTED')
    expect(fallbackReasonOf(e)).toMatchObject({ code: 'no_announcement' })
  })
  test('a refusal with no fallback carries no fallback reason', async () => {
    delete circle!['identity']
    nwc.handler = (method) => (method === 'get_info' ? { result: { circle_wallet: circle } } : { error: { code: 'RESTRICTED', message: 'not a member' } })
    const e = await client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 }).catch((x: unknown) => x)
    expect(fallbackReasonOf(e)).toBeUndefined()
    expect(fallbackReasonOf(undefined)).toBeUndefined()
  })
  // TestJoin_RequirePrivateRefusesFallback.
  test.each([
    ['no identity', () => void delete circle!['identity']],
    ['no announcement', () => void (circle!['identity'] = getPublicKey(fill(0x55, 32)))],
  ])('requirePrivate with %s refuses and sends nothing', async (_, setup) => {
    setup()
    await expect(client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 }, { requirePrivate: true })).rejects.toBeInstanceOf(PrivateJoinUnavailableError)
    expect([privateRequests(), standardJoins()]).toEqual([0, 0])
  })
  test('requirePrivate refuses a private join that fails before sending', async () => {
    const picky = { ...member, signEvent: (t: Parameters<typeof member.signEvent>[0]) => (t.kind === 23192 ? Promise.reject(new Error('no')) : member.signEvent(t)) }
    await expect(client().join({ signer: picky, maxAmountMillis: 1n, expirySeconds: 0 }, { requirePrivate: true })).rejects.toMatchObject({ code: 'private_join_unavailable' })
    expect(standardJoins()).toBe(0)
  })
  // TestJoin_SentPrivateJoinNeverFallsBack.
  test.each(['NOT_READY', 'RESTRICTED', 'WALLET_EXISTS', 'RATE_LIMITED'])('a sent private join refused with %s keeps the code and never falls back', async (code) => {
    hub.handler = () => ({ error: { code, message: 'no' } })
    const e = await client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 }).catch((x: unknown) => x)
    expect(e).toBeInstanceOf(WalletError)
    expect((e as WalletError).walletCode).toBe(code)
    expect(standardJoins()).toBe(0)
  })
  test('a sent private join with no reply never falls back', async () => {
    hub.faults = { drop: true }
    await expect(client({ notAfterSeconds: 1 }).join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 })).rejects.toMatchObject({ code: 'timeout' })
    expect([privateRequests(), standardJoins()]).toEqual([1, 0])
  })
  test('a private reply sealed by the inbox key is undecodable, not a refusal, and never falls back', async () => {
    hub.handler = (_m, info) => ({ result: { encrypted_details: nip44.encrypt(joinDetails('aa'), nip44.getConversationKey(hub.inboxKey, info.params['pubkey'] as string)) } })
    await expect(client().join({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 })).rejects.toMatchObject({ code: 'undecodable_result' })
    expect(standardJoins()).toBe(0)
  })
  test('a retry over the same transport stays private', async () => {
    const c = client()
    const via = await c.chooseTransport()
    hub.handler = () => ({ error: { code: 'BAD_REQUEST', message: 'identity_event has already been used' } })
    await expect(c.createCircleWallet({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 }, via)).rejects.toBeInstanceOf(WalletError)
    circle!['identity'] = getPublicKey(fill(0x55, 32)) // even if the Hub stopped announcing
    hub.handler = (_m, info) => ({ result: sealed('aa', info.params['pubkey'] as string) })
    const r = await c.createCircleWallet({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 }, via)
    expect(r.private).toBe(true)
    expect(standardJoins()).toBe(0)
  })
})
