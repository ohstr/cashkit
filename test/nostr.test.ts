// Unit tests for NIP-19, NIP-47 and NIP-CW messages. Cases follow nmilat
// nip19/*_test.go, nip47/{pairing,events,events_response_fallback}_test.go and
// nipcw/{create_circle_wallet,connection_key_kat}_test.go.
import { describe, expect, test } from 'vitest'
import {
  buildPairingURI,
  CIRCLE_POLICY_ALLOWLIST,
  CIRCLE_POLICY_FOLLOW_SET,
  connectionKeyFromSecret,
  CoreError,
  createCircleWalletRequest,
  decodeNaddr,
  decodeNevent,
  decodeNprofile,
  decodeNpub,
  decodeNsec,
  encodeNaddr,
  encodeNevent,
  encodeNprofile,
  encodeNpub,
  encodeNsec,
  finalizeEvent,
  getPublicKey,
  KIND_CIRCLE_IDENTITY_PROOF,
  localSigner,
  nip44,
  nwcRequestEvent,
  parseCircleWalletInfo,
  parseCreateCircleWalletResult,
  parseInfoEvent,
  parsePairingURI,
  parseResponseEvent,
  verifyEvent,
  type NostrEvent,
} from '../src/core/index.js'
import { fill } from './helpers.js'

const PK = '7e'.repeat(32)

describe('nip19', () => {
  test('npub and nsec round-trip', () => {
    expect(decodeNpub(encodeNpub(PK))).toBe(PK)
    expect(decodeNsec(encodeNsec(PK))).toBe(PK)
  })
  test('the decoders refuse the other prefix', () => {
    expect(() => decodeNpub(encodeNsec(PK))).toThrow(CoreError)
    expect(() => decodeNsec(encodeNpub(PK))).toThrow(CoreError)
  })
  test('nprofile, nevent and naddr round-trip', () => {
    const profile = { pubkey: PK, relays: ['wss://r1', 'wss://r2'] }
    expect(decodeNprofile(encodeNprofile(profile))).toEqual(profile)
    const ev = { id: '1d'.repeat(32), relays: ['wss://r'], author: PK, kind: 30000 }
    expect(decodeNevent(encodeNevent(ev))).toEqual(ev)
    const bare = { id: '1d'.repeat(32), relays: [], author: '', kind: 0 }
    expect(decodeNevent(encodeNevent(bare))).toEqual(bare)
    const addr = { identifier: 'my-list', pubkey: PK, kind: 30000, relays: ['wss://r'] }
    expect(decodeNaddr(encodeNaddr(addr))).toEqual(addr)
  })
  test('encoders refuse a wrong-length key and a value over 255 bytes', () => {
    expect(() => encodeNprofile({ pubkey: PK.slice(2), relays: [] })).toThrow(CoreError)
    expect(() => encodeNprofile({ pubkey: PK, relays: ['r'.repeat(256)] })).toThrow(CoreError)
    expect(() => encodeNevent({ id: '1d'.repeat(32), relays: [], author: 'ab', kind: 0 })).toThrow(CoreError)
  })
})

describe('nip47 pairing (pairing_test.go)', () => {
  const wallet = 'ab'.repeat(32)
  test('build and parse round-trip, extra parameters kept', () => {
    const uri = buildPairingURI(wallet, ['wss://r1.example', 'wss://r2.example'], 's'.repeat(64), { lud16: ['a@b.example'] })
    expect(uri).toBe(`nostr+walletconnect://${wallet}?lud16=a%40b.example&relay=wss%3A%2F%2Fr1.example&relay=wss%3A%2F%2Fr2.example&secret=${'s'.repeat(64)}`)
    expect(parsePairingURI(uri)).toEqual({ walletPubkey: wallet, relays: ['wss://r1.example', 'wss://r2.example'], secret: 's'.repeat(64), extra: { lud16: ['a@b.example'] } })
  })
  test('the connection key KAT pairing URI (TestParseResult_ConnectionStringKnownAnswer)', () => {
    const secret = '11'.repeat(32)
    expect(buildPairingURI(wallet, ['wss://r1.example', 'wss://r2.example'], secret)).toBe(
      `nostr+walletconnect://${wallet}?relay=wss%3A%2F%2Fr1.example&relay=wss%3A%2F%2Fr2.example&secret=${secret}`,
    )
  })
  test('escapes like Go: space as +, unreserved kept, UTF-8 percent-encoded', () => {
    expect(buildPairingURI(wallet, [], 'a b~c.d-e_f/é')).toBe(`nostr+walletconnect://${wallet}?secret=a+b~c.d-e_f%2F%C3%A9`)
  })
  test.each([
    ['missing relay', `nostr+walletconnect://${wallet}?secret=s`],
    ['missing secret', `nostr+walletconnect://${wallet}?relay=wss://r`],
    ['wrong scheme', `https://${wallet}?relay=wss://r&secret=s`],
    ['short pubkey', `nostr+walletconnect://${wallet.slice(2)}?relay=wss://r&secret=s`],
    ['a port', `nostr+walletconnect://${wallet}:1?relay=wss://r&secret=s`],
    ['a control character', `nostr+walletconnect://${wallet}?relay=wss://r&secret=s\n`],
  ])('parse refuses %s', (_, uri) => {
    expect(() => parsePairingURI(uri)).toThrow(CoreError)
  })
})

describe('nip47 events (events_test.go)', () => {
  const app = fill(4, 32)
  const walletKey = fill(5, 32)
  const walletPub = getPublicKey(walletKey)
  const appPub = getPublicKey(app)

  test('a request is encrypted to the wallet and tagged nip44_v2', () => {
    const unsigned = nwcRequestEvent({ connectionSecret: app, walletPubkey: walletPub, method: 'pay_invoice', params: { invoice: 'lnfc1x' }, createdAt: 1 })
    const ev = finalizeEvent(unsigned, app)
    expect(verifyEvent(ev)).toBe(true)
    expect(ev.pubkey).toBe(appPub)
    expect(ev.tags).toEqual([['p', walletPub], ['encryption', 'nip44_v2']])
    expect(JSON.parse(nip44.decrypt(ev.content, nip44.getConversationKey(walletKey, appPub)))).toEqual({ method: 'pay_invoice', params: { invoice: 'lnfc1x' } })
  })
  test('a request without params has no params key', () => {
    const ev = nwcRequestEvent({ connectionSecret: app, walletPubkey: walletPub, method: 'get_info', createdAt: 1 })
    expect(nip44.decrypt(ev.content, nip44.getConversationKey(walletKey, appPub))).toBe('{"method":"get_info"}')
  })

  function response(body: string, tags: string[][]): NostrEvent {
    const content = nip44.encrypt(body, nip44.getConversationKey(walletKey, appPub))
    return finalizeEvent({ kind: 23195, created_at: 1, tags, content }, walletKey)
  }
  test('parses a result and an error', () => {
    expect(parseResponseEvent(response('{"result_type":"get_balance","result":{"balance":21000}}', [['p', appPub], ['e', 'r1']]), app)).toEqual({
      resultType: 'get_balance',
      result: { balance: 21000 },
      requestEventId: 'r1',
      subPaymentId: '',
    })
    expect(parseResponseEvent(response('{"result_type":"pay_invoice","error":{"code":"RESTRICTED","message":"no"}}', [['e', 'r1']]), app).error).toEqual({ code: 'RESTRICTED', message: 'no' })
  })
  test('an untagged response uses the fallback encryption (events_response_fallback_test.go)', () => {
    const ev = response('{"result_type":"get_info","result":{}}', [['e', 'r1']])
    expect(parseResponseEvent(ev, app, 'nip44_v2').resultType).toBe('get_info')
    // nip04 is read too (design §2.3): a nip44 body under it simply fails to decrypt.
    expect(() => parseResponseEvent(ev, app, 'nip04')).toThrow(/decrypt/)
    expect(() => parseResponseEvent(ev, app, 'nip99')).toThrow(/unsupported/)
  })
  test.each<[string, NostrEvent | (() => NostrEvent)]>([
    ['no e tag', () => response('{}', [['p', appPub]])],
    ['an e tag with no value', () => response('{}', [['e']])],
    ['two e tags', () => response('{}', [['e', 'a'], ['e', 'b']])],
    ['two d tags', () => response('{}', [['e', 'a'], ['d', '1'], ['d', '2']])],
    ['a non-JSON body', () => response('nope', [['e', 'a']])],
    ['a non-string result_type', () => response('{"result_type":1}', [['e', 'a']])],
  ])('refuses a response with %s', (_, make) => {
    expect(() => parseResponseEvent(typeof make === 'function' ? make() : make, app)).toThrow(CoreError)
  })
  const info = (tags: string[][], content: string) => parseInfoEvent(finalizeEvent({ kind: 13194, created_at: 1, tags, content }, walletKey))
  test('the info event: methods, encryption, and the nip04 default', () => {
    expect(info([['encryption', 'nip44_v2 nip04']], 'get_info  pay_invoice')).toEqual({ methods: ['get_info', 'pay_invoice'], notificationTypes: [], supportedEncryptions: ['nip44_v2', 'nip04'] })
    expect(info([], '').supportedEncryptions).toEqual(['nip04'])
  })
})

describe('nipcw create_circle_wallet (create_circle_wallet_test.go)', () => {
  const memberKey = fill(2, 32)
  const signer = localSigner(memberKey)
  const hubKey = fill(6, 32)
  const hub = getPublicKey(hubKey)
  const conn = connectionKeyFromSecret('11'.repeat(32))

  test('the request carries a proof binding the Hub and the connection key', async () => {
    const req = await createCircleWalletRequest({ signer, connection: conn, hubPubkey: hub, maxAmountMillis: 100000n, expirySeconds: 60, budgetRenewal: 'monthly', now: 5 })
    const proof = JSON.parse(req.identity_event) as NostrEvent
    expect(verifyEvent(proof)).toBe(true)
    expect(proof.kind).toBe(KIND_CIRCLE_IDENTITY_PROOF)
    expect(proof.tags).toEqual([['d', hub], ['connection', conn.pubkey]])
    expect(req).toMatchObject({ pubkey: signer.pubkey, connection_pubkey: conn.pubkey, max_amount: 100000n, expiry: 60, budget_renewal: 'monthly' })
  })
  test('refuses a missing connection key, one equal to the member key, and a bad expiry', async () => {
    await expect(createCircleWalletRequest({ signer, connection: undefined, hubPubkey: hub, maxAmountMillis: 1n, expirySeconds: 0 })).rejects.toThrow(CoreError)
    await expect(createCircleWalletRequest({ signer, connection: connectionKeyFromSecret('02'.repeat(32)), hubPubkey: hub, maxAmountMillis: 1n, expirySeconds: 0 })).rejects.toThrow(/differ/)
    await expect(createCircleWalletRequest({ signer, connection: conn, hubPubkey: hub, maxAmountMillis: 1n, expirySeconds: 1.5 })).rejects.toThrow(CoreError)
  })
  const seal = (details: string) => ({ encrypted_details: nip44.encrypt(details, nip44.getConversationKey(hubKey, signer.pubkey)) })
  test('the result decrypts the details and pairs over the member’s connection secret', async () => {
    const w = await parseCreateCircleWalletResult(seal(`{"wallet_pubkey":"${'9a'.repeat(32)}","relays":[" ","wss://r1.example"],"max_amount":5,"expires_at":9,"fees_ppm":2500,"budget_renewal":"weekly"}`), { signer, connection: conn, hubPubkey: hub })
    expect(w).toEqual({
      pairingUri: buildPairingURI('9a'.repeat(32), ['wss://r1.example'], conn.secret),
      walletPubkey: '9a'.repeat(32),
      relays: ['wss://r1.example'],
      maxAmountMillis: 5n,
      expiresAt: 9,
      feesPpm: 2500,
      budgetRenewal: 'weekly',
    })
  })
  test.each([
    ['no encrypted_details', {}],
    ['no usable relay', null],
    ['a bad wallet pubkey', 'bad'],
  ] as const)('the result refuses %s', async (_, kind) => {
    const result = kind === null ? seal(`{"wallet_pubkey":"${'9a'.repeat(32)}","relays":[" "]}`) : kind === 'bad' ? seal('{"wallet_pubkey":"abc","relays":["wss://r"]}') : kind
    await expect(parseCreateCircleWalletResult(result, { signer, connection: conn, hubPubkey: hub })).rejects.toThrow(CoreError)
  })
  test('details sealed by another key fail to decrypt', async () => {
    const other = { encrypted_details: nip44.encrypt('{}', nip44.getConversationKey(fill(8, 32), signer.pubkey)) }
    await expect(parseCreateCircleWalletResult(other, { signer, connection: conn, hubPubkey: hub })).rejects.toThrow(/decrypt/)
  })
})

describe('nipcw get_info circle_wallet (nip47/methods_test.go)', () => {
  const ID = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  // TestGetInfoResult_CircleWalletRoundTrips.
  test('decodes the block, identity included', () => {
    const info = JSON.parse(`{"alias":"hub","circle_wallet":{"available_millis":42000,"max_exp_secs":86400,"fees_ppm":5000,"circle_policy":"follow_set","identity":"${ID}"}}`) as unknown
    expect(parseCircleWalletInfo(info)).toEqual({ available_millis: 42000n, max_exp_secs: 86400, fees_ppm: 5000, circle_policy: CIRCLE_POLICY_FOLLOW_SET, identity: ID })
  })
  test('no identity means no Private Join; an empty one is the same', () => {
    expect(parseCircleWalletInfo({ circle_wallet: { available_millis: 1, max_exp_secs: 0, fees_ppm: 0, circle_policy: 'allowlist' } })).toEqual({ available_millis: 1n, max_exp_secs: 0, fees_ppm: 0, circle_policy: CIRCLE_POLICY_ALLOWLIST })
    expect(parseCircleWalletInfo({ circle_wallet: { identity: '' } })).not.toHaveProperty('identity')
  })
  test('no block means not a Circle Hub', () => {
    expect(parseCircleWalletInfo({ alias: 'wallet' })).toBeUndefined()
    expect(parseCircleWalletInfo({ circle_wallet: null })).toBeUndefined()
    expect(parseCircleWalletInfo(null)).toBeUndefined()
  })
  test('an unknown policy, the retired "following" included, is left out', () => {
    expect(parseCircleWalletInfo({ circle_wallet: { circle_policy: 'following' } })).not.toHaveProperty('circle_policy')
  })
  test.each([
    ['a string amount', { available_millis: '1' }],
    ['a negative amount', { available_millis: -1 }],
    ['a numeric identity', { identity: 7 }],
    ['an array block', []],
  ] as const)('refuses %s', (_, block) => {
    expect(() => parseCircleWalletInfo({ circle_wallet: block })).toThrow(CoreError)
  })
})
