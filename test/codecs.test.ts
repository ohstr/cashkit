// Unit tests for the TLV-string codecs and bech32 framing. Cases follow
// nmilat nipcash/{token,decode_tlv_rules,hub_group,encode_relay}_test.go and
// cashctl cmd/decode_{tlv,provenance}_test.go.
import { describe, expect, test } from 'vitest'
import { bech32Decode, bech32Encode, convertBits, fromWords, toWords } from '../src/core/bech32.js'
import {
  CoreError,
  decodeCashHubConnection,
  decodeCircleHubConnection,
  decodeNConnection,
  decodeOrderConnection,
  fromHex,
  getPublicKey,
  decodeToken,
  encodeNConnection,
  encodeToken,
  hasProvenance,
  hubGroupFor,
  joinCashString,
  sameHubGroup,
  splitCashString,
  toHex,
  type Token,
} from '../src/core/index.js'
import { BASE, fill, HUB_KEY, KEY_HEX, RELAY, rawBech32, SECRET_HEX, signedConnection, type RawTLV } from './helpers.js'

const token = (over: Partial<Token> = {}): Token => ({
  hrp: 'lokicash',
  walletPubkey: KEY_HEX,
  secret: SECRET_HEX,
  relays: [RELAY],
  scheme: 'mint_v1',
  mintSignature: fill(1, 65),
  attestedAmountMillis: 21000n,
  ...over,
})
/** What a decoder returns beside the fields given: the raw relay hints. */
const decoded = (t: Token) => ({ ...t, relays: [...t.relays], relayBytes: t.relays.map((r) => new TextEncoder().encode(r)) })

describe('bech32 framing', () => {
  test('encode then decode round-trips any HRP and payload', () => {
    for (const hrp of ['a', 'lokicash', 'satscash', 'nconnection']) {
      const words = toWords(Uint8Array.from({ length: 300 }, (_, i) => i & 0xff))
      const s = bech32Encode(hrp, words)
      const back = bech32Decode(s)
      expect(back.hrp).toBe(hrp)
      expect(back.words).toEqual(words)
    }
  })
  test('no 90-character limit: a token is routinely longer', () => {
    const s = bech32Encode('lokicash', toWords(fill(7, 200)))
    expect(s.length).toBeGreaterThan(90)
    expect(fromWords(bech32Decode(s).words)).toEqual(fill(7, 200))
  })
  test('all-uppercase input is read as lowercase; mixed case is refused', () => {
    const s = bech32Encode('lokicash', toWords(fill(1, 10)))
    expect(bech32Decode(s.toUpperCase()).hrp).toBe('lokicash')
    expect(() => bech32Decode('L' + s.slice(1))).toThrow(CoreError)
  })
  test('the HRP is lowercased on encode', () => {
    expect(bech32Encode('LOKICASH', toWords(fill(1, 4))).startsWith('lokicash1')).toBe(true)
  })
  test('the last 1 is the separator, so an HRP may contain 1', () => {
    expect(bech32Decode(bech32Encode('loki1cash', toWords(fill(1, 4)))).hrp).toBe('loki1cash')
  })
  test.each([
    ['empty', ''],
    ['too short', 'a1qqqqq'],
    ['no separator', 'lokicashqqqqqqqq'],
    ['empty HRP', '1qqqqqqqqq'],
    ['space', ' lokicash1qqqqqqqq'],
    ['character outside the charset', 'lokicash1bqqqqqqq'],
  ])('refuses %s', (_, s) => {
    expect(() => bech32Decode(s)).toThrow(CoreError)
  })
  test('a single flipped character breaks the checksum', () => {
    const s = bech32Encode('lokicash', toWords(fill(9, 40)))
    const flipped = s.slice(0, -1) + (s.endsWith('q') ? 'p' : 'q')
    expect(() => bech32Decode(flipped)).toThrow(/checksum/)
  })
  test('convertBits refuses non-zero and excess padding, and pads only when asked', () => {
    expect(convertBits(Uint8Array.of(0xff), 8, 5, true)).toEqual(Uint8Array.of(31, 28))
    expect(() => convertBits(Uint8Array.of(31, 29), 5, 8, false)).toThrow(/padding/)
    expect(() => convertBits(Uint8Array.of(31, 28, 0), 5, 8, false)).toThrow(/padding/)
  })
})

describe('cash token', () => {
  test('round-trips every field', () => {
    const t = token({
      relays: ['wss://r1.example', 'wss://r2.example'],
      identityRequired: true,
      mintSignature: fill(1, 65),
      attestedAmountMillis: 21000n,
      hubGroup: hubGroupFor('cd'.repeat(32)),
    })
    const back = decodeToken(encodeToken(t))
    expect(back).toEqual(decoded(t))
    expect(hasProvenance(back)).toBe(true)
    expect(decodeToken(encodeToken({ ...t, scheme: 'zap_v1' })).scheme).toBe('zap_v1')
  })
  test('optional fields are absent, not undefined-valued, when missing', () => {
    const back = decodeToken(encodeToken(token()))
    expect(new Set(Object.keys(back))).toEqual(new Set(['hrp', 'relays', 'relayBytes', 'secret', 'walletPubkey', 'scheme', 'mintSignature', 'attestedAmountMillis']))
    expect(hasProvenance(back)).toBe(true)
  })
  test('identity_required false survives (it is not the same as absent)', () => {
    expect(decodeToken(encodeToken(token({ identityRequired: false }))).identityRequired).toBe(false)
  })
  test('the full uint64 attested amount survives as a bigint', () => {
    const t = token({ mintSignature: fill(1, 65), attestedAmountMillis: 18446744073709551615n })
    expect(decodeToken(encodeToken(t)).attestedAmountMillis).toBe(18446744073709551615n)
  })
  test.each<[string, Partial<Token>]>([
    ['no relays', { relays: [] }],
    ['only blank relays', { relays: [' ', '\t'] }],
    ['a blank relay beside a usable one', { relays: ['', RELAY] }],
    ['a non-ASCII relay', { relays: ['wss://bücher.example'] }],
    ['no provenance', { mintSignature: undefined as never, attestedAmountMillis: undefined as never }],
    ['no scheme', { scheme: 'none' }],
    ['a malformed scheme', { scheme: 'malformed' }],
    ['a relay over 255 bytes', { relays: ['r'.repeat(256)] }],
    ['a signature without an amount', { attestedAmountMillis: undefined as never }],
    ['an amount without a signature', { mintSignature: undefined as never }],
    ['a 64-byte signature', { mintSignature: fill(1, 64), attestedAmountMillis: 1n }],
    ['a negative amount', { mintSignature: fill(1, 65), attestedAmountMillis: -1n }],
    ['an amount above uint64', { mintSignature: fill(1, 65), attestedAmountMillis: 1n << 64n }],
    ['a 2-byte hub group', { hubGroup: Uint8Array.of(1, 2) }],
    ['a short wallet pubkey', { walletPubkey: KEY_HEX.slice(2) }],
    ['a non-hex secret', { secret: 'zz' + SECRET_HEX.slice(2) }],
  ])('encode refuses %s', (_, over) => {
    expect(() => encodeToken(token(over))).toThrow(CoreError)
  })
  test('a 255-byte relay is the largest accepted', () => {
    expect(decodeToken(encodeToken(token({ relays: ['r'.repeat(255)] }))).relays[0]).toHaveLength(255)
  })

  // cashctl TestDecode_RejectsMalformedCashTokenTLVs / nmilat sharedTLVCases.
  test.each<[string, Parameters<typeof rawBech32>[1], number[]?]>([
    ['missing pubkey', [[1, RELAY], [2, fill(0x33, 32)]]],
    ['missing secret', [[0, fill(0x22, 32)], [1, RELAY]]],
    ['duplicate pubkey', [[0, fill(0x22, 32)], ...BASE]],
    ['duplicate secret', [...BASE, [2, fill(0x33, 32)]]],
    ['short pubkey', [[0, fill(0x22, 31)], [1, RELAY], [2, fill(0x33, 32)]]],
    ['long secret', [[0, fill(0x22, 32)], [1, RELAY], [2, fill(0x33, 33)]]],
    ['no relay', [[0, fill(0x22, 32)], [2, fill(0x33, 32)]]],
    ['identity_required of two bytes', [...BASE, [3, Uint8Array.of(0, 1)]]],
    ['identity_required of 2', [...BASE, [3, Uint8Array.of(2)]]],
    ['duplicate identity_required', [...BASE, [3, Uint8Array.of(1)], [3, Uint8Array.of(1)]]],
    ['truncated entry', [[0, fill(0x22, 32)], [1, RELAY]], [2, 32, 1, 2, 3]],
  ])('decode refuses %s', (_, entries, raw) => {
    expect(() => decodeToken(rawBech32('lokicash', entries, raw))).toThrow(CoreError)
  })

  // cashctl TestDecode_BadProvenanceIsNoProvenanceNotAFailure.
  test.each<[string, Parameters<typeof rawBech32>[1]]>([
    ['signature alone', [[5, fill(1, 65)]]],
    ['amount alone', [[6, fill(0, 8)]]],
    ['short signature', [[5, fill(1, 64)], [6, fill(0, 8)]]],
    ['short amount', [[5, fill(1, 65)], [6, fill(0, 7)]]],
    ['duplicate signature', [[5, fill(1, 65)], [5, fill(1, 65)], [6, fill(0, 8)]]],
    ['no scheme beside a pair', [[5, fill(1, 65)], [6, fill(0, 8)]]],
    ['scheme 0', [[5, fill(1, 65)], [6, fill(0, 8)], [8, Uint8Array.of(0)]]],
    ['scheme 3', [[5, fill(1, 65)], [6, fill(0, 8)], [8, Uint8Array.of(3)]]],
    ['scheme 255', [[5, fill(1, 65)], [6, fill(0, 8)], [8, Uint8Array.of(255)]]],
    ['an empty scheme', [[5, fill(1, 65)], [6, fill(0, 8)], [8, new Uint8Array()]]],
    ['a 2-byte scheme', [[5, fill(1, 65)], [6, fill(0, 8)], [8, Uint8Array.of(1, 1)]]],
    ['a repeated scheme, same value', [[5, fill(1, 65)], [6, fill(0, 8)], [8, Uint8Array.of(1)], [8, Uint8Array.of(1)]]],
    ['a valid scheme without the pair', [[5, fill(1, 65)], [8, Uint8Array.of(1)]]],
  ])('anomalous provenance is dropped, not fatal: %s', (_, extra) => {
    const t = decodeToken(rawBech32('lokicash', [...BASE, ...extra]))
    expect(hasProvenance(t)).toBe(false)
    expect(t.scheme).toBe('malformed')
    expect(t.mintSignature).toBeUndefined()
    expect(t.walletPubkey).toBe(KEY_HEX)
  })
  test.each([
    ['too short', [[7, Uint8Array.of(1)]]],
    ['too long', [[7, fill(1, 8)]]],
    ['empty', [[7, new Uint8Array()]]],
    ['duplicated', [[7, fill(1, 4)], [7, fill(1, 4)]]],
  ] as [string, Parameters<typeof rawBech32>[1]][])('an anomalous hub group is dropped, the rest kept: %s', (_, extra) => {
    const t = decodeToken(rawBech32('lokicash', [...BASE, [5, fill(1, 65)], [6, fill(0, 8)], [8, Uint8Array.of(1)], ...extra]))
    expect(t.hubGroup).toBeUndefined()
    expect(hasProvenance(t)).toBe(true)
  })
  test('unknown TLV types, including reserved 4, are ignored (cashctl TestDecode_UnknownTLVsAreIgnored)', () => {
    const t = decodeToken(rawBech32('lokicash', [[0, fill(0x22, 32)], [4, Uint8Array.of(1, 2, 3)], [1, RELAY], [200, 'future'], [2, fill(0x33, 32)], [99, new Uint8Array()], [255, fill(0xee, 40)]]))
    expect(t.relays).toEqual([RELAY])
  })
  test('decode skips an ASCII-blank relay, lists any other hint, and keeps every raw byte', () => {
    const t = decodeToken(rawBech32('lokicash', [...BASE, [1, ' '], [1, '\uFEFFwss://x'], [1, Uint8Array.of(0xff)]]))
    expect(t.relays).toEqual([RELAY, '\uFEFFwss://x', '\uFFFD'])
    expect(t.relayBytes).toHaveLength(4)
    expect(t.relayBytes![3]).toEqual(Uint8Array.of(0xff))
    expect(t.scheme).toBe('none')
  })
  test('any HRP decodes as a token', () => {
    expect(decodeToken(rawBech32('xyzcash', BASE)).hrp).toBe('xyzcash')
  })
  test('errors never echo the input', () => {
    const s = rawBech32('lokicash', [[0, fill(0x22, 32)], [2, fill(0x33, 32)]])
    try {
      decodeToken(s)
      expect.unreachable()
    } catch (err) {
      expect((err as Error).message).not.toContain(SECRET_HEX)
      expect((err as Error).message).not.toContain(s)
      expect((err as CoreError).code).toBe('invalid_tlv')
    }
  })
})

describe('hub connections (cashhub1, cashorder1, circlehub1)', () => {
  const SIGNED: RawTLV[] = [[4, fromHex(getPublicKey(HUB_KEY))], [5, fill(1, 65)], [6, 'bitcoin']]
  const signedBase = (): RawTLV[] => [...BASE, ...SIGNED]
  test.each([
    ['cashhub', decodeCashHubConnection],
    ['cashorder', decodeOrderConnection],
    ['circlehub', decodeCircleHubConnection],
  ] as const)('%s round-trips, label included', (hrp, decode) => {
    const c = { walletPubkey: KEY_HEX, secret: SECRET_HEX, relays: [RELAY], label: 'Family ☕' }
    const s = signedConnection(hrp, c)
    expect(s.startsWith(`${hrp}1`)).toBe(true)
    expect(decode(s)).toMatchObject({ ...c, hubIdentity: getPublicKey(HUB_KEY), chain: 'bitcoin' })
    expect(decode(signedConnection(hrp, { ...c, label: '' })).label).toBe('')
    expect(decode(signedConnection(hrp, { ...c, label: '' })).labelBytes).toBeUndefined()
  })
  test('each decoder refuses the other HRPs and a token', () => {
    const c = { walletPubkey: KEY_HEX, secret: SECRET_HEX, relays: [RELAY] }
    expect(() => decodeCashHubConnection(signedConnection('circlehub', c))).toThrow(CoreError)
    expect(() => decodeCircleHubConnection(signedConnection('cashhub', c))).toThrow(CoreError)
    expect(() => decodeOrderConnection(signedConnection('cashhub', c))).toThrow(CoreError)
    expect(() => decodeCircleHubConnection(rawBech32('lokicash', BASE))).toThrow(CoreError)
  })
  test('a duplicate label is refused, even an empty one', () => {
    expect(() => decodeCircleHubConnection(rawBech32('circlehub', [...signedBase(), [3, ''], [3, '']]))).toThrow(/duplicate label/)
  })
  test('a label over 255 bytes is refused on encode', () => {
    expect(() => signedConnection('cashhub', { walletPubkey: KEY_HEX, secret: SECRET_HEX, relays: [RELAY], label: 'é'.repeat(128) })).toThrow(CoreError)
  })
  // cashctl TestDecode_RejectsMalformedCircleHubTLVs.
  test.each<[string, RawTLV[], number[]?]>([
    ['missing pubkey', [[1, RELAY], [2, fill(0x33, 32)], ...SIGNED]],
    ['missing secret', [[0, fill(0x22, 32)], [1, RELAY], ...SIGNED]],
    ['no relay', [[0, fill(0x22, 32)], [2, fill(0x33, 32)], ...SIGNED]],
    ['truncated entry', [...BASE, ...SIGNED], [3, 9, 1]],
  ])('circlehub decode refuses %s', (_, entries, raw) => {
    expect(() => decodeCircleHubConnection(rawBech32('circlehub', entries, raw))).toThrow(CoreError)
  })
})

describe('nconnection1', () => {
  const ck = '44'.repeat(32)
  test('round-trips key, relays and platform', () => {
    const c = { connectionKey: ck, relays: ['wss://a', 'wss://b'], platform: 'discord' }
    expect(decodeNConnection(encodeNConnection(c))).toEqual(c)
  })
  test('refuses a second key, a second platform, a bad platform name and a truncated tail', () => {
    expect(() => decodeNConnection(rawBech32('nconnection', [[0, fill(0x44, 32)], [0, fill(0x55, 32)]]))).toThrow(/more than one ConnectionKey/)
    expect(() => decodeNConnection(rawBech32('nconnection', [[0, fill(0x44, 32)], [2, 'x'], [2, 'dns']]))).toThrow(/more than one platform/)
    expect(() => decodeNConnection(rawBech32('nconnection', [[0, fill(0x44, 32)], [2, 'X']]))).toThrow(/platform name/)
    expect(() => decodeNConnection(rawBech32('nconnection', [[0, fill(0x44, 32)]], [1, 32, 119]))).toThrow(/runs past the end/)
  })
  test('refuses a missing or short key, and the wrong HRP', () => {
    expect(() => decodeNConnection(rawBech32('nconnection', [[1, RELAY]]))).toThrow(CoreError)
    expect(() => decodeNConnection(rawBech32('nconnection', [[0, fill(0x44, 31)]]))).toThrow(CoreError)
    expect(() => decodeNConnection(rawBech32('npub', [[0, fill(0x44, 32)]]))).toThrow(CoreError)
  })
  test('refuses a value too long for its length byte instead of corrupting the stream', () => {
    expect(() => encodeNConnection({ connectionKey: ck, relays: ['r'.repeat(256)], platform: '' })).toThrow(CoreError)
  })
})

describe('cash string (nmilat TestSplitCashSliceString)', () => {
  test.each([
    ['lokicash1abc', 'lokicash1abc', ''],
    ['lokicash1abc#deadbeef', 'lokicash1abc', 'deadbeef'],
    ['lokicash1abc#dead#beef', 'lokicash1abc', 'dead#beef'],
    ['', '', ''],
  ])('split %j', (input, tok, secret) => {
    expect(splitCashString(input)).toEqual({ token: tok, cashSecret: secret })
  })
  test('join and split are inverse', () => {
    expect(splitCashString(joinCashString('lokicash1x', 'ab'.repeat(32)))).toEqual({ token: 'lokicash1x', cashSecret: 'ab'.repeat(32) })
  })
})

describe('hub group (nmilat hub_group_test.go)', () => {
  test('is deterministic, distinct per Hub, and 4 bytes', () => {
    expect(hubGroupFor('hub-a')).toEqual(hubGroupFor('hub-a'))
    expect(hubGroupFor('hub-a')).not.toEqual(hubGroupFor('hub-b'))
    expect(hubGroupFor('hub-a')).toHaveLength(4)
  })
  test('hashes the hex text, so case changes the fingerprint', () => {
    const pk = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'
    expect(toHex(hubGroupFor(pk))).not.toBe(toHex(hubGroupFor(pk.toUpperCase())))
  })
  test('does not leak the Hub identifier verbatim', () => {
    expect(toHex(hubGroupFor('hub-a'))).not.toContain(toHex(new TextEncoder().encode('hub-a')))
  })
  test('missing is never a wildcard (TestSameHubGroup_MissingIsNeverAWildcard)', () => {
    const a = hubGroupFor('hub-a')
    expect(sameHubGroup(a, a)).toBe(true)
    expect(sameHubGroup(a, hubGroupFor('hub-b'))).toBe(false)
    expect(sameHubGroup(undefined, undefined)).toBe(false)
    expect(sameHubGroup(a, undefined)).toBe(false)
    expect(sameHubGroup(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(false)
  })
  test('adding a hub group costs about ten characters (TestHubGroup_CostsAboutTenCharacters)', () => {
    const t = token({ mintSignature: fill(1, 65), attestedAmountMillis: 123456n })
    const grew = encodeToken({ ...t, hubGroup: hubGroupFor('hub-pubkey-aaa') }).length - encodeToken(t).length
    expect(grew).toBeLessThanOrEqual(12)
  })
})
