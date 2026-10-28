// The cash token on the wire (NIP-CASH §Wire Format, §Relay Hints Are
// Mandatory, §Token Test Vectors). Cases follow nmilat
// nipcash/{token,decode_tlv_rules}_test.go and cashctl cmd/decode_tlv_test.go.
import { describe, expect, test } from 'vitest'
import { bech32Decode, fromWords } from '../src/core/bech32.js'
import { utf8 } from '../src/core/bytes.js'
import {
  CoreError,
  decodeToken,
  encodeToken,
  fromHex,
  mintPayloadV1,
  relayHash,
  signCompact,
  signedMessageDigest,
  toHex,
  verifyProvenance,
  type Token,
} from '../src/core/index.js'
import { fill, rawBech32, type RawTLV } from './helpers.js'

const WALLET = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
const R1 = 'wss://relay.example.com'
const R2 = 'wss://backup.example.net'
const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i)
const SPEC_TOKEN =
  'satscash1qqsvvprlj3q76ltdxpz5qm54cp7dshrh3e9cemeu5746czdet3cfaegpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgprpmhxue69uhkyctrdd6hqtn90psk6urvv5hxuet5qgsqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8crqyqs2sfq7gvnhvt0jjxg049a9kg9jnl306hyqexhxn6gw3e0928ftmtxr7n5r2emz4x3r8q6lrx6hgjhzrykwj9wtnchnh78hjcz23pr6n2tf7sxpqqqqqqqqqq9yzq8qnkhn68lpqqszp39gk7'
const SPEC_TLV5 = '20f2193bb16f948c87d4bd2d90594ff17eae4064d734f487472f2a8e95ed661fa741ab3b154d119c1af8cdaba25710c96748ae5cf179dfc7bcb0254423d4d4b4fa'
const SPEC_STREAM =
  '0020c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5' +
  '01177773733a2f2f72656c61792e6578616d706c652e636f6d' +
  '01187773733a2f2f6261636b75702e6578616d706c652e6e6574' +
  '0220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
  '030101' +
  '0541' +
  SPEC_TLV5 +
  '06080000000000005208' +
  '0704ed79e8ff' +
  '080101'

const base: RawTLV[] = [
  [0, fromHex(WALLET)],
  [1, R1],
  [2, SECRET],
]
const pair: RawTLV[] = [
  [5, fill(1, 65)],
  [6, fill(0, 8)],
]
const words = (s: string) => toHex(Uint8Array.from(bech32Decode(s).words))

describe('T-006 encoder: the NIP token vector', () => {
  const fields = {
    hrp: 'satscash',
    walletPubkey: WALLET,
    secret: toHex(SECRET),
    relays: [R1, R2],
    identityRequired: true,
    hubGroup: fromHex('ed79e8ff'),
  }
  test('signing with key 0x01×32 under RFC 6979 gives the NIP TLV 5 and the 348-character string', () => {
    const digest = signedMessageDigest('satscash', mintPayloadV1({ hrp: 'satscash', walletPubkey: WALLET, amountMillis: 21000n, relayHash: relayHash(fields) }))!
    expect(toHex(digest)).toBe('278d47f6702494ccb7127d9ff80ed049ac324ac6bb30287a20a11c54520cdf23')
    const sig = signCompact(digest, fill(1, 32))
    expect(toHex(sig)).toBe(SPEC_TLV5)
    expect(sig[0]).toBe(32)
    const s = encodeToken({ ...fields, scheme: 'mint_v1', mintSignature: sig, attestedAmountMillis: 21000n })
    expect(s).toBe(SPEC_TOKEN)
    expect(s).toHaveLength(348)
  })
  test('the TLV stream is in ascending type order, TLV 8 last', () => {
    const t = decodeToken(SPEC_TOKEN)
    const raw = toHex(fromWords(bech32Decode(SPEC_TOKEN).words))
    expect(raw).toBe(SPEC_STREAM)
    expect(encodeToken(t)).toBe(SPEC_TOKEN)
  })
  test('the decoded spec token: every field, and its minter', () => {
    const t = decodeToken(SPEC_TOKEN)
    expect(t).toMatchObject({ hrp: 'satscash', walletPubkey: WALLET, secret: toHex(SECRET), relays: [R1, R2], identityRequired: true, scheme: 'mint_v1', attestedAmountMillis: 21000n })
    expect(toHex(t.hubGroup!)).toBe('ed79e8ff')
    expect(verifyProvenance(t)?.minter).toBe('031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f')
  })
  test.each<[string, Partial<Token>]>([
    ['an unsigned token', { mintSignature: undefined as never, attestedAmountMillis: undefined as never, scheme: 'none' }],
    ['a pair without a scheme', { scheme: 'none' }],
    ['an empty hint', { relays: [R1, ''] }],
    ['a whitespace hint', { relays: ['  '] }],
    ['a non-ASCII hint', { relays: ['wss://ü.example'] }],
    ['a 3-byte hub group', { hubGroup: fill(1, 3) }],
  ])('refuses %s', (_, over) => {
    const t = { ...decodeToken(SPEC_TOKEN), ...over }
    expect(() => encodeToken(t)).toThrow(CoreError)
  })
  test('a decoded token re-encodes from its usable hints; raw bytes are not an encoder input', () => {
    const t = decodeToken(SPEC_TOKEN)
    expect(encodeToken({ ...t, relayBytes: [utf8('ignored')] })).toBe(SPEC_TOKEN)
  })
})

describe('T-005 decoder table', () => {
  test.each<[string, RawTLV[], string]>([
    ['TLV 8 = 1', [...base, ...pair, [8, Uint8Array.of(1)]], 'mint_v1'],
    ['TLV 8 = 2', [...base, ...pair, [8, Uint8Array.of(2)]], 'zap_v1'],
    ['TLV 8 = 0', [...base, ...pair, [8, Uint8Array.of(0)]], 'malformed'],
    ['TLV 8 = 3', [...base, ...pair, [8, Uint8Array.of(3)]], 'malformed'],
    ['TLV 8 = 255', [...base, ...pair, [8, Uint8Array.of(255)]], 'malformed'],
    ['TLV 8 of length 0', [...base, ...pair, [8, new Uint8Array()]], 'malformed'],
    ['TLV 8 of length 2', [...base, ...pair, [8, Uint8Array.of(1, 0)]], 'malformed'],
    ['TLV 8 twice, same value', [...base, ...pair, [8, Uint8Array.of(1)], [8, Uint8Array.of(1)]], 'malformed'],
    ['TLV 8 absent beside 5/6', [...base, ...pair], 'malformed'],
    ['TLV 8 without 5/6', [...base, [8, Uint8Array.of(1)]], 'none'],
    ['5 without 6', [...base, [5, fill(1, 65)], [8, Uint8Array.of(1)]], 'malformed'],
    ['6 twice', [...base, ...pair, [6, fill(0, 8)], [8, Uint8Array.of(1)]], 'malformed'],
    ['no 5, 6 or 8', base, 'none'],
  ])('%s ⇒ %s', (_, entries, scheme) => {
    const t = decodeToken(rawBech32('satscash', entries))
    expect(t.scheme).toBe(scheme)
    expect(t.mintSignature !== undefined).toBe(scheme === 'mint_v1' || scheme === 'zap_v1')
    expect(t.walletPubkey).toBe(WALLET)
  })
  test('TLV 7 of length 3, or repeated, is dropped and the token kept', () => {
    expect(decodeToken(rawBech32('satscash', [...base, [7, fill(1, 3)]])).hubGroup).toBeUndefined()
    expect(decodeToken(rawBech32('satscash', [...base, [7, fill(1, 4)], [7, fill(1, 4)]])).hubGroup).toBeUndefined()
  })
  test('types 4 and 9 are ignored; entries decode in any order', () => {
    const shuffled: RawTLV[] = [[8, Uint8Array.of(1)], [2, SECRET], [9, 'x'], ...pair, [4, fill(1, 3)], [1, R1], [0, fromHex(WALLET)]]
    const t = decodeToken(rawBech32('satscash', shuffled))
    expect(t).toMatchObject({ walletPubkey: WALLET, relays: [R1], scheme: 'mint_v1' })
  })
  test('a token above 300 characters decodes (no 90-character limit)', () => {
    expect(SPEC_TOKEN.length).toBeGreaterThan(300)
    expect(decodeToken(SPEC_TOKEN).relays).toHaveLength(2)
  })
  test('an all-uppercase token decodes as its lowercase form; a mixed-case one is refused (mixed_case)', () => {
    expect(decodeToken(SPEC_TOKEN.toUpperCase())).toEqual(decodeToken(SPEC_TOKEN))
    const mixed = SPEC_TOKEN.slice(0, 20) + SPEC_TOKEN.slice(20).toUpperCase()
    expect(() => decodeToken(mixed)).toThrow(expect.objectContaining({ code: 'mixed_case' }))
    expect(words(SPEC_TOKEN)).toBe(words(SPEC_TOKEN.toUpperCase()))
  })
  test.each<[string, RawTLV[]]>([
    ['missing TLV 0', [[1, R1], [2, SECRET]]],
    ['missing TLV 2', [[0, fromHex(WALLET)], [1, R1]]],
    ['a 31-byte TLV 0', [[0, fill(1, 31)], [1, R1], [2, SECRET]]],
    ['TLV 0 twice', [...base, [0, fromHex(WALLET)]]],
    ['TLV 3 of 2', [...base, [3, Uint8Array.of(2)]]],
  ])('rejects %s', (_, entries) => {
    expect(() => decodeToken(rawBech32('satscash', entries))).toThrow(CoreError)
  })
})

describe('T-007 relay hints', () => {
  test('dial order is encode order; skipped hints keep their raw bytes', () => {
    const t = decodeToken(rawBech32('satscash', [[0, fromHex(WALLET)], [1, R2], [1, ''], [1, '   '], [1, R1], [2, SECRET]]))
    expect(t.relays).toEqual([R2, R1])
    expect(t.relayBytes!.map((b) => b.length)).toEqual([R2.length, 0, 3, R1.length])
  })
  test('[""] and ASCII-whitespace-only hints alone are rejected: no usable relay', () => {
    expect(() => decodeToken(rawBech32('satscash', [[0, fromHex(WALLET)], [1, ''], [2, SECRET]]))).toThrow(/usable relay/)
    expect(() => decodeToken(rawBech32('satscash', [[0, fromHex(WALLET)], [1, ' \t'], [2, SECRET]]))).toThrow(/usable relay/)
  })
  test('a non-ASCII hint alone still counts as a hint', () => {
    expect(decodeToken(rawBech32('satscash', [[0, fromHex(WALLET)], [1, Uint8Array.of(0xc3, 0xbc)], [2, SECRET]])).relays).toEqual(['\u00fc'])
  })
  test('a 255-byte hint is the largest an encoder writes', () => {
    const t = { ...decodeToken(SPEC_TOKEN), relays: ['w'.repeat(255)] }
    expect(decodeToken(encodeToken(t)).relays[0]).toHaveLength(255)
    expect(() => encodeToken({ ...t, relays: ['w'.repeat(256)] })).toThrow(CoreError)
  })
})
