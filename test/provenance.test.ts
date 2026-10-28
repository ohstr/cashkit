// Mint provenance (NIP-CASH §Mint Provenance, §Token Test Vectors): relay
// hash, the scheme-1 and scheme-2 payloads, recovery headers, x-only
// comparison and the chain table. The literals are the NIP's own; cases
// follow nmilat nipcash/{kat,provenance}_test.go and cashctl
// cmd/decode_provenance_test.go.
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import { concatBytes, utf8 } from '../src/core/bytes.js'
import {
  chainForHrp,
  CHAIN_TABLE,
  decodeToken,
  fromHex,
  LND_SIGNED_MESSAGE_PREFIX,
  mintPayloadV1,
  needsZapEvent,
  recoveryId,
  relayHash,
  relayHashOf,
  sameMinter,
  signCompact,
  signedMessageDigest,
  signedMessagePrefix,
  toHex,
  verifyProvenance,
  verifyZapProvenance,
  zapPayloadV1,
  zapTargetHash,
  type Token,
} from '../src/core/index.js'
import { fill, rawBech32, signedToken } from './helpers.js'

const R1 = 'wss://relay.example.com'
const R2 = 'wss://backup.example.net'
const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i)
const SECRET_HEX = toHex(SECRET)
const WALLET = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
const KRH1 = '487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c'
const SPEC_TOKEN =
  'satscash1qqsvvprlj3q76ltdxpz5qm54cp7dshrh3e9cemeu5746czdet3cfaegpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgprpmhxue69uhkyctrdd6hqtn90psk6urvv5hxuet5qgsqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8crqyqs2sfq7gvnhvt0jjxg049a9kg9jnl306hyqexhxn6gw3e0928ftmtxr7n5r2emz4x3r8q6lrx6hgjhzrykwj9wtnchnh78hjcz23pr6n2tf7sxpqqqqqqqqqq9yzq8qnkhn68lpqqszp39gk7'
const SPEC_MINTER = '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f'
const xonly = (k: number) => toHex(secp256k1.getPublicKey(Uint8Array.of(...fill(0, 31), k), true).subarray(1))

const lenPrefixed = (r: string) => concatBytes(Uint8Array.of(r.length), utf8(r))
const hexOf = (b: Uint8Array) => toHex(sha256(b))

describe('T-001 relayHash (K-RH-1..8)', () => {
  test('K-RH-1: the NIP example', () => {
    expect(relayHashOf([utf8(R1), utf8(R2)], SECRET)).toBe(KRH1)
    expect(relayHashOf([utf8(R1), utf8(R2)], SECRET_HEX)).toBe(KRH1)
  })
  test.each<[string, string, string, string]>([
    ['K-RH-2 no length bytes', hexOf(concatBytes(utf8(R1), utf8(R2), SECRET)), '1105ab44', '7740'],
    ['K-RH-3 no secret', hexOf(concatBytes(lenPrefixed(R1), lenPrefixed(R2))), '69900c59', '45a7'],
    ['K-RH-4 [r1, "", r2]', relayHashOf([utf8(R1), new Uint8Array(), utf8(R2)], SECRET), 'abe08272', 'b153'],
    ['K-RH-5 [r2, r1]', relayHashOf([utf8(R2), utf8(R1)], SECRET), 'eb757e18', 'a53f'],
    ['K-RH-6 secret as hex text', hexOf(concatBytes(lenPrefixed(R1), lenPrefixed(R2), utf8(SECRET_HEX))), 'a6a986b2', '2d0f'],
    ['K-RH-7 [" ", r1]', relayHashOf([utf8(' '), utf8(R1)], SECRET), '5eef6ec8', '0f2edb'],
    ['K-RH-8 [r1]', relayHashOf([utf8(R1)], SECRET), '454ad3fb', 'c958'],
  ])('%s', (_, got, head, tail) => {
    expect(got.startsWith(head) && got.endsWith(tail)).toBe(true)
    expect(got).not.toBe(KRH1)
  })
  test('hashes raw bytes: a non-UTF-8 hint, an empty one and a 255-byte one, each after its 1-byte length', () => {
    const odd = Uint8Array.of(0xff, 0xfe, 0x00)
    const long = fill(0x61, 255)
    expect(relayHashOf([odd, new Uint8Array(), long], SECRET)).toBe(hexOf(concatBytes(Uint8Array.of(3), odd, Uint8Array.of(0), Uint8Array.of(255), long, SECRET)))
  })
  test('a token hashes every TLV 1 as encoded, including a hint it skips when dialling', () => {
    const t = decodeToken(rawBech32('satscash', [[0, fromHex(WALLET)], [1, R1], [1, ''], [1, R2], [2, SECRET]]))
    expect(t.relays).toEqual([R1, R2])
    expect(relayHash(t)).toBe(relayHashOf([utf8(R1), new Uint8Array(), utf8(R2)], SECRET))
  })
})

describe('T-002 payloads (K-PAY-1, K-PAY-2, K-ZAP-1)', () => {
  test('K-PAY-1: scheme 1 for satscash', () => {
    expect(mintPayloadV1({ hrp: 'satscash', walletPubkey: WALLET, amountMillis: 21000n, relayHash: KRH1 })).toBe(`cash-mint:v1:satscash:${WALLET}:21000:${KRH1}`)
  })
  test('K-PAY-2: the label stays cash-mint:v1 for every HRP; only <hrp> changes', () => {
    expect(mintPayloadV1({ hrp: 'lokicash', walletPubkey: WALLET, amountMillis: 21000n, relayHash: KRH1 })).toBe(`cash-mint:v1:lokicash:${WALLET}:21000:${KRH1}`)
  })
  test('the HRP and hex are lowercased; integers are unsigned decimal without leading zeros', () => {
    expect(mintPayloadV1({ hrp: 'SATSCASH', walletPubkey: WALLET.toUpperCase(), amountMillis: 0n, relayHash: KRH1.toUpperCase() })).toBe(`cash-mint:v1:satscash:${WALLET}:0:${KRH1}`)
    expect(mintPayloadV1({ hrp: 'satscash', walletPubkey: WALLET, amountMillis: 18446744073709551615n, relayHash: KRH1 })).toContain(':18446744073709551615:')
    expect(() => mintPayloadV1({ hrp: 'satscash', walletPubkey: WALLET, amountMillis: -1n, relayHash: KRH1 })).toThrow()
  })
  test('K-ZAP-1: the NIP scheme-2 example', () => {
    const target = '30023:e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13:my-article'
    expect(zapTargetHash(target)).toBe('79c69fd2170904248edc898066fce02a7fefa36235f4fb863f4329c99f891b8f')
    expect(xonly(5)).toBe('2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4')
    expect(xonly(6)).toBe('fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556')
    const p = zapPayloadV1({ hrp: 'satscash', walletPubkey: WALLET, amountMillis: 5000n, relayHash: KRH1, recipient: xonly(5), sender: xonly(6), zapTarget: target, issuedAt: 1720000000, expiresAt: 0 })
    expect(p).toBe(
      'cash-zap:v1:satscash:c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5:5000:' +
        '487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c:' +
        'pubkey/2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4:' +
        'pubkey/fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556:' +
        '79c69fd2170904248edc898066fce02a7fefa36235f4fb863f4329c99f891b8f:1720000000:0',
    )
  })
  test('target_hash is over the exact UTF-8 string', () => {
    expect(zapTargetHash('hello world')).toBe('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9')
  })
})

const spec = () => decodeToken(SPEC_TOKEN)
const tamper = (over: Partial<Token>) => verifyProvenance({ ...spec(), ...over })?.minter

describe('T-003 verify', () => {
  test('K-TOK-1: the NIP token verifies to its minter, compressed and x-only', () => {
    const t = spec()
    expect(signedMessageDigest('satscash', mintPayloadV1({ hrp: 'satscash', walletPubkey: WALLET, amountMillis: 21000n, relayHash: KRH1 }))).toEqual(
      fromHex('278d47f6702494ccb7127d9ff80ed049ac324ac6bb30287a20a11c54520cdf23'),
    )
    expect(verifyProvenance(t)).toEqual({ minter: SPEC_MINTER, xonly: SPEC_MINTER.slice(2) })
  })
  test.each<[string, Partial<Token>]>([
    ['a hint swapped', { relayBytes: [utf8(R2), utf8(R1)] }],
    ['a hint appended', { relayBytes: [utf8(R1), utf8(R2), utf8('wss://evil.example')] }],
    ['the secret swapped', { secret: '11'.repeat(32) }],
    ['the amount changed', { attestedAmountMillis: 21001n }],
    ['another wallet', { walletPubkey: '22'.repeat(32) }],
  ])('%s never names the minter', (_, over) => {
    expect(tamper(over)).not.toBe(SPEC_MINTER)
  })
  test('a token with TLV 5/6 and no TLV 8 has no provenance, and still decodes', () => {
    const t = decodeToken(rawBech32('satscash', [[0, fromHex(WALLET)], [1, R1], [1, R2], [2, SECRET], [5, fill(1, 65)], [6, fill(0, 8)]]))
    expect(t.scheme).toBe('malformed')
    expect(verifyProvenance(t)).toBeUndefined()
  })
  test('an HRP with no chain row decodes but has no provenance', () => {
    const s = signedToken({ hrp: 'satscash', walletPubkey: WALLET, secret: SECRET_HEX, relays: [R1] })
    const t = decodeToken(s)
    expect(verifyProvenance(t)).toBeDefined()
    expect(verifyProvenance({ ...t, hrp: 'xyzcash' })).toBeUndefined()
  })
  test('scheme 2: no provenance without the Cash Zap fields; verifies with them', () => {
    const key = fill(0x11, 32)
    const zap = { recipient: xonly(5), sender: xonly(6), zapTarget: 'note1x', issuedAt: 1720000000, expiresAt: 0 }
    const base = { hrp: 'satscash', walletPubkey: WALLET, secret: SECRET_HEX, relays: [R1], relayBytes: [utf8(R1)], attestedAmountMillis: 5000n }
    const digest = signedMessageDigest('satscash', zapPayloadV1({ hrp: 'satscash', walletPubkey: WALLET, amountMillis: 5000n, relayHash: relayHashOf([utf8(R1)], SECRET), ...zap }))!
    const t: Token = { ...base, scheme: 'zap_v1', mintSignature: signCompact(digest, key) }
    expect(needsZapEvent(t)).toBe(true)
    expect(verifyProvenance(t)).toBeUndefined()
    const m = verifyZapProvenance(t, zap)!
    expect(m.minter).toBe(toHex(secp256k1.getPublicKey(key, true)))
    expect(verifyZapProvenance(t, { ...zap, zapTarget: 'note1y' })?.minter).not.toBe(m.minter)
    expect(verifyZapProvenance({ ...t, scheme: 'mint_v1' }, zap)).toBeUndefined()
  })
})

// cashctl TestDecode_BadMintSignatureIsNeverValid: unrecoverable ⇒ no minter.
describe('a signature that cannot recover is never valid', () => {
  test.each<[string, (s: Uint8Array) => void]>([
    ['r is zero', (s) => s.fill(0, 1, 33)],
    ['s is zero', (s) => s.fill(0, 33)],
    ['r beyond the curve order', (s) => s.fill(0xff, 1, 33)],
  ])('%s', (_, mutate) => {
    const t = decodeToken(SPEC_TOKEN)
    const sig = t.mintSignature!.slice()
    mutate(sig)
    expect(verifyProvenance({ ...t, mintSignature: sig })).toBeUndefined()
  })
  test('a flipped signature bit never names the minter', () => {
    const t = decodeToken(SPEC_TOKEN)
    const sig = t.mintSignature!.slice()
    sig[64]! ^= 1
    expect(verifyProvenance({ ...t, mintSignature: sig })?.minter).not.toBe(SPEC_MINTER)
  })
})

describe('T-004 recovery headers', () => {
  test('27..34 and 0..3 give a recid; 26 and 35 do not', () => {
    expect([27, 28, 29, 30, 31, 32, 33, 34].map(recoveryId)).toEqual([0, 1, 2, 3, 0, 1, 2, 3])
    expect([0, 1, 2, 3].map(recoveryId)).toEqual([0, 1, 2, 3])
    expect(recoveryId(26)).toBeUndefined()
    expect(recoveryId(35)).toBeUndefined()
    expect(recoveryId(4)).toBeUndefined()
  })
  test('the spec token re-headed as 28 (uncompressed form) or raw recid 1 still recovers; 26 and 35 do not', () => {
    const t = decodeToken(SPEC_TOKEN)
    const sig = t.mintSignature!
    expect(sig[0]).toBe(32)
    const reheaded = (h: number) => verifyProvenance({ ...t, mintSignature: Uint8Array.of(h, ...sig.subarray(1)) })?.minter
    expect(reheaded(28)).toBe(SPEC_MINTER)
    expect(reheaded(1)).toBe(SPEC_MINTER)
    expect(reheaded(26)).toBeUndefined()
    expect(reheaded(35)).toBeUndefined()
  })
  test('the encoder side emits 31 + recid', () => {
    const sig = signCompact(fill(0x42, 32), fill(0x11, 32))
    expect(sig).toHaveLength(65)
    expect([31, 32]).toContain(sig[0])
  })
})

describe('T-008 sameMinter', () => {
  const k = SPEC_MINTER.slice(2)
  test('02‖K, 03‖K and K are the same minter; another key is not', () => {
    expect(sameMinter(`02${k}`, `03${k}`)).toBe(true)
    expect(sameMinter(`03${k}`, k)).toBe(true)
    expect(sameMinter(k.toUpperCase(), k)).toBe(true)
    expect(sameMinter(`04${k}`, k)).toBe(false)
    expect(sameMinter(k, `${k.slice(0, 63)}0`)).toBe(false)
    expect(sameMinter('', '')).toBe(false)
  })
  test('the recovered key matches an announcement author given x-only', () => {
    expect(sameMinter(verifyProvenance(decodeToken(SPEC_TOKEN))!.minter, k)).toBe(true)
  })
})

describe('T-014 chain table', () => {
  test('satscash is bitcoin under the Lightning prefix', () => {
    expect(chainForHrp('satscash')).toBe('bitcoin')
    expect(signedMessagePrefix('satscash')).toBe(LND_SIGNED_MESSAGE_PREFIX)
    expect(LND_SIGNED_MESSAGE_PREFIX).toBe('Lightning Signed Message:')
  })
  test('every row has a chain name and a prefix; lookups are own-property and lowercase only', () => {
    for (const [hrp, r] of Object.entries(CHAIN_TABLE)) {
      expect(hrp).toBe(hrp.toLowerCase())
      expect(r.chain).toMatch(/^[a-z0-9-]{1,32}$/)
      expect(r.prefix.endsWith('Signed Message:')).toBe(true)
    }
    expect(signedMessagePrefix('constructor')).toBeUndefined()
    expect(signedMessagePrefix('SATSCASH')).toBeUndefined()
    expect(chainForHrp('xyzcash')).toBeUndefined()
  })
  test('an unknown HRP is still accepted by the decoder', () => {
    expect(decodeToken(rawBech32('xyzcash', [[0, fromHex(WALLET)], [1, R1], [2, SECRET]])).hrp).toBe('xyzcash')
  })
})
