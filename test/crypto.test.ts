// Unit tests for provenance, connection keys and NIP-44. Cases follow
// cashctl cmd/decode_provenance_test.go, nmilat nipcash/{kat,provenance}_test.go,
// nipcw/connection_key_kat_test.go and nip44/auditC_qa_kat_test.go.
import { chacha20 } from '@noble/ciphers/chacha.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { expand as hkdfExpand } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { base64 } from '@scure/base'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import { concatBytes, utf8 } from '../src/core/bytes.js'
import {
  connectionKeyFromSecret,
  CoreError,
  decodeToken,
  fromHex,
  mintPayload,
  newConnectionKey,
  nip44,
  signedMessagePrefix,
  toHex,
  verifyProvenance,
} from '../src/core/index.js'
import { BASE, fill, rawBech32 } from './helpers.js'

const KAT_MINTER = '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'
const KAT_SIG = fromHex(
  '20c72cfbb8e8566000d6d90904c0c04fd047ce066dd599ede34c84dfb314f3126709ad9a50800f285c90a9683f8282b268a8bb85f8b7a9599f9b4482cbfd83b508',
)
const WALLET = '22'.repeat(32)

/** Signs like a Lightning node's signmessage: header 31 + recovery, r, s. */
function signMint(secret: Uint8Array, hrp: string, wallet: string, amount: bigint): Uint8Array {
  const digest = sha256(sha256(utf8(signedMessagePrefix(hrp)! + mintPayload(hrp, wallet, amount))))
  const sig = secp256k1.sign(digest, secret, { prehash: false, format: 'recovered' })
  return concatBytes(Uint8Array.of(31 + sig[0]!), sig.subarray(1))
}

const pub = (s: Uint8Array) => toHex(secp256k1.getPublicKey(s, true).subarray(1))

const amountTLV = (m: bigint) => {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, m)
  return b
}

describe('provenance', () => {
  test('mint payload scheme (TestKAT_MintProvenance)', () => {
    expect(mintPayload('lokicash', WALLET, 21000n)).toBe(`lokicash-mint:v1:lokicash:${WALLET}:21000`)
  })
  test('the KAT token decodes and verifies end to end (TestDecode_KATProvenanceVerifies)', () => {
    const t = decodeToken(rawBech32('lokicash', [[0, fill(0x22, 32)], ...BASE.slice(1), [5, KAT_SIG], [6, amountTLV(21000n)]]))
    expect(verifyProvenance(t)).toBe(KAT_MINTER)
  })
  test('a signature made here verifies, for both prefixes', () => {
    const secret = fill(7, 32)
    const minter = toHex(secp256k1.getPublicKey(secret, true))
    for (const hrp of ['lokicash', 'satscash']) {
      const sig = signMint(secret, hrp, WALLET, 5000n)
      expect(verifyProvenance({ hrp, walletPubkey: WALLET, mintSignature: sig, attestedAmountMillis: 5000n })).toBe(minter)
    }
  })
  // TestDecode_BadMintSignatureIsNeverValid: unrecoverable → no minter.
  test.each<[string, (s: Uint8Array) => void, string?]>([
    ['recovery byte out of range', (s) => (s[0] = 0)],
    ['r is zero', (s) => s.fill(0, 1, 33)],
    ['s is zero', (s) => s.fill(0, 33)],
    ['r beyond the curve order', (s) => s.fill(0xff, 1, 33)],
    ['unknown HRP, no prefix', () => {}, 'xyzcash'],
  ])('never valid: %s', (_, mutate, hrp = 'lokicash') => {
    const sig = KAT_SIG.slice()
    mutate(sig)
    expect(verifyProvenance({ hrp, walletPubkey: WALLET, mintSignature: sig, attestedAmountMillis: 21000n })).toBeUndefined()
  })
  // Tampered tokens recover some key, never the real minter.
  test.each<[string, string, bigint, (s: Uint8Array) => void]>([
    ['amount raised', WALLET, 21001n, () => {}],
    ['other wallet', '23'.repeat(32), 21000n, () => {}],
    ['signature bit flip', WALLET, 21000n, (s) => (s[64]! ^= 1)],
  ])('tampered (%s) never names the real minter', (_, wallet, amount, mutate) => {
    const sig = KAT_SIG.slice()
    mutate(sig)
    expect(verifyProvenance({ hrp: 'lokicash', walletPubkey: wallet, mintSignature: sig, attestedAmountMillis: amount })).not.toBe(KAT_MINTER)
  })
  test('no provenance, or half of it, is undefined', () => {
    expect(verifyProvenance({ hrp: 'lokicash', walletPubkey: WALLET })).toBeUndefined()
    expect(verifyProvenance({ hrp: 'lokicash', walletPubkey: WALLET, mintSignature: KAT_SIG })).toBeUndefined()
    expect(verifyProvenance({ hrp: 'lokicash', walletPubkey: WALLET, attestedAmountMillis: 1n })).toBeUndefined()
  })
  test('only lokicash and satscash have a prefix; lookups are own-property only', () => {
    expect(signedMessagePrefix('lokicash')).toBe('Flokicoin Lightning Signed Message:')
    expect(signedMessagePrefix('satscash')).toBe('Lightning Signed Message:')
    expect(signedMessagePrefix('constructor')).toBeUndefined()
  })
})

describe('connection keys', () => {
  test('NIP-IC key is sha256(platform:id) (TestKAT_ConnectionKey)', () => {
    expect(newConnectionKey('github', '12345')).toBe('2db75fb4d7a8e3005aca09c643b4e6f40142ddcfc18c675509988c1b111d0dcf')
  })
  test('NIP-CW key pair KAT (TestConnectionKey_KnownAnswer)', () => {
    const k = connectionKeyFromSecret('11'.repeat(32))
    expect(k.pubkey).toBe('4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')
    expect(k.secret).toBe('11'.repeat(32))
  })
  test.each(['', '11'.repeat(31), 'zz'.repeat(32), '00'.repeat(32), 'ff'.repeat(32)])('refuses secret %j', (s) => {
    expect(() => connectionKeyFromSecret(s)).toThrow(CoreError)
  })
})

describe('nip44', () => {
  const a = fill(1, 32)
  const b = fill(2, 32)
  test('the conversation key is symmetric', () => {
    expect(nip44.getConversationKey(a, pub(b))).toEqual(nip44.getConversationKey(b, pub(a)))
  })
  test('round-trips ASCII, unicode and the size limits', () => {
    const ck = nip44.getConversationKey(a, pub(b))
    for (const msg of ['a', '{"v":1,"results":[]}', 'Café ☕ 🦄', 'x'.repeat(65535)]) {
      expect(nip44.decrypt(nip44.encrypt(msg, ck), ck)).toBe(msg)
    }
  })
  test('a fresh nonce each time, so equal plaintexts do not repeat', () => {
    const ck = nip44.getConversationKey(a, pub(b))
    expect(nip44.encrypt('same', ck)).not.toBe(nip44.encrypt('same', ck))
  })
  test('refuses an empty plaintext (where nmilat does not)', () => {
    const ck = nip44.getConversationKey(a, pub(b))
    expect(() => nip44.encrypt('', ck)).toThrow(CoreError)
  })
  // Current NIP-44: from 65536 bytes the length goes in an extended prefix
  // (two zero bytes, then a u32). Pinned against nostr-tools 2.24.1 with a
  // fixed key and nonce (sha256 of the payload).
  test.each([
    [65535, 'a', 87472, '6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84'],
    [65536, 'a', 87476, 'b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616'],
    [100000, 'b', 153012, '4f8c443b8117abbd206f817ee294cd8c4f7af12cf08b4c0067e3b94d11e2e6b9'],
  ])('%i bytes match nostr-tools byte for byte and round-trip', (len, ch, payloadLen, digest) => {
    const ck = fromHex('c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d')
    const nonce = fromHex('00'.repeat(31) + '01')
    const pt = ch.repeat(len)
    const payload = nip44.encrypt(pt, ck, nonce)
    expect(payload.length).toBe(payloadLen)
    expect(toHex(sha256(utf8(payload)))).toBe(digest)
    expect(nip44.decrypt(payload, ck)).toBe(pt)
  })
  test('an extended prefix carrying a length below 65536 is refused', () => {
    // Seal by hand a block whose prefix says "extended, 40 bytes": valid MAC, bad framing.
    const ck = nip44.getConversationKey(a, pub(b))
    const nonce = new Uint8Array(32).fill(3)
    const keys = hkdfExpand(sha256, ck, nonce, 76)
    const block = new Uint8Array(6 + nip44.calcPaddedLen(40))
    new DataView(block.buffer).setUint32(2, 40)
    block.set(utf8('x'.repeat(40)), 6)
    const ct = chacha20(keys.subarray(0, 32), keys.subarray(32, 44), block)
    const mac = hmac(sha256, keys.subarray(44, 76), concatBytes(nonce, ct))
    const payload = base64.encode(concatBytes(Uint8Array.of(2), nonce, ct, mac))
    expect(() => nip44.decrypt(payload, ck)).toThrow(/invalid padding/)
  })
  test('the wrong key or a flipped byte fails the MAC', () => {
    const ck = nip44.getConversationKey(a, pub(b))
    const payload = nip44.encrypt('secret', ck)
    expect(() => nip44.decrypt(payload, nip44.getConversationKey(a, pub(fill(3, 32))))).toThrow(/MAC/)
    const raw = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0))
    raw[40]! ^= 1
    expect(() => nip44.decrypt(btoa(String.fromCharCode(...raw)), ck)).toThrow(/MAC/)
  })
  test('refuses a future version and a #-prefixed payload', () => {
    const ck = nip44.getConversationKey(a, pub(b))
    const raw = Uint8Array.from(atob(nip44.encrypt('hi', ck)), (c) => c.charCodeAt(0))
    raw[0] = 3
    expect(() => nip44.decrypt(btoa(String.fromCharCode(...raw)), ck)).toThrow(/version/)
    expect(() => nip44.decrypt('#' + 'a'.repeat(200), ck)).toThrow(/version/)
  })
  test('padding follows the NIP (calc_padded_len)', () => {
    expect([1, 32, 33, 64, 65, 256, 257, 65535].map(nip44.calcPaddedLen)).toEqual([32, 32, 64, 64, 96, 256, 320, 65536])
  })
  test('refuses an invalid pubkey', () => {
    expect(() => nip44.getConversationKey(a, 'ff'.repeat(32))).toThrow(CoreError)
  })
})
