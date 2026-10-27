// Unit tests for connection keys and NIP-44. Cases follow
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
import { connectionKeyFromSecret, CoreError, fromHex, newConnectionKey, nip44, toHex } from '../src/core/index.js'
import { fill } from './helpers.js'

const pub = (s: Uint8Array) => toHex(secp256k1.getPublicKey(s, true).subarray(1))


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
  // NIP-44 v2 caps a plaintext at 65535 bytes (a u16 length prefix). Pinned
  // against nostr-tools 2.24.1 with a fixed key and nonce (sha256 of the payload).
  test('65535 bytes match nostr-tools byte for byte and round-trip; 65536 is refused', () => {
    const ck = fromHex('c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d')
    const nonce = fromHex('00'.repeat(31) + '01')
    const pt = 'a'.repeat(65535)
    const payload = nip44.encrypt(pt, ck, nonce)
    expect(payload.length).toBe(87472)
    expect(toHex(sha256(utf8(payload)))).toBe('6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84')
    expect(nip44.decrypt(payload, ck)).toBe(pt)
    expect(() => nip44.encrypt('a'.repeat(65536), ck, nonce)).toThrow(CoreError)
  })
  test('a zero length prefix is refused', () => {
    // Seal by hand a block whose u16 prefix is 0: valid MAC, bad framing.
    const ck = nip44.getConversationKey(a, pub(b))
    const nonce = new Uint8Array(32).fill(3)
    const keys = hkdfExpand(sha256, ck, nonce, 76)
    const block = new Uint8Array(2 + 32)
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
