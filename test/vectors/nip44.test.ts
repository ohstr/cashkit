// nip44.json: the NIP-44 v2 vectors (paulmillr/nip44) as nmilat checks them.
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import { fromHex, nip44, toHex } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const file = load('nip44.json')
const v = file.v2
// The extended prefix lets cashkit encrypt these lengths, which the file lists
// as invalid (and records as a divergence of nmilat from cashkit).
const MISMATCH = new Set([65536, 100000, 10000000])

describe('nip44.json', () => {
  test('records what nmilat checks and where it diverges', () => {
    expect(file.checkedAgainstNmilat.length).toBeGreaterThan(0)
    expect(file.nmilatDivergences).toHaveLength(3)
  })
  test.each(named(v.valid.get_conversation_key, (_c, i) => String(i)))('conversation key %s', (_: string, c: Json) => {
    expect(toHex(nip44.getConversationKey(fromHex(c.sec1), c.pub2))).toBe(c.conversation_key)
  })
  test.each(v.valid.calc_padded_len as [number, number][])('calcPaddedLen(%i) = %i', (len: number, padded: number) => {
    expect(nip44.calcPaddedLen(len)).toBe(padded)
  })
  test.each(named(v.valid.encrypt_decrypt, (_c, i) => String(i)))('encrypt/decrypt %s', (_: string, c: Json) => {
    const pub2 = toHex(secp256k1.getPublicKey(fromHex(c.sec2), true).subarray(1))
    expect(toHex(nip44.getConversationKey(fromHex(c.sec1), pub2))).toBe(c.conversation_key)
    expect(nip44.encrypt(c.plaintext, fromHex(c.conversation_key), fromHex(c.nonce))).toBe(c.payload)
    expect(nip44.decrypt(c.payload, fromHex(c.conversation_key))).toBe(c.plaintext)
  })
  test.each(named(v.valid.encrypt_decrypt_long_msg, (_c, i) => String(i)))('long message %s', (_: string, c: Json) => {
    const plaintext = c.pattern.repeat(c.repeat)
    expect(toHex(sha256(new TextEncoder().encode(plaintext)))).toBe(c.plaintext_sha256)
    const payload = nip44.encrypt(plaintext, fromHex(c.conversation_key), fromHex(c.nonce))
    expect(toHex(sha256(new TextEncoder().encode(payload)))).toBe(c.payload_sha256)
    expect(nip44.decrypt(payload, fromHex(c.conversation_key))).toBe(plaintext)
  })
  test.each((v.invalid.encrypt_msg_lengths as number[]).filter((n) => !MISMATCH.has(n)))('refuses to encrypt %i bytes', (len: number) => {
    expect(() => nip44.encrypt('a'.repeat(len), new Uint8Array(32).fill(1))).toThrow()
  })
  test.each(named(v.invalid.decrypt, (c) => c.note))('refuses to decrypt: %s', (_: string, c: Json) => {
    expect(() => nip44.decrypt(c.payload, fromHex(c.conversation_key))).toThrow()
  })
  test.each(named(v.invalid.get_conversation_key, (c) => c.note))('refuses a conversation key: %s', (_: string, c: Json) => {
    expect(() => nip44.getConversationKey(fromHex(c.sec1), c.pub2)).toThrow()
  })
})
