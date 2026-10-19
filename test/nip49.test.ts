// NIP-49 against the spec's own test vector, plus round trips and refusals.
import { describe, expect, test } from 'vitest'
import { CoreError, nip49Decrypt, nip49Encrypt, toHex } from '../src/core/index.js'
import { fill } from './helpers.js'

// NIP-49 §Test Data: password "nostr", log_n 16.
const VECTOR = 'ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p'
const VECTOR_KEY = '3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683'

describe('nip49', () => {
  test('decrypts the NIP-49 test vector', () => {
    const r = nip49Decrypt(VECTOR, 'nostr')
    expect(toHex(r.secretKey)).toBe(VECTOR_KEY)
    expect(r.logN).toBe(16)
  })
  test('round-trips with a cheap log_n, and normalizes the password to NFKC', () => {
    const key = fill(0x11, 32)
    const enc = nip49Encrypt(key, 'Å', { logN: 4, keySecurity: 0x01 })
    expect(enc.startsWith('ncryptsec1')).toBe(true)
    const r = nip49Decrypt(enc, 'Å')
    expect(r.secretKey).toEqual(key)
    expect(r.keySecurity).toBe(0x01)
  })
  test('a wrong password is refused', () => {
    const enc = nip49Encrypt(fill(0x11, 32), 'right', { logN: 4 })
    expect(() => nip49Decrypt(enc, 'wrong')).toThrow(CoreError)
  })
  test('refuses a short key and a bad log_n', () => {
    expect(() => nip49Encrypt(fill(1, 31), 'p')).toThrow(/32 bytes/)
    expect(() => nip49Encrypt(fill(1, 32), 'p', { logN: 0 })).toThrow(/log_n/)
  })
})
