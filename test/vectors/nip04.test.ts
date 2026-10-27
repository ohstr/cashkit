// nip04.json: NIP-04 decryption and byte-for-byte re-encryption, and refusals.
import { base64 } from '@scure/base'
import { describe, expect, test } from 'vitest'
import { fromHex, getPublicKey, nip04 } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('nip04.json')

describe('nip04.json', () => {
  test.each(named(v.valid))('decrypts, and re-encrypts byte for byte: %s', (_: string, c: Json) => {
    expect(nip04.decrypt(c.payload, fromHex(c.receiverSecret), c.senderPubkey)).toBe(c.plaintext)
    const iv = base64.decode(c.payload.split('?iv=')[1])
    expect(nip04.encrypt(c.plaintext, fromHex(c.senderSecret), c.receiverPubkey, iv)).toBe(c.payload)
  })
  test.each(named(v.invalid))('refuses: %s', (_: string, c: Json) => {
    expect(c.nmilat).toBe('refused')
    expect(() => nip04.decrypt(c.payload, fromHex(`${'00'.repeat(31)}02`), getPublicKey(fromHex(`${'00'.repeat(31)}01`)))).toThrow()
  })
})
