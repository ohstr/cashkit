// vectors/connection-key.json: NIP-IC ConnectionKeys and NIP-CW member
// connection keys: the hashing half. Canonical user ids (`canonicalUserId`,
// typed `kats`, `legacy`, `idna_corpus`) run in connection-key-idna.test.ts.
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import { connectionKeyFromSecret, connectionKeyFromAttested, toHex } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('connection-key.json')


describe('connection-key.json', () => {
  // An attested id is hashed as given; a typed one is hashed in its canonical form. A key with an error is the
  // hash of a spelling no implementation produces: the raw hash matches it, and the attested derivation refuses.
  const hashed = v.kats.filter((c: Json) => c.key !== undefined)
  test.each(named(hashed, (c, i) => `${c.id || '#'} ${c.mode} ${c.platform}:${c.input} #${i}`))('kat %s', (_, c: Json) => {
    const id = c.mode === 'typed' ? c.canonical : c.input
    expect(toHex(sha256(new TextEncoder().encode(`${c.platform}:${id}`)))).toBe(c.key)
    if (c.error !== undefined) expect(() => connectionKeyFromAttested(c.platform, id)).toThrow(c.error)
    else expect(connectionKeyFromAttested(c.platform, id)).toBe(c.key)
  })
  test.each(named(v.fromSecret, (c, i) => `${c.secret || '(empty)'} #${i}`))('connectionKeyFromSecret %s', (_, c: Json) => {
    if (c.error) expect(() => connectionKeyFromSecret(c.secret)).toThrow()
    else expect(connectionKeyFromSecret(c.secret).pubkey).toBe(c.pubkey)
  })
})
