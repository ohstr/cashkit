// vectors/connection-key.json: NIP-IC ConnectionKeys and NIP-CW member
// connection keys: the hashing half. Canonical user ids (`canonicalUserId`,
// typed `kats`, `legacy`, `idna_corpus`) run in connection-key-idna.test.ts.
import { describe, expect, test } from 'vitest'
import { connectionKeyFromSecret, newConnectionKey } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('connection-key.json')

// Genuine mismatch: nmilat refuses a secret that is not 64 lowercase hex; cashkit's fromHex reads uppercase.
const MISMATCH = new Set<string>()

describe('connection-key.json', () => {
  // An attested id is hashed as given; a typed one is hashed in its canonical form.
  const hashed = v.kats.filter((c: Json) => c.key !== undefined)
  test.each(named(hashed, (c, i) => `${c.id || '#'} ${c.mode} ${c.platform}:${c.input} #${i}`))('kat %s', (_, c: Json) => {
    expect(newConnectionKey(c.platform, c.mode === 'typed' ? c.canonical : c.input)).toBe(c.key)
  })
  test.each(named(v.fromSecret.filter((c: Json) => !MISMATCH.has(c.secret)), (c, i) => `${c.secret || '(empty)'} #${i}`))('connectionKeyFromSecret %s', (_, c: Json) => {
    if (c.error) expect(() => connectionKeyFromSecret(c.secret)).toThrow()
    else expect(connectionKeyFromSecret(c.secret).pubkey).toBe(c.pubkey)
  })
})
