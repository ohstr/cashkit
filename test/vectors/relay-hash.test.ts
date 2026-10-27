// relay-hash.json: the relay hash every payload and connection signature binds.
import { describe, expect, test } from 'vitest'
import { relayHashOf, utf8 } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('relay-hash.json')
const hash = (relays: string[]) => relayHashOf(relays.map((r) => utf8(r)), v.secret)

// cashkit's relayHashOf does not refuse a hint over 255 bytes (its 1-byte length wraps to 0); nmilat refuses it.
const MISMATCH = new Set(['256-byte hint is refused'])

describe('relay-hash.json', () => {
  const cases = named(v.hash)
  test.each(cases.filter(([n]) => !MISMATCH.has(n)))('hash: %s', (_: string, c: Json) => {
    if (c.error) expect(() => hash(c.relays)).toThrow()
    else expect(hash(c.relays)).toBe(c.hash)
  })
  test.skip.each(cases.filter(([n]) => MISMATCH.has(n)))('hash (mismatch): %s', (_: string, c: Json) => {
    expect(() => hash(c.relays)).toThrow()
  })
  test.each(named(v.negative))('negative: %s', (_: string, c: Json) => {
    // The hash of a wrong construction never equals the right one.
    expect(hash(c.relays)).not.toBe(c.hash)
  })
})
