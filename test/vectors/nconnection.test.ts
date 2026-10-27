// vectors/nconnection.json: nconnection1 (NIP-IC) decode and encode, and K-NCN-1.
import { describe, expect, test } from 'vitest'
import { decodeNConnection, encodeNConnection, type NConnection } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('nconnection.json')

// Genuine mismatches: cashkit ports nmilat's earlier, lenient decoder (last key or platform wins,
// truncated tail ignored, platform and relay text unchecked); nmilat now refuses each of these.
const MISMATCH = new Set([
  'decode two keys', // nmilat: "more than one ConnectionKey"; cashkit: decodes, the last key wins
  'decode two platforms', // nmilat: "more than one platform"; cashkit: decodes, the last platform wins
  'decode platform Discord', // nmilat: platform must match [a-z0-9._-]+; cashkit: decodes "Discord"
  'decode platform git:hub', // nmilat: platform must match [a-z0-9._-]+; cashkit: decodes "git:hub"
  'decode overrun', // nmilat: "TLV at offset 34 runs past the end"; cashkit: ignores the truncated tail
  'decode lone trailing byte', // nmilat: "truncated TLV at offset 34"; cashkit: ignores the trailing byte
  'encode platform Discord', // nmilat: refuses the platform; cashkit: encodes it
  'encode non-ASCII relay', // nmilat: refuses a non-ASCII relay; cashkit: encodes it as UTF-8
])
const plainNc = (c: NConnection) => ({ connectionKey: c.connectionKey, relays: [...c.relays], platform: c.platform })
const fieldsOf = (f: Json): NConnection => ({ connectionKey: f.connectionKey, relays: f.relays ?? [], platform: f.platform ?? '' })

describe('nconnection.json', () => {
  test('K-NCN-1 round trip', () => {
    expect(encodeNConnection(fieldsOf(v.kat.fields))).toBe(v.kat.string)
    expect(plainNc(decodeNConnection(v.kat.string))).toEqual(v.kat.fields)
  })
  test.each(named(v.decode).filter(([n]) => !MISMATCH.has(`decode ${n}`)))('decode %s', (_, c: Json) => {
    if (c.error) expect(() => decodeNConnection(c.input)).toThrow()
    else expect(plainNc(decodeNConnection(c.input))).toEqual(c.want)
  })
  test.each(named(v.encode).filter(([n]) => !MISMATCH.has(`encode ${n}`)))('encode %s', (_, c: Json) => {
    if (c.error) expect(() => encodeNConnection(fieldsOf(c.fields))).toThrow()
    else expect(encodeNConnection(fieldsOf(c.fields))).toBe(c.output)
  })
})
