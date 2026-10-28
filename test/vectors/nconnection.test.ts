// vectors/nconnection.json: nconnection1 (NIP-IC) decode and encode, and K-NCN-1.
import { describe, expect, test } from 'vitest'
import { decodeNConnection, encodeNConnection, type NConnection } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('nconnection.json')

// Genuine mismatches: cashkit ports nmilat's earlier, lenient decoder (last key or platform wins,
// truncated tail ignored, platform and relay text unchecked); nmilat now refuses each of these.
const MISMATCH = new Set<string>()
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
