// vectors/npv1.json: NIP-IC npv1 challenge tokens. cashkit has no npv1
// builder or verifier; only the bech32 TLV framing every token shares runs
// here: the npv1 HRP, and TLV 0 carrying the vector's hash.
import { describe, expect, test } from 'vitest'
import { toHex } from '../../src/core/index.js'
import { decodeBech32TLV, readTLVs } from '../../src/core/tlv.js'
import { load, named, type Json } from './helpers.js'

const v = load('npv1.json')

describe('npv1.json framing', () => {
  test.each(named(v.token.filter((c: Json) => !c.error), (c, i) => `${c.id ?? ''} #${i}`))('token %s', (_, c: Json) => {
    const { hrp, data } = decodeBech32TLV(c.token)
    expect(hrp).toBe('npv1')
    expect(readTLVs(data).map((e) => [e.type, toHex(e.value)])).toEqual([[0, c.hash]])
  })
  test.each(named(v.verify.filter((c: Json) => !c.error)))('verify %s decodes to the K-NPV-1 hash', (_, c: Json) => {
    const { hrp, data } = decodeBech32TLV(c.token)
    expect(hrp).toBe('npv1')
    expect(toHex(readTLVs(data)[0]!.value)).toBe(v.token[0].hash)
  })
})
