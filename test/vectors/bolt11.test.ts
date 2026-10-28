// bolt11.json: BOLT-11 decoding of what cashkit reads from an invoice.
import { describe, expect, test } from 'vitest'
import { decodeBolt11 } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

describe('bolt11.json', () => {
  test.each(named(load('bolt11.json').decode))('decode: %s', (_: string, c: Json) => {
    if (c.error !== undefined || c.overflow) {
      expect(() => decodeBolt11(c.invoice)).toThrow()
      return
    }
    // The fields nmilat reads; cashkit also reads the creation time, expiry and payee.
    const { currency, amountMillis, description, descriptionHash, paymentHash } = decodeBolt11(c.invoice)
    expect({ currency, amountMillis, description, descriptionHash, paymentHash }).toEqual({ ...c.want, amountMillis: BigInt(c.want.amountMillis) })
  })
  test("the BOLT 11 example's payee recovers from its signature", () => {
    const c = load('bolt11.json').decode.find((x: Json) => x.name === 'real lnbc no amount (BOLT 11 example)')
    expect(decodeBolt11(c.invoice).payee).toBe('03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad')
  })
})
