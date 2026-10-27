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
    expect(decodeBolt11(c.invoice)).toEqual({ ...c.want, amountMillis: BigInt(c.want.amountMillis) })
  })
})
