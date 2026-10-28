// canonical-params.json: the params hash (ph) an item proof binds.
import { describe, expect, test } from 'vitest'
import { canonicalParams, paramsHash } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('canonical-params.json')

describe('canonical-params.json', () => {
  test.each(named(v.hash))('%s', (_: string, c: Json) => {
    if (c.error) {
      expect(() => paramsHash(c.params)).toThrow()
      return
    }
    expect(paramsHash(c.params)).toBe(c.hash)
    if (c.canonical !== undefined) expect(canonicalParams(c.params)).toBe(c.canonical)
  })
})
