// request-id.json: request ids and the derived id of a re-placed call.
import { describe, expect, test } from 'vitest'
import { derivedRequestId, isRequestId, requiresRequestId } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('request-id.json')

// cashkit's derivedRequestId hashes any input; nmilat refuses one that is not a request_id.
const MISMATCH = new Set<string>()

describe('request-id.json', () => {
  test.each(named(v.valid, (c) => c.id ?? JSON.stringify(c.input)))('valid: %s', (_: string, c: Json) => {
    expect(isRequestId(c.input)).toBe(c.valid)
  })
  const derived = named(v.derived, (c) => c.id ?? c.replaced)
  test.each(derived.filter(([n]) => !MISMATCH.has(n)))('derived: %s', (_: string, c: Json) => {
    if (c.error) expect(() => derivedRequestId(c.replaced)).toThrow()
    else expect(derivedRequestId(c.replaced)).toBe(c.derived)
  })
  test.skip.each(derived.filter(([n]) => MISMATCH.has(n)))('derived (mismatch): %s', (_: string, c: Json) => {
    expect(() => derivedRequestId(c.replaced)).toThrow()
  })
  test.each(named(v.privateTransportRequiresRequestId, (c) => c.method))('privateTransportRequiresRequestId: %s', (_: string, c: Json) => {
    expect(requiresRequestId(c.method)).toBe(c.value)
  })
})
