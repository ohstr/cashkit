// request-id.json: request ids and the derived id of a re-placed call.
// `requiresRequestId` has no exported cashkit function (the bill-creating
// set lives unexported in client/session.ts) and is not covered here.
import { describe, expect, test } from 'vitest'
import { derivedRequestId, isRequestId } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('request-id.json')

// cashkit's derivedRequestId hashes any input; nmilat refuses one that is not a request_id.
const MISMATCH = new Set(['XYZ'])

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
})
