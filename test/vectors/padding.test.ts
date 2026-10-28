// padding.json: envelope limits, padded sizes, validation and size estimates.
import { describe, expect, test } from 'vitest'
import {
  DEFAULT_LIMITS,
  encodeEnvelope,
  estimatedConsolidateItemBytes,
  estimatedWireBytes,
  maxSourcesForEnvelope,
  paddedSize,
  validateAnnouncedLimits,
  validateLimits,
  type Envelope,
} from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('padding.json')

/** nmilat's envelopeWith(n): n cash_status items with fixed proofs. */
function envelopeWith(n: number): Envelope {
  return {
    notAfter: 1760000060,
    nonce: '11'.repeat(32),
    replyTo: '22'.repeat(32),
    items: Array.from({ length: n }, (_, i) => ({
      id: `i${i}`,
      target: (i + 1).toString(16).padStart(64, '0'),
      method: 'cash_status',
      params: '{"scope":"mine"}',
      proof: '{"id":"aa","kind":23192,"tags":[]}',
      billProof: '{"id":"bb","kind":23193,"tags":[]}',
    })),
  }
}

describe('padding.json', () => {
  test('defaults', () => {
    expect({ ...DEFAULT_LIMITS }).toEqual(v.defaults)
  })
  test.each(named(v.paddedSize, (c, i) => `${c.id ?? i} ${c.limits.padBucketBytes}/${c.limits.maxEnvelopeBytes} n=${c.n}`))('paddedSize %s', (_: string, c: Json) => {
    if (c.error) expect(() => paddedSize(c.limits, c.n)).toThrow()
    else expect(paddedSize(c.limits, c.n)).toBe(c.padded)
  })
  test.each(named(v.validate))('validate: %s', (_: string, c: Json) => {
    if (c.validateError) expect(() => validateLimits(c.limits)).toThrow()
    else expect(() => validateLimits(c.limits)).not.toThrow()
    if (c.validateAnnouncedError) expect(() => validateAnnouncedLimits(c.limits)).toThrow()
    else expect(() => validateAnnouncedLimits(c.limits)).not.toThrow()
  })
  test.each(v.maxSourcesForEnvelope as [number, number][])('maxSourcesForEnvelope(%i) = %i', (n, want) => {
    expect(maxSourcesForEnvelope(n)).toBe(want)
  })
  test.each(v.estimatedConsolidateItemBytes as [number, number][])('estimatedConsolidateItemBytes(%i) = %i', (n, want) => {
    expect(estimatedConsolidateItemBytes(n)).toBe(want)
  })
  test.each(named(v.estimatedWireBytes, (c) => `${c.limits.maxEnvelopeBytes}`))('estimatedWireBytes %s', (_: string, c: Json) => {
    expect(estimatedWireBytes(c.limits)).toBe(c.wireBytes)
  })
  test.each(named(v.envelopeSizes, (c) => `${c.items} items`))('envelope size, %s', (_: string, c: Json) => {
    expect(new TextEncoder().encode(encodeEnvelope(envelopeWith(c.items), DEFAULT_LIMITS)).length).toBe(c.bytes)
  })
})
