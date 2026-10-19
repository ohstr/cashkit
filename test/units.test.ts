// Cases from cashctl internal/output/output_test.go (TestFormatAmount,
// TestParseAmount*), which is what cashkit's amount handling must match.
import { describe, expect, test } from 'vitest'
import { formatAmount, formatMillis, MAX_AMOUNT_MILLIS, parseUnits, unitForHrp } from '../src/core/index.js'

test('display unit comes from the HRP', () => {
  expect(unitForHrp('lokicash')).toBe('loki')
  expect(unitForHrp('satscash')).toBe('sat')
  expect(unitForHrp('xyzcash')).toBeUndefined()
  expect(unitForHrp('toString')).toBeUndefined()
})

describe('formatAmount (TestFormatAmount)', () => {
  test.each([
    [0n, '0 loki'],
    [1000n, '1 loki'],
    [1500n, '1.5 loki'],
    [1005n, '1.005 loki'],
    [1050n, '1.05 loki'],
    [999n, '0.999 loki'],
    [1n, '0.001 loki'],
    [-1500n, '-1.5 loki'],
    [10_000_000n, '10000 loki'],
  ])('%s → %s', (m, s) => {
    expect(formatAmount(m, 'loki')).toBe(s)
  })
  test('formatMillis has no unit and handles the uint64 maximum', () => {
    expect(formatMillis(18446744073709551615n)).toBe('18446744073709551.615')
  })
})

describe('parseUnits (TestParseAmount)', () => {
  test.each([
    ['0', 0n],
    ['5', 5000n],
    ['0.5', 500n],
    ['1.234', 1234n],
    ['0.001', 1n],
    ['10000', 10_000_000n],
    ['1.5', 1500n],
    ['1.05', 1050n],
    ['  5  ', 5000n],
    ['.5', 500n], // TestParseAmount_LeadingDotIsHalfALoki
    ['007', 7000n],
  ])('%j → %s', (s, m) => {
    expect(parseUnits(s)).toBe(m)
  })

  // TestParseAmount_RejectsInvalid, plus forms Go's ParseUint also refuses.
  test.each(['', '   ', '-5', 'abc', '1.2.3', '1.', '1.2345', '5 loki', '5,000', '.', '+5', '1e3', '0x10', '１'])(
    'refuses %j',
    (s) => {
      expect(() => parseUnits(s)).toThrow()
    },
  )

  // TestParseAmount_RejectsOverflow: each must be refused, never wrapped.
  test.each(['18446744073709552', '18446744073709551', '9223372036854776', '9223372036854775.9', '9'.repeat(32)])(
    'refuses overflow %s',
    (s) => {
      expect(() => parseUnits(s)).toThrow()
    },
  )

  test('accepts the exact boundary (TestParseAmount_AcceptsTheExactBoundary)', () => {
    const maxUnits = MAX_AMOUNT_MILLIS / 1000n
    expect(parseUnits(maxUnits.toString())).toBe(maxUnits * 1000n)
    expect(parseUnits('9223372036854775.807')).toBe(MAX_AMOUNT_MILLIS)
    expect(() => parseUnits('9223372036854775.808')).toThrow()
    expect(() => parseUnits((maxUnits + 1_000_000n).toString())).toThrow()
  })

  test.each([0n, 1n, 5n, 999n, 1000n, 1234n, 10_000_000n])('round-trips %s through formatMillis', (m) => {
    expect(parseUnits(formatMillis(m))).toBe(m)
  })
})
