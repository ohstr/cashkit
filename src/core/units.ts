// Amounts are bigint millis everywhere, never number (design §2.1). The
// display unit comes from the token's HRP; 1 unit = 1000 millis.
import { trimSpace } from './bytes.js'
import { CoreError } from './errors.js'

export const MILLIS_PER_UNIT = 1000n

const UNITS: Readonly<Record<string, string>> = {
  lokicash: 'loki',
  satscash: 'sat',
}

/** The display unit for a token HRP, or undefined for an unknown HRP. */
export function unitForHrp(hrp: string): string | undefined {
  return Object.hasOwn(UNITS, hrp) ? UNITS[hrp] : undefined
}

/**
 * Formats millis as whole units plus up to three decimals, trailing zeros
 * dropped: 21000n → "21", 1500n → "1.5", 1n → "0.001".
 */
export function formatMillis(millis: bigint): string {
  const neg = millis < 0n
  const abs = neg ? -millis : millis
  const whole = abs / MILLIS_PER_UNIT
  const frac = abs % MILLIS_PER_UNIT
  const fracText = frac === 0n ? '' : '.' + frac.toString().padStart(3, '0').replace(/0+$/, '')
  return `${neg ? '-' : ''}${whole}${fracText}`
}

/** `formatMillis` plus the unit: 1500n, "loki" → "1.5 loki". */
export function formatAmount(millis: bigint, unit: string): string {
  return `${formatMillis(millis)} ${unit}`
}

/** The largest amount accepted: int64 millis, as cashctl caps it. */
export const MAX_AMOUNT_MILLIS = (1n << 63n) - 1n

/**
 * Parses a decimal unit amount ("21", "1.5", "0.001", ".5") into millis, as
 * cashctl's `output.ParseAmount` does: surrounding whitespace is trimmed, a
 * missing whole part reads as 0, and a sign, a trailing dot, more than three
 * decimals, separators or anything above `MAX_AMOUNT_MILLIS` is refused
 * rather than reinterpreted.
 */
export function parseUnits(text: string): bigint {
  const s = trimSpace(text)
  const m = /^([0-9]*)(?:\.([0-9]{1,3}))?$/.exec(s)
  if (s === '' || s === '.' || m === null) {
    throw new CoreError('invalid_field', 'amount: expected a decimal with at most 3 decimal places')
  }
  const total = BigInt(m[1] || '0') * MILLIS_PER_UNIT + BigInt((m[2] ?? '').padEnd(3, '0'))
  if (total > MAX_AMOUNT_MILLIS) throw new CoreError('invalid_field', 'amount: too large')
  return total
}
