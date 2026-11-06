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
 * A Lightning invoice's currency (the bolt11 HRP between `ln` and the amount,
 * e.g. `bc`, `tb`, `bcrt`, `fc`) → the token HRP whose bills can pay it: every
 * Bitcoin network is `satscash`, every Flokicoin network is `lokicash`. The
 * currency encodes both the coin and its network; a redeem checks the coin.
 * The prefixes are the same ones `get_info` reports for segwit addresses.
 */
const INVOICE_CURRENCY_HRP: Readonly<Record<string, string>> = {
  bc: 'satscash',
  tb: 'satscash',
  bcrt: 'satscash',
  fc: 'lokicash',
  tf: 'lokicash',
  fcrt: 'lokicash',
}

/**
 * The token HRP a Lightning invoice of this currency must be paid from, or
 * undefined for a currency this build has no row for. An unlisted currency is
 * not assumed to match or mismatch any holding: only a listed one that names a
 * different HRP is a wrong-network invoice.
 */
export function hrpForInvoiceCurrency(currency: string): string | undefined {
  return Object.hasOwn(INVOICE_CURRENCY_HRP, currency) ? INVOICE_CURRENCY_HRP[currency] : undefined
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
