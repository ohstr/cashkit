// A slice's redeem fee (NIP-CASH §Fees): what the recipient pays out of the
// slice, never the routing cost. Port of nmilat nipcash.RedeemFee.
import { CoreError } from './errors.js'

/** `redeem_fee_ppm` is parts per million, bounded at the whole slice. */
export const MAX_FEE_PPM = 1_000_000n

/** The largest millis amount the wire carries (an unsigned 64-bit integer). */
export const MAX_U64 = (1n << 64n) - 1n

/** min(amount, base + ⌊ppm · amount / 1e6⌋). Refuses a ppm above 1,000,000 or a negative input. */
export function redeemFeeQuote(amount: bigint, base: bigint, ppm: bigint): bigint {
  if (amount < 0n || base < 0n || ppm < 0n) throw new CoreError('invalid_field', 'fee inputs must be non-negative')
  if (ppm > MAX_FEE_PPM) throw new CoreError('invalid_field', 'redeem_fee_ppm must be at most 1000000')
  const fee = base + (ppm * amount) / 1_000_000n
  return fee < amount ? fee : amount
}

/** The x-only part of a 64- or 66-hex key, lowercase; '' for anything else. */
const xOnlyOf = (k: string): string => (/^[0-9a-fA-F]{64}$/.test(k) ? k.toLowerCase() : /^0[23][0-9a-fA-F]{64}$/.test(k) ? k.slice(2).toLowerCase() : '')

/**
 * The amount a redeem invoice should carry for a row (port of nmilat
 * RedeemInvoiceMillis): the full amount when the invoice's payee is the
 * bill's own minter (a same-node payment, fee-free), else the net
 * redeemable amount. Keys compare by their x-only part. The Hub decides
 * with its own payment path; a wrong guess is refused.
 */
export function redeemInvoiceMillis(row: { readonly amount_millis: bigint; readonly net_redeemable_millis: bigint }, payee: string | undefined, minter: string | undefined): { millis: bigint; sameNode: boolean } {
  const m = xOnlyOf(minter ?? '')
  if (m !== '' && m === xOnlyOf(payee ?? '')) return { millis: row.amount_millis, sameNode: true }
  return { millis: row.net_redeemable_millis, sameNode: false }
}
