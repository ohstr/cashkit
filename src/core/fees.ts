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
