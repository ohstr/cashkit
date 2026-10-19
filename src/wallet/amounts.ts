// Hub-reported amounts are checked before they are trusted. Port of cashctl
// cmd/cash_receive.go validateClaimedAmount and validateQuotedAmounts
// (auditC_ledger_amount_invariant, auditC_sdk_quote_unvalidated).
import { formatMillis, MAX_AMOUNT_MILLIS, type Token } from '../core/index.js'
import { CashkitError } from './errors.js'

export interface Quote {
  readonly amount: bigint
  readonly fee: bigint
  readonly net: bigint
  readonly expiresAt?: number
}

const refuse = (msg: string) => new CashkitError('invalid_input', msg)

/** A received amount: sane, and equal to the attested amount when the mint signature verified. */
export function validateClaimedAmount(tok: Pick<Token, 'attestedAmountMillis'>, verifiedMinter: string | undefined, amount: bigint): void {
  if (amount > MAX_AMOUNT_MILLIS) throw refuse(`the Hub reports an amount (${amount} millis) too large to be real — refusing to trust it`)
  if (verifiedMinter !== undefined && tok.attestedAmountMillis !== undefined && amount !== tok.attestedAmountMillis) {
    throw refuse(
      `the Hub reports ${formatMillis(amount)} for this token, but its own signed provenance attests to ${formatMillis(tok.attestedAmountMillis)} — refusing to trust either figure`,
    )
  }
}

/** A quote: every figure sane, net + fee = amount, and not above the attested amount. */
export function validateQuote(tok: Pick<Token, 'attestedAmountMillis'>, verifiedMinter: string | undefined, q: Quote): void {
  for (const [name, v] of [
    ['amount', q.amount],
    ['redeem fee', q.fee],
    ['net redeemable amount', q.net],
  ] as const) {
    if (v > MAX_AMOUNT_MILLIS) throw refuse(`the Hub quotes a ${name} (${v} millis) too large to be real — refusing to trust it`)
  }
  if (q.net + q.fee !== q.amount) {
    throw refuse(`the Hub's quote doesn't add up: ${q.net} millis net + ${q.fee} millis fee != ${q.amount} millis amount — refusing to trust it`)
  }
  if (verifiedMinter !== undefined && tok.attestedAmountMillis !== undefined && q.amount > tok.attestedAmountMillis) {
    throw refuse(
      `the Hub quotes ${formatMillis(q.amount)} for this bill, but its own signed provenance attests the whole bill is only ${formatMillis(tok.attestedAmountMillis)} — refusing to trust it`,
    )
  }
}

/** A caller-supplied amount: positive and within int64 millis. */
export function validateRequestedAmount(amount: bigint, what = 'amount'): void {
  if (amount <= 0n) throw new CashkitError('usage', `${what} must be greater than 0`)
  if (amount > MAX_AMOUNT_MILLIS) throw new CashkitError('invalid_input', `${what} is larger than any real bill`)
}
