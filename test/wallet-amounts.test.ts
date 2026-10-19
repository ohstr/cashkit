// Amount bounds (design §11.2). Ported from cashctl
// cmd/auditC_sdk_quote_unvalidated_test.go (TestAuditC_ValidateQuotedAmounts_Matrix),
// cmd/auditC_ledger_amount_invariant_test.go and cash_receive_test.go
// (TestValidateClaimedAmount_*).
import { describe, expect, test } from 'vitest'
import { MAX_AMOUNT_MILLIS } from '../src/core/index.js'
import { validateClaimedAmount, validateQuote, validateRequestedAmount } from '../src/wallet/amounts.js'

const MINTER = 'aa'.repeat(32)
const code = (f: () => void) => {
  try {
    f()
    return 'ok'
  } catch (e) {
    return (e as { code: string }).code
  }
}

describe('validateClaimedAmount', () => {
  test('matching verified provenance is accepted (TestValidateClaimedAmount_MatchingProvenanceIsAccepted)', () => {
    expect(code(() => validateClaimedAmount({ attestedAmountMillis: 500n }, MINTER, 500n))).toBe('ok')
  })
  test('a mismatch against verified provenance is refused (TestValidateClaimedAmount_RejectsMismatchAgainstVerifiedProvenance)', () => {
    expect(code(() => validateClaimedAmount({ attestedAmountMillis: 500n }, MINTER, 501n))).toBe('invalid_input')
  })
  test('unverified provenance is not compared (TestValidateClaimedAmount_UnverifiedProvenanceIsNotCompared)', () => {
    expect(code(() => validateClaimedAmount({ attestedAmountMillis: 500n }, undefined, 9n))).toBe('ok')
  })
  test('an absurdly large amount is refused (TestValidateClaimedAmount_RejectsAbsurdlyLargeAmount)', () => {
    expect(code(() => validateClaimedAmount({}, undefined, MAX_AMOUNT_MILLIS + 1n))).toBe('invalid_input')
    expect(code(() => validateClaimedAmount({}, undefined, MAX_AMOUNT_MILLIS))).toBe('ok')
  })
})

describe('validateQuote (TestAuditC_ValidateQuotedAmounts_Matrix)', () => {
  const cases: [string, Parameters<typeof validateQuote>, string][] = [
    ['consistent', [{}, undefined, { amount: 1000n, fee: 10n, net: 990n }], 'ok'],
    ['net + fee short of amount', [{}, undefined, { amount: 1000n, fee: 10n, net: 980n }], 'invalid_input'],
    ['net + fee over amount', [{}, undefined, { amount: 1000n, fee: 10n, net: 995n }], 'invalid_input'],
    ['amount above int64', [{}, undefined, { amount: MAX_AMOUNT_MILLIS + 1n, fee: 0n, net: MAX_AMOUNT_MILLIS + 1n }], 'invalid_input'],
    ['fee above int64', [{}, undefined, { amount: 1n, fee: MAX_AMOUNT_MILLIS + 1n, net: 0n }], 'invalid_input'],
    ['amount above the verified attestation', [{ attestedAmountMillis: 500n }, MINTER, { amount: 600n, fee: 0n, net: 600n }], 'invalid_input'],
    ['amount below the attestation (a partial claim) is fine', [{ attestedAmountMillis: 500n }, MINTER, { amount: 400n, fee: 0n, net: 400n }], 'ok'],
    ['unverified attestation is not compared', [{ attestedAmountMillis: 500n }, undefined, { amount: 600n, fee: 0n, net: 600n }], 'ok'],
  ]
  for (const [name, args, want] of cases) test(name, () => expect(code(() => validateQuote(...args))).toBe(want))
})

test('requested amounts are positive and within int64 millis', () => {
  expect(code(() => validateRequestedAmount(0n))).toBe('usage')
  expect(code(() => validateRequestedAmount(-1n))).toBe('usage')
  expect(code(() => validateRequestedAmount(MAX_AMOUNT_MILLIS + 1n))).toBe('invalid_input')
  expect(code(() => validateRequestedAmount(1n))).toBe('ok')
})
