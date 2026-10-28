// Wallet errors. Ported from cashctl internal/output/errors_test.go,
// nwc_errors_test.go and cmd/nwc_errors_spend_test.go (names in comments).
import { describe, expect, test } from 'vitest'
import { CoreError } from '../src/core/index.js'
import { ClientError, NotServedError, WalletError } from '../src/client/index.js'
import {
  CashkitError,
  classifyReadError,
  classifySpendError,
  codeForNwc,
  exitCode,
  fromWalletError,
  isDefiniteRefusal,
  type ErrorCode,
} from '../src/wallet/errors.js'

describe('codes', () => {
  test('each code has its own exit code (TestExitCode_EachClassifierMapsToItsOwnCode)', () => {
    const table: Record<ErrorCode, number> = {
      internal: 1, usage: 2, invalid_input: 3, not_found: 4, conflict: 5, network: 6, auth: 7, indeterminate: 8, exists: 9, spent: 10,
    }
    for (const [code, n] of Object.entries(table)) expect(exitCode(code as ErrorCode)).toBe(n)
    expect(new CashkitError('spent', 'x').exitCode).toBe(10)
  })
  test('only conflict and network are retryable (TestRetryableCodes)', () => {
    const retryable = (['usage', 'invalid_input', 'not_found', 'conflict', 'network', 'auth', 'indeterminate', 'exists', 'spent', 'internal'] as const).filter((c) => new CashkitError(c, '').retryable)
    expect(retryable).toEqual(['conflict', 'network'])
  })
  test('NWC mapping (nwc_errors.go nwcErrorCode)', () => {
    expect(codeForNwc('BAD_REQUEST')).toBe('invalid_input')
    expect(codeForNwc('NOT_FOUND')).toBe('not_found')
    for (const c of ['RESTRICTED', 'UNAUTHORIZED', 'EXPIRED']) expect(codeForNwc(c)).toBe('auth')
    expect(codeForNwc('RATE_LIMITED')).toBe('conflict')
    expect(codeForNwc('NOT_READY')).toBe('network')
    expect(codeForNwc('WALLET_EXISTS')).toBe('exists')
    for (const c of ['INSUFFICIENT_BALANCE', 'NOT_IMPLEMENTED', 'PAYMENT_FAILED', 'INTERNAL', 'OTHER', 'SOME_FUTURE_CODE']) expect(codeForNwc(c)).toBe('internal')
  })
})

describe('fromWalletError', () => {
  test('a known code translates and keeps the raw message (TestNWCError_KnownCodeMapsAndTranslates, …TranslatedCodeStillPreservesRawMessage)', () => {
    expect(codeForNwc('QUOTA_EXCEEDED')).toBe('conflict')
    const e = fromWalletError(new WalletError('pay_invoice', 'QUOTA_EXCEEDED', 'raw wallet message'))
    expect(e).toMatchObject({ code: 'conflict', nwcCode: 'QUOTA_EXCEEDED', rawMessage: 'raw wallet message' })
    expect(e.message).toMatch(/spending limit/)
    expect(e.toJSON()).toMatchObject({ code: 'conflict', nwc_code: 'QUOTA_EXCEEDED' })
  })
  test('EXPIRED is auth, exit 7 (TestNWCError_ExpiredMapsToAuth)', () => {
    const e = fromWalletError(new WalletError('m', 'EXPIRED', '...'))
    expect([e.code, e.exitCode]).toEqual(['auth', 7])
  })
  test('on a cash token EXPIRED talks about the token (TestNWCErrorForCashToken_ExpiredDoesNotCallItAWallet)', () => {
    const e = fromWalletError(new WalletError('m', 'EXPIRED', 'raw'), { cashToken: true })
    expect(e.message).toMatch(/cash token has expired/)
    expect(e.code).toBe('auth')
  })
  test('other codes read the same for a cash token (TestNWCErrorForCashToken_OtherCodesMatchNWCError)', () => {
    for (const c of ['BAD_REQUEST', 'RATE_LIMITED', 'INTERNAL', 'SOME_FUTURE_CODE']) {
      const w = new WalletError('m', c, `raw ${c}`)
      expect(fromWalletError(w, { cashToken: true }).message).toBe(fromWalletError(w).message)
    }
  })
  test('an unknown code falls back to the sanitized wallet message (TestNWCError_UnknownCodeFallsBackToWalletMessage)', () => {
    const e = fromWalletError(new WalletError('m', 'SOME_FUTURE_CODE', 'a message‮ cashkit does not know'))
    expect(e.code).toBe('internal')
    expect(e.message).toContain('cashkit does not know')
    expect(e.message).not.toContain('‮')
  })
})

describe('classifySpendError (TestClassifyCashSpendErr)', () => {
  const cases: [string, unknown, ErrorCode][] = [
    ['timeout', new ClientError('timeout', 'no reply'), 'indeterminate'],
    ['omission', new NotServedError('cash_transfer'), 'indeterminate'],
    ['incomplete reply', new ClientError('incomplete_reply', 'x'), 'indeterminate'],
    ['undecodable result', new ClientError('undecodable_result', 'x'), 'indeterminate'],
    ['no relay took it', new ClientError('no_relay', 'refused'), 'network'],
    ['hub decline', new WalletError('cash_transfer', 'EXPIRED', 'gone'), 'auth'],
    ['refused before send', new CoreError('invalid_request', 'cash source'), 'invalid_input'],
    ['item too large', new ClientError('item_too_large', 'x'), 'invalid_input'],
    ['no private transport', new ClientError('no_announcement', 'x'), 'network'],
    ['anything else', new Error('boom'), 'indeterminate'],
  ]
  for (const [name, err, want] of cases) {
    test(name, () => {
      const e = classifySpendError(err, 'transfer', ['h-a'])
      expect(e.code).toBe(want)
      if (want === 'indeterminate') expect(e.message).toContain('wallet.status({ holdings: ["h-a"] })')
      expect(isDefiniteRefusal(err)).toBe(want !== 'indeterminate')
    })
  }
  test('a CashkitError passes through', () => {
    const e = new CashkitError('spent', 'x')
    expect(classifySpendError(e, 'transfer')).toBe(e)
  })
})

describe('classifyReadError', () => {
  test('a timeout is neutral and retryable (TestClassifyCashTokenNWCErr_TimeoutIsNeutralAndRetryable)', () => {
    const e = classifyReadError(new ClientError('timeout', 'x'))
    expect(e.code).toBe('network')
    expect(e.retryable).toBe(true)
  })
  test('an omission explains the information-free answer (explainNoAnswer)', () => {
    const e = classifyReadError(new NotServedError('cash_status'))
    expect(e.code).toBe('network')
    expect(e.message).toMatch(/deliberately does not distinguish/)
  })
  test('a refusal is read by its code, never its message (NIP-CASH §Errors)', () => {
    for (const msg of ['no slice of this bill matches this cash secret', 'neither a slice proof nor a cash secret', 'anything at all']) {
      expect(classifyReadError(new WalletError('cash_status', 'NOT_FOUND', msg)).code).toBe('not_found')
      expect(classifyReadError(new WalletError('cash_status', 'BAD_REQUEST', msg)).code).toBe('invalid_input')
    }
  })
  test('other wallet refusals map through the table', () => {
    expect(classifyReadError(new WalletError('cash_status', 'NOT_FOUND', 'no slice of this bill is registered for the identity that signed this item')).code).toBe('not_found')
  })
})

describe('CashkitError', () => {
  test('input is redacted, recovery is verbatim (§10)', () => {
    const secret = 'ab'.repeat(32)
    const e = new CashkitError('internal', 'x', { input: `cash:${secret}`, recovery: `save this: lokicash1xyz#${secret}` })
    expect(e.input).not.toContain(secret)
    expect(e.recovery).toContain(secret)
    expect(JSON.stringify(e.toJSON())).not.toContain(`cash:${secret}`)
  })
  test('toJSON never includes the cause chain', () => {
    const e = new CashkitError('network', 'x', { cause: new Error('secret detail') })
    expect(JSON.stringify(e.toJSON())).not.toContain('secret detail')
  })
})

