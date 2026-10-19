// The one error type the wallet throws (design §8). Codes, exit codes and the
// NWC mapping are cashctl's table (internal/output/errors.go, nwc_errors.go),
// so an app and an agent driving cashctl branch the same way. Classification
// of Hub answers ports cmd/nwc_errors.go.
import { CoreError, redact, sanitize } from '../core/index.js'
import { ClientError, NotServedError, PartialProgressError, WalletError } from '../client/index.js'

export type ErrorCode =
  | 'usage'
  | 'invalid_input'
  | 'not_found'
  | 'conflict'
  | 'network'
  | 'auth'
  | 'indeterminate'
  | 'exists'
  | 'spent'
  | 'internal'

const EXIT_CODES: Readonly<Record<ErrorCode, number>> = {
  internal: 1,
  usage: 2,
  invalid_input: 3,
  not_found: 4,
  conflict: 5,
  network: 6,
  auth: 7,
  // 8, not a reuse: a script must not mistake "maybe applied" for any outcome it already handles.
  indeterminate: 8,
  exists: 9,
  spent: 10,
}

/** The process exit code cashctl uses for `code`. */
export const exitCode = (code: ErrorCode): number => EXIT_CODES[code]

export interface CashkitErrorOptions {
  /** Echoed back to the caller; always passed through `redact` (§10). */
  readonly input?: string
  readonly nwcCode?: string
  /** The wallet's own message, as cashctl's `--json` prints it. */
  readonly rawMessage?: string
  readonly hint?: string
  /** Verbatim handoffs for a confirmed Hub mutation the local commit missed. */
  readonly recovery?: string
  readonly recoveryHandoffs?: readonly string[]
  readonly cause?: unknown
}

export class CashkitError extends Error {
  override readonly name = 'CashkitError'
  readonly code: ErrorCode
  readonly input?: string
  readonly nwcCode?: string
  readonly rawMessage?: string
  readonly hint?: string
  /** Deliberately never redacted or truncated (§10): it is the only copy. */
  readonly recovery?: string
  readonly recoveryHandoffs?: readonly string[]

  constructor(code: ErrorCode, message: string, o: CashkitErrorOptions = {}) {
    super(message, o.cause !== undefined ? { cause: o.cause } : undefined)
    this.code = code
    if (o.input !== undefined) this.input = redact(o.input)
    if (o.nwcCode !== undefined) this.nwcCode = o.nwcCode
    if (o.rawMessage !== undefined) this.rawMessage = sanitize(o.rawMessage)
    if (o.hint !== undefined) this.hint = o.hint
    if (o.recovery !== undefined) this.recovery = o.recovery
    if (o.recoveryHandoffs !== undefined) this.recoveryHandoffs = [...o.recoveryHandoffs]
  }

  /** Only a conflict or a network failure is worth retrying as is. */
  get retryable(): boolean {
    return this.code === 'conflict' || this.code === 'network'
  }

  get exitCode(): number {
    return exitCode(this.code)
  }

  /** cashctl's `--json` error shape. The cause chain is never included. */
  toJSON(): Record<string, unknown> {
    return {
      error: this.rawMessage ?? this.message,
      code: this.code,
      ...(this.nwcCode !== undefined && { nwc_code: this.nwcCode }),
      ...(this.input !== undefined && this.input !== '' && { input: this.input }),
      ...(this.hint !== undefined && { hint: this.hint }),
      ...(this.recovery !== undefined && { recovery: this.recovery }),
    }
  }
}

export const isCashkitError = (e: unknown): e is CashkitError => e instanceof CashkitError

/** NIP-47 / NIP-CW error code → cashkit code (`nwcErrorCode`). */
export function codeForNwc(nwcCode: string): ErrorCode {
  switch (nwcCode) {
    case 'BAD_REQUEST':
      return 'invalid_input'
    case 'NOT_FOUND':
      return 'not_found'
    case 'RESTRICTED':
    case 'UNAUTHORIZED':
    case 'EXPIRED':
      return 'auth'
    case 'RATE_LIMITED':
      return 'conflict'
    case 'NOT_SENT': // the client never sent it (design §3): retrying is safe
    case 'NOT_READY':
      return 'network'
    case 'WALLET_EXISTS':
      return 'exists'
    default:
      return 'internal'
  }
}

// cashctl's nwcErrorMessages, verbatim apart from the product name.
const NWC_MESSAGES: Readonly<Record<string, string>> = {
  RATE_LIMITED: "You're making requests too quickly. Wait a moment and try again.",
  NOT_IMPLEMENTED: "This wallet doesn't support that operation.",
  INSUFFICIENT_BALANCE: 'Not enough balance to do that.',
  QUOTA_EXCEEDED: "You've hit this wallet's spending limit for this period.",
  RESTRICTED: "The wallet declined: this connection isn't permitted to do that (its permissions or limits rule it out, not a login problem).",
  UNAUTHORIZED: 'Not authorized for that.',
  INTERNAL: 'The wallet hit an internal error. Try again.',
  UNSUPPORTED_ENCRYPTION: "This wallet uses an encryption scheme cashkit doesn't support.",
  OTHER: 'The wallet declined this request.',
  PAYMENT_FAILED: 'The payment failed.',
  NOT_FOUND: "Couldn't find that.",
  EXPIRED: 'This wallet has expired and can no longer send payments.',
  BAD_REQUEST: "That request wasn't valid.",
  NOT_READY: "The Hub isn't ready yet. Wait a moment and try again.",
  WALLET_EXISTS: 'You already hold a wallet from this circle.',
}

// On a cash token, EXPIRED is the token's own deadline, not "this wallet".
const CASH_TOKEN_NWC_MESSAGES: Readonly<Record<string, string>> = {
  EXPIRED: 'This cash token has expired and can no longer be claimed or spent.',
}

/** A wallet's refusal, with cashctl's plain-language message. */
export function fromWalletError(err: WalletError, o: { cashToken?: boolean; input?: string } = {}): CashkitError {
  const friendly = (o.cashToken ? CASH_TOKEN_NWC_MESSAGES[err.walletCode] : undefined) ?? NWC_MESSAGES[err.walletCode]
  return new CashkitError(codeForNwc(err.walletCode), friendly ?? (sanitize(err.walletMessage) || err.walletCode), {
    nwcCode: err.walletCode,
    rawMessage: err.walletMessage,
    cause: err,
    ...(o.input !== undefined && { input: o.input }),
  })
}

/** The send never left: there was no Hub to send to, or no relay took it. */
export function isNotSent(err: unknown): boolean {
  return err instanceof ClientError && (err.code === 'no_announcement' || err.code === 'no_relay')
}

/** Refused locally before anything went out (cashctl `rejectedBeforeSend`). */
export function isRejectedBeforeSend(err: unknown): boolean {
  if (err instanceof CoreError) return true
  return err instanceof ClientError && (err.code === 'bad_input' || err.code === 'item_too_large' || err.code === 'signer_too_slow')
}

/** A decodable refusal or a pre-send failure: nothing moved (`isDefiniteRefusal`). */
export function isDefiniteRefusal(err: unknown): boolean {
  if (err instanceof CashkitError) return err.code !== 'indeterminate' && err.code !== 'internal'
  return err instanceof WalletError || isNotSent(err) || isRejectedBeforeSend(err)
}

/**
 * A failed spend (`classifyCashSpendErr`): a decodable refusal keeps its
 * code; a send that never left is `network`; a local refusal is
 * `invalid_input`; anything else may have been applied, so `indeterminate`.
 */
export function classifySpendError(err: unknown, verb: string, holdingIds: readonly string[] = []): CashkitError {
  if (err instanceof CashkitError) return err
  const input = holdingIds.length === 1 ? holdingIds[0] : undefined
  const withInput = input !== undefined ? { input } : {}
  if (err instanceof WalletError) return fromWalletError(err, { cashToken: true, ...withInput })
  if (isNotSent(err)) return new CashkitError('network', `the ${verb} was not sent, so nothing moved: ${messageOf(err)}`, { cause: err })
  if (isRejectedBeforeSend(err)) {
    return new CashkitError('invalid_input', `this ${verb} was refused before it was sent, so nothing moved: ${messageOf(err)}`, { cause: err, ...withInput })
  }
  return new CashkitError(
    'indeterminate',
    `the Hub gave no answer to this ${verb}, so whether it was applied is unknown. Do not resend it: check first with ${statusHint(holdingIds)}: ${messageOf(err)}`,
    { cause: err, hint: statusHint(holdingIds), ...withInput },
  )
}

/**
 * A failed read about a bill (`classifyCashTokenNWCErr`): reads move nothing,
 * so the worst case is `network`, never `indeterminate`.
 */
export function classifyReadError(err: unknown, holdingId?: string): CashkitError {
  if (err instanceof CashkitError) return err
  const withInput = holdingId !== undefined ? { input: holdingId } : {}
  if (err instanceof WalletError) {
    const refusal = explainCashSecretRefusal(err)
    if (refusal !== undefined) return new CashkitError('invalid_input', refusal, { cause: err, nwcCode: err.walletCode, rawMessage: err.walletMessage, ...withInput })
    return fromWalletError(err, { cashToken: true, ...withInput })
  }
  if (err instanceof NotServedError) {
    return new CashkitError(
      'network',
      'the Hub gave no answer for this bill. Any of these produces exactly this result, and the Hub deliberately does not distinguish them: ' +
        'the bill does not name you, it has already been spent, it has expired, or the Hub is unreachable. ' +
        'Do not resend a redeem or transfer blind, since an unanswered spend may already have happened.',
      { cause: err, ...withInput },
    )
  }
  if (err instanceof ClientError && err.code === 'timeout') {
    return new CashkitError('network', 'the Hub did not answer in time, which says nothing about this bill\'s state. Asking again is safe.', { cause: err, ...withInput })
  }
  return new CashkitError('network', messageOf(err), { cause: err, ...withInput })
}

/**
 * cashctl `explainCashSecretRefusal`, matched on the message whatever the
 * code: lokihub answers a wrong cash secret with NOT_FOUND "no slice of this
 * bill matches this cash secret" for every method (nip47/private_dispatch.go),
 * where cashctl expects BAD_REQUEST.
 */
export function explainCashSecretRefusal(err: WalletError): string | undefined {
  if (err.walletCode !== 'BAD_REQUEST' && err.walletCode !== 'NOT_FOUND') return undefined
  if (err.walletMessage.includes('neither a slice proof nor a cash secret')) {
    return 'this is a cash-mode bill, and its Hub answers about it only with its cash secret: pass it as <token>#<secret>'
  }
  if (err.walletMessage.includes('matches this cash secret')) {
    return "the cash secret does not match this bill: check the part after '#' in <token>#<secret>"
  }
  return undefined
}

/** A Hub "different Hubs" decline (`isCrossHubSourcesDecline`). */
export function isCrossHubDecline(err: unknown): boolean {
  const msg = err instanceof WalletError ? err.walletMessage : err instanceof CashkitError ? (err.rawMessage ?? err.message) : ''
  return msg.toLowerCase().includes('same cash hub')
}

export const isExpiredDecline = (err: unknown): boolean => err instanceof WalletError && err.walletCode === 'EXPIRED'

export { PartialProgressError }

const statusHint = (ids: readonly string[]) =>
  ids.length === 0 ? 'wallet.status()' : `wallet.status({ holdings: [${ids.map((i) => JSON.stringify(i)).join(', ')}] })`

function messageOf(err: unknown): string {
  return redact(err instanceof Error ? err.message : String(err))
}
