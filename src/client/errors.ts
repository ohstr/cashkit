// Client errors. Each is a distinct class because a caller must act on the
// difference, not parse a message.

export type ClientErrorCode =
  | 'no_announcement'
  | 'no_relay'
  | 'incomplete_reply'
  | 'reply_malformed'
  | 'timeout'
  | 'item_too_large'
  | 'bad_input'
  | 'not_served'
  | 'wallet_error'
  | 'partial_progress'
  | 'claim_not_found'
  | 'spent'
  /** The Hub answered with a success this client could not decode: it ran. */
  | 'undecodable_result'
  /** Signing one item took the whole not_after window (design §3). Nothing was sent. */
  | 'signer_too_slow'

export class ClientError extends Error {
  override readonly name: string = 'ClientError'
  readonly code: ClientErrorCode
  constructor(code: ClientErrorCode, message: string, options?: { cause?: unknown }) {
    super(`client: ${message}`, options)
    this.code = code
  }
}

/**
 * The Hub gave this item no answer. It may or may not have been applied, so
 * ask (cash_status) before resending a spend.
 */
export class NotServedError extends ClientError {
  override readonly name = 'NotServedError'
  readonly method: string
  constructor(method: string, options?: { cause?: unknown }) {
    super('not_served', `the hub returned no answer for this ${method}; it may or may not have been applied, so ask before retrying`, options)
    this.method = method
  }
}

/**
 * The first step of a two-step flow landed and the second did not. Holds the
 * landed result: for a consolidate it is the only copy of the new bill.
 */
export class PartialProgressError extends ClientError {
  override readonly name = 'PartialProgressError'
  readonly transferred?: unknown
  readonly consolidated?: unknown
  constructor(landed: { transferred?: unknown; consolidated?: unknown }, cause: unknown) {
    super(
      'partial_progress',
      landed.transferred !== undefined
        ? 'interim transfer landed, but the following consolidate failed'
        : 'interim consolidate landed, but the following transfer failed',
      { cause },
    )
    if (landed.transferred !== undefined) this.transferred = landed.transferred
    if (landed.consolidated !== undefined) this.consolidated = landed.consolidated
  }
}

/** The Hub (or wallet) answered with a refusal and a reason. */
export class WalletError extends ClientError {
  override readonly name = 'WalletError'
  readonly method: string
  readonly walletCode: string
  readonly walletMessage: string
  constructor(method: string, walletCode: string, walletMessage = '') {
    super('wallet_error', `${method}: ${walletCode}${walletMessage ? `: ${walletMessage}` : ''}`)
    this.method = method
    this.walletCode = walletCode
    this.walletMessage = walletMessage
  }
}
