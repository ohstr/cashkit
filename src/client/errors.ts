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
  | 'claim_not_found'
  | 'spent'
  /** The Hub answered with a success this client could not decode: it ran. */
  | 'undecodable_result'
  /** Signing one item took the whole not_after window (design §3). Nothing was sent. */
  | 'signer_too_slow'
  /** The Circle Wallet Hub's announcement could not be found or verified, so no join was sent (NIP-CW §Finding the Private Transport). */
  | 'join_unavailable'
  /** The Circle Wallet Hub is not taking joins (`accepting` false). Nothing was signed. */
  | 'not_accepting'
  /** The Order connection sells nothing (a retired one answers `{}`). Nothing was written or sent. */
  | 'order_not_sold'
  /** The Order connection does not list `cash_order` on the private transport. Nothing was written or sent. */
  | 'order_unavailable'
  /** A zap bill's provenance needs its Cash Zap's fields, which were not given. Nothing was sent. */
  | 'no_zap_event'
  /** The token carries no mint signature that verifies, so its Hub cannot be identified. Nothing was sent. */
  | 'no_provenance'
  /** The Hub announces no usable max_request_age, so it takes no bill-creating call. Nothing was sent. */
  | 'hub_unusable'
  /** Too little time was left before the deadline after the write-ahead. Nothing was sent. */
  | 'deadline_too_close'
  /** The items do not fit the one envelope the caller required. Nothing was sent. */
  | 'single_envelope_required'
  /** Not a connection string of the expected kind, or a malformed one. Nothing was dialled. */
  /** Proof of work the relays ask for exceeds the mining budget. Nothing was sent. */
  | 'pow_too_hard'
  | 'connection_invalid'
  /** `get_info` names another Hub identity or chain than the connection string. */
  | 'connection_mismatch'
  /** The string's signature does not verify, and the user did not confirm it. Nothing was sent. */
  | 'connection_unverified'

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
