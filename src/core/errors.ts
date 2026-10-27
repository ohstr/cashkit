/** Why a `core` function refused its input. */
export type CoreErrorCode =
  | 'invalid_hex'
  | 'invalid_bech32'
  | 'mixed_case'
  | 'invalid_tlv'
  | 'invalid_field'
  | 'invalid_key'
  | 'invalid_payload'
  | 'invalid_request'
  /** The online check: `get_info` names another Hub identity than the string's TLV 4. */
  | 'hub_identity_mismatch'
  /** The online check: `get_info`'s `chain` is not the string's TLV 6, or is missing. */
  | 'chain_mismatch'
  /** A cash secret whose order buyer key is zero or not below the group order (NIP-CO §The Buyer Key). */
  | 'buyer_key_unusable'
  /** Not a segwit address of the expected chain and network. */
  | 'invalid_address'
  /** Withdrawal addresses (NIP-CASH §Quoting a Withdrawal). */
  | 'address_malformed'
  | 'address_network'
  | 'address_no_witness'
  | 'script_type_not_paid'
  /** A withdraw quote, answer or receipt that does not check out. */
  | 'quote_malformed'
  | 'quote_mismatch'
  | 'receipt_invalid'
  | 'withdraw_fee_invalid'
  /** A payout transaction that does not pay what the receipt says. */
  | 'tx_mismatch'
  /** A Cash Zap that fails a verification rule (NIP-CZ). */
  | 'zap_invalid'

/**
 * The error every `core` function throws for bad input. Messages name the
 * field and the rule, never the value: inputs here are often secrets.
 */
export class CoreError extends Error {
  override readonly name = 'CoreError'
  readonly code: CoreErrorCode

  constructor(code: CoreErrorCode, message: string) {
    super(message)
    this.code = code
  }
}

/**
 * How an external signer (NIP-07, NIP-46, NIP-LS) failed, from the error
 * string's prefix: `denied: ` is a refusal by the signer's policy (do not
 * retry the same request), `invalid: ` a malformed request or unknown
 * method, anything else a failure while carrying out an allowed request.
 */
export type SignerErrorCode = 'denied' | 'invalid' | 'failed'

export class SignerError extends Error {
  override readonly name = 'SignerError'
  readonly code: SignerErrorCode
  constructor(code: SignerErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.code = code
  }
}

/** A signer's error string as a `SignerError`, prefixed with `who` (e.g. `signer-nip46`). */
export function signerErrorFrom(who: string, text: string): SignerError {
  const code: SignerErrorCode = text.startsWith('denied: ') ? 'denied' : text.startsWith('invalid: ') ? 'invalid' : 'failed'
  return new SignerError(code, `${who}: ${text}`)
}
