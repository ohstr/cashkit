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
