/** Why a transport function refused. */
export type TransportErrorCode =
  | 'limits_invalid'
  | 'envelope_malformed'
  | 'envelope_version'
  | 'envelope_no_items'
  | 'envelope_too_large'
  | 'too_many_items'
  | 'verify_budget_exceeded'
  | 'duplicate_item_id'
  | 'duplicate_item'
  | 'envelope_expired'
  | 'envelope_too_far_ahead'
  | 'proof_malformed'
  | 'proof_wrong_target'
  | 'proof_wrong_hub'
  | 'proof_wrong_method'
  | 'proof_wrong_params'
  | 'proof_wrong_envelope'
  | 'proof_stale'
  | 'proof_signature'
  | 'response_malformed'
  | 'response_mismatch'
  | 'unknown_item_id'
  | 'announcement_malformed'
  | 'announcement_author'
  | 'announcement_signature'
  | 'mixed_hubs'
  | 'method_not_servable'
  | 'pow_aborted'

/** Thrown by `transport`. Messages never carry params or secrets. */
export class TransportError extends Error {
  override readonly name = 'TransportError'
  readonly code: TransportErrorCode

  constructor(code: TransportErrorCode, message: string) {
    super(`transport: ${message}`)
    this.code = code
  }
}
