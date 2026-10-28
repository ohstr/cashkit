// Local coherence checks for an envelope. Port of nmilat
// nipcash/transport/validate.go. A Hub answers every one of these mistakes
// by silent omission, so this is the only place they can be diagnosed.
import { paramsHash } from './canonical.js'
import { hasBillProof, hasProof, type Envelope } from './envelope.js'
import { TransportError } from './errors.js'
import { verifyBillProof, verifyItemProof, type ProofBinding } from './proof.js'

const SERVABLE = new Set(['cash_status', 'cash_redeem', 'cash_withdraw_quote', 'cash_withdraw', 'cash_transfer', 'cash_consolidate', 'cash_lookup', 'cash_order', 'create_circle_wallet'])

/** Whether a method may travel over the private transport. `mint_cash` may not. */
export const isServableMethod = (method: string): boolean => SERVABLE.has(method)

/**
 * Checks that every item's item proof (when it has one) and bill proof
 * authorize exactly that item, for this Hub and this envelope, at `now`. A proofless item's shape was checked when
 * the envelope was encoded (`bearerShapeOK`).
 */
export function validateEnvelope(e: Envelope, hub: string, now: number): void {
  if (!/^[0-9a-f]{64}$/.test(hub)) throw new TransportError('announcement_malformed', 'hub pubkey must be 64 lowercase hex characters')
  if (e.items.length === 0) throw new TransportError('envelope_no_items', 'envelope carries no items')
  for (const item of e.items) {
    if (!isServableMethod(item.method)) throw new TransportError('method_not_servable', `method ${item.method} is not servable over the private transport`)
    const binding: ProofBinding = { target: item.target, hub, method: item.method, paramsHash: paramsHash(item.params ?? ''), nonce: e.nonce, notAfter: e.notAfter }
    if (hasProof(item)) check(() => verifyItemProof(item.proof ?? '', binding, now))
    // Every item carries a bill proof bound to the same six fields; its signer
    // is the bill's connection key, which only the Hub can match.
    if (!hasBillProof(item)) throw new TransportError('envelope_malformed', `item ${item.id} has no bill proof`)
    check(() => verifyBillProof(item.billProof ?? '', binding, now))
  }
}

function check(verify: () => unknown): void {
  try {
    verify()
  } catch (err) {
    if (err instanceof TransportError && err.code === 'proof_wrong_hub') {
      throw new TransportError('mixed_hubs', 'envelope mixes items bound to different hubs')
    }
    throw err
  }
}
