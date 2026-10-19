// Local coherence checks for an envelope. Port of nmilat
// nipcash/transport/validate.go. A Hub answers every one of these mistakes
// by silent omission, so this is the only place they can be diagnosed.
import { paramsHash } from './canonical.js'
import { hasProof, isBearer, type Envelope } from './envelope.js'
import { TransportError } from './errors.js'
import { verifyItemProof } from './proof.js'

const SERVABLE = new Set(['cash_status', 'cash_redeem', 'cash_transfer', 'cash_consolidate', 'create_circle_wallet'])

/** Whether a method may travel over the private transport. `mint_cash` may not. */
export const isServableMethod = (method: string): boolean => SERVABLE.has(method)

/**
 * Checks that every item's proof authorizes exactly that item, for this Hub
 * and this envelope, at `now`. A cash-mode item has no proof and must not
 * carry one.
 */
export function validateEnvelope(e: Envelope, hub: string, now: number): void {
  if (!/^[0-9a-f]{64}$/.test(hub)) throw new TransportError('announcement_malformed', 'hub pubkey must be 64 lowercase hex characters')
  if (e.items.length === 0) throw new TransportError('envelope_no_items', 'envelope carries no items')
  for (const item of e.items) {
    if (!isServableMethod(item.method)) throw new TransportError('method_not_servable', `method ${item.method} is not servable over the private transport`)
    if (isBearer(item)) {
      if (hasProof(item)) throw new TransportError('envelope_malformed', 'a cash-mode item authorizes with its secret alone and must not carry a proof')
      continue
    }
    const hash = paramsHash(item.params ?? '')
    try {
      verifyItemProof(item.proof ?? '', { target: item.target, hub, method: item.method, paramsHash: hash, nonce: e.nonce, notAfter: e.notAfter }, now)
    } catch (err) {
      if (err instanceof TransportError && err.code === 'proof_wrong_hub') {
        throw new TransportError('mixed_hubs', 'envelope mixes items bound to different hubs')
      }
      throw err
    }
  }
}
