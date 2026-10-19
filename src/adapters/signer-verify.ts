// Shared check for external signers: what comes back must be the event that
// was asked for, signed by the identity that was promised.
import { verifyEvent, type EventTemplate, type NostrEvent } from '../core/index.js'

export function checkSigned(asked: EventTemplate, got: unknown, pubkey: string, who: string): NostrEvent {
  const e = got as NostrEvent
  if (e === null || typeof e !== 'object' || typeof e.id !== 'string' || typeof e.sig !== 'string') throw new Error(`${who}: the signer returned no event`)
  if (e.pubkey !== pubkey) throw new Error(`${who}: the signer signed as a different identity`)
  const same =
    e.kind === asked.kind &&
    e.created_at === asked.created_at &&
    e.content === asked.content &&
    JSON.stringify(e.tags) === JSON.stringify(asked.tags)
  if (!same) throw new Error(`${who}: the signer returned a different event than the one asked for`)
  if (!verifyEvent(e)) throw new Error(`${who}: the signer's signature does not verify`)
  return e
}
