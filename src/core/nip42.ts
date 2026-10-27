// NIP-42 client authentication: the kind-22242 event a client signs to
// answer a relay's AUTH challenge.
import type { EventTemplate } from './nip01.js'

export const KIND_CLIENT_AUTH = 22242

/** The unsigned answer to `challenge` from `relay`. */
export function authEventTemplate(relay: string, challenge: string, now: number): EventTemplate {
  return { kind: KIND_CLIENT_AUTH, created_at: now, tags: [['relay', relay], ['challenge', challenge]], content: '' }
}

/** Whether a relay refusal (`OK` false or `CLOSED`) asks the client to authenticate first. */
export const isAuthRequired = (message: string | undefined): boolean => message !== undefined && message.startsWith('auth-required:')
