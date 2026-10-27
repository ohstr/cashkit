// Resolving a NIP-IC ConnectionKey to a Nostr identity over the RelayPool
// port (§Verification Model). For display and linking only: a claim is
// checked by the Hub, never authorized by this.
import {
  evaluateConnection,
  KIND_ATTESTATION,
  KIND_IDENTITY_CONNECTION,
  verifyEvent,
  type Attestation,
  type AttestationRef,
  type AttestationSource,
  type NostrEvent,
  type VerificationState,
  type Verdict,
} from '../core/index.js'
import type { RelayPool } from './ports.js'
import { readEvents } from './relayIO.js'

export const RESOLVE_READ_MS = 5_000

export interface ResolveConnectionOptions {
  /** The IA pubkeys (hex) this client trusts. */
  readonly trustedIas: readonly string[]
  /** Where to query the 35521s; also where an attestation is fetched when its `e` tag has no relay hint. */
  readonly relays: readonly string[]
  /** Unix seconds. Default: now. */
  readonly now?: number
  /** Per relay read. Default 5 s. */
  readonly timeoutMs?: number
}

export interface ResolvedConnection {
  /** `verified` when one claim verifies; `unverified` when none was found; `spoofed` otherwise. */
  readonly state: VerificationState
  /** The verified pubkey; "" unless verified. */
  readonly pubkey: string
  /** The attestation that verified it; its `evidence` holds the user id and handle to show, never the claim's `content`. */
  readonly attestation?: Attestation
  /** One per claim found (or the single `unverified` one). */
  readonly verdicts: readonly Verdict[]
}

/** The latest event (ties: lowest id), as a replaceable event resolves. */
const latest = (evs: readonly NostrEvent[]) =>
  evs.reduce<NostrEvent | undefined>((best, e) => (best === undefined || e.created_at > best.created_at || (e.created_at === best.created_at && e.id < best.id) ? e : best), undefined)

/** Reads attestations, current events and deletions over a RelayPool. */
export function relayAttestationSource(pool: RelayPool, fallbackRelays: readonly string[], timeoutMs = RESOLVE_READ_MS): AttestationSource {
  const relaysOf = (ref: AttestationRef) => (ref.relay !== '' ? [ref.relay] : fallbackRelays)
  return {
    async fetch(ref) {
      const evs = await readEvents(pool, relaysOf(ref), { ids: [ref.eventId] }, timeoutMs)
      return evs.find((e) => e.id === ref.eventId)
    },
    async current(ia, key, ref) {
      const evs = await readEvents(pool, relaysOf(ref), { kinds: [KIND_ATTESTATION], authors: [ia], '#d': [key] }, timeoutMs)
      return latest(evs.filter((e) => e.kind === KIND_ATTESTATION && e.pubkey === ia && e.tags.some((t) => t[0] === 'd' && t[1] === key) && verifyEvent(e)))?.id
    },
    async deletedByAuthor(ia, eventId, ref) {
      const evs = await readEvents(pool, relaysOf(ref), { kinds: [5], authors: [ia], '#e': [eventId] }, timeoutMs)
      return evs.some((e) => e.kind === 5 && e.pubkey === ia && e.tags.some((t) => t[0] === 'e' && t[1] === eventId) && verifyEvent(e))
    },
  }
}

/**
 * Resolves `key` (64 lowercase hex): queries its 35521s, Deep-Checks every
 * referenced 35522 against the trusted IAs, and applies the latest-wins rule.
 */
export async function resolveConnection(pool: RelayPool, key: string, o: ResolveConnectionOptions): Promise<ResolvedConnection> {
  const timeoutMs = o.timeoutMs ?? RESOLVE_READ_MS
  const now = o.now ?? Math.floor(Date.now() / 1000)
  const claims = await readEvents(pool, o.relays, { kinds: [KIND_IDENTITY_CONNECTION], '#d': [key] }, timeoutMs)
  const trusted = new Set(o.trustedIas)
  const verdicts = await evaluateConnection(key, claims, relayAttestationSource(pool, o.relays, timeoutMs), (ia) => trusted.has(ia), now)
  const won = verdicts.find((v) => v.state === 'verified')
  if (won !== undefined) return { state: 'verified', pubkey: won.pubkey, ...(won.attestation !== undefined && { attestation: won.attestation }), verdicts }
  return { state: verdicts[0]!.state === 'unverified' ? 'unverified' : 'spoofed', pubkey: '', verdicts }
}
