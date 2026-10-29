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
import { readEvents, readEventsAnswered } from './relayIO.js'

export const RESOLVE_READ_MS = 5_000

export interface ResolveConnectionOptions {
  /** The IA pubkeys (hex) this client trusts. */
  readonly trustedIas: readonly string[]
  /**
   * Where to query the 35521s and each IA's NIP-65 relay list; also where an
   * attestation is fetched when its `e` tag has no relay hint.
   */
  readonly relays: readonly string[]
  /** An IA's relays as the trust configuration names them (hex IA pubkey to relays), in place of its NIP-65 list. */
  readonly iaRelays?: Readonly<Record<string, readonly string[]>>
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

/** The write relays (unmarked or `write`) of the newest validly signed kind 10002 by `author`. */
function writeRelays(events: readonly NostrEvent[], author: string): string[] {
  const list = latest(events.filter((e) => e.kind === 10002 && e.pubkey === author && verifyEvent(e)))
  return [...new Set(list?.tags.filter((t) => t[0] === 'r' && typeof t[1] === 'string' && t[1] !== '' && (t[2] === undefined || t[2] === 'write')).map((t) => t[1]!) ?? [])]
}

/**
 * Reads attestations, current events and deletions over a RelayPool (NIP-IC
 * §Verification Model, step 3). The referenced 35522 is fetched from the
 * claim's relay hint; whether it is the IA's current attestation and
 * whether the IA deleted it are asked of the IA's own relays only: the
 * write relays of its NIP-65 list (read from `listRelays`) or those
 * `iaRelays` names. The hint is the claimant's choice, so it never answers
 * those two. An IA with no relays, or none that answers, makes both checks
 * fail, and the attestation does not count.
 */
export function relayAttestationSource(pool: RelayPool, listRelays: readonly string[], timeoutMs = RESOLVE_READ_MS, iaRelays: Readonly<Record<string, readonly string[]>> = {}): AttestationSource {
  const relaysOf = (ref: AttestationRef) => (ref.relay !== '' ? [ref.relay] : listRelays)
  const lists = new Map<string, Promise<string[]>>()
  const relaysOfIa = (ia: string): Promise<string[]> => {
    let r = lists.get(ia)
    if (r === undefined) {
      const named = Object.hasOwn(iaRelays, ia) ? iaRelays[ia] : undefined
      r = named !== undefined ? Promise.resolve([...named]) : readEvents(pool, listRelays, { kinds: [10002], authors: [ia] }, timeoutMs).then((evs) => writeRelays(evs, ia))
      lists.set(ia, r)
    }
    return r
  }
  /** Events from the IA's relays; throws when the IA has none or none answered. */
  const askIa = async (ia: string, filter: Parameters<typeof readEvents>[2]): Promise<NostrEvent[]> => {
    const relays = await relaysOfIa(ia)
    if (relays.length === 0) throw new Error(`no relays are known for IA ${ia}`)
    const r = await readEventsAnswered(pool, relays, filter, timeoutMs)
    if (r.answered.length === 0) throw new Error(`none of IA ${ia}'s relays answered`)
    return r.events
  }
  return {
    async fetch(ref) {
      const evs = await readEvents(pool, relaysOf(ref), { ids: [ref.eventId] }, timeoutMs)
      return evs.find((e) => e.id === ref.eventId)
    },
    async current(ia, key) {
      const evs = await askIa(ia, { kinds: [KIND_ATTESTATION], authors: [ia], '#d': [key] })
      return latest(evs.filter((e) => e.kind === KIND_ATTESTATION && e.pubkey === ia && e.tags.some((t) => t[0] === 'd' && t[1] === key) && verifyEvent(e)))?.id
    },
    async deletedByAuthor(ia, eventId) {
      const evs = await askIa(ia, { kinds: [5], authors: [ia], '#e': [eventId] })
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
  const verdicts = await evaluateConnection(key, claims, relayAttestationSource(pool, o.relays, timeoutMs, o.iaRelays), (ia) => trusted.has(ia), now)
  const won = verdicts.find((v) => v.state === 'verified')
  if (won !== undefined) return { state: 'verified', pubkey: won.pubkey, ...(won.attestation !== undefined && { attestation: won.attestation }), verdicts }
  return { state: verdicts[0]!.state === 'unverified' ? 'unverified' : 'spoofed', pubkey: '', verdicts }
}
