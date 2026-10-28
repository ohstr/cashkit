// NIP-IC §Verification Model: Kind 35521 identity connections and the Deep
// Check of the attestations they reference. Port of nmilat nipIC
// identity_connection.go ParseIdentityConnection and evaluate.go Evaluate.
// The relay reads are behind `AttestationSource`; nothing here does I/O.
import { parseAttestation, type Attestation } from './attestation.js'
import { CoreError } from './errors.js'
import { decodeGoStruct, parseGoJSON } from './gojson.js'
import { validPlatformName } from './idna.js'
import { verifyEvent, type NostrEvent } from './nip01.js'

export const KIND_IDENTITY_CONNECTION = 35521

/** How far ahead of the verifier's clock an attestation may be dated and still count, in seconds. */
export const MAX_ATTESTATION_FUTURE = 900

/** An `e` tag of a 35521: the attestation's id and the IA relay it is fetched from. */
export interface AttestationRef {
  readonly eventId: string
  /** "" when the tag has no relay hint. */
  readonly relay: string
}

/** A parsed Kind 35521. On its own it is an unverified claim. */
export interface IdentityConnection {
  readonly event: NostrEvent
  readonly connectionKey: string
  readonly platform: string
  /** One or more, in tag order. */
  readonly attestations: readonly AttestationRef[]
}

const HEX64 = /^[0-9a-f]{64}$/
const bad = (msg: string) => new CoreError('invalid_payload', msg)

/** The listed tags with a value, each at most once (a repeated one is refused). */
function singleTags(event: NostrEvent, names: readonly string[]): Map<string, string> {
  const out = new Map<string, string>()
  for (const tag of event.tags) {
    if (tag.length < 2 || !names.includes(tag[0]!)) continue
    if (out.has(tag[0]!)) throw bad(`nipIC: invalid tag: ${JSON.stringify(tag[0])} tag repeated`)
    out.set(tag[0]!, tag[1]!)
  }
  return out
}

/**
 * Parses a Kind 35521: kind, signature, `d` once as a bare ConnectionKey (64
 * lowercase hex), `platform` once as a valid name, and at least one `e`.
 */
export function parseIdentityConnection(event: NostrEvent): IdentityConnection {
  if (event.kind !== KIND_IDENTITY_CONNECTION) throw bad(`nipIC: unexpected event kind: expected kind ${KIND_IDENTITY_CONNECTION}, got ${event.kind}`)
  if (!verifyEvent(event)) throw bad('nipIC: invalid event signature')
  const tags = singleTags(event, ['d', 'platform'])
  const d = tags.get('d') ?? ''
  const platform = tags.get('platform') ?? ''
  if (d === '') throw bad('nipIC: missing required tag: #d tag is required for Kind 35521')
  if (d.includes(':')) throw bad(`nipIC: #d tag must be a bare ConnectionKey, not platform-prefixed: ${JSON.stringify(d)}`)
  if (!HEX64.test(d)) throw bad('nipIC: invalid tag: d is not a ConnectionKey')
  if (platform === '') throw bad('nipIC: missing required tag: platform tag is required for Kind 35521')
  if (!validPlatformName(platform)) throw bad('nipIC: platform name must match [a-z0-9._-]+')
  const attestations = event.tags.filter((t) => t.length >= 2 && t[0] === 'e').map((t) => ({ eventId: t[1]!, relay: t[2] ?? '' }))
  if (attestations.length === 0) throw bad('nipIC: missing required tag: a 35521 references at least one attestation (e)')
  return { event, connectionKey: d, platform, attestations }
}

/**
 * The relay reads a Deep Check needs. Each may reject or return nothing; the
 * reference then does not count.
 */
export interface AttestationSource {
  /** The event a reference names, from its relay hint. */
  fetch(ref: AttestationRef): Promise<NostrEvent | undefined>
  /** The id of the IA's current 35522 for `key` on the IA relay `ref` names. */
  current(ia: string, key: string, ref: AttestationRef): Promise<string | undefined>
  /** Whether `ia` itself deleted `eventId` (NIP-09), on the IA relay `ref` names. */
  deletedByAuthor(ia: string, eventId: string, ref: AttestationRef): Promise<boolean>
}

export type VerificationState = 'verified' | 'unverified' | 'spoofed'

/**
 * The outcome for one 35521 (or, with none at all, the single `unverified`
 * verdict). `pubkey` is the claim's author, `attestation` the one that
 * verified it, `reasons` why the other references did not count.
 */
export interface Verdict {
  readonly state: VerificationState
  /** "" for the `unverified` verdict. */
  readonly pubkey: string
  readonly attestation?: Attestation
  readonly reasons: readonly string[]
}

/** a later than b: the latest created_at, ties to the lowest event id. */
const newer = (a: Attestation, b: Attestation) => (a.event.created_at !== b.event.created_at ? a.event.created_at > b.event.created_at : a.event.id < b.event.id)

const hasD = (ev: NostrEvent, key: string) => ev.tags.some((t) => t.length >= 2 && t[0] === 'd' && t[1] === key)

const PROFILE_FIELDS = { display_name: 'string', picture: 'string', user_id: 'string', username: 'string' } as const

/** A `content` naming another account than the evidence makes the claim spoofed. */
function contentMismatch(claim: IdentityConnection, att: Attestation): string {
  if (claim.event.content === '') return ''
  let c: Record<string, unknown>
  try {
    c = decodeGoStruct(parseGoJSON(claim.event.content, 'content'), PROFILE_FIELDS, 'content')
  } catch {
    return ''
  }
  const userId = (c['user_id'] as string | undefined) ?? ''
  const username = (c['username'] as string | undefined) ?? ''
  if ((userId !== '' && userId !== att.evidence.userId) || (username !== '' && username !== att.evidence.username)) {
    return `${att.event.id}: content names another account than the evidence`
  }
  return ''
}

const settle = async <T>(p: () => Promise<T>): Promise<T | undefined> => {
  try {
    return await p()
  } catch {
    return undefined
  }
}

/** Step 3 for one reference: the attestation when it counts, else why not. */
async function deepCheck(claim: IdentityConnection, ref: AttestationRef, src: AttestationSource, trusted: (ia: string) => boolean, now: number): Promise<Attestation | string> {
  const ev = await settle(() => src.fetch(ref))
  if (ev === undefined) return `${ref.eventId}: not fetched`
  if (ev.id !== ref.eventId) return `${ref.eventId}: the relay returned another event`
  let att: Attestation
  try {
    att = parseAttestation(ev)
  } catch (err) {
    return `${ref.eventId}: ${(err as Error).message}`
  }
  if (!trusted(att.event.pubkey)) return `${ref.eventId}: not a trusted IA`
  if (att.event.pubkey === claim.event.pubkey) return `${ref.eventId}: self-attested`
  if (att.connectionKey !== claim.connectionKey || att.platform !== claim.platform) return `${ref.eventId}: d or platform differs from the claim`
  if (att.userPubkey !== claim.event.pubkey) return `${ref.eventId}: p names another pubkey`
  if (att.expiresAt !== undefined && now >= att.expiresAt) return `${ref.eventId}: expired`
  if (att.event.created_at > now + MAX_ATTESTATION_FUTURE) return `${ref.eventId}: dated more than 15 minutes ahead`
  const deleted = await settle(() => src.deletedByAuthor(att.event.pubkey, att.event.id, ref))
  if (deleted !== false) return `${ref.eventId}: deleted by its IA, or the deletion check failed`
  const current = await settle(() => src.current(att.event.pubkey, claim.connectionKey, ref))
  if (current !== att.event.id) return `${ref.eventId}: not the IA's current attestation`
  return att
}

/**
 * Runs the Verification Model for `key` over the 35521s queried by its `d`
 * tag. The key is the caller's, never one read from a claim; a claim for
 * another `d` is ignored, and a malformed one for this `d` is spoofed. A
 * reference counts only if every step-3 check passes (an unreachable
 * source means it does not), and its claim's `content` must not name
 * another account than the evidence. Of all attestations that count, the
 * latest `created_at` wins (ties: the lowest event id); claims by any other
 * pubkey are spoofed. `now` is Unix seconds.
 */
export async function evaluateConnection(
  key: string,
  claims: readonly NostrEvent[],
  src: AttestationSource,
  trusted: (ia: string) => boolean,
  now: number,
): Promise<Verdict[]> {
  const out: { state: VerificationState; pubkey: string; attestation?: Attestation; reasons: string[] }[] = []
  let winner: Attestation | undefined
  for (const ev of claims) {
    let claim: IdentityConnection
    try {
      claim = parseIdentityConnection(ev)
    } catch (err) {
      if (ev.kind === KIND_IDENTITY_CONNECTION && hasD(ev, key)) out.push({ state: 'spoofed', pubkey: ev.pubkey, reasons: [(err as Error).message] })
      continue
    }
    if (claim.connectionKey !== key) continue
    const v: (typeof out)[number] = { state: 'spoofed', pubkey: ev.pubkey, reasons: [] }
    for (const ref of claim.attestations) {
      const att = await deepCheck(claim, ref, src, trusted, now)
      if (typeof att === 'string') {
        v.reasons.push(att)
        continue
      }
      const mismatch = contentMismatch(claim, att)
      if (mismatch !== '') {
        v.reasons.push(mismatch)
        continue
      }
      if (v.attestation === undefined || newer(att, v.attestation)) v.attestation = att
    }
    if (v.attestation !== undefined) {
      v.state = 'verified'
      if (winner === undefined || newer(v.attestation, winner)) winner = v.attestation
    }
    out.push(v)
  }
  if (out.length === 0) return [{ state: 'unverified', pubkey: '', reasons: [] }]
  for (const v of out) {
    if (v.state === 'verified' && v.pubkey !== winner!.userPubkey) {
      v.state = 'spoofed'
      v.reasons.push('a newer trusted attestation names another pubkey')
    }
  }
  return out
}
