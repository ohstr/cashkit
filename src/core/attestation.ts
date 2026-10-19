// NIP-IC Kind 35522 attestations: an Identity Authority vouching that a
// pubkey controls an account on a platform. Port of nmilat
// nipIC/attestation.go ParseAttestation.
import { CoreError } from './errors.js'
import { decodeGoStruct, parseGoJSON, type GoFieldType } from './gojson.js'
import { verifyEvent, type NostrEvent } from './nip01.js'

export const KIND_ATTESTATION = 35522

export interface Evidence {
  readonly userId: string
  readonly username: string
  readonly verifiedAt: number
  readonly evidenceUrl: string
  readonly challenge: string
  readonly preAuthCode: string
}

export interface Attestation {
  readonly event: NostrEvent
  /** The `d` tag: the account's ConnectionKey. */
  readonly connectionKey: string
  /** The `p` tag: the attested user's pubkey. */
  readonly userPubkey: string
  readonly platform: string
  readonly evidence: Evidence
  /** Unix seconds; absent when the attestation does not expire. */
  readonly expiresAt?: number
}

const fail = (msg: string) => new CoreError('invalid_payload', `attestation: ${msg}`)

// nmilat's evidence struct; version, platform and auth_type are type-checked
// but not surfaced.
const EVIDENCE_FIELDS = {
  version: 'int',
  platform: 'string',
  auth_type: 'string',
  user_id: 'string',
  username: 'string',
  verified_at: 'int',
  evidence_url: 'string',
  challenge: 'string',
  pre_auth_code: 'string',
} as const satisfies Record<string, GoFieldType>

function parseEvidence(text: string): Evidence {
  const e = decodeGoStruct(parseGoJSON(text, 'attestation evidence'), EVIDENCE_FIELDS, 'attestation evidence')
  return {
    userId: (e['user_id'] as string | undefined) ?? '',
    username: (e['username'] as string | undefined) ?? '',
    verifiedAt: (e['verified_at'] as number | undefined) ?? 0,
    evidenceUrl: (e['evidence_url'] as string | undefined) ?? '',
    challenge: (e['challenge'] as string | undefined) ?? '',
    preAuthCode: (e['pre_auth_code'] as string | undefined) ?? '',
  }
}

/** Go's strconv.ParseInt(s, 10, 64), or undefined. */
function parseInt64(s: string): number | undefined {
  if (!/^[+-]?[0-9]+$/.test(s)) return undefined
  const v = BigInt(s)
  if (v < -(1n << 63n) || v >= 1n << 63n) return undefined
  return Number(v)
}

/**
 * Parses and validates an attestation: kind 35522, a valid event, non-empty
 * `d` (not platform-prefixed), `p`, `platform` and `evidence` tags. For a
 * repeated tag the last one wins. An expired attestation still parses;
 * callers decide what to do with it.
 */
export function parseAttestation(event: NostrEvent): Attestation {
  if (event.kind !== KIND_ATTESTATION) throw fail(`expected kind ${KIND_ATTESTATION}, got ${event.kind}`)
  if (!verifyEvent(event)) throw fail('invalid event signature')

  const values: Record<string, string> = { d: '', p: '', platform: '', evidence: '', expiration: '' }
  for (const tag of event.tags) {
    if (tag.length < 2) continue
    if (Object.hasOwn(values, tag[0]!)) values[tag[0]!] = tag[1]!
  }
  for (const name of ['d', 'p', 'platform', 'evidence']) {
    if (values[name] === '') throw fail(`#${name} tag is required`)
  }
  if (values['d']!.includes(':')) throw fail('#d tag must be a bare ConnectionKey, not platform-prefixed')

  const evidence = parseEvidence(values['evidence']!)
  const expiresAt = values['expiration'] === '' ? undefined : parseInt64(values['expiration']!)
  return {
    event,
    connectionKey: values['d']!,
    userPubkey: values['p']!,
    platform: values['platform']!,
    evidence,
    ...(expiresAt !== undefined && { expiresAt }),
  }
}
