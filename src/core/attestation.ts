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
  if (e['version'] !== 1) throw fail('evidence version must be 1')
  const authType = (e['auth_type'] as string | undefined) ?? ''
  if (authType === '') throw fail('evidence auth_type is empty')
  if (authType === 'public_post' && (!e['evidence_url'] || !e['challenge'] || !e['pre_auth_code'])) {
    throw fail('public_post evidence needs evidence_url, challenge and pre_auth_code')
  }
  return {
    userId: (e['user_id'] as string | undefined) ?? '',
    username: (e['username'] as string | undefined) ?? '',
    verifiedAt: (e['verified_at'] as number | undefined) ?? 0,
    evidenceUrl: (e['evidence_url'] as string | undefined) ?? '',
    challenge: (e['challenge'] as string | undefined) ?? '',
    preAuthCode: (e['pre_auth_code'] as string | undefined) ?? '',
  }
}

/** Go's strconv.ParseUint(s, 10, 63), or undefined. */
function parseUint63(s: string): number | undefined {
  if (!/^[0-9]+$/.test(s)) return undefined
  const v = BigInt(s)
  return v < 1n << 63n ? Number(v) : undefined
}

const HEX64 = /^[0-9a-f]{64}$/
const PLATFORM_NAME = /^[a-z0-9._-]+$/
const ATTESTATION_TAGS = new Set(['d', 'p', 'platform', 'evidence', 'expiration'])

/**
 * Parses and validates an attestation as nmilat does: kind 35522, a valid
 * event, empty content, each of `d`, `p`, `platform`, `evidence` and
 * `expiration` at most once (a repeated one is refused), `d` a bare 64-hex
 * ConnectionKey (never platform-prefixed), `p` 64 lowercase hex, `platform`
 * a valid name, v1 evidence with an `auth_type` (`public_post` evidence
 * carries `evidence_url`, `challenge` and `pre_auth_code`), and a decimal
 * `expiration` when present (a malformed one is refused, never read as no
 * expiry). An expired attestation still parses; callers decide.
 */
export function parseAttestation(event: NostrEvent): Attestation {
  if (event.kind !== KIND_ATTESTATION) throw fail(`expected kind ${KIND_ATTESTATION}, got ${event.kind}`)
  if (!verifyEvent(event)) throw fail('invalid event signature')
  if (event.content !== '') throw fail("a 35522's content is empty")

  const values = new Map<string, string>()
  for (const tag of event.tags) {
    if (tag.length < 2 || !ATTESTATION_TAGS.has(tag[0]!)) continue
    if (values.has(tag[0]!)) throw fail(`#${tag[0]} tag repeated`)
    values.set(tag[0]!, tag[1]!)
  }
  for (const name of ['d', 'p', 'platform', 'evidence']) {
    if (!values.get(name)) throw fail(`#${name} tag is required`)
  }
  const d = values.get('d')!
  if (d.includes(':')) throw fail('#d tag must be a bare ConnectionKey, not platform-prefixed')
  if (!HEX64.test(d)) throw fail('#d tag is not a ConnectionKey')
  const p = values.get('p')!
  if (!HEX64.test(p)) throw fail('#p tag is not a pubkey')
  const platform = values.get('platform')!
  if (!PLATFORM_NAME.test(platform)) throw fail('platform name must match [a-z0-9._-]+')

  const evidence = parseEvidence(values.get('evidence')!)
  let expiresAt: number | undefined
  const exp = values.get('expiration')
  if (exp !== undefined) {
    expiresAt = parseUint63(exp)
    if (expiresAt === undefined) throw fail(`invalid expiration ${JSON.stringify(exp)}`)
  }
  return {
    event,
    connectionKey: d,
    userPubkey: p,
    platform,
    evidence,
    ...(expiresAt !== undefined && { expiresAt }),
  }
}

/**
 * The checks NIP-CASH §Claim Proofs applies to the attestation behind a
 * `connection_key` slice's claim proof, run before sending one: kind 35522,
 * id and signature, author = the IA recorded on the slice, `d` = the
 * slice's identity value, `p` = the claim-proof signer, `platform`,
 * `evidence` and an `expiration` not yet passed. Throws `CoreError` naming
 * the failed check.
 */
export function checkAttestationForClaim(event: NostrEvent, p: { readonly identityValue: string; readonly iaPubkey: string; readonly signer: string; readonly now: number }): Attestation {
  const att = parseAttestation(event)
  if (event.pubkey !== p.iaPubkey) throw fail('signed by another key than the Identity Authority recorded on the slice')
  if (att.connectionKey !== p.identityValue) throw fail("#d tag is not the slice's identity value")
  if (att.userPubkey !== p.signer) throw fail('#p tag is not the claim-proof signer')
  if (att.expiresAt === undefined) throw fail('#expiration tag is required')
  if (p.now > att.expiresAt) throw fail('has expired')
  return att
}
