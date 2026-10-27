// NIP-IC Kind 35522 attestations: an Identity Authority vouching that a
// pubkey controls an account on a platform. Port of nmilat
// nipIC/attestation.go ParseAttestation.
import { CoreError } from './errors.js'
import { decodeGoStruct, parseGoJSON, type GoFieldType } from './gojson.js'
import { validPlatformName } from './idna.js'
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
const PLATFORM_NAME_ERROR = 'nipIC: platform name must match [a-z0-9._-]+'

// nmilat's evidence struct; version and auth_type are checked, platform is
// type-checked; none of the three is surfaced.
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
  let e: Record<string, unknown>
  try {
    e = decodeGoStruct(parseGoJSON(text, 'evidence'), EVIDENCE_FIELDS, 'evidence')
  } catch (err) {
    throw new CoreError('invalid_payload', `nipIC: invalid tag: evidence tag is not valid JSON: ${(err as Error).message}`)
  }
  if (e['version'] !== 1) throw new CoreError('invalid_payload', 'nipIC: invalid tag: evidence version must be 1')
  const authType = (e['auth_type'] as string | undefined) ?? ''
  if (authType === '') throw new CoreError('invalid_payload', 'nipIC: invalid tag: evidence auth_type is empty')
  const evidence = {
    userId: (e['user_id'] as string | undefined) ?? '',
    username: (e['username'] as string | undefined) ?? '',
    verifiedAt: (e['verified_at'] as number | undefined) ?? 0,
    evidenceUrl: (e['evidence_url'] as string | undefined) ?? '',
    challenge: (e['challenge'] as string | undefined) ?? '',
    preAuthCode: (e['pre_auth_code'] as string | undefined) ?? '',
  }
  if (authType === 'public_post' && (evidence.evidenceUrl === '' || evidence.challenge === '' || evidence.preAuthCode === '')) {
    throw new CoreError('invalid_payload', 'nipIC: invalid tag: public_post evidence needs evidence_url, challenge and pre_auth_code')
  }
  return evidence
}

const HEX64 = /^[0-9a-f]{64}$/
const SINGLE_TAGS = ['d', 'p', 'platform', 'evidence', 'expiration']

/** The listed tags with a value, each at most once (a repeated one is refused). */
export function singleTags(event: NostrEvent, names: readonly string[]): Map<string, string> {
  const out = new Map<string, string>()
  for (const tag of event.tags) {
    if (tag.length < 2 || !names.includes(tag[0]!)) continue
    if (out.has(tag[0]!)) throw new CoreError('invalid_payload', `nipIC: invalid tag: ${JSON.stringify(tag[0])} tag repeated`)
    out.set(tag[0]!, tag[1]!)
  }
  return out
}

/**
 * Parses and validates an attestation (nmilat `ParseAttestation`): kind
 * 35522, a valid event, an empty `content`, each of `d`, `p`, `platform`
 * and `evidence` exactly once and non-empty, `d` and `p` as 64 lowercase hex
 * (`d` never platform-prefixed), a valid platform name, a decimal
 * `expiration` when present (a malformed one is refused, never read as "no
 * expiry"), and v1 evidence with an `auth_type` (`public_post` evidence
 * carries `evidence_url`, `challenge` and `pre_auth_code`). An expired
 * attestation still parses; callers decide what to do with it.
 */
export function parseAttestation(event: NostrEvent): Attestation {
  if (event.kind !== KIND_ATTESTATION) throw new CoreError('invalid_payload', `nipIC: unexpected event kind: expected kind ${KIND_ATTESTATION}, got ${event.kind}`)
  if (!verifyEvent(event)) throw new CoreError('invalid_payload', 'nipIC: invalid event signature: invalid signature')
  if (event.content !== '') throw new CoreError('invalid_payload', "nipIC: invalid tag: a 35522's content is empty")
  const tags = singleTags(event, SINGLE_TAGS)
  for (const name of ['d', 'p', 'platform', 'evidence']) {
    if ((tags.get(name) ?? '') === '') throw new CoreError('invalid_payload', `nipIC: missing required tag: ${JSON.stringify(name)} tag is required for Kind 35522`)
  }
  const d = tags.get('d')!
  if (d.includes(':')) throw new CoreError('invalid_payload', `nipIC: #d tag must be a bare ConnectionKey, not platform-prefixed: ${JSON.stringify(d)}`)
  if (!HEX64.test(d)) throw new CoreError('invalid_payload', 'nipIC: invalid tag: d is not a ConnectionKey')
  const p = tags.get('p')!
  if (!HEX64.test(p)) throw new CoreError('invalid_payload', 'nipIC: invalid tag: p is not a pubkey')
  const platform = tags.get('platform')!
  if (!validPlatformName(platform)) throw new CoreError('invalid_payload', PLATFORM_NAME_ERROR)
  const evidence = parseEvidence(tags.get('evidence')!)
  let expiresAt: number | undefined
  const exp = tags.get('expiration')
  if (exp !== undefined) {
    if (!/^[0-9]+$/.test(exp) || BigInt(exp) >= 1n << 63n) throw new CoreError('invalid_payload', `nipIC: invalid tag: expiration ${JSON.stringify(exp)}`)
    expiresAt = Number(exp)
  }
  return { event, connectionKey: d, userPubkey: p, platform, evidence, ...(expiresAt !== undefined && { expiresAt }) }
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
