// Per-item proofs. Port of nmilat nipcash/transport/proof.go.
//
// A slice proof (kind 23192) is signed by the holder's identity key: "I am
// identity K". A bill proof (kind 23193) is signed by the bill's own
// connection secret: "I hold this bill". Both bind the same six fields, so
// neither can be lifted onto another item, method, params, envelope or Hub.
import { finalizeEvent, verifyEvent, type Signer } from '../core/index.js'
import { KIND_BILL_PROOF, KIND_ITEM_PROOF } from './envelope.js'
import { TransportError } from './errors.js'
import { goEventJSON, parseGoEvent } from './event.js'

/** Seconds a proof's created_at may lie in the past, and in the future. */
export const PROOF_FRESHNESS_PAST = 5 * 60
export const PROOF_FRESHNESS_FUTURE = 60

export interface ProofBinding {
  /** The bill's wallet pubkey (`d`). */
  readonly target: string
  /** The Hub's x-only identity (`h`). */
  readonly hub: string
  /** `m` */
  readonly method: string
  /** `ph`: the canonical params hash. */
  readonly paramsHash: string
  /** `en`: the envelope nonce. */
  readonly nonce: string
  /** `expiration`, unix seconds; not checked on verify. */
  readonly notAfter: number
}

const REQUIRED = ['d', 'h', 'm', 'ph', 'en'] as const

function proofTags(b: ProofBinding): string[][] {
  if (!b.target || !b.hub || !b.method || !b.paramsHash || !b.nonce) {
    throw new TransportError('proof_malformed', 'every binding field is required')
  }
  return [
    ['d', b.target],
    ['h', b.hub],
    ['m', b.method],
    ['ph', b.paramsHash],
    ['en', b.nonce],
    ['expiration', String(b.notAfter)],
  ]
}

/** A kind 23192 slice proof, signed by the holder's identity. Returns event JSON. */
export async function buildItemProof(signer: Signer, b: ProofBinding, now: number): Promise<string> {
  const tags = proofTags(b)
  return goEventJSON(await signer.signEvent({ kind: KIND_ITEM_PROOF, created_at: now, tags, content: '' }))
}

/** A kind 23193 bill proof, signed with the bill's connection secret. Returns event JSON. */
export function buildBillProof(connectionSecret: Uint8Array, b: ProofBinding, now: number): string {
  const tags = proofTags(b)
  return goEventJSON(finalizeEvent({ kind: KIND_BILL_PROOF, created_at: now, tags, content: '' }, connectionSecret))
}

function verify(wantKind: number, proof: string, want: ProofBinding, now: number): string {
  const ev = parseGoEvent(proof, 'proof_malformed', 'proof')
  if (ev.kind !== wantKind) throw new TransportError('proof_malformed', `kind ${ev.kind}, want ${wantKind}`)
  if (!/^[0-9a-f]{64}$/.test(ev.pubkey)) throw new TransportError('proof_malformed', 'signer pubkey must be 64 lowercase hex characters')

  const got = new Map<string, string>()
  for (const tag of ev.tags) {
    if (tag.length < 2 || !(REQUIRED as readonly string[]).includes(tag[0]!)) continue
    if (got.has(tag[0]!)) throw new TransportError('proof_malformed', `duplicate ${tag[0]} tag`)
    got.set(tag[0]!, tag[1]!)
  }
  for (const name of REQUIRED) {
    if (!got.get(name)) throw new TransportError('proof_malformed', `missing ${name} tag`)
  }
  if (got.get('d') !== want.target) throw new TransportError('proof_wrong_target', 'proof is bound to a different wallet')
  if (got.get('h') !== want.hub) throw new TransportError('proof_wrong_hub', 'proof is bound to a different hub')
  if (got.get('m') !== want.method) throw new TransportError('proof_wrong_method', 'proof is bound to a different method')
  if (got.get('ph') !== want.paramsHash) throw new TransportError('proof_wrong_params', 'proof is bound to different params')
  if (got.get('en') !== want.nonce) throw new TransportError('proof_wrong_envelope', 'proof is bound to a different envelope')
  if (ev.created_at < now - PROOF_FRESHNESS_PAST || ev.created_at > now + PROOF_FRESHNESS_FUTURE) {
    throw new TransportError('proof_stale', 'proof is outside its freshness window')
  }
  if (!verifyEvent(ev, { checkPow: false })) throw new TransportError('proof_signature', 'proof signature is invalid')
  return ev.pubkey
}

/** Checks a slice proof against the binding; returns the signer's pubkey. */
export const verifyItemProof = (proof: string, want: ProofBinding, now: number): string => verify(KIND_ITEM_PROOF, proof, want, now)

/** Checks a bill proof against the binding; returns the signer's pubkey. */
export const verifyBillProof = (proof: string, want: ProofBinding, now: number): string => verify(KIND_BILL_PROOF, proof, want, now)
