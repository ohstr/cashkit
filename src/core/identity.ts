// Who a bill moves to (targets) and how its holder proves the right to move
// it (credentials). Port of nmilat nipcash/identity.go and proof.go.
import { sha256 } from '@noble/hashes/sha2.js'
import { fromHex, toHex, utf8 } from './bytes.js'
import { newConnectionKey } from './connectionKey.js'
import { CoreError } from './errors.js'
import { finalizeEvent, getPublicKey, type EventTemplate, type NostrEvent } from './nip01.js'
import { decrypt, encrypt, getConversationKey } from './nip44.js'
import type { Attestation } from './attestation.js'

export type IdentityType = 'pubkey' | 'connection_key' | 'cash'

/** A new owner for a bill: what `new_identity` carries on the wire. */
export interface Target {
  readonly identityType: IdentityType
  /** Hex pubkey, connection key, or the cash commitment hex(sha256(secret bytes)). */
  readonly identityValue: string
  /** Identity Authority pubkey; "" unless connection_key. */
  readonly iaPubkey: string
}

/** A cash-mode target. `secret` is secret-bearing: it is the bill (§10). */
export interface CashTarget extends Target {
  readonly identityType: 'cash'
  readonly secret: string
}

/** A pubkey target. The hex is used exactly as given, case included. */
export function pubkeyTarget(pubkeyHex: string): Target {
  return { identityType: 'pubkey', identityValue: pubkeyHex, iaPubkey: '' }
}

/**
 * A connection-key target for an account on a platform, attested by an IA.
 * As in nmilat, an empty platform makes it a plain pubkey-typed identity.
 */
export function connectionKeyTarget(platform: string, externalId: string, iaPubkey: string): Target {
  return resolvedConnectionKeyTarget(newConnectionKey(platform, externalId), platform, iaPubkey)
}

/** A connection-key target from an already-computed key. */
export function resolvedConnectionKeyTarget(connectionKey: string, platform: string, iaPubkey: string): Target {
  return platform === ''
    ? { identityType: 'pubkey', identityValue: connectionKey, iaPubkey }
    : { identityType: 'connection_key', identityValue: connectionKey, iaPubkey }
}

/** A cash secret: 64 lowercase hex (32 bytes). */
export const isCashSecret = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s)

/** A cash commitment: 64 lowercase hex. */
export const isCommitment = isCashSecret

/** `cash` identity value: hex(sha256(the 32 secret bytes)), never of the hex text. */
export function cashCommitment(secretHex: string): string {
  if (!isCashSecret(secretHex)) throw new CoreError('invalid_field', 'a cash secret is 64 lowercase hex characters')
  return toHex(sha256(fromHex(secretHex)))
}

/** A cash target from a known 32-byte secret (hex), e.g. when recovering. */
export function cashTargetFromSecret(secretHex: string): CashTarget {
  const raw = fromHex(secretHex, 'cash secret')
  if (raw.length !== 32) throw new CoreError('invalid_field', 'cash secret must be 32 bytes')
  return { identityType: 'cash', identityValue: toHex(sha256(raw)), iaPubkey: '', secret: toHex(raw) }
}

/** A fresh cash target. `random` defaults to the platform CSPRNG. */
export function newCashTarget(random: (n: number) => Uint8Array = randomBytes): CashTarget {
  return cashTargetFromSecret(toHex(random(32)))
}

export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n))
}

/** `new_identity_hash`: hex(sha256(type ":" value ":" ia)). */
export function newIdentityHash(t: Target): string {
  return toHex(sha256(utf8(`${t.identityType}:${t.identityValue}:${t.iaPubkey}`)))
}

/**
 * Signs with an identity key. A local key implements it directly; NIP-07 or
 * NIP-46 signers can implement it later (design §3).
 */
export interface Signer {
  /** x-only, hex. */
  readonly pubkey: string
  signEvent(t: EventTemplate): Promise<NostrEvent>
  /** NIP-44 v2 decrypt of a payload from `senderPubkey`. */
  nip44Decrypt(senderPubkey: string, ciphertext: string): Promise<string>
  /** NIP-44 v2 encrypt to `recipientPubkey`; needed for a Cash Pocket's seals. */
  nip44Encrypt?(recipientPubkey: string, plaintext: string): Promise<string>
}

/** A Signer over a 32-byte secret key held in memory. */
export function localSigner(secretKey: Uint8Array): Signer {
  let pubkey: string
  try {
    pubkey = getPublicKey(secretKey)
  } catch {
    throw new CoreError('invalid_key', 'signer: invalid secret key')
  }
  const key = secretKey.slice()
  return {
    pubkey,
    signEvent: async (t) => finalizeEvent(t, key),
    nip44Decrypt: async (sender, ciphertext) => decrypt(ciphertext, getConversationKey(key, sender)),
    nip44Encrypt: async (recipient, plaintext) => encrypt(plaintext, getConversationKey(key, recipient)),
  }
}

/** How a bill's holder authorizes a call on it. */
export type Credential =
  | { readonly kind: 'secret'; readonly secret: string }
  | { readonly kind: 'signing'; readonly signer: Signer }
  | {
      readonly kind: 'connection_key'
      readonly signer: Signer
      readonly platform: string
      readonly externalId: string
      readonly attestation: Attestation | undefined
    }

/** Cash mode: the bill's cash secret is the credential. Secret-bearing. */
export const bySecret = (secret: string): Credential => ({ kind: 'secret', secret })

/** Pubkey mode: a claim proof signed by the holder's key. */
export const bySigning = (signer: Signer): Credential => ({ kind: 'signing', signer })

/** Connection-key mode: a claim proof plus the IA attestation for the account. */
export const bySigningConnectionKey = (
  signer: Signer,
  platform: string,
  externalId: string,
  attestation: Attestation | undefined,
): Credential => ({ kind: 'connection_key', signer, platform, externalId, attestation })

/**
 * Opens a token delivered to the claimant: NIP-44 from the new wallet's
 * pubkey. A cash-mode delivery is not encrypted.
 */
export async function decryptDelivery(c: Credential, newWalletPubkey: string, ciphertext: string): Promise<string> {
  if (c.kind === 'secret') return ciphertext
  return c.signer.nip44Decrypt(newWalletPubkey, ciphertext)
}
