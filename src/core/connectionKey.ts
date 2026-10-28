// Two different things are called a "connection key":
// - NIP-IC's identity ConnectionKey, a hash naming an account on a platform,
//   which always travels with the pubkey of the IA it rests on
//   (`ConnectionKeyRef`; nmilat nipcash.ResolvedConnectionKey and friends);
// - NIP-CW's member connection key pair, the secret a circle wallet's NWC
//   connection is built on (nmilat nipcw.ConnectionKeyFromSecret).
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { fromHex, toHex } from './bytes.js'
import { CoreError } from './errors.js'
import { canonicalUserId, connectionKeyFromAttested, connectionKeyFromTyped, hasCanonicalForm, NOT_CANONICAL, validPlatformName } from './idna.js'
import type { Attestation } from './attestation.js'
import type { NConnection } from './nconnection.js'

/**
 * A NIP-IC ConnectionKey with what it rests on: the account's platform and
 * the pubkey of the Identity Authority that attested it. A key never
 * travels without its IA (§Canonical Platform User IDs).
 */
export interface ConnectionKeyRef {
  /** 64 lowercase hex. */
  readonly key: string
  /** A valid platform name, `[a-z0-9._-]+`. */
  readonly platform: string
  /** The IA's pubkey, hex; "" only until the caller supplies one (a request refuses it). */
  readonly ia: string
}

export const PLATFORM_NAME = 'nipIC: platform name must match [a-z0-9._-]+'
export const BAD_CONNECTION_KEY = 'nipIC: a ConnectionKey is 64 lowercase hex characters'
export const MISSING_IA_PUBKEY = 'nipcash: a connection_key identity requires an ia_pubkey'

/**
 * A key the caller already holds (nmilat `ResolvedConnectionKey`): never
 * hashed; refuses a key that is not 64 lowercase hex and an invalid
 * platform name.
 */
export function connectionKeyRef(key: string, platform: string, ia: string): ConnectionKeyRef {
  if (!/^[0-9a-f]{64}$/.test(key)) throw new CoreError('invalid_field', BAD_CONNECTION_KEY)
  if (!validPlatformName(platform)) throw new CoreError('invalid_field', PLATFORM_NAME)
  return { key, platform, ia }
}

/**
 * The key of typed input on a platform with a canonical form (x, discord,
 * email, dns). Every other platform is refused: its key comes from the
 * recipient's attestation or `nconnection`.
 */
export function connectionKeyRefFromTyped(platform: string, typed: string, ia: string): ConnectionKeyRef {
  if (!validPlatformName(platform)) throw new CoreError('invalid_field', PLATFORM_NAME)
  return connectionKeyRef(connectionKeyFromTyped(platform, typed), platform, ia)
}

const isCanonical = (platform: string, userId: string): boolean => {
  try {
    return canonicalUserId(platform, userId) === userId
  } catch {
    return false
  }
}

/**
 * The key a recipient's attestation names, with the attestation's author as
 * the IA. Its `d` is taken only when it is the hash of the attestation's
 * `platform` and `evidence.user_id`, byte for byte; on a platform with a
 * canonical form that user id must be canonical.
 */
export function connectionKeyFromAttestation(att: Attestation): ConnectionKeyRef {
  if (!validPlatformName(att.platform)) throw new CoreError('invalid_field', PLATFORM_NAME)
  if (hasCanonicalForm(att.platform) && !isCanonical(att.platform, att.evidence.userId)) throw new CoreError('invalid_field', NOT_CANONICAL)
  if (connectionKeyFromAttested(att.platform, att.evidence.userId) !== att.connectionKey) {
    throw new CoreError('invalid_field', 'nipIC: d is not the ConnectionKey of platform and user_id')
  }
  return connectionKeyRef(att.connectionKey, att.platform, att.event.pubkey)
}

/** Whether `connectionKeyFromAttestation` accepts the attestation. */
export function attestationKeyMatchesD(att: Attestation): boolean {
  try {
    connectionKeyFromAttestation(att)
    return true
  } catch {
    return false
  }
}

/**
 * The key an `nconnection` carries, byte for byte (never re-derived), with
 * the IA the sender trusts for it. The IA is required, and so is a platform:
 * one without is refused.
 */
export function connectionKeyFromNConnection(n: NConnection, ia: string): ConnectionKeyRef {
  if (ia === '') throw new CoreError('invalid_field', MISSING_IA_PUBKEY)
  return connectionKeyRef(n.connectionKey, n.platform, ia)
}

/** A NIP-CW member connection key pair. `secret` is secret-bearing. */
export interface ConnectionKeyPair {
  /** Hex, 32 bytes, exactly as given. */
  readonly secret: string
  /** x-only pubkey, hex. */
  readonly pubkey: string
}

/**
 * Derives the connection key pair for a 32-byte lowercase hex secret.
 *
 * Stricter than nmilat on purpose: a zero secret or one at or above the
 * curve order is refused, where nmilat silently reduces it mod n.
 */
export function connectionKeyFromSecret(secretHex: string): ConnectionKeyPair {
  if (!/^[0-9a-f]*$/.test(secretHex)) throw new CoreError('invalid_hex', 'connection secret: not lowercase hex')
  const secret = fromHex(secretHex, 'connection secret')
  if (secret.length !== 32) throw new CoreError('invalid_key', 'connection secret: invalid private key length')
  if (!secp256k1.utils.isValidSecretKey(secret)) {
    throw new CoreError('invalid_key', 'connection secret: out of range for secp256k1')
  }
  return { secret: secretHex, pubkey: toHex(secp256k1.getPublicKey(secret, true).subarray(1)) }
}
