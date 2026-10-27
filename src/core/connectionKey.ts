// Two different things are called a "connection key":
// - NIP-IC's identity ConnectionKey, a hash naming an account on a platform
//   (nmilat nipIC.NewConnectionKey);
// - NIP-CW's member connection key pair, the secret a circle wallet's NWC
//   connection is built on (nmilat nipcw.ConnectionKeyFromSecret).
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { fromHex, toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'

/** The NIP-IC ConnectionKey: hex(sha256(platform ":" externalId)). */
export function newConnectionKey(platform: string, externalId: string): string {
  return toHex(sha256(utf8(`${platform}:${externalId}`)))
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
