import { sha256 } from '@noble/hashes/sha2.js'
import { equalBytes, utf8 } from './bytes.js'

/** Byte length of the hub-group fingerprint (token TLV type 7). */
export const HUB_GROUP_LEN = 4

/**
 * The fingerprint a Hub stamps on every bill it mints.
 *
 * It hashes the pubkey's hex TEXT as given, not the 32 decoded bytes, and
 * case matters. That is what the Hub does, so it is what a client must do.
 */
export function hubGroupFor(hubPubkeyHex: string): Uint8Array {
  return sha256(utf8(hubPubkeyHex)).slice(0, HUB_GROUP_LEN)
}

/**
 * Whether two bills may be consolidated together: both carry a well-formed
 * fingerprint and they match. A missing fingerprint means "unknown Hub",
 * never a wildcard, so two bills without one do not group.
 */
export function sameHubGroup(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  if (a?.length !== HUB_GROUP_LEN || b?.length !== HUB_GROUP_LEN) return false
  return equalBytes(a, b)
}
