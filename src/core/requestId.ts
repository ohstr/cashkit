// Request ids (NIP-CASH §`request_id`): the caller's name for one call,
// which makes a lost reply answerable by `cash_lookup` and a resend
// impossible. Port of nmilat nipcash/request_id.go.
import { sha256 } from '@noble/hashes/sha2.js'
import { toHex, utf8 } from './bytes.js'
import { randomBytes } from './identity.js'

/** 16 to 32 bytes as lowercase hex. */
export const REQUEST_ID_RE = /^(?:[0-9a-f]{2}){16,32}$/

export const isRequestId = (s: unknown): s is string => typeof s === 'string' && REQUEST_ID_RE.test(s)

/** A fresh 32-byte request id. `random` defaults to the platform CSPRNG. */
export function newRequestId(random: (n: number) => Uint8Array = randomBytes): string {
  return toHex(random(32))
}

/** The id a re-placed call uses: hex(sha256(utf8(`retry:<id>`))). */
export function derivedRequestId(id: string): string {
  return toHex(sha256(utf8(`retry:${id}`)))
}
