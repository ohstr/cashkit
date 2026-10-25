// Connection signatures (NIP-CASH §Connection Signatures): the node identity
// signs every `cashhub1`, `cashorder1` and `circlehub1` it issues, so a client
// checks the string offline; the online check then compares `get_info` with
// the string. Port of nmilat nipcash/connection_sig.go and the online-check
// helpers of nipcash/client.
import { sha256 } from '@noble/hashes/sha2.js'
import { toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'
import { CHAIN_TABLE, recoverCompact, relayHashOf, signCompact } from './provenance.js'

export const CONN_LABEL_CASH_HUB = 'cash-hub:v1'
export const CONN_LABEL_CASH_ORDER = 'cash-order:v1'
export const CONN_LABEL_CIRCLE_HUB = 'circle-hub:v1'

/** The HRPs whose strings carry a connection signature, and their signed-text labels. */
export const CONN_LABELS: Readonly<Record<string, string>> = {
  cashhub: CONN_LABEL_CASH_HUB,
  cashorder: CONN_LABEL_CASH_ORDER,
  circlehub: CONN_LABEL_CIRCLE_HUB,
}

/** The fields a connection signature covers: TLV 0–4 and 6. */
export interface ConnFields {
  readonly hrp: string
  /** TLV 6, byte for byte. */
  readonly chain: string
  /** TLV 0, 64 hex. */
  readonly pubkey: string
  /** TLV 4, 64 hex (x-only). */
  readonly hubIdentity: string
  /** Every TLV 1 exactly as encoded. */
  readonly relayBytes: readonly Uint8Array[]
  /** TLV 2, 64 hex. */
  readonly secret: string
  /** TLV 3 as encoded; undefined when the string has none. */
  readonly labelBytes?: Uint8Array
}

/** Why a decoded string is not signed by its TLV 4. */
export type ConnUnverifiedReason = 'chain_no_prefix' | 'signer_mismatch'

export type ConnVerdict = { readonly verified: true } | { readonly verified: false; readonly reason: ConnUnverifiedReason }

/** TLV 6: 1 to 32 bytes of `a`–`z`, `0`–`9` and `-`. */
export function validChainName(s: string): boolean {
  return /^[a-z0-9-]{1,32}$/.test(s)
}

/** The signed-message prefix for a chain name (TLV 6), or undefined for a chain this build has no row for. */
export function chainSignedMessagePrefix(chain: string): string | undefined {
  for (const r of Object.values(CHAIN_TABLE)) if (r.chain === chain) return r.prefix
  return undefined
}

/** `<label>:<chain>:<connection_pubkey>:<hub_identity>:<relay_hash>:<label_hash>`; `<label_hash>` is '' without TLV 3. */
export function connSignedText(f: ConnFields): string {
  const label = CONN_LABELS[f.hrp]
  if (label === undefined || !Object.hasOwn(CONN_LABELS, f.hrp)) throw new CoreError('invalid_field', `no connection signature is defined for ${f.hrp}`)
  const labelHash = f.labelBytes === undefined ? '' : toHex(sha256(f.labelBytes))
  return `${label}:${f.chain}:${f.pubkey.toLowerCase()}:${f.hubIdentity.toLowerCase()}:${relayHashOf(f.relayBytes, f.secret)}:${labelHash}`
}

/** SHA256(SHA256(prefix ‖ text)), or undefined when the chain has no prefix. */
export function connectionDigest(f: ConnFields): Uint8Array | undefined {
  const prefix = chainSignedMessagePrefix(f.chain)
  return prefix === undefined ? undefined : sha256(sha256(utf8(prefix + connSignedText(f))))
}

/** Checks TLV 5 against TLV 4 over the rebuilt text. Never throws for a bad signature: the string stays decodable. */
export function verifyConnection(f: ConnFields, signature: Uint8Array): ConnVerdict {
  const digest = connectionDigest(f)
  if (digest === undefined) return { verified: false, reason: 'chain_no_prefix' }
  const k = recoverCompact(signature, digest)
  if (k === undefined || k.slice(2) !== f.hubIdentity.toLowerCase()) return { verified: false, reason: 'signer_mismatch' }
  return { verified: true }
}

/**
 * Signs a connection string's fields as its Hub does (header `31 + recid`,
 * RFC 6979). For the fake Hub and tests: cashkit issues no strings. Refuses
 * a key that is not TLV 4's.
 */
export function signConnection(f: ConnFields, privateKey: Uint8Array): Uint8Array {
  const digest = connectionDigest(f)
  if (digest === undefined) throw new CoreError('invalid_field', `chain ${f.chain} has no signed-message prefix`)
  const sig = signCompact(digest, privateKey)
  if (recoverCompact(sig, digest)?.slice(2) !== f.hubIdentity.toLowerCase()) throw new CoreError('invalid_key', 'the signing key is not the Hub identity in TLV 4')
  return sig
}

/**
 * `get_info`'s Hub identity names TLV 4: lowercased, a 66-hex value
 * starting `02`/`03` loses those two characters, then compared as 64 hex.
 */
export function hubIdentityEqual(tlv4: string, value: string): boolean {
  let v = value.toLowerCase()
  if (v.length === 66 && (v.startsWith('02') || v.startsWith('03'))) v = v.slice(2)
  return /^[0-9a-f]{64}$/.test(v) && v === tlv4.toLowerCase()
}

/**
 * The online check: the identity `get_info` returns must equal TLV 4 and
 * its `chain` must equal TLV 6. Throws `CoreError('hub_identity_mismatch' |
 * 'chain_mismatch')`; a missing `chain` fails.
 */
export function onlineCheck(conn: { readonly hubIdentity: string; readonly chain: string }, info: { readonly identity?: string; readonly chain?: unknown }): void {
  if (info.identity === undefined || !hubIdentityEqual(conn.hubIdentity, info.identity)) {
    throw new CoreError('hub_identity_mismatch', 'the Hub identity get_info returned is not the one this connection string names')
  }
  if (typeof info.chain !== 'string' || info.chain !== conn.chain) throw new CoreError('chain_mismatch', 'the chain get_info returned is not the one this connection string names')
}

/** The string in uppercase, for a QR code's alphanumeric mode only; it decodes back unchanged. */
export const qrForm = (s: string): string => s.toUpperCase()
