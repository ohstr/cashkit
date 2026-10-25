// Mint provenance (NIP-CASH §Mint Provenance). Port of nmilat
// nipcash/provenance.go: the minting node signs the scheme's payload with
// its Lightning identity key exactly as `signmessage` does, and anyone can
// recover that key from the token.
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes, fromHex, toHex, utf8 } from './bytes.js'
import { MINT_SIGNATURE_LEN, type Token } from './token.js'

/** The scheme labels: fixed ASCII, the same for every HRP. */
export const MINT_LABEL_V1 = 'cash-mint:v1'
export const ZAP_LABEL_V1 = 'cash-zap:v1'

/** The signed-message prefix of a Bitcoin Lightning node (lnd). */
export const LND_SIGNED_MESSAGE_PREFIX = 'Lightning Signed Message:'

/**
 * Token HRP → chain name → the chain's signed-message prefix. `satscash`
 * is Bitcoin's row; any other row is local to the implementation of that
 * coin, kept here and nowhere in the protocol.
 */
export const CHAIN_TABLE: Readonly<Record<string, { readonly chain: string; readonly prefix: string }>> = {
  satscash: { chain: 'bitcoin', prefix: LND_SIGNED_MESSAGE_PREFIX },
  lokicash: { chain: 'flokicoin', prefix: 'Flokicoin Lightning Signed Message:' },
}

// Keyed by the lowercase HRP a decoder returns; other spellings have no row.
const row = (hrp: string) => (Object.hasOwn(CHAIN_TABLE, hrp) ? CHAIN_TABLE[hrp] : undefined)

/** The chain a token HRP names, or undefined for an HRP this build has no row for. */
export function chainForHrp(hrp: string): string | undefined {
  return row(hrp)?.chain
}

/**
 * The signed-message prefix for a token HRP, or undefined when the HRP has
 * none. A token under such an HRP still decodes but carries no verifiable
 * provenance.
 */
export function signedMessagePrefix(hrp: string): string | undefined {
  return row(hrp)?.prefix
}

const lenPrefixed = (b: Uint8Array) => concatBytes(Uint8Array.of(b.length), b)

/**
 * `relay_hash`: lowercase hex sha256 of every relay hint exactly as encoded,
 * each after its 1-byte length, then the 32-byte secret. Shared with the
 * signed connection strings.
 */
export function relayHashOf(relayBytes: readonly Uint8Array[], secret: Uint8Array | string): string {
  const s = typeof secret === 'string' ? fromHex(secret, 'secret') : secret
  return toHex(sha256(concatBytes(...relayBytes.map(lenPrefixed), s)))
}

/** A token's `relay_hash`, over its TLV 1 entries as encoded. */
export function relayHash(t: Pick<Token, 'relays' | 'relayBytes' | 'secret'>): string {
  return relayHashOf(t.relayBytes ?? t.relays.map((r) => utf8(r)), t.secret)
}

const dec = (n: bigint | number) => {
  const b = BigInt(n)
  if (b < 0n) throw new RangeError('payload integers are unsigned')
  return b.toString(10)
}

export interface MintPayloadFields {
  readonly hrp: string
  readonly walletPubkey: string
  readonly amountMillis: bigint
  readonly relayHash: string
}

/** Scheme 1: `cash-mint:v1:<hrp>:<wallet_pubkey_hex>:<amount_millis>:<relay_hash>`. */
export function mintPayloadV1(f: MintPayloadFields): string {
  return `${MINT_LABEL_V1}:${f.hrp.toLowerCase()}:${f.walletPubkey.toLowerCase()}:${dec(f.amountMillis)}:${f.relayHash.toLowerCase()}`
}

/** The scheme-2 fields a token does not carry; a verifier rebuilds them from the Cash Zap. */
export interface ZapFields {
  /** The bill's registered pubkey (x-only hex). */
  readonly recipient: string
  /** The source slice's registered pubkey (x-only hex). */
  readonly sender: string
  /** The `zap_target` string; hashed exactly as sent. */
  readonly zapTarget: string
  readonly issuedAt: number
  /** 0 for a bill that never expires. */
  readonly expiresAt: number
}

/** `<target_hash>`: lowercase hex sha256 of the UTF-8 `zap_target`. */
export const zapTargetHash = (zapTarget: string) => toHex(sha256(utf8(zapTarget)))

/** Scheme 2: `cash-zap:v1:<hrp>:<wallet>:<amount>:<relay_hash>:pubkey/<recipient>:pubkey/<sender>:<target_hash>:<issued_at>:<expires_at>`. */
export function zapPayloadV1(f: MintPayloadFields & Omit<ZapFields, 'zapTarget'> & { readonly targetHash: string }): string {
  return `${ZAP_LABEL_V1}:${f.hrp.toLowerCase()}:${f.walletPubkey.toLowerCase()}:${dec(f.amountMillis)}:${f.relayHash.toLowerCase()}:pubkey/${f.recipient.toLowerCase()}:pubkey/${f.sender.toLowerCase()}:${f.targetHash.toLowerCase()}:${dec(f.issuedAt)}:${dec(f.expiresAt)}`
}

type ProvenanceInput = Pick<Token, 'hrp' | 'walletPubkey' | 'secret' | 'relays' | 'relayBytes' | 'scheme' | 'mintSignature' | 'attestedAmountMillis'>

/** The payload a token's signature covers, or undefined when it has none to verify (no pair, unknown scheme, zap fields missing). */
export function provenancePayload(t: ProvenanceInput, zap?: ZapFields): string | undefined {
  if (t.attestedAmountMillis === undefined) return undefined
  const base = { hrp: t.hrp, walletPubkey: t.walletPubkey, amountMillis: t.attestedAmountMillis, relayHash: relayHash(t) }
  if (t.scheme === 'mint_v1') return mintPayloadV1(base)
  if (t.scheme === 'zap_v1' && zap !== undefined) return zapPayloadV1({ ...base, ...zap, targetHash: zapTargetHash(zap.zapTarget) })
  return undefined
}

/** `SHA256(SHA256(prefix ‖ payload))`, or undefined when the HRP has no prefix. */
export function signedMessageDigest(hrp: string, payload: string): Uint8Array | undefined {
  const prefix = signedMessagePrefix(hrp)
  return prefix === undefined ? undefined : sha256(sha256(utf8(prefix + payload)))
}

/** The recid of a compact signature header: 27..34 as `(h − 27) mod 4`, or a raw 0..3. */
export function recoveryId(header: number): number | undefined {
  if (header >= 27 && header <= 34) return (header - 27) & 3
  if (header >= 0 && header <= 3) return header
  return undefined
}

/** Recovers the compressed signer of a 65-byte compact signature over `digest`. */
export function recoverCompact(sig: Uint8Array, digest: Uint8Array): string | undefined {
  if (sig.length !== MINT_SIGNATURE_LEN) return undefined
  const recovery = recoveryId(sig[0]!)
  if (recovery === undefined) return undefined
  try {
    return toHex(secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(recovery), sig.subarray(1)), digest, { prehash: false }))
  } catch {
    return undefined
  }
}

/** Signs `digest` as a signed-message signer does: header `31 + recid`, low S, RFC 6979 nonces. */
export function signCompact(digest: Uint8Array, privateKey: Uint8Array): Uint8Array {
  const sig = secp256k1.sign(digest, privateKey, { prehash: false, format: 'recovered' })
  return Uint8Array.of(31 + sig[0]!, ...sig.subarray(1))
}

/** A recovered minter: the 33-byte compressed key, and its x-only part for comparing with Nostr keys. */
export interface Minter {
  readonly minter: string
  readonly xonly: string
}

const minterOf = (compressed: string): Minter => ({ minter: compressed, xonly: compressed.slice(2) })

/**
 * Recovers the minter of a scheme-1 token, or undefined when it has no
 * valid provenance. A scheme-2 (zap) token needs its Cash Zap's fields:
 * `needsZapEvent` says so, and `verifyZapProvenance` checks it.
 *
 * A tampered token usually still recovers SOME key, just not the real
 * minter's. Callers compare the result against a minter they trust.
 */
export function verifyProvenance(t: ProvenanceInput): Minter | undefined {
  if (t.scheme !== 'mint_v1') return undefined
  return verifyWith(t, undefined)
}

/** Recovers the minter of a scheme-2 (zap) token from the Cash Zap's fields. */
export function verifyZapProvenance(t: ProvenanceInput, zap: ZapFields): Minter | undefined {
  if (t.scheme !== 'zap_v1') return undefined
  return verifyWith(t, zap)
}

function verifyWith(t: ProvenanceInput, zap: ZapFields | undefined): Minter | undefined {
  if (t.mintSignature === undefined) return undefined
  const payload = provenancePayload(t, zap)
  if (payload === undefined) return undefined
  const digest = signedMessageDigest(t.hrp, payload)
  if (digest === undefined) return undefined
  const k = recoverCompact(t.mintSignature, digest)
  return k === undefined ? undefined : minterOf(k)
}

/** A zap bill: its provenance verifies only with the Cash Zap that carries it. */
export function needsZapEvent(t: Pick<Token, 'scheme'>): boolean {
  return t.scheme === 'zap_v1'
}

/** Two keys name the same minter: compared by x-only part (`02‖K`, `03‖K` and `K` are equal). */
export function sameMinter(a: string, b: string): boolean {
  const xa = xonlyOf(a)
  return xa !== undefined && xa === xonlyOf(b)
}

function xonlyOf(k: string): string | undefined {
  const l = k.toLowerCase()
  if (l.length === 66 && (l.startsWith('02') || l.startsWith('03'))) return l.slice(2)
  return l.length === 64 ? l : undefined
}
