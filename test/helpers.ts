// Shared test helpers: hand-built TLV strings, as cashctl's rawBech32 and
// nmilat's encodeTLVs build them, so malformed inputs can be produced.
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { bech32Encode, convertBits, toWords } from '../src/core/bech32.js'
import { concatBytes, utf8 } from '../src/core/bytes.js'
import { zapPayloadV1, encodeCashHubConnection, encodeCircleHubConnection, encodeOrderConnection, getPublicKey, signCashHubConnection, signCircleHubConnection, signOrderConnection, encodeToken, mintPayloadV1, relayHashOf, signCompact, signedMessageDigest, type TokenFields } from '../src/core/index.js'

export type RawTLV = [type: number, value: Uint8Array | string]

export const fill = (byte: number, n: number): Uint8Array => new Uint8Array(n).fill(byte)

export function tlvBytes(entries: RawTLV[], raw: number[] = []): Uint8Array {
  const parts: Uint8Array[] = []
  for (const [type, v] of entries) {
    const value = typeof v === 'string' ? utf8(v) : v
    parts.push(Uint8Array.of(type, value.length), value)
  }
  return concatBytes(...parts, Uint8Array.from(raw))
}

export function rawBech32(hrp: string, entries: RawTLV[], raw: number[] = []): string {
  return bech32Encode(hrp, toWords(tlvBytes(entries, raw)))
}

export const KEY = fill(0x22, 32)
export const SECRET = fill(0x33, 32)
export const RELAY = 'wss://r.example'
export const KEY_HEX = '22'.repeat(32)
export const SECRET_HEX = '33'.repeat(32)
export const BASE: RawTLV[] = [
  [0, KEY],
  [1, RELAY],
  [2, SECRET],
]

/**
 * A structurally valid bolt11 on the `lnfc` HRP, built the way
 * tools/export-vectors builds them: zero timestamp and signature, and one
 * payment_hash field. With no amount the invoice is amount-less; millis
 * are written in pico units.
 */
export function invoice(amountMillis?: bigint, hashByte = 0x42): string {
  const hash = toWords(fill(hashByte, 32))
  const words = Uint8Array.from([...fill(0, 7), 1, hash.length >> 5, hash.length & 31, ...hash, ...fill(0, 104)])
  const amount = amountMillis === undefined ? '' : `${amountMillis * 10n}p`
  return bech32Encode(`lnfc${amount}`, words)
}

/** A big-endian number as `n` 5-bit words. */
const intWords = (v: number, n: number): number[] => Array.from({ length: n }, (_, i) => Math.floor(v / 32 ** (n - 1 - i)) % 32)

/**
 * A bolt11 signed by `nodeKey` (so its payee recovers to that node), with a
 * creation time and an optional `x` expiry and `n` payee field.
 */
export function signedInvoice(o: { amountMillis?: bigint; nodeKey: Uint8Array; timestamp: number; expiry?: number; payeeField?: string; hashByte?: number }): string {
  const hash = toWords(fill(o.hashByte ?? 0x42, 32))
  const fields: number[] = [1, hash.length >> 5, hash.length & 31, ...hash]
  if (o.expiry !== undefined) {
    const w = intWords(o.expiry, Math.max(1, Math.ceil(Math.log2(o.expiry + 1) / 5)))
    fields.push(6, w.length >> 5, w.length & 31, ...w)
  }
  if (o.payeeField !== undefined) {
    const w = toWords(hexToBytes(o.payeeField))
    fields.push(19, w.length >> 5, w.length & 31, ...w)
  }
  const data = Uint8Array.from([...intWords(o.timestamp, 7), ...fields])
  const hrp = `lnfc${o.amountMillis === undefined ? '' : `${o.amountMillis * 10n}p`}`
  const digest = sha256(concatBytes(utf8(hrp), convertBits(data, 5, 8, true)))
  const sig = secp256k1.sign(digest, o.nodeKey, { prehash: false, format: 'recovered' })
  const sigWords = toWords(concatBytes(sig.subarray(1), sig.subarray(0, 1)))
  return bech32Encode(hrp, concatBytes(data, sigWords))
}

/** The fixture minter key (nmilat LocalMintSigner). */
export const MINT_KEY = fill(0x11, 32)

/** A scheme-1 token signed by `key`, as a Hub mints it. */
export function signedToken(f: Omit<TokenFields, 'scheme' | 'mintSignature' | 'attestedAmountMillis'> & { readonly amount?: bigint }, key: Uint8Array = MINT_KEY): string {
  const { amount = 21000n, ...rest } = f
  const payload = mintPayloadV1({ hrp: f.hrp, walletPubkey: f.walletPubkey, amountMillis: amount, relayHash: relayHashOf(f.relays.map(utf8), f.secret) })
  const mintSignature = signCompact(signedMessageDigest(f.hrp, payload)!, key)
  return encodeToken({ ...rest, scheme: 'mint_v1', mintSignature, attestedAmountMillis: amount })
}

/** A scheme-2 (zap) token signed by `key` over its `cash-zap:v1` payload. */
export function zapSignedToken(
  f: Omit<TokenFields, 'scheme' | 'mintSignature' | 'attestedAmountMillis'> & { readonly amount: bigint },
  zap: { recipient: string; sender: string; zapTarget: string; issuedAt: number; expiresAt: number },
  key: Uint8Array,
): string {
  const { amount, ...rest } = f
  const payload = zapPayloadV1({ hrp: f.hrp, walletPubkey: f.walletPubkey, amountMillis: amount, relayHash: relayHashOf(f.relays.map(utf8), f.secret), ...zap })
  const mintSignature = signCompact(signedMessageDigest(f.hrp, payload)!, key)
  return encodeToken({ ...rest, scheme: 'zap_v1', mintSignature, attestedAmountMillis: amount })
}

/** The fixture Hub identity key for connection strings (private key 1, as the NIP examples). */
export const HUB_KEY = Uint8Array.of(...fill(0, 31), 1)

/** A connection string signed by `key` (TLV 4 = its x-only key, TLV 6 `bitcoin` unless given). */
export function signedConnection(
  hrp: 'cashhub' | 'cashorder' | 'circlehub',
  f: { walletPubkey: string; secret: string; relays: readonly string[]; label?: string; chain?: string; hubIdentity?: string },
  key: Uint8Array = HUB_KEY,
): string {
  const c = { label: '', chain: 'bitcoin', hubIdentity: getPublicKey(key), ...f }
  const sign = { cashhub: signCashHubConnection, cashorder: signOrderConnection, circlehub: signCircleHubConnection }[hrp]
  const encode = { cashhub: encodeCashHubConnection, cashorder: encodeOrderConnection, circlehub: encodeCircleHubConnection }[hrp]
  return encode(sign(c, key))
}
