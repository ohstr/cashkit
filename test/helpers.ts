// Shared test helpers: hand-built TLV strings, as cashctl's rawBech32 and
// nmilat's encodeTLVs build them, so malformed inputs can be produced.
import { bech32Encode, toWords } from '../src/core/bech32.js'
import { concatBytes, utf8 } from '../src/core/bytes.js'
import { encodeCashHubConnection, encodeCircleHubConnection, encodeOrderConnection, getPublicKey, signCashHubConnection, signCircleHubConnection, signOrderConnection, encodeToken, mintPayloadV1, relayHashOf, signCompact, signedMessageDigest, type TokenFields } from '../src/core/index.js'

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

/** The fixture minter key (nmilat LocalMintSigner). */
export const MINT_KEY = fill(0x11, 32)

/** A scheme-1 token signed by `key`, as a Hub mints it. */
export function signedToken(f: Omit<TokenFields, 'scheme' | 'mintSignature' | 'attestedAmountMillis'> & { readonly amount?: bigint }, key: Uint8Array = MINT_KEY): string {
  const { amount = 21000n, ...rest } = f
  const payload = mintPayloadV1({ hrp: f.hrp, walletPubkey: f.walletPubkey, amountMillis: amount, relayHash: relayHashOf(f.relays.map(utf8), f.secret) })
  const mintSignature = signCompact(signedMessageDigest(f.hrp, payload)!, key)
  return encodeToken({ ...rest, scheme: 'mint_v1', mintSignature, attestedAmountMillis: amount })
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
