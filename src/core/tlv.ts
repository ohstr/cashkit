// The TLV stream inside cash tokens, cashhub1, circlehub1 and nconnection1:
// one type byte, one length byte, then the value.
import { bech32Decode, bech32Encode, fromWords, toWords } from './bech32.js'
import { concatBytes, fromHex, fromUtf8, isBlank, utf8 } from './bytes.js'
import { CoreError } from './errors.js'

export interface TLVEntry {
  readonly type: number
  readonly value: Uint8Array
}

/** Largest value a one-byte length can describe. */
export const MAX_TLV_VALUE_LEN = 255

/** Raw 32-byte keys and secrets, as in every Nostr key. */
export const KEY_LEN = 32

/**
 * Reads every entry. A truncated entry is fatal, as in nipcash; the lenient
 * nconnection1 reader is separate.
 */
export function readTLVs(data: Uint8Array): TLVEntry[] {
  const out: TLVEntry[] = []
  let pos = 0
  while (pos < data.length) {
    if (data.length - pos < 2 || data.length - pos < 2 + data[pos + 1]!) {
      throw new CoreError('invalid_tlv', `truncated TLV entry at offset ${pos}`)
    }
    const len = data[pos + 1]!
    out.push({ type: data[pos]!, value: data.subarray(pos + 2, pos + 2 + len) })
    pos += 2 + len
  }
  return out
}

export function writeTLVs(entries: readonly TLVEntry[]): Uint8Array {
  const parts: Uint8Array[] = []
  for (const e of entries) {
    if (e.value.length > MAX_TLV_VALUE_LEN) {
      throw new CoreError('invalid_field', `TLV ${e.type} value exceeds ${MAX_TLV_VALUE_LEN} bytes`)
    }
    parts.push(Uint8Array.of(e.type, e.value.length), e.value)
  }
  return concatBytes(...parts)
}

/**
 * Decodes a credential's bech32 framing; returns the lowercase HRP and the TLV
 * bytes. Credentials are NIP-19 bech32 (BIP-173): a bech32m checksum is refused.
 */
export function decodeBech32TLV(s: string): { hrp: string; data: Uint8Array } {
  const { hrp, words, bech32m } = bech32Decode(s)
  if (bech32m) throw new CoreError('invalid_bech32', 'bech32: bech32m checksum where a bech32 checksum is required')
  return { hrp, data: fromWords(words) }
}

export function encodeBech32TLV(hrp: string, entries: readonly TLVEntry[]): string {
  return bech32Encode(hrp, toWords(writeTLVs(entries)))
}

/** Parses a required 32-byte hex key or secret for an encoder. */
export function keyFromHex(s: string, field: string): Uint8Array {
  const b = fromHex(s, field)
  if (b.length !== KEY_LEN) throw new CoreError('invalid_field', `${field} must be ${KEY_LEN} bytes, got ${b.length}`)
  return b
}

/**
 * Relay entries for an encoder: blank ones are skipped, at least one must
 * remain, and each must fit a TLV value.
 */
export function relayEntries(relays: readonly string[], what: string): TLVEntry[] {
  if (countUsableRelays(relays) === 0) {
    throw new CoreError('invalid_field', `${what} needs at least one non-empty relay url`)
  }
  const out: TLVEntry[] = []
  for (const r of relays) {
    const value = utf8(r)
    if (value.length > MAX_TLV_VALUE_LEN) {
      throw new CoreError('invalid_field', `relay url exceeds ${MAX_TLV_VALUE_LEN} bytes`)
    }
    if (!isBlank(r)) out.push({ type: 1, value })
  }
  return out
}

/** Relays that are non-empty once trimmed; blank ones count as absent. */
export function countUsableRelays(relays: readonly string[]): number {
  let n = 0
  for (const r of relays) if (!isBlank(r)) n++
  return n
}

/**
 * A decoded relay hint as a client lists it, or undefined when it is blank:
 * empty once ASCII whitespace (space, \t, \n, \v, \f, \r) is trimmed. Any
 * other hint counts, non-ASCII ones included, as nmilat counts them.
 */
export function usableHint(value: Uint8Array): string | undefined {
  for (const b of value) if (b !== 0x20 && (b < 0x09 || b > 0x0d)) return fromUtf8(value)
  return undefined
}
