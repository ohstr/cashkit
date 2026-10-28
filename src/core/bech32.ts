// bech32 framing as nmilat sees it (go-flokicoin chainutil/bech32):
// - no 90-character limit (DecodeNoLimit), since tokens run to hundreds;
// - a bech32 or bech32m checksum passes the framing check and `bech32Decode`
//   reports which one it was; credential decoders (tokens, Hub connection
//   strings, nconnection) refuse bech32m; encode always writes bech32;
// - every character must be printable ASCII (33..126), case must not mix,
//   and an all-uppercase string is read as lowercase;
// - 8<->5 bit regrouping refuses non-zero or excess padding (BIP-173).
// It is written out rather than taken from @scure/base for the unlimited
// length and the checksum report.
import { CoreError } from './errors.js'

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const BECH32_CONST = 1
const BECH32M_CONST = 0x2bc830a3
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

function polymod(values: number[]): number {
  let chk = 1
  for (const v of values) {
    const top = chk >>> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GEN[i]!
    }
  }
  return chk >>> 0
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = []
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5)
  out.push(0)
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31)
  return out
}

const bad = (msg: string) => new CoreError('invalid_bech32', `bech32: ${msg}`)

/** Splits a bech32 string into its lowercase HRP and 5-bit words, saying whether the checksum was bech32m. */
export function bech32Decode(s: string): { hrp: string; words: Uint8Array; bech32m: boolean } {
  if (s.length < 8) throw bad('string shorter than 8 characters')
  let hasLower = false
  let hasUpper = false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 33 || c > 126) throw bad('character outside printable ASCII')
    hasLower ||= c >= 97 && c <= 122
    hasUpper ||= c >= 65 && c <= 90
  }
  if (hasLower && hasUpper) throw new CoreError('mixed_case', 'bech32: mixed case (a string is either all lowercase or all uppercase)')
  const lower = hasUpper ? s.toLowerCase() : s

  const one = lower.lastIndexOf('1')
  if (one < 1 || one + 7 > lower.length) throw bad('invalid separator position')
  const hrp = lower.slice(0, one)
  const data: number[] = []
  for (let i = one + 1; i < lower.length; i++) {
    const v = CHARSET.indexOf(lower[i]!)
    if (v < 0) throw bad('character outside the bech32 charset')
    data.push(v)
  }
  const check = polymod([...hrpExpand(hrp), ...data])
  if (check !== BECH32_CONST && check !== BECH32M_CONST) throw bad('invalid checksum')
  return { hrp, words: Uint8Array.from(data.slice(0, -6)), bech32m: check === BECH32M_CONST }
}

/** Builds a bech32 (not bech32m) string; the HRP is lowercased. */
export function bech32Encode(hrp: string, words: Uint8Array): string {
  const h = hrp.toLowerCase()
  const values = [...hrpExpand(h), ...words]
  const mod = polymod([...values, 0, 0, 0, 0, 0, 0]) ^ BECH32_CONST
  let out = h + '1'
  for (const w of words) out += CHARSET[w]!
  for (let i = 0; i < 6; i++) out += CHARSET[(mod >>> (5 * (5 - i))) & 31]!
  return out
}

/** Regroups bits, refusing leftover padding when `pad` is false. */
export function convertBits(data: Uint8Array, from: number, to: number, pad: boolean): Uint8Array {
  const out: number[] = []
  let acc = 0
  let bits = 0
  const maxv = (1 << to) - 1
  for (const v of data) {
    acc = (acc << from) | v
    bits += from
    while (bits >= to) {
      bits -= to
      out.push((acc >> bits) & maxv)
    }
    acc &= (1 << bits) - 1
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv)
  } else if (bits >= from || acc !== 0) {
    throw bad('invalid padding')
  }
  return Uint8Array.from(out)
}

export const toWords = (bytes: Uint8Array): Uint8Array => convertBits(bytes, 8, 5, true)
export const fromWords = (words: Uint8Array): Uint8Array => convertBits(words, 5, 8, false)
