import { CoreError } from './errors.js'

const HEX = '0123456789abcdef'

/** Lowercase hex of `bytes`. */
export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += HEX[b >> 4]! + HEX[b & 15]!
  return out
}

function nibble(c: number): number {
  if (c >= 48 && c <= 57) return c - 48 // 0-9
  if (c >= 97 && c <= 102) return c - 87 // a-f
  if (c >= 65 && c <= 70) return c - 55 // A-F
  return -1
}

/**
 * Parses hex in either case, like Go's `hex.DecodeString`. Throws on an odd
 * length or a non-hex character. `field` names the value in the error; the
 * value itself is never echoed, since it may be a secret.
 */
export function fromHex(s: string, field = 'hex'): Uint8Array {
  if (s.length % 2 !== 0) throw new CoreError('invalid_hex', `${field}: odd length hex`)
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) {
    const hi = nibble(s.charCodeAt(2 * i))
    const lo = nibble(s.charCodeAt(2 * i + 1))
    if (hi < 0 || lo < 0) throw new CoreError('invalid_hex', `${field}: invalid hex character`)
    out[i] = (hi << 4) | lo
  }
  return out
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0
  for (const p of parts) len += p.length
  const out = new Uint8Array(len)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

const encoder = new TextEncoder()
// ignoreBOM keeps a leading U+FEFF: by default TextDecoder strips it, and
// a relay or label must come back byte for byte as Go's string() gives it.
const decoder = new TextDecoder('utf-8', { ignoreBOM: true })

export const utf8 = (s: string): Uint8Array => encoder.encode(s)

/** Decodes UTF-8, replacing invalid sequences with U+FFFD. */
export const fromUtf8 = (b: Uint8Array): string => decoder.decode(b)

/**
 * Reports whether `s` is empty after trimming whitespace, using Go's
 * `unicode.IsSpace` set (as `strings.TrimSpace` does). It differs from
 * `String.prototype.trim`: U+0085 counts as space and U+FEFF does not.
 */
export function isBlank(s: string): boolean {
  for (const ch of s) {
    if (!isGoSpace(ch.codePointAt(0)!)) return false
  }
  return true
}

/** Go's `strings.TrimSpace`: trims the `unicode.IsSpace` set from both ends. */
export function trimSpace(s: string): string {
  const chars = [...s]
  let start = 0
  let end = chars.length
  while (start < end && isGoSpace(chars[start]!.codePointAt(0)!)) start++
  while (end > start && isGoSpace(chars[end - 1]!.codePointAt(0)!)) end--
  return chars.slice(start, end).join('')
}

/** Go's `strings.Fields`: splits on runs of `unicode.IsSpace`. */
export function goFields(s: string): string[] {
  const out: string[] = []
  let cur = ''
  for (const ch of s) {
    if (isGoSpace(ch.codePointAt(0)!)) {
      if (cur !== '') out.push(cur)
      cur = ''
    } else cur += ch
  }
  if (cur !== '') out.push(cur)
  return out
}

function isGoSpace(c: number): boolean {
  switch (c) {
    case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d: case 0x20:
    case 0x85: case 0xa0: case 0x1680: case 0x2028: case 0x2029:
    case 0x202f: case 0x205f: case 0x3000:
      return true
  }
  return c >= 0x2000 && c <= 0x200a
}
