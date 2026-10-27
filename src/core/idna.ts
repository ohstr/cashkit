// NIP-IC canonical platform user IDs (§Canonical Platform User IDs): numeric
// X and Discord ids, and email and DNS domains as IDNA A-labels by UTS #46
// ToASCII, non-transitional, with CheckHyphens, CheckBidi, CheckJoiners,
// UseSTD3ASCIIRules and VerifyDnsLength, refusing (never mapping) a domain
// UTS #46 mapping or NFC would change or one with a deviation character.
// Port of nmilat nipIC/canonical.go over golang.org/x/net/idna (Unicode 15.0.0,
// tables in idnaData.ts).
import { sha256 } from '@noble/hashes/sha2.js'
import { toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'
import { BIDI_CLASSES, IDNA_VALID, MARKS } from './idnaData.js'

export const NOT_CANONICAL = 'nipIC: user id is not in canonical form'
export const NO_CANONICAL_FORM = "nipIC: this platform has no canonical form; take the key from the recipient's attestation or nconnection"

const notCanonical = () => new CoreError('invalid_field', NOT_CANONICAL)

// ---- range tables

type Ranges = { starts: Uint32Array; ends: Uint32Array }
function decodeRanges(s: string): Ranges {
  const pairs = s === '' ? [] : s.split(',')
  const starts = new Uint32Array(pairs.length)
  const ends = new Uint32Array(pairs.length)
  let prev = 0
  pairs.forEach((p, i) => {
    const [gap, span] = p.split('.').map((x) => parseInt(x, 36)) as [number, number]
    starts[i] = prev + gap
    ends[i] = starts[i]! + span
    prev = ends[i]! + 1
  })
  return { starts, ends }
}
function inRanges(r: Ranges, cp: number): boolean {
  let lo = 0
  let hi = r.starts.length - 1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (cp < r.starts[mid]!) hi = mid - 1
    else if (cp > r.ends[mid]!) lo = mid + 1
    else return true
  }
  return false
}
let tables: { valid: Ranges; marks: Ranges; bidi: [string, Ranges][] } | undefined
const t = () => (tables ??= { valid: decodeRanges(IDNA_VALID), marks: decodeRanges(MARKS), bidi: Object.entries(BIDI_CLASSES).map(([c, s]) => [c, decodeRanges(s)]) })

const bidiClass = (cp: number): string => t().bidi.find(([, r]) => inRanges(r, cp))?.[0] ?? 'L'
/** A code point UTS #46 keeps as it is under STD3 rules (ASCII: a–z, 0–9 and `-` only). */
const isValid = (cp: number): boolean => (cp < 0x80 ? (cp >= 0x61 && cp <= 0x7a) || (cp >= 0x30 && cp <= 0x39) || cp === 0x2d : inRanges(t().valid, cp))

// ---- punycode (RFC 3492)

const BASE = 36
const TMIN = 1
const TMAX = 26
const SKEW = 38
const DAMP = 700
const adapt = (delta: number, n: number, first: boolean): number => {
  let d = first ? Math.floor(delta / DAMP) : delta >> 1
  d += Math.floor(d / n)
  let k = 0
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN))
    k += BASE
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW))
}
const digit = (c: number): number => (c >= 0x30 && c <= 0x39 ? c - 22 : c >= 0x41 && c <= 0x5a ? c - 0x41 : c >= 0x61 && c <= 0x7a ? c - 0x61 : -1)
const char = (d: number): string => String.fromCharCode(d < 26 ? d + 0x61 : d + 22)

/** Decodes a punycode label (without `xn--`); undefined when it is not valid punycode. */
export function punycodeDecode(s: string): string | undefined {
  const out: number[] = []
  const b = s.lastIndexOf('-')
  for (let i = 0; i < Math.max(b, 0); i++) {
    const c = s.charCodeAt(i)
    if (c >= 0x80) return undefined
    out.push(c)
  }
  let n = 128
  let i = 0
  let bias = 72
  for (let p = b > 0 ? b + 1 : 0; p < s.length; ) {
    const oldi = i
    let w = 1
    for (let k = BASE; ; k += BASE) {
      if (p >= s.length) return undefined
      const d = digit(s.charCodeAt(p++))
      if (d < 0) return undefined
      if (d > Math.floor((0x7fffffff - i) / w)) return undefined
      i += d * w
      const tk = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias
      if (d < tk) break
      w *= BASE - tk
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0)
    n += Math.floor(i / (out.length + 1))
    i %= out.length + 1
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return undefined
    out.splice(i++, 0, n)
  }
  return String.fromCodePoint(...out)
}

/** Encodes a label's code points as punycode (without `xn--`). */
export function punycodeEncode(input: string): string {
  const cps = [...input].map((c) => c.codePointAt(0)!)
  let out = cps.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join('')
  const basic = out.length
  let h = basic
  if (basic > 0) out += '-'
  let n = 128
  let delta = 0
  let bias = 72
  while (h < cps.length) {
    const m = Math.min(...cps.filter((c) => c >= n))
    delta += (m - n) * (h + 1)
    n = m
    for (const c of cps) {
      if (c < n) delta++
      if (c === n) {
        let q = delta
        for (let k = BASE; ; k += BASE) {
          const tk = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias
          if (q < tk) break
          out += char(tk + ((q - tk) % (BASE - tk)))
          q = Math.floor((q - tk) / (BASE - tk))
        }
        out += char(q)
        bias = adapt(delta, h + 1, h === basic)
        delta = 0
        h++
      }
    }
    delta++
    n++
  }
  return out
}

// ---- UTS #46 validity, as golang.org/x/net/idna checks it

const DEVIATIONS = /[ßς‌‍]/u

/** Section 4.1 for one label: hyphens (V2, V3) and a leading combining mark (V5). */
function labelOk(u: string): boolean {
  if (u === '') return false
  if (u.length > 4 && u[2] === '-' && u[3] === '-') return false
  if (u.startsWith('-') || u.endsWith('-')) return false
  return !inRanges(t().marks, u.codePointAt(0)!)
}

/** RFC 5893's Bidi Rule for one label. */
function bidiRuleOk(label: string): boolean {
  const cls = [...label].map((c) => bidiClass(c.codePointAt(0)!))
  if (cls.length === 0) return true
  const first = cls[0]!
  let end = cls.length - 1
  while (end >= 0 && cls[end] === 'NSM') end--
  const lastNonNsm = end >= 0 ? cls[end] : undefined
  if (first === 'R' || first === 'AL') {
    if (!cls.every((c) => ['R', 'AL', 'AN', 'EN', 'ES', 'CS', 'ET', 'ON', 'BN', 'NSM'].includes(c))) return false
    if (lastNonNsm === undefined || !['R', 'AL', 'EN', 'AN'].includes(lastNonNsm)) return false
    return !(cls.includes('EN') && cls.includes('AN'))
  }
  if (first !== 'L') return false
  if (!cls.every((c) => ['L', 'EN', 'ES', 'CS', 'ET', 'ON', 'BN', 'NSM'].includes(c))) return false
  return lastNonNsm === 'L' || lastNonNsm === 'EN'
}

const isRtl = (s: string) => [...s].some((c) => ['R', 'AL', 'AN'].includes(bidiClass(c.codePointAt(0)!)))
const allValid = (s: string) => [...s].every((c) => isValid(c.codePointAt(0)!))

const ASCII_WS = ' \t\n\v\f\r'
const trimAscii = (s: string): string => {
  let a = 0
  let b = s.length
  while (a < b && ASCII_WS.includes(s[a]!)) a++
  while (b > a && ASCII_WS.includes(s[b - 1]!)) b--
  return s.slice(a, b)
}
const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => c.toLowerCase())

/**
 * A domain as IDNA A-labels (§Canonical Platform User IDs): refused, never
 * repaired, when mapping or NFC would change it, when it holds a deviation
 * character, or when ToASCII (hyphens, bidi, joiners, STD3, DNS lengths)
 * rejects it.
 */
export function canonicalDomain(input: string): string {
  const s = asciiLower(input)
  if (s === '' || s.startsWith('@') || s.endsWith('.')) throw notCanonical()
  if (DEVIATIONS.test(s) || s.normalize('NFC') !== s) throw notCanonical()
  const labels = s.split('.')
  const unicode: string[] = []
  for (const label of labels) {
    if (label === '') throw notCanonical()
    if (label.startsWith('xn--')) {
      const u = punycodeDecode(label.slice(4))
      if (u === undefined || DEVIATIONS.test(u) || u.normalize('NFC') !== u || !allValid(u) || !labelOk(u)) throw notCanonical()
      unicode.push(u)
    } else {
      if (!allValid(label) || !labelOk(label)) throw notCanonical()
      unicode.push(label)
    }
  }
  if (unicode.some(isRtl) && !unicode.every(bidiRuleOk)) throw notCanonical()
  const out = unicode.map((u) => ([...u].every((c) => c.charCodeAt(0) < 0x80) ? u : `xn--${punycodeEncode(u)}`))
  if (out.some((l) => l.length === 0 || l.length > 63) || out.join('.').length > 253) throw notCanonical()
  const result = out.join('.')
  if (result !== asciiLower(result)) throw notCanonical()
  return result
}

const NUMERIC = /^[1-9][0-9]{0,19}$/

/** A platform name: one or more of a–z, 0–9, `.`, `_` and `-`. */
export const validPlatformName = (p: string): boolean => /^[a-z0-9._-]+$/.test(p)

/** Whether a sender may derive a ConnectionKey from typed input on this platform. */
export const hasCanonicalForm = (p: string): boolean => p === 'x' || p === 'discord' || p === 'email' || p === 'dns'

/**
 * The canonical user id of typed input (§Canonical Platform User IDs): X
 * and Discord numeric ids; email (trimmed, lowercased, NFC local part, its
 * domain as A-labels); DNS (trimmed, as A-labels). Any other platform has no
 * canonical form: its key is taken from an attestation or nconnection.
 */
export function canonicalUserId(platform: string, typed: string): string {
  if (!validPlatformName(platform)) throw new CoreError('invalid_field', 'nipIC: platform name must match [a-z0-9._-]+')
  switch (platform) {
    case 'x':
    case 'discord':
      if (!NUMERIC.test(typed) || BigInt(typed) >= 1n << 64n) throw notCanonical()
      return typed
    case 'email': {
      const s = asciiLower(trimAscii(typed))
      const at = s.lastIndexOf('@')
      if (at <= 0) throw notCanonical()
      const local = s.slice(0, at)
      if (local.normalize('NFC') !== local) throw notCanonical()
      return `${local}@${canonicalDomain(s.slice(at + 1))}`
    }
    case 'dns':
      return canonicalDomain(trimAscii(typed))
    default:
      throw new CoreError('invalid_field', NO_CANONICAL_FORM)
  }
}

/** The ConnectionKey of typed input on a platform with a canonical form. */
export function connectionKeyFromTyped(platform: string, typed: string): string {
  return toHex(sha256(utf8(`${platform}:${canonicalUserId(platform, typed)}`)))
}

/**
 * The ConnectionKey of an attested user id: the exact string, byte for byte.
 * On a platform with a canonical form the id must already be canonical; an
 * IA that attests any other spelling is refused.
 */
export function connectionKeyFromAttested(platform: string, userId: string): string {
  if (!validPlatformName(platform)) throw new CoreError('invalid_field', 'nipIC: platform name must match [a-z0-9._-]+')
  if (hasCanonicalForm(platform) && canonicalUserId(platform, userId) !== userId) throw notCanonical()
  return toHex(sha256(utf8(`${platform}:${userId}`)))
}
