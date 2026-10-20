// NIP-01 events as nmilat serializes, hashes, signs and verifies them. Port of
// nmilat nip01/event.go. The Hub recomputes event ids with nmilat, so cashkit
// hashes exactly nmilat's bytes, including where its escaping departs from
// NIP-01 (control characters as \u00xx). Tags and content escape alike.
import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { fromHex, toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'

export interface EventTemplate {
  readonly kind: number
  /** Unix seconds. */
  readonly created_at: number
  readonly tags: readonly (readonly string[])[]
  readonly content: string
}

export interface UnsignedEvent extends EventTemplate {
  /** x-only, hex. */
  readonly pubkey: string
}

export interface NostrEvent extends UnsignedEvent {
  readonly id: string
  readonly sig: string
}

const HEX = '0123456789abcdef'
const u00 = (c: number) => '\\u00' + HEX[c >> 4]! + HEX[c & 15]!

/** A string as nmilat's utils.EscapeJSONString writes it, for tags and content alike. */
function jsonString(s: string): string {
  let out = '"'
  for (const ch of s) {
    const c = ch.codePointAt(0)!
    if (ch === '"') out += '\\"'
    else if (ch === '\\') out += '\\\\'
    else if (c === 0x0a) out += '\\n'
    else if (c === 0x0d) out += '\\r'
    else if (c === 0x09) out += '\\t'
    else if (c === 0x08) out += '\\b'
    else if (c === 0x0c) out += '\\f'
    else if (c < 0x20) out += u00(c)
    else if (c >= 0xd800 && c <= 0xdfff) out += '�'
    else out += ch
  }
  return out + '"'
}

function checkTemplate(e: EventTemplate): void {
  if (!Number.isSafeInteger(e.created_at) || e.created_at < 0) {
    throw new CoreError('invalid_field', 'event: created_at must be a non-negative integer')
  }
  if (!Number.isInteger(e.kind)) throw new CoreError('invalid_field', 'event: kind must be an integer')
}

/** `[0,pubkey,created_at,kind,tags,content]`, byte for byte as nmilat writes it. */
export function serializeEvent(e: UnsignedEvent): string {
  checkTemplate(e)
  const tags = '[' + e.tags.map((t) => '[' + t.map(jsonString).join(',') + ']').join(',') + ']'
  return `[0,"${e.pubkey.toLowerCase()}",${e.created_at},${e.kind},${tags},${jsonString(e.content)}]`
}

/** The event id: sha256 of the serialization, hex. */
export function getEventHash(e: UnsignedEvent): string {
  return toHex(sha256(utf8(serializeEvent(e))))
}

/** The x-only pubkey (hex) of a 32-byte secret key. */
export function getPublicKey(secretKey: Uint8Array): string {
  return toHex(schnorr.getPublicKey(secretKey))
}

/**
 * Signs a template with BIP-340. `auxRand` defaults to fresh randomness;
 * pass 32 bytes only for reproducible tests.
 */
export function finalizeEvent(t: EventTemplate, secretKey: Uint8Array, auxRand?: Uint8Array): NostrEvent {
  let pubkey: string
  try {
    pubkey = getPublicKey(secretKey)
  } catch {
    throw new CoreError('invalid_key', 'event: invalid secret key')
  }
  const unsigned: UnsignedEvent = {
    kind: t.kind,
    created_at: t.created_at,
    tags: t.tags.map((tag) => [...tag]),
    content: t.content,
    pubkey,
  }
  const id = getEventHash(unsigned)
  const sig = toHex(schnorr.sign(fromHex(id), secretKey, auxRand))
  return { ...unsigned, id, sig }
}

const isHex64 = (s: string) => /^[0-9a-fA-F]{64}$/.test(s)

/** Leading zero bits of a 64-hex id (NIP-13 difficulty). */
export function powDifficulty(idHex: string): number {
  let count = 0
  for (const b of fromHex(idHex, 'event id')) {
    if (b === 0) {
      count += 8
      continue
    }
    count += Math.clz32(b) - 24
    break
  }
  return count
}

/** Go's strconv.Atoi on a 64-bit platform: optional sign, decimal digits, int64 range. */
function atoi(s: string): number | undefined {
  if (!/^[+-]?[0-9]+$/.test(s)) return undefined
  const v = BigInt(s)
  if (v < -(1n << 63n) || v >= 1n << 63n) return undefined
  return Number(v)
}

function powOk(e: NostrEvent): boolean {
  const nonces = e.tags.filter((t) => t.length > 0 && t[0] === 'nonce')
  if (nonces.length === 0) return true
  if (nonces.length > 1 || nonces[0]!.length !== 3) return false
  const want = atoi(nonces[0]![2]!)
  return want !== undefined && powDifficulty(e.id) >= want
}

/**
 * Whether `e` is a valid event as nmilat's `Event.Verify` decides: a
 * well-formed id and pubkey, a kind in 0..65535, a satisfied NIP-13 nonce
 * tag if there is one, an id equal to the recomputed hash (lowercase), and a
 * valid BIP-340 signature. `checkPow: false` skips the nonce tag check, as
 * nmilat's WithoutPowCheck does for events that never travel on their own.
 */
export function verifyEvent(e: NostrEvent, opts: { checkPow?: boolean } = {}): boolean {
  try {
    if (!isHex64(e.id) || !isHex64(e.pubkey)) return false
    if (!Number.isInteger(e.kind) || e.kind < 0 || e.kind > 65535) return false
    if (opts.checkPow !== false && !powOk(e)) return false
    if (!/^[0-9a-fA-F]{128}$/.test(e.sig)) return false
    const id = getEventHash(e)
    if (e.id !== id) return false
    return schnorr.verify(fromHex(e.sig), fromHex(id), fromHex(e.pubkey))
  } catch {
    return false
  }
}
