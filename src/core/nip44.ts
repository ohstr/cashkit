// NIP-44 v2, implemented on noble and checked against the upstream vectors
// (vectors/nip44.json). Plaintexts are 1 to 2^32-1 bytes, as the current NIP
// says: a u16 length prefix below 65536 bytes, and from 65536 on two zero
// bytes then a u32 (the extended prefix), as nostr-tools and rust-nostr do.
// nmilat checks no length at all; this follows the NIP.
import { chacha20 } from '@noble/ciphers/chacha.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { expand, extract } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'
import { concatBytes, equalBytes, fromHex, fromUtf8, utf8 } from './bytes.js'
import { CoreError } from './errors.js'

const VERSION = 2
const MIN_PLAINTEXT = 1
const MAX_PLAINTEXT = 0xffffffff
/** From this many bytes on, the length goes in the extended prefix. */
export const EXTENDED_PREFIX_THRESHOLD = 65536
const SALT = utf8('nip44-v2')

const fail = (msg: string) => new CoreError('invalid_payload', `nip44: ${msg}`)

/**
 * The conversation key between a secret key and an x-only pubkey (hex). It
 * is symmetric: A's secret with B's pubkey equals B's secret with A's.
 */
export function getConversationKey(secretKey: Uint8Array, xOnlyPubkeyHex: string): Uint8Array {
  let shared: Uint8Array
  try {
    shared = secp256k1.getSharedSecret(secretKey, fromHex('02' + xOnlyPubkeyHex, 'pubkey'))
  } catch {
    throw new CoreError('invalid_key', 'nip44: invalid secret key or pubkey')
  }
  return extract(sha256, shared.subarray(1, 33), SALT)
}

function messageKeys(conversationKey: Uint8Array, nonce: Uint8Array) {
  if (conversationKey.length !== 32) throw fail('conversation key must be 32 bytes')
  if (nonce.length !== 32) throw fail('nonce must be 32 bytes')
  const keys = expand(sha256, conversationKey, nonce, 76)
  return { chachaKey: keys.subarray(0, 32), chachaNonce: keys.subarray(32, 44), hmacKey: keys.subarray(44, 76) }
}

/** Padded length for a plaintext of `len` bytes. */
export function calcPaddedLen(len: number): number {
  if (!Number.isSafeInteger(len) || len < 1) throw fail('expected a positive integer length')
  if (len <= 32) return 32
  const nextPower = 2 ** (Math.floor(Math.log2(len - 1)) + 1)
  const chunk = nextPower <= 256 ? 32 : nextPower / 8
  return chunk * (Math.floor((len - 1) / chunk) + 1)
}

function pad(plaintext: string): Uint8Array {
  const unpadded = utf8(plaintext)
  const len = unpadded.length
  if (len < MIN_PLAINTEXT || len > MAX_PLAINTEXT) throw fail('plaintext must be 1 to 4294967295 bytes')
  const prefix = len >= EXTENDED_PREFIX_THRESHOLD ? 6 : 2
  const out = new Uint8Array(prefix + calcPaddedLen(len))
  const dv = new DataView(out.buffer)
  if (prefix === 6) dv.setUint32(2, len)
  else dv.setUint16(0, len)
  out.set(unpadded, prefix)
  return out
}

function unpad(padded: Uint8Array): string {
  if (padded.length < 2) throw fail('invalid padding')
  const dv = new DataView(padded.buffer, padded.byteOffset, padded.byteLength)
  let len = dv.getUint16(0)
  let prefix = 2
  if (len === 0) {
    // A u16 of zero is never a length (a plaintext is at least 1 byte): it marks the extended prefix.
    if (padded.length < 6) throw fail('invalid padding')
    len = dv.getUint32(2)
    prefix = 6
    if (len < EXTENDED_PREFIX_THRESHOLD) throw fail('invalid padding')
  }
  const unpadded = padded.subarray(prefix, prefix + len)
  if (unpadded.length !== len || padded.length !== prefix + calcPaddedLen(len)) throw fail('invalid padding')
  return fromUtf8(unpadded)
}

function hmacAad(key: Uint8Array, message: Uint8Array, aad: Uint8Array): Uint8Array {
  return hmac(sha256, key, concatBytes(aad, message))
}

/**
 * Encrypts `plaintext` (1 to 2^32-1 UTF-8 bytes). `nonce` is 32 bytes and
 * defaults to fresh randomness; pass one only for test vectors.
 */
export function encrypt(
  plaintext: string,
  conversationKey: Uint8Array,
  nonce: Uint8Array = globalThis.crypto.getRandomValues(new Uint8Array(32)),
): string {
  const { chachaKey, chachaNonce, hmacKey } = messageKeys(conversationKey, nonce)
  const ciphertext = chacha20(chachaKey, chachaNonce, pad(plaintext))
  const mac = hmacAad(hmacKey, ciphertext, nonce)
  return base64.encode(concatBytes(Uint8Array.of(VERSION), nonce, ciphertext, mac))
}

export function decrypt(payload: string, conversationKey: Uint8Array): string {
  const plen = payload.length
  if (plen === 0 || payload[0] === '#') throw fail('unknown encryption version')
  if (plen < 132) throw fail('invalid payload size')
  let data: Uint8Array
  try {
    data = base64.decode(payload)
  } catch {
    throw fail('invalid base64')
  }
  const dlen = data.length
  if (dlen < 99) throw fail('invalid data size')
  if (data[0] !== VERSION) throw fail('unknown encryption version')
  const nonce = data.subarray(1, 33)
  const ciphertext = data.subarray(33, dlen - 32)
  const mac = data.subarray(dlen - 32)

  const { chachaKey, chachaNonce, hmacKey } = messageKeys(conversationKey, nonce)
  if (!equalBytes(hmacAad(hmacKey, ciphertext, nonce), mac)) throw fail('invalid MAC')
  return unpad(chacha20(chachaKey, chachaNonce, ciphertext))
}
