// NIP-04, the deprecated AES-256-CBC scheme, kept only for NWC wallets that
// speak nothing newer (design §2.3). Checked against nmilat
// (vectors/nip04.json). Prefer nip44 everywhere else.
//
// A ciphertext that is not a whole number of AES blocks is refused with an
// error, like every other malformed payload.
import { cbc } from '@noble/ciphers/aes.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { base64 } from '@scure/base'
import { fromHex, fromUtf8, utf8 } from './bytes.js'
import { CoreError } from './errors.js'

const fail = (msg: string) => new CoreError('invalid_payload', `nip04: ${msg}`)

/** The shared x-coordinate: NIP-04's AES key, used as is (not hashed). */
export function sharedKey(secretKey: Uint8Array, xOnlyPubkeyHex: string): Uint8Array {
  try {
    return secp256k1.getSharedSecret(secretKey, fromHex('02' + xOnlyPubkeyHex, 'pubkey')).subarray(1, 33)
  } catch {
    throw new CoreError('invalid_key', 'nip04: invalid secret key or pubkey')
  }
}

/** `base64(ciphertext) + "?iv=" + base64(iv)`. `iv` is 16 bytes and defaults to fresh randomness. */
export function encrypt(plaintext: string, secretKey: Uint8Array, peerPubkeyHex: string, iv: Uint8Array = globalThis.crypto.getRandomValues(new Uint8Array(16))): string {
  if (iv.length !== 16) throw fail('iv must be 16 bytes')
  const ct = cbc(sharedKey(secretKey, peerPubkeyHex), iv).encrypt(utf8(plaintext))
  return `${base64.encode(ct)}?iv=${base64.encode(iv)}`
}

export function decrypt(payload: string, secretKey: Uint8Array, peerPubkeyHex: string): string {
  const parts = payload.split('?iv=')
  if (parts.length !== 2) throw fail('invalid data format: missing or incorrect IV')
  let ct: Uint8Array
  let iv: Uint8Array
  try {
    iv = base64.decode(parts[1]!.trim())
  } catch {
    throw fail('invalid IV')
  }
  try {
    ct = base64.decode(parts[0]!.trim())
  } catch {
    throw fail('invalid ciphertext')
  }
  if (iv.length !== 16) throw fail(`iv: invalid length ${iv.length}`)
  if (ct.length === 0 || ct.length % 16 !== 0) throw fail('ciphertext is not a whole number of blocks')
  let pt: Uint8Array
  try {
    pt = cbc(sharedKey(secretKey, peerPubkeyHex), iv).decrypt(ct)
  } catch {
    throw fail('invalid padding')
  }
  return fromUtf8(pt)
}
