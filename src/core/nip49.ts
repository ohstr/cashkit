// NIP-49 private key encryption (ncryptsec): scrypt over the NFKC password,
// then XChaCha20-Poly1305 with the key-security byte as associated data.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { scrypt } from '@noble/hashes/scrypt.js'
import { bech32Decode, bech32Encode, fromWords, toWords } from './bech32.js'
import { concatBytes, utf8 } from './bytes.js'
import { CoreError } from './errors.js'

export const NCRYPTSEC_HRP = 'ncryptsec'
const VERSION = 0x02
const ENCODED_LEN = 1 + 1 + 16 + 24 + 1 + 48

/** 0x00: known to have been handled insecurely; 0x01: not; 0x02: unknown. */
export type KeySecurity = 0x00 | 0x01 | 0x02

function deriveKey(password: string, salt: Uint8Array, logN: number): Uint8Array {
  return scrypt(utf8(password.normalize('NFKC')), salt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32, maxmem: 2 ** (logN + 11) })
}

export interface Nip49EncryptOptions {
  /** scrypt cost; 16 is NIP-49's interactive minimum. */
  readonly logN?: number
  readonly keySecurity?: KeySecurity
  readonly random?: (n: number) => Uint8Array
}

/** Encrypts a 32-byte secret key under `password`. */
export function nip49Encrypt(secretKey: Uint8Array, password: string, o: Nip49EncryptOptions = {}): string {
  if (secretKey.length !== 32) throw new CoreError('invalid_key', 'nip49: secret key must be 32 bytes')
  const logN = o.logN ?? 16
  if (!Number.isInteger(logN) || logN < 1 || logN > 22) throw new CoreError('invalid_field', 'nip49: log_n out of range')
  const random = o.random ?? ((n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)))
  const keySecurity = o.keySecurity ?? 0x02
  const salt = random(16)
  const nonce = random(24)
  const ad = Uint8Array.of(keySecurity)
  const ct = xchacha20poly1305(deriveKey(password, salt, logN), nonce, ad).encrypt(secretKey)
  return bech32Encode(NCRYPTSEC_HRP, toWords(concatBytes(Uint8Array.of(VERSION, logN), salt, nonce, ad, ct)))
}

/** Decrypts an ncryptsec. A wrong password fails authentication. */
export function nip49Decrypt(ncryptsec: string, password: string): { secretKey: Uint8Array; keySecurity: KeySecurity; logN: number } {
  const { hrp, words } = bech32Decode(ncryptsec.trim())
  if (hrp !== NCRYPTSEC_HRP) throw new CoreError('invalid_tlv', `nip49: want hrp ${NCRYPTSEC_HRP}`)
  const raw = fromWords(words)
  if (raw.length !== ENCODED_LEN || raw[0] !== VERSION) throw new CoreError('invalid_tlv', 'nip49: unsupported version or length')
  const logN = raw[1]!
  const salt = raw.subarray(2, 18)
  const nonce = raw.subarray(18, 42)
  const keySecurity = raw[42]!
  if (keySecurity > 0x02) throw new CoreError('invalid_tlv', 'nip49: unknown key security byte')
  let secretKey: Uint8Array
  try {
    secretKey = xchacha20poly1305(deriveKey(password, salt, logN), nonce, raw.subarray(42, 43)).decrypt(raw.subarray(43))
  } catch {
    throw new CoreError('invalid_key', 'nip49: wrong password, or the ncryptsec is corrupted')
  }
  return { secretKey, keySecurity: keySecurity as KeySecurity, logN }
}
