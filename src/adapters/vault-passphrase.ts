// A SecretVault under a passphrase (design §3, §10): scrypt with NIP-49's
// parameters derives one key, and every value is sealed with
// XChaCha20-Poly1305 under a fresh 24-byte nonce.
//
// The vault's non-secret parameters (salt, cost, and a key check) are what
// lets a later process unlock it and tell a wrong passphrase at once; the
// app keeps them next to the wallet, e.g. in localStorage or a file.
//
//   const vault = await PassphraseVault.create(passphrase)    // first run
//   save(JSON.stringify(vault.params))
//   const vault = await PassphraseVault.unlock(passphrase, JSON.parse(load()))
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { scrypt } from '@noble/hashes/scrypt.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'
import { toHex, utf8 } from '../core/index.js'
import type { Sealed } from '../wallet/model.js'
import type { SecretVault } from '../wallet/ports.js'

export const PASSPHRASE_ALG = 'passphrase-v1'
const AAD = utf8('cashkit/vault/passphrase/v1')
const CHECK = utf8('cashkit vault key check')

/** Not secret: safe to store in the clear next to the wallet. */
export interface PassphraseVaultParams {
  readonly v: 1
  /** scrypt N = 2^logN, r = 8, p = 1 (NIP-49). */
  readonly logN: number
  /** base64, 16 bytes. */
  readonly salt: string
  /** base64: a known plaintext sealed under the key, to recognise the right passphrase. */
  readonly check: string
}

export class WrongPassphraseError extends Error {
  override readonly name = 'WrongPassphraseError'
  constructor() {
    super('vault: wrong passphrase')
  }
}

const rand = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n))

function derive(passphrase: string, salt: Uint8Array, logN: number): Uint8Array {
  if (!Number.isInteger(logN) || logN < 1 || logN > 22) throw new Error('vault: logN out of range')
  return scrypt(utf8(passphrase.normalize('NFKC')), salt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32, maxmem: 2 ** (logN + 11) })
}

function sealWith(key: Uint8Array, plain: Uint8Array): string {
  const nonce = rand(24)
  const ct = xchacha20poly1305(key, nonce, AAD).encrypt(plain)
  const out = new Uint8Array(24 + ct.length)
  out.set(nonce)
  out.set(ct, 24)
  return base64.encode(out)
}

function openWith(key: Uint8Array, data: string): Uint8Array {
  const raw = base64.decode(data)
  if (raw.length < 24 + 16) throw new Error('vault: sealed value too short')
  return xchacha20poly1305(key, raw.subarray(0, 24), AAD).decrypt(raw.subarray(24))
}

export class PassphraseVault implements SecretVault {
  private key: Uint8Array | undefined
  /** Which vault sealed a value: the salt's fingerprint, so values from another vault are refused plainly. */
  private readonly kid: string

  private constructor(
    readonly params: PassphraseVaultParams,
    key: Uint8Array,
  ) {
    this.key = key
    this.kid = toHex(sha256(base64.decode(params.salt))).slice(0, 16)
  }

  /** A new vault: a fresh salt, at NIP-49's interactive cost (logN 16) unless told otherwise. */
  static async create(passphrase: string, o: { logN?: number } = {}): Promise<PassphraseVault> {
    if (passphrase === '') throw new Error('vault: the passphrase is empty')
    const logN = o.logN ?? 16
    const salt = rand(16)
    const key = derive(passphrase, salt, logN)
    return new PassphraseVault({ v: 1, logN, salt: base64.encode(salt), check: sealWith(key, CHECK) }, key)
  }

  /** Unlocks an existing vault; throws WrongPassphraseError on the wrong passphrase. */
  static async unlock(passphrase: string, params: PassphraseVaultParams): Promise<PassphraseVault> {
    if (params.v !== 1) throw new Error(`vault: unsupported params version ${String(params.v)}`)
    const key = derive(passphrase, base64.decode(params.salt), params.logN)
    try {
      openWith(key, params.check)
    } catch {
      throw new WrongPassphraseError()
    }
    return new PassphraseVault(params, key)
  }

  /** Forgets the key. Until `unlock`, seal and open refuse and the wallet will not move money. */
  lock(): void {
    this.key?.fill(0)
    this.key = undefined
  }

  /** Re-derives the key after `lock`; throws WrongPassphraseError on the wrong passphrase. */
  async unlock(passphrase: string): Promise<void> {
    const v = await PassphraseVault.unlock(passphrase, this.params)
    this.key = v.key
  }

  locked(): boolean {
    return this.key === undefined
  }

  private requireKey(): Uint8Array {
    if (this.key === undefined) throw new Error('vault: locked')
    return this.key
  }

  async seal(plain: Uint8Array): Promise<Sealed> {
    return { alg: PASSPHRASE_ALG, data: `${this.kid}.${sealWith(this.requireKey(), plain)}` }
  }

  async open(sealed: Sealed): Promise<Uint8Array> {
    if (sealed.alg !== PASSPHRASE_ALG) throw new Error(`vault-passphrase: cannot open a value sealed with ${sealed.alg}`)
    const dot = sealed.data.indexOf('.')
    if (dot < 0 || sealed.data.slice(0, dot) !== this.kid) throw new Error('vault-passphrase: this value was sealed by a different vault')
    try {
      return openWith(this.requireKey(), sealed.data.slice(dot + 1))
    } catch (err) {
      if ((err as Error).message === 'vault: locked') throw err
      throw new Error('vault-passphrase: the sealed value is corrupted', { cause: err })
    }
  }
}
