// A SecretVault bound to this browser profile (design §3, §10): a
// non-extractable WebCrypto AES-GCM key, generated once and kept in
// IndexedDB. Script can use the key but never read it out, so a copied
// IndexedDB (or an exported backup) is useless without this profile.
//
// It protects data at rest, not against script running in the page: an XSS
// can call `open` like the wallet does. Ship a strict CSP.
import { base64 } from '@scure/base'
import type { Sealed } from '../wallet/model.js'
import type { SecretVault } from '../wallet/ports.js'

export const DEVICE_ALG = 'device-aesgcm-v1'
const STORE = 'keys'
const KEY_ID = 'device'
const AAD = new TextEncoder().encode('cashkit/vault/device/v1')

export interface DeviceVaultOptions {
  /** Default "cashkit-vault". */
  readonly name?: string
  /** Default globalThis.indexedDB. */
  readonly indexedDB?: IDBFactory
  /** Default globalThis.crypto. */
  readonly crypto?: Crypto
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.addEventListener('success', () => resolve(r.result))
    r.addEventListener('error', () => reject(r.error ?? new Error('indexeddb: request failed')))
  })
}

export class DeviceVault implements SecretVault {
  private constructor(
    private readonly key: CryptoKey,
    private readonly crypto: Crypto,
  ) {}

  /** Opens this profile's key, creating it on first use. */
  static async open(o: DeviceVaultOptions = {}): Promise<DeviceVault> {
    const factory = o.indexedDB ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB
    const crypto = o.crypto ?? globalThis.crypto
    if (factory === undefined) throw new Error('vault-device: no indexedDB in this environment')
    if (crypto?.subtle === undefined) throw new Error('vault-device: no WebCrypto in this environment')
    const openReq = factory.open(o.name ?? 'cashkit-vault', 1)
    openReq.addEventListener('upgradeneeded', () => {
      if (!openReq.result.objectStoreNames.contains(STORE)) openReq.result.createObjectStore(STORE)
    })
    const db = await req(openReq)
    try {
      const existing = (await req(db.transaction(STORE, 'readonly').objectStore(STORE).get(KEY_ID))) as CryptoKey | undefined
      if (existing !== undefined) return new DeviceVault(existing, crypto)
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
      // add, not put: two tabs racing to create the key keep the first one.
      const tx = db.transaction(STORE, 'readwrite')
      try {
        await req(tx.objectStore(STORE).add(key, KEY_ID))
        return new DeviceVault(key, crypto)
      } catch {
        const winner = (await req(db.transaction(STORE, 'readonly').objectStore(STORE).get(KEY_ID))) as CryptoKey
        return new DeviceVault(winner, crypto)
      }
    } finally {
      db.close()
    }
  }

  locked(): boolean {
    return false
  }

  async seal(plain: Uint8Array): Promise<Sealed> {
    const iv = this.crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await this.crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, this.key, plain.slice()))
    const out = new Uint8Array(12 + ct.length)
    out.set(iv)
    out.set(ct, 12)
    return { alg: DEVICE_ALG, data: base64.encode(out) }
  }

  async open(sealed: Sealed): Promise<Uint8Array> {
    if (sealed.alg !== DEVICE_ALG) throw new Error(`vault-device: cannot open a value sealed with ${sealed.alg}`)
    const raw = base64.decode(sealed.data)
    if (raw.length < 12 + 16) throw new Error('vault-device: sealed value too short')
    try {
      return new Uint8Array(await this.crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: AAD }, this.key, raw.slice(12)))
    } catch {
      throw new Error('vault-device: the sealed value is corrupted, or was sealed on another device')
    }
  }
}
