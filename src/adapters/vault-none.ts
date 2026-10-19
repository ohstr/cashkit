// A SecretVault that does not encrypt (design §3). It MUST be chosen
// explicitly: it is for tests and CLI-style use where the store itself is
// protected some other way.
import { fromHex, toHex } from '../core/index.js'
import type { SecretVault } from '../wallet/ports.js'
import type { Sealed } from '../wallet/model.js'

export const NONE_ALG = 'none'

export class NoneVault implements SecretVault {
  async seal(plain: Uint8Array): Promise<Sealed> {
    return { alg: NONE_ALG, data: toHex(plain) }
  }
  async open(sealed: Sealed): Promise<Uint8Array> {
    if (sealed.alg !== NONE_ALG) throw new Error(`vault-none: cannot open a value sealed with ${sealed.alg}`)
    return fromHex(sealed.data, 'sealed value')
  }
  locked(): boolean {
    return false
  }
}
