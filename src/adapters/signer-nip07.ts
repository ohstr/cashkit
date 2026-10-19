// A Signer over a NIP-07 browser extension (window.nostr). The pubkey is
// asked for once, here, so the engine can use it synchronously (design §3).
import type { EventTemplate, NostrEvent, Signer } from '../core/index.js'
import { checkSigned } from './signer-verify.js'

/** The slice of window.nostr this needs. */
export interface Nip07 {
  getPublicKey(): Promise<string>
  signEvent(e: EventTemplate): Promise<NostrEvent>
  nip44?: {
    encrypt(pubkey: string, plaintext: string): Promise<string>
    decrypt(pubkey: string, ciphertext: string): Promise<string>
  }
}

export interface Nip07Signer extends Signer {
  nip44Encrypt(peer: string, plaintext: string): Promise<string>
}

export async function nip07Signer(nostr?: Nip07): Promise<Nip07Signer> {
  const ext = nostr ?? (globalThis as { nostr?: Nip07 }).nostr
  if (ext === undefined) throw new Error('signer-nip07: no window.nostr: install or enable a NIP-07 extension')
  const pubkey = await ext.getPublicKey()
  if (!/^[0-9a-f]{64}$/.test(pubkey)) throw new Error('signer-nip07: the extension returned an invalid pubkey')
  const nip44 = () => {
    if (ext.nip44 === undefined) throw new Error('signer-nip07: this extension does not support NIP-44')
    return ext.nip44
  }
  return {
    pubkey,
    signEvent: async (t) => checkSigned(t, await ext.signEvent({ kind: t.kind, created_at: t.created_at, tags: t.tags, content: t.content }), pubkey, 'signer-nip07'),
    nip44Decrypt: async (peer, ct) => nip44().decrypt(peer, ct),
    nip44Encrypt: async (peer, pt) => nip44().encrypt(peer, pt),
  }
}
