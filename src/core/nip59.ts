// NIP-59 Gift Wrap, as a Cash Pocket uses it: a rumor (unsigned) sealed
// (kind 13, signed by the user, NIP-44 to the user) and gift-wrapped (kind
// 1059, signed by a one-time wrap key, `p` = the user). Timestamps are
// randomized up to two days into the past.
import { CoreError } from './errors.js'
import { encrypt, getConversationKey } from './nip44.js'
import { finalizeEvent, getEventHash, verifyEvent, type NostrEvent, type UnsignedEvent } from './nip01.js'
import type { Signer } from './identity.js'

export const KIND_SEAL = 13
export const KIND_GIFT_WRAP = 1059
const TWO_DAYS = 172800

/** An unsigned event with its id: what a seal carries. */
export type Rumor = UnsignedEvent & { readonly id: string }

export function createRumor(t: Omit<UnsignedEvent, 'id'>): Rumor {
  const u = { kind: t.kind, pubkey: t.pubkey, created_at: t.created_at, tags: t.tags.map((x) => [...x]), content: t.content }
  return { ...u, id: getEventHash(u) }
}

const randomPast = (now: number, random: (n: number) => Uint8Array) => {
  const b = random(4)
  return Math.max(0, now - ((((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0) % TWO_DAYS))
}

/** Seals a rumor to its own author: NIP-44 to the signer's own pubkey, signed by the signer. */
export async function createSeal(rumor: Rumor, signer: Signer, o: { now: number; random: (n: number) => Uint8Array }): Promise<NostrEvent> {
  if (signer.nip44Encrypt === undefined) throw new CoreError('invalid_key', 'this signer cannot encrypt (NIP-44), which a Cash Pocket needs')
  if (rumor.pubkey !== signer.pubkey) throw new CoreError('invalid_request', 'a seal is signed by the rumor’s author')
  const content = await signer.nip44Encrypt(signer.pubkey, JSON.stringify(rumor))
  return signer.signEvent({ kind: KIND_SEAL, created_at: randomPast(o.now, o.random), tags: [], content })
}

/** Wraps a seal for `recipient` with a one-time `wrapKey` (generated first, so the entry can record it). */
export function createWrap(seal: NostrEvent, wrapKey: Uint8Array, recipient: string, o: { now: number; random: (n: number) => Uint8Array; expiration?: number }): NostrEvent {
  const content = encrypt(JSON.stringify(seal), getConversationKey(wrapKey, recipient))
  return finalizeEvent({ kind: KIND_GIFT_WRAP, created_at: randomPast(o.now, o.random), tags: [['p', recipient], ...(o.expiration !== undefined ? [['expiration', String(o.expiration)]] : [])], content }, wrapKey)
}

/**
 * Unwraps a gift wrap addressed to the signer: the seal must verify, and its
 * author and the rumor's author must both be the signer. Returns the rumor,
 * or undefined for anything else (a DM, a forgery).
 */
export async function unwrap(wrap: NostrEvent, signer: Signer): Promise<Rumor | undefined> {
  try {
    if (wrap.kind !== KIND_GIFT_WRAP || !verifyEvent(wrap)) return undefined
    const seal = JSON.parse(await signer.nip44Decrypt(wrap.pubkey, wrap.content)) as NostrEvent
    if (seal.kind !== KIND_SEAL || !verifyEvent(seal) || seal.pubkey !== signer.pubkey) return undefined
    const rumor = JSON.parse(await signer.nip44Decrypt(seal.pubkey, seal.content)) as Rumor
    if (rumor.pubkey !== signer.pubkey || getEventHash(rumor) !== rumor.id) return undefined
    return rumor
  } catch {
    return undefined
  }
}

/** A NIP-09 deletion of a wrap, signed by its own wrap key, at a randomized time. */
export function wrapDeletion(wrapId: string, wrapKey: Uint8Array, o: { now: number; random: (n: number) => Uint8Array }): NostrEvent {
  return finalizeEvent({ kind: 5, created_at: randomPast(o.now, o.random), tags: [['e', wrapId], ['k', String(KIND_GIFT_WRAP)]], content: '' }, wrapKey)
}

