// Proof of work on kind-23190 requests (NIP-CASH §Proof of Work): a relay
// that enforces it advertises its minimum in NIP-11 and refuses a weaker
// event with `OK false "pow: …"`. The client mines a NIP-13 `nonce` and adds
// a NIP-40 `expiration` equal to the envelope's `not_after`; on a `pow:`
// refusal it re-mines the same event (same key, content and created_at), so
// a request the Hub already ran is never a new one. Port of nmilat
// nipcash/transport pow helpers (RelayPowMinimum, WrapRequestPow,
// PowRequest.Remine, ParsePowRejection, MaxPowAhead).
import { getEventHash, getPublicKey, nip44, powDifficulty, finalizeEvent, type NostrEvent } from '../core/index.js'
import { KIND_PRIVATE_REQUEST } from './envelope.js'
import { TransportError } from './errors.js'
import { randomizedCreatedAt } from './wrap.js'

/** A relay refuses a 23190 whose `expiration` lies more than 1 day ahead. */
export const MAX_POW_AHEAD = 86400
/** Nonces tried between yields to the event loop. */
const CHUNK = 2000

type Random = (n: number) => Uint8Array
const defaultRandom: Random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n))

/** The minimum NIP-13 difficulty a relay's NIP-11 document states for kind 23190; absent or invalid ⇒ 0. */
export function relayPowMinimum(info: unknown): number {
  const lim = info !== null && typeof info === 'object' ? (info as Record<string, unknown>)['limitation'] : undefined
  const v = lim !== null && typeof lim === 'object' ? (lim as Record<string, unknown>)['min_pow_difficulty'] : undefined
  return typeof v === 'number' && Number.isInteger(v) && v > 0 && v <= 256 ? v : 0
}

/** Whether a relay's `OK false` message is a proof-of-work refusal. */
export const isPowRejection = (message: string | undefined): boolean => message !== undefined && message.startsWith('pow:')

/**
 * The difficulty a `pow:` refusal names: its first whitespace-separated word
 * after `pow:` that is a positive integer (`pow: difficulty 20 required`,
 * `pow:20`). Undefined when it names none, or one above 256 bits (then
 * re-read NIP-11).
 */
export function parsePowRejection(message: string | undefined): number | undefined {
  if (!isPowRejection(message)) return undefined
  for (const word of message!.slice(4).split(/\s+/)) {
    if (!/^[+-]?[0-9]+$/.test(word)) continue
    const n = Number(word)
    if (n > 0) return n <= 256 ? n : undefined
  }
  return undefined
}

/** Mines a NIP-13 nonce: increments it until the id has `difficulty` leading zero bits. Aborts with `signal`. */
export async function mineNonce(
  template: { readonly pubkey: string; readonly created_at: number; readonly kind: number; readonly tags: readonly string[][]; readonly content: string },
  difficulty: number,
  o: { readonly start?: bigint; readonly signal?: AbortSignal } = {},
): Promise<{ readonly tags: string[][]; readonly id: string }> {
  const base = template.tags.filter((t) => t[0] !== 'nonce')
  for (let n = o.start ?? 0n; ; n++) {
    if (n % BigInt(CHUNK) === 0n) {
      if (o.signal?.aborted === true) throw new TransportError('pow_aborted', 'mining stopped before the difficulty was met')
      await new Promise((r) => setTimeout(r, 0))
    }
    const tags = [...base.slice(0, 1), ['nonce', n.toString(), String(difficulty)], ...base.slice(1)]
    const id = getEventHash({ ...template, tags })
    if (powDifficulty(id) >= difficulty) return { tags, id }
  }
}

/** A request event the session can re-mine; holds the ephemeral key until `dispose()`. */
export interface PowRequest {
  readonly event: NostrEvent
  readonly conversationKey: Uint8Array
  readonly difficulty: number
  /** The same event (key, content, created_at) mined to `difficulty`, with `nonce` and `expiration`. */
  remine(difficulty: number, o?: { readonly signal?: AbortSignal }): Promise<PowRequest>
  /** Wipes the ephemeral key, once a relay accepted the event or the call closed. */
  dispose(): void
}

/**
 * Wraps an encoded envelope plaintext for the Hub's inbox, as `wrapRequest`
 * does, mined to `difficulty`. Difficulty 0 adds neither `nonce` nor
 * `expiration` (the tag would disclose the deadline). A `notAfter` more
 * than `MAX_POW_AHEAD` past `now` is refused.
 */
export async function wrapRequestPow(
  plaintext: string,
  inbox: string,
  o: { readonly notAfter: number; readonly difficulty: number; readonly now: number; readonly random?: Random; readonly signal?: AbortSignal },
): Promise<PowRequest> {
  if (plaintext === '') throw new TransportError('envelope_malformed', 'refusing to wrap an empty payload')
  if (!/^[0-9a-f]{64}$/.test(inbox)) throw new TransportError('announcement_malformed', 'inbox pubkey must be 64 lowercase hex characters')
  if (o.notAfter - o.now > MAX_POW_AHEAD) throw new TransportError('envelope_too_far_ahead', 'a proof-of-work request expires at most one day ahead')
  const random = o.random ?? defaultRandom
  let key: Uint8Array
  let conversationKey: Uint8Array
  for (;;) {
    key = random(32)
    try {
      conversationKey = nip44.getConversationKey(key, inbox)
      break
    } catch {
      continue
    }
  }
  const content = nip44.encrypt(plaintext, conversationKey, random(32))
  const createdAt = randomizedCreatedAt(o.now, random)
  const pubkey = getPublicKey(key)
  const build = async (difficulty: number, signal?: AbortSignal): Promise<PowRequest> => {
    let tags: string[][] = [['p', inbox]]
    if (difficulty > 0) {
      const mined = await mineNonce({ pubkey, created_at: createdAt, kind: KIND_PRIVATE_REQUEST, tags: [['p', inbox], ['expiration', String(o.notAfter)]], content }, difficulty, signal !== undefined ? { signal } : {})
      tags = mined.tags
    }
    const event = finalizeEvent({ kind: KIND_PRIVATE_REQUEST, created_at: createdAt, tags, content }, key)
    return {
      event,
      conversationKey,
      difficulty,
      remine: (d, ro = {}) => {
        if (key.every((b) => b === 0)) return Promise.reject(new TransportError('pow_aborted', 'this request was disposed'))
        return build(d, ro.signal)
      },
      dispose: () => key.fill(0),
    }
  }
  return build(o.difficulty, o.signal)
}
