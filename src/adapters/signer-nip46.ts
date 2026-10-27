// A Signer over a NIP-46 remote signer ("bunker"), from a bunker:// URI.
// Requests and replies are kind 24133, NIP-44 encrypted between a local
// client key and the remote signer's key. Only replies authored by the
// remote signer are read. An auth_url reply is handed to `onAuthUrl` and
// the request keeps waiting for its real answer, as NIP-46 says. An error
// answer is a SignerError: `denied: ` a refusal, `invalid: ` a malformed
// request, anything else a failure.
//
// A phone bunker can take seconds per signature: the batch session sizes
// envelopes to fit (design §3), so this adapter does not hurry anything.
import { finalizeEvent, getPublicKey, nip44, signerErrorFrom, toHex, verifyEvent, type EventTemplate, type NostrEvent, type Signer } from '../core/index.js'
import type { RelayPool } from '../client/index.js'
import { checkSigned } from './signer-verify.js'

export const KIND_NIP46 = 24133

export interface BunkerPointer {
  readonly remotePubkey: string
  readonly relays: readonly string[]
  readonly secret?: string
}

/**
 * Parses bunker://<remote-signer-pubkey>?relay=…&relay=…&secret=…. A local
 * signer's address (`bunker+unix://`, `unix://`, an absolute path) is
 * refused here: it needs a socket, which `./adapters/signer-unix` (Node
 * only) opens; its `signerFromUri` takes both kinds.
 */
export function parseBunkerUri(uri: string): BunkerPointer {
  const u = uri.trim()
  if (/^(bunker\+unix|unix):/i.test(u) || u.startsWith('/')) {
    throw new Error('signer-nip46: a local signer (unix socket) URI: use signerFromUri from ./adapters/signer-unix (Node)')
  }
  const m = /^bunker:\/\/([0-9a-fA-F]{64})(?:\?(.*))?$/.exec(u)
  if (m === null) throw new Error('signer-nip46: not a bunker:// URI with a hex pubkey')
  const q = new URLSearchParams(m[2] ?? '')
  const relays = q.getAll('relay').filter((r) => r.trim() !== '')
  if (relays.length === 0) throw new Error('signer-nip46: the bunker URI names no relay')
  const secret = q.get('secret') ?? undefined
  return { remotePubkey: m[1]!.toLowerCase(), relays, ...(secret !== undefined && secret !== '' && { secret }) }
}

export interface Nip46Options {
  /** A bunker:// URI, or its parsed form. */
  readonly bunker: string | BunkerPointer
  readonly relays: RelayPool
  /** This app's key toward the bunker; generated when omitted. Persist it to stay paired. */
  readonly clientSecret?: Uint8Array
  /** How long one request waits for its answer. Default 60 s. */
  readonly timeoutMs?: number
  /** Called with a URL the user must open to approve (NIP-46 auth_url). */
  readonly onAuthUrl?: (url: string) => void
  /** Permissions to ask for at connect, e.g. "sign_event:23198,nip44_decrypt". */
  readonly perms?: string
}

export interface Nip46Signer extends Signer {
  /** The remote signer's own key (not necessarily the user's). */
  readonly remotePubkey: string
  /** Secret-bearing: this app's pairing key, to reuse next time. */
  readonly clientSecret: Uint8Array
  close(): void
}

interface Pending {
  resolve(v: string): void
  reject(e: Error): void
  timer: ReturnType<typeof setTimeout>
}

/** Connects to the bunker and resolves the user's pubkey once. */
export async function nip46Signer(o: Nip46Options): Promise<Nip46Signer> {
  const ptr = typeof o.bunker === 'string' ? parseBunkerUri(o.bunker) : o.bunker
  let clientSecret = o.clientSecret
  if (clientSecret === undefined) {
    for (;;) {
      clientSecret = globalThis.crypto.getRandomValues(new Uint8Array(32))
      try {
        getPublicKey(clientSecret)
        break
      } catch {
        // out of range: draw again
      }
    }
  }
  const secret = clientSecret
  const clientPubkey = getPublicKey(secret)
  const ck = nip44.getConversationKey(secret, ptr.remotePubkey)
  const timeoutMs = o.timeoutMs ?? 60_000
  const pending = new Map<string, Pending>()

  const stop = o.relays.subscribe(ptr.relays, { kinds: [KIND_NIP46], authors: [ptr.remotePubkey], '#p': [clientPubkey] }, {
    onEvent: (e) => {
      if (e.pubkey !== ptr.remotePubkey || !verifyEvent(e)) return
      let msg: { id?: unknown; result?: unknown; error?: unknown }
      try {
        msg = JSON.parse(nip44.decrypt(e.content, ck))
      } catch {
        return
      }
      if (typeof msg.id !== 'string') return
      const p = pending.get(msg.id)
      if (p === undefined) return
      if (msg.result === 'auth_url') {
        if (typeof msg.error === 'string') o.onAuthUrl?.(msg.error)
        return // keep waiting for the real answer
      }
      pending.delete(msg.id)
      clearTimeout(p.timer)
      if (typeof msg.error === 'string' && msg.error !== '') p.reject(signerErrorFrom('signer-nip46', msg.error))
      else if (typeof msg.result === 'string') p.resolve(msg.result)
      else p.reject(new Error('signer-nip46: the bunker answered without a result'))
    },
    onEose: () => {},
  })

  async function call(method: string, params: string[]): Promise<string> {
    const id = toHex(globalThis.crypto.getRandomValues(new Uint8Array(16)))
    const content = nip44.encrypt(JSON.stringify({ id, method, params }), ck)
    const req = finalizeEvent({ kind: KIND_NIP46, created_at: Math.floor(Date.now() / 1000), tags: [['p', ptr.remotePubkey]], content }, secret)
    const answer = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id)
        reject(new Error(`signer-nip46: ${method}: no answer from the bunker`))
      }, timeoutMs)
      pending.set(id, { resolve, reject, timer })
    })
    const results = await Promise.allSettled(ptr.relays.map((r) => o.relays.publish(r, req)))
    if (!results.some((r) => r.status === 'fulfilled' && r.value.ok)) {
      const p = pending.get(id)
      pending.delete(id)
      if (p !== undefined) clearTimeout(p.timer)
      throw new Error(`signer-nip46: ${method}: no relay took the request`)
    }
    return answer
  }

  try {
    const ack = await call('connect', [ptr.remotePubkey, ptr.secret ?? '', o.perms ?? ''])
    if (ack !== 'ack' && ack !== ptr.secret) throw new Error('signer-nip46: the bunker did not accept the connection')
    const pubkey = await call('get_public_key', [])
    if (!/^[0-9a-f]{64}$/.test(pubkey)) throw new Error('signer-nip46: the bunker returned an invalid pubkey')
    return {
      pubkey,
      remotePubkey: ptr.remotePubkey,
      clientSecret: secret,
      signEvent: async (t: EventTemplate): Promise<NostrEvent> => {
        const raw = await call('sign_event', [JSON.stringify({ kind: t.kind, content: t.content, tags: t.tags, created_at: t.created_at })])
        let got: unknown
        try {
          got = JSON.parse(raw)
        } catch {
          throw new Error('signer-nip46: sign_event answered with something that is not an event')
        }
        return checkSigned(t, got, pubkey, 'signer-nip46')
      },
      nip44Decrypt: (peer, ct) => call('nip44_decrypt', [peer, ct]),
      nip44Encrypt: (peer, pt) => call('nip44_encrypt', [peer, pt]),
      close: () => {
        stop()
        for (const [id, p] of pending) {
          clearTimeout(p.timer)
          p.reject(new Error('signer-nip46: closed'))
          pending.delete(id)
        }
      },
    }
  } catch (err) {
    stop()
    throw err
  }
}
