// An in-memory relay pool and a Hub that serves the private transport over
// it, with failure injection (design §11.2). Test support only.
import { finalizeEvent, getPublicKey, toHex, type NostrEvent } from '../src/core/index.js'
import { signedToken } from './helpers.js'
import type { Filter, RelayPool, SubscriptionHandlers } from '../src/client/index.js'
import {
  checkFreshness,
  conversationKeyFor,
  decodeEnvelope,
  DEFAULT_LIMITS,
  encodeResponse,
  goEventJSON,
  isBearer,
  KIND_HUB_ANNOUNCEMENT,
  KIND_PRIVATE_REQUEST,
  KIND_PRIVATE_RESPONSE,
  paramsHash,
  sealReply,
  verifyBillProof,
  verifyItemProof,
  type Item,
  type ItemResult,
  type Limits,
} from '../src/transport/index.js'
import { nip44 } from '../src/core/index.js'

// ---- relays

interface Sub {
  readonly filter: Filter
  readonly h: SubscriptionHandlers
}

interface RelayState {
  stored: NostrEvent[]
  subs: Set<Sub>
  down: boolean
  refuse: boolean
  eose: boolean
}

export function matches(f: Filter, e: NostrEvent): boolean {
  if (f.kinds && !f.kinds.includes(e.kind)) return false
  if (f.authors && !f.authors.includes(e.pubkey)) return false
  if (f.ids && !f.ids.includes(e.id)) return false
  if (f.since !== undefined && e.created_at < f.since) return false
  if (f.until !== undefined && e.created_at > f.until) return false
  for (const k of ['p', 'e'] as const) {
    const want = f[`#${k}`]
    if (want && !e.tags.some((t) => t[0] === k && want.includes(t[1]!))) return false
  }
  return true
}

const isEphemeral = (k: number) => k >= 20000 && k < 30000

export class MemoryRelayPool implements RelayPool {
  readonly relays = new Map<string, RelayState>()
  readonly published: { relay: string; event: NostrEvent }[] = []

  relay(url: string): RelayState {
    let r = this.relays.get(url)
    if (!r) {
      r = { stored: [], subs: new Set(), down: false, refuse: false, eose: true }
      this.relays.set(url, r)
    }
    return r
  }

  subscribe(relays: readonly string[], filter: Filter, h: SubscriptionHandlers): () => void {
    const subs: [RelayState, Sub][] = []
    for (const url of relays) {
      const r = this.relay(url)
      if (r.down) {
        queueMicrotask(() => h.onClose?.(url, 'down'))
        continue
      }
      const sub = { filter, h: { ...h, onEvent: (e: NostrEvent) => h.onEvent(e, url) } }
      r.subs.add(sub)
      subs.push([r, sub])
      const stored = r.stored.filter((e) => matches(filter, e))
      queueMicrotask(() => {
        for (const e of stored) sub.h.onEvent(e)
        if (r.eose) h.onEose(url)
      })
    }
    return () => subs.forEach(([r, s]) => r.subs.delete(s))
  }

  async publish(url: string, e: NostrEvent): Promise<{ ok: boolean; message?: string }> {
    const r = this.relay(url)
    if (r.down) throw new Error('connection refused')
    if (r.refuse) return { ok: false, message: 'blocked: test' }
    this.published.push({ relay: url, event: e })
    if (!isEphemeral(e.kind)) {
      // Replaceable kinds keep only the newest per author.
      if (e.kind >= 10000 && e.kind < 20000) r.stored = r.stored.filter((x) => !(x.kind === e.kind && x.pubkey === e.pubkey))
      r.stored.push(e)
    }
    for (const s of Array.from(r.subs)) if (matches(s.filter, e)) queueMicrotask(() => s.h.onEvent(e, url))
    return { ok: true }
  }

  /** Puts an event on a relay without anything noticing (a stale replay, say). */
  store(url: string, e: NostrEvent): void {
    this.relay(url).stored.push(e)
  }
}

// ---- hub

export type Answer = { result: unknown } | { error: { code: string; message?: string } } | 'omit'

export interface RequestInfo {
  readonly item: Item
  readonly params: Record<string, unknown>
  /** The slice proof's signer, or undefined for a bearer item. */
  readonly signer: string | undefined
  /** The bill proof's signer: the bill's connection pubkey. */
  readonly billSigner: string
}

export interface Faults {
  /** Never reply. */
  drop?: boolean
  /** Reply after this many ms. */
  delayMs?: number
  /** Item ids answered by omission. */
  omit?: Set<string>
  /** An envelope-level error instead of results. */
  envelopeError?: { code: string; message?: string }
  /** Split the reply into this many chunks. */
  chunks?: number
  /** Send only the first N chunks. */
  sendChunks?: number
  /** Also publish an imposter reply that does not decrypt. */
  imposter?: boolean
  /** Publish the reply on every relay, not just the one the request came on. */
  replyOnAllRelays?: boolean
  /** Declare this total instead of the real chunk count. */
  declaredTotal?: number
}

export class FakeHub {
  readonly nodeKey: Uint8Array
  readonly inboxKey: Uint8Array
  readonly node: string
  readonly inbox: string
  limits: Limits = DEFAULT_LIMITS
  faults: Faults = {}
  /** Handles one served item. Default: cash_status says every bill is available. */
  handler: (method: string, info: RequestInfo) => Answer = () => ({ result: { recipients: [] } })
  readonly requests: RequestInfo[] = []
  /** Bill wallet pubkey -> its connection pubkey, as the Hub's records hold it. */
  readonly bills = new Map<string, string>()
  clock: () => number = () => Date.now()

  constructor(
    readonly pool: MemoryRelayPool,
    readonly relayUrls: readonly string[],
    seed = 0x0a,
  ) {
    this.nodeKey = new Uint8Array(32).fill(seed)
    this.inboxKey = new Uint8Array(32).fill(seed + 1)
    this.node = getPublicKey(this.nodeKey)
    this.inbox = getPublicKey(this.inboxKey)
  }

  /** Publishes an announcement and starts serving the inbox on every relay. */
  async start(opts: { announceRelays?: readonly string[]; createdAt?: number } = {}): Promise<void> {
    await this.announce({ relays: opts.announceRelays ?? this.relayUrls, createdAt: opts.createdAt ?? Math.floor(this.clock() / 1000) })
    this.pool.subscribe(this.relayUrls, { kinds: [KIND_PRIVATE_REQUEST], '#p': [this.inbox] }, {
      onEvent: (e, relay) => void this.serve(e, relay),
      onEose: () => {},
    })
  }

  announcementEvent(p: { relays: readonly string[]; createdAt: number; limits?: Limits; inbox?: string }): NostrEvent {
    const l = p.limits ?? this.limits
    const content = JSON.stringify({
      v: 1,
      inbox: p.inbox ?? this.inbox,
      limits: { max_bytes: l.maxEnvelopeBytes, max_items: l.maxItems, max_consolidate_sources: l.maxConsolidateSources, pad_bucket_bytes: l.padBucketBytes, max_verify_budget: l.maxVerifyBudget },
      relays: p.relays,
    })
    return finalizeEvent({ kind: KIND_HUB_ANNOUNCEMENT, created_at: p.createdAt, tags: [], content }, this.nodeKey)
  }

  async announce(p: { relays: readonly string[]; createdAt: number; limits?: Limits }): Promise<void> {
    const e = this.announcementEvent(p)
    for (const r of this.relayUrls) await this.pool.publish(r, e).catch(() => undefined)
  }

  private async serve(e: NostrEvent, relay: string): Promise<void> {
    const f = this.faults
    const ck = conversationKeyFor(e.pubkey, this.inboxKey)
    const { envelope } = decodeEnvelope(nip44.decrypt(e.content, ck), this.limits)
    const now = Math.floor(this.clock() / 1000)
    checkFreshness(envelope, now)
    const results: ItemResult[] = []
    for (const item of envelope.items) {
      const binding = { target: item.target, hub: this.node, method: item.method, paramsHash: paramsHash(item.params ?? ''), nonce: envelope.nonce, notAfter: envelope.notAfter }
      let info: RequestInfo
      try {
        const billSigner = verifyBillProof(item.billProof ?? '', binding, now)
        const known = this.bills.get(item.target)
        if (known !== undefined && known !== billSigner) continue // not the bill's key: omit
        const signer = isBearer(item) ? undefined : verifyItemProof(item.proof ?? '', binding, now)
        info = { item, params: JSON.parse(item.params ?? '{}'), signer, billSigner }
      } catch {
        continue // an unverifiable item is omitted
      }
      this.requests.push(info)
      if (f.omit?.has(item.id)) continue
      const a = this.handler(item.method, info)
      if (a === 'omit') continue
      if ('error' in a) results.push({ id: item.id, error: a.error })
      else results.push({ id: item.id, resultType: item.method, result: typeof a.result === 'string' ? a.result : JSON.stringify(a.result, (_k, v) => (typeof v === 'bigint' ? Number(v) : v)) })
    }
    if (f.drop) return
    if (f.delayMs) await new Promise((r) => setTimeout(r, f.delayMs))

    if (f.imposter) {
      // Addressed like the reply, but not sealed with the reply key: must be ignored.
      const fake = finalizeEvent({ kind: KIND_PRIVATE_RESPONSE, created_at: now, tags: [['p', envelope.replyTo]], content: nip44.encrypt('{"v":1}', new Uint8Array(32).fill(5)) }, crypto.getRandomValues(new Uint8Array(32)))
      await this.pool.publish(relay, fake)
    }
    const chunks = Math.max(f.chunks ?? 1, 1)
    const total = f.declaredTotal ?? chunks
    const parts: ItemResult[][] = Array.from({ length: chunks }, () => [])
    results.forEach((r, i) => parts[i % chunks]!.push(r))
    const send = f.sendChunks ?? chunks
    const relays = f.replyOnAllRelays ? this.relayUrls : [relay]
    for (let i = 0; i < send; i++) {
      const plaintext = encodeResponse(
        { v: 1, reqNonce: envelope.nonce, ...(f.envelopeError && { error: f.envelopeError }), results: f.envelopeError ? [] : parts[i]!, seq: i + 1, total },
        this.limits,
      )
      const reply = finalizeEvent({ kind: KIND_PRIVATE_RESPONSE, created_at: now, tags: [['p', envelope.replyTo]], content: sealReply(plaintext, ck, envelope.replyTo) }, crypto.getRandomValues(new Uint8Array(32)))
      for (const r of relays) await this.pool.publish(r, reply).catch(() => undefined)
    }
  }

  /** A real bill minted by this Hub's node: token string, and its credential secret. */
  mintBill(p: {
    walletKey: Uint8Array
    connSecret: Uint8Array
    amount: bigint
    relays?: readonly string[]
    hubGroup?: Uint8Array
    identityRequired?: boolean
  }): string {
    const wallet = getPublicKey(p.walletKey)
    this.bills.set(wallet, getPublicKey(p.connSecret))
    return signedToken(
      {
        hrp: 'lokicash',
        walletPubkey: wallet,
        secret: toHex(p.connSecret),
        relays: p.relays ?? this.relayUrls,
        amount: p.amount,
        ...(p.hubGroup !== undefined && { hubGroup: p.hubGroup }),
        ...(p.identityRequired !== undefined && { identityRequired: p.identityRequired }),
      },
      this.nodeKey,
    )
  }
}

export { goEventJSON }
