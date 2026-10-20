// One Hub's private transport: its announcement, packing, sending and reply
// collection. Port of nmilat nipcash/client/{batch_session,batch_pack,
// batch_send}.go.
import { nip44, type NostrEvent } from '../core/index.js'
import {
  decodeResponse,
  deriveReplyKey,
  encodeEnvelope,
  KIND_HUB_ANNOUNCEMENT,
  KIND_PRIVATE_RESPONSE,
  newNonce,
  normalizeNodeIdentity,
  parseAnnouncement,
  TransportError,
  validateLimits,
  wrapRequest,
  type Announcement,
  type Envelope,
  type Item,
  type ItemResult,
  type Limits,
  type ResultError,
} from '../transport/index.js'
import { ClientError } from './errors.js'
import { joinOutcomes, notServedOutcomes, type ItemOutcome } from './outcome.js'
import { nowMs, nowSeconds, randomOf, type ClientDeps } from './ports.js'
import { EventQueue, readEvents } from './relayIO.js'

/** How long a batch stays valid: well inside the Hub's 120 s ceiling. */
export const NOT_AFTER_WINDOW = 60
/** How long a send waits for a relay to acknowledge the reply subscription. */
export const SUBSCRIPTION_ACK_WAIT_MS = 2000

/** The refusal given to items never sent because a later envelope could not be built. */
export const NOT_SENT = 'NOT_SENT'
/** How long an announcement fetch waits for relays to answer. */
export const ANNOUNCEMENT_FETCH_MS = 5000

/** Where an item's proofs bind: the session's Hub and one envelope. */
export interface ItemBinding {
  readonly hub: string
  readonly nonce: string
  readonly notAfter: number
}

/**
 * Produces one item once its envelope is known. Deferred because an item's
 * proofs commit to the envelope nonce: packing decides the split first,
 * then items are built per envelope.
 */
export interface ItemBuilder {
  readonly id: string
  build(id: string, b: ItemBinding): Promise<Item>
}

interface Packed {
  readonly envelope: Envelope
  readonly ids: readonly string[]
}

export interface SendResult {
  readonly outcomes: ItemOutcome[]
  /** Set when part of the picture is missing; outcomes still hold what arrived. */
  readonly error?: Error
}

export class BatchSession {
  /** The Hub's identity key: what proofs bind to and announcements are checked against. */
  readonly hub: string
  private readonly fallbackRelays: readonly string[]
  private announcement: Announcement | undefined
  private currentRelays: readonly string[]

  private constructor(
    private readonly deps: ClientDeps,
    hub: string,
    relays: readonly string[],
  ) {
    this.hub = hub
    this.fallbackRelays = relays
    this.currentRelays = relays
  }

  /**
   * Fetches and verifies the Hub's announcement. `hub` is the identity the
   * caller already trusts, typically recovered from a bill's mint signature
   * (compressed or x-only); `relays` are where to look first.
   */
  static async open(deps: ClientDeps, hub: string, relays: readonly string[]): Promise<BatchSession> {
    if (relays.length === 0) throw new ClientError('no_relay', 'no relays to look for the hub announcement on')
    const s = new BatchSession(deps, normalizeNodeIdentity(hub), relays)
    await s.refresh()
    return s
  }

  /**
   * Re-fetches the announcement and keeps the newest valid one, never moving
   * back to an older one already held. The bill's own relay hints are always
   * retried, in case the announced relays have gone away.
   */
  async refresh(): Promise<void> {
    const candidates = [...new Set([...this.currentRelays, ...this.fallbackRelays])]
    const events = await readEvents(this.deps.relays, candidates, { kinds: [KIND_HUB_ANNOUNCEMENT], authors: [this.hub], limit: 1 }, ANNOUNCEMENT_FETCH_MS)
    let newest: Announcement | undefined
    for (const e of events) {
      try {
        const a = parseAnnouncement(e, this.hub)
        if (newest === undefined || a.createdAt > newest.createdAt) newest = a
      } catch {
        // A relay can serve any bytes; only a verified announcement counts.
      }
    }
    if (newest === undefined) throw new ClientError('no_announcement', 'hub publishes no private-transport announcement')
    if (this.announcement === undefined || newest.createdAt >= this.announcement.createdAt) {
      this.announcement = newest
      if (newest.relays.length > 0) this.currentRelays = [...newest.relays]
    }
  }

  get limits(): Limits {
    return this.announcement!.limits
  }

  /** The key envelopes are encrypted and p-tagged to. Not the Hub identity. */
  get inbox(): string {
    return this.announcement!.inbox
  }

  /** Announcement relays first, else the caller's hints. */
  get relays(): readonly string[] {
    return this.currentRelays
  }

  /**
   * Builds the next envelope from the head of `rest`: as many items as fit
   * the limits (tested by encoding) and the signing budget. Items are signed
   * as they are added (design §3), so a slow signer just gets smaller envelopes:
   * once half the not_after window has gone on signing, the envelope closes.
   * A single item that takes the whole window is refused (`signer_too_slow`);
   * one that fits no envelope is `item_too_large`. Both before anything is sent.
   */
  private async packOne(rest: readonly ItemBuilder[]): Promise<{ packed: Packed; consumed: number }> {
    try {
      validateLimits(this.limits)
    } catch (err) {
      throw new ClientError('bad_input', 'hub announced an unusable envelope policy', { cause: err })
    }
    const random = randomOf(this.deps)
    const window = this.deps.notAfterSeconds ?? NOT_AFTER_WINDOW
    const startMs = nowMs(this.deps)
    const notAfter = Math.floor(startMs / 1000) + window
    const budgetMs = (window * 1000) / 2
    const binding: ItemBinding = { hub: this.hub, nonce: newNonce(random), notAfter }
    let env: Envelope = { v: 1, notAfter, nonce: binding.nonce, replyTo: newNonce(random), items: [] }
    const ids: string[] = []
    let consumed = 0
    for (const b of rest) {
      const item = await b.build(b.id, binding)
      const elapsed = nowMs(this.deps) - startMs
      if (consumed === 0 && elapsed >= window * 1000) {
        throw new ClientError('signer_too_slow', `signing item ${b.id} took ${Math.round(elapsed / 1000)} s, longer than the hub's ${window} s window`)
      }
      const candidate: Envelope = { ...env, items: [...env.items, item] }
      try {
        encodeEnvelope(candidate, this.limits)
      } catch (err) {
        if (consumed === 0) throw new ClientError('item_too_large', `item ${b.id} does not fit any envelope the hub accepts`, { cause: err })
        break
      }
      env = candidate
      ids.push(b.id)
      consumed++
      if (elapsed >= budgetMs) break
    }
    return { packed: { envelope: env, ids }, consumed }
  }

  /**
   * Packs and sends envelope by envelope, each with its own not_after, so a
   * later envelope never goes out already stale. One outcome per item,
   * always: an envelope that got no answer yields `not_served` for
   * everything in it; items that were never sent, because building a later
   * envelope failed, are refused with NOT_SENT (safe to resend). Nothing is
   * retried here except one send after a stale-policy refresh.
   */
  async send(builders: readonly ItemBuilder[]): Promise<SendResult> {
    if (builders.length === 0) return { outcomes: [] }
    const outcomes: ItemOutcome[] = []
    const errors: Error[] = []
    let rest = builders
    for (let i = 0; rest.length > 0; i++) {
      let packed: { packed: Packed; consumed: number }
      try {
        packed = await this.packOne(rest)
      } catch (err) {
        // Nothing went out yet: the caller gets the error itself.
        if (i === 0) throw err
        for (const b of rest) outcomes.push({ id: b.id, state: 'error', error: { code: NOT_SENT, message: (err as Error).message }, undecodable: false, envelope: i })
        errors.push(err as Error)
        break
      }
      const p = packed.packed
      let r = await this.sendOne(p, i)
      if (r.error && isStalePolicy(r.error)) {
        try {
          await this.refresh()
          r = await this.sendOne(p, i)
        } catch {
          // keep the first failure
        }
      }
      if (r.outcomes.length > 0) {
        outcomes.push(...r.outcomes)
        if (r.error) errors.push(r.error)
      } else {
        outcomes.push(...notServedOutcomes(p.ids, i))
        if (r.error) errors.push(r.error)
      }
      rest = rest.slice(packed.consumed)
    }
    if (errors.length === 1) return { outcomes, error: errors[0]! }
    if (errors.length > 1) return { outcomes, error: new AggregateError(errors, 'client: several envelopes failed') }
    return { outcomes }
  }

  private async sendOne(p: Packed, index: number): Promise<SendResult> {
    let plaintext: string
    try {
      plaintext = encodeEnvelope(p.envelope, this.limits)
    } catch (err) {
      return { outcomes: [], error: err as Error }
    }
    const { event, conversationKey } = wrapRequest(plaintext, this.inbox, { now: nowSeconds(this.deps), random: randomOf(this.deps) })
    const replyKey = deriveReplyKey(conversationKey, p.envelope.replyTo)
    const queue = new EventQueue()
    let stop: () => void
    try {
      stop = await this.subscribeAndPublish(p.envelope.replyTo, event, queue)
    } catch (err) {
      return { outcomes: [], error: err as Error }
    }
    try {
      return await this.collect(queue, replyKey, p, index)
    } finally {
      stop()
    }
  }

  /**
   * Per relay, in order: subscribe for the reply, wait (bounded) for the
   * relay to acknowledge, then publish. The first relay to accept wins. A
   * relay whose publish failed keeps its subscription, since the request may
   * still have arrived.
   */
  private async subscribeAndPublish(replyTo: string, request: NostrEvent, queue: EventQueue): Promise<() => void> {
    const stops: (() => void)[] = []
    const stopAll = () => stops.forEach((s) => s())
    const failures: string[] = []
    for (const relay of this.relays) {
      let ack!: () => void
      const acked = new Promise<void>((r) => (ack = r))
      queue.opened()
      let closed = false
      stops.push(
        this.deps.relays.subscribe([relay], { kinds: [KIND_PRIVATE_RESPONSE], '#p': [replyTo] }, {
          onEvent: (e) => queue.push(e),
          onEose: () => ack(),
          onClose: () => {
            ack()
            if (!closed) {
              closed = true
              queue.sourceClosed()
            }
          },
        }),
      )
      await Promise.race([acked, new Promise((r) => setTimeout(r, SUBSCRIPTION_ACK_WAIT_MS))])
      try {
        const res = await this.deps.relays.publish(relay, request)
        if (res.ok) return stopAll
        failures.push(`${relay}: refused${res.message ? `: ${res.message}` : ''}`)
      } catch (err) {
        failures.push(`${relay}: ${(err as Error).message}`)
      }
    }
    stopAll()
    throw new ClientError('no_relay', `no relay took the request (${failures.join('; ')})`)
  }

  /**
   * Gathers the reply's chunks until the Hub's own total arrives or the
   * envelope's not_after passes. A chunk that does not decrypt under the
   * reply key is someone else's and is ignored; partial replies keep what
   * arrived and say so.
   */
  private async collect(queue: EventQueue, replyKey: Uint8Array, p: Packed, index: number): Promise<SendResult> {
    const results: ItemResult[] = []
    let envError: ResultError | undefined
    const seenSeq = new Set<number>()
    const seenEvents = new Set<string>()
    const answered = new Set<string>()
    let declared = 0
    let total = 0
    const merged = () => ({ results, ...(envError && { error: envError }) })
    const partial = (msg: string): SendResult =>
      seenSeq.size > 0
        ? { outcomes: joinOutcomes(p.ids, merged(), index), error: new ClientError('incomplete_reply', `envelope ${index}: ${msg}`) }
        : { outcomes: [], error: new ClientError('timeout', `envelope ${index}: no reply before not_after`) }

    for (;;) {
      const wait = p.envelope.notAfter * 1000 - nowMs(this.deps)
      const ev = await queue.next(wait)
      if (ev === undefined) {
        return partial(queue.closed ? `got ${seenSeq.size} of ${total} chunks before the relay closed` : `got ${seenSeq.size} of ${total} chunks`)
      }
      if (ev.id !== '') {
        if (seenEvents.has(ev.id)) continue
        seenEvents.add(ev.id)
      }
      let plaintext: string
      try {
        plaintext = nip44.decrypt(ev.content, replyKey)
      } catch {
        continue // addressed to us, but not written by the Hub
      }
      let chunk
      try {
        chunk = decodeResponse(plaintext, p.envelope.nonce, p.ids, this.limits)
      } catch (err) {
        const e = new ClientError('reply_malformed', `decode reply for envelope ${index}`, { cause: err })
        return seenSeq.size > 0 ? { outcomes: joinOutcomes(p.ids, merged(), index), error: e } : { outcomes: [], error: e }
      }
      if (declared === 0) {
        declared = chunk.total
        total = Math.min(declared, p.ids.length)
      } else if (chunk.total !== declared) {
        return { outcomes: [], error: new ClientError('reply_malformed', `envelope ${index}: chunks disagree about the total`) }
      }
      if (seenSeq.has(chunk.seq)) return { outcomes: [], error: new ClientError('reply_malformed', `envelope ${index}: repeated chunk ${chunk.seq}`) }
      seenSeq.add(chunk.seq)
      if (chunk.error && envError === undefined) envError = chunk.error
      for (const r of chunk.results) {
        if (answered.has(r.id)) return { outcomes: [], error: new ClientError('reply_malformed', `envelope ${index}: an item answered in more than one chunk`) }
        answered.add(r.id)
      }
      results.push(...chunk.results)
      if (seenSeq.size === total) return { outcomes: joinOutcomes(p.ids, merged(), index) }
    }
  }
}

/**
 * `BatchSession.open` for a caller with no bill, such as a prospective circle
 * member joining over the private transport: `hub` is then the identity the
 * Hub reported in get_info (NIP-CW §Finding the Private Transport), and
 * `relays` are the Hub connection's.
 */
export const openBatchSession = (deps: ClientDeps, hub: string, relays: readonly string[]): Promise<BatchSession> => BatchSession.open(deps, hub, relays)

function isStalePolicy(err: Error): boolean {
  return err instanceof TransportError && (err.code === 'envelope_too_large' || err.code === 'too_many_items' || err.code === 'verify_budget_exceeded')
}
