// One Hub's private transport: its announcement, packing, sending and reply
// collection. Port of nmilat nipcash/client/{batch_session,batch_pack,
// batch_send}.go.
import { nip44 } from '../core/index.js'
import {
  decodeResponse,
  deriveReplyKey,
  hubUsableForBills,
  isPowRejection,
  parsePowRejection,
  relayPowMinimum,
  wrapRequestPow,
  type PowRequest,
  encodeEnvelope,
  KIND_HUB_ANNOUNCEMENT,
  KIND_PRIVATE_RESPONSE,
  newNonce,
  normalizeNodeIdentity,
  parseAnnouncement,
  TransportError,
  validateLimits,
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
import { EventQueue, fetchRelayInfo, readEvents } from './relayIO.js'

/**
 * A call's deadline (its envelope's `not_after`): well inside the Hub's
 * announced `max_request_age` H, never more than 60 s ahead:
 * now + min(60, ⌊H/2⌋). A Hub that announces no H gets the 30 s of H = 60.
 */
export function deadlineFor(h: number | undefined, now: number): number {
  return now + Math.min(60, Math.floor((h ?? 60) / 2))
}
/** A call is not published with less than this left before its deadline (after its write-ahead). */
export const MIN_PUBLISH_MARGIN = 20
/** The methods that create a bill or move value under a request_id: never sent to a Hub without a usable H. */
const BILL_CREATING = new Set(['cash_transfer', 'cash_consolidate', 'cash_withdraw', 'cash_order'])
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
  /** The item's method, when known: a bill-creating one needs a Hub with a usable `max_request_age`. */
  readonly method?: string
  build(id: string, b: ItemBinding): Promise<Item>
}

export interface SendOptions {
  /** The deadline to use, e.g. one already written ahead; default `deadlineFor(H, now)`. */
  readonly notAfter?: number
  /** Refuse (`single_envelope_required`) rather than split: the deadline is then final before the write-ahead. */
  readonly singleEnvelope?: boolean
  /**
   * Runs once the envelope (and so its deadline and ids) is final, before
   * anything is published: the caller's write-ahead. A throw sends nothing.
   * With less than 20 s then left, nothing is sent either (`deadline_too_close`).
   */
  readonly beforePublish?: (p: { readonly notAfter: number; readonly ids: readonly string[]; readonly envelope: number }) => Promise<void>
}

interface Packed {
  readonly envelope: Envelope
  readonly ids: readonly string[]
}

export interface SendResult {
  readonly outcomes: ItemOutcome[]
  /** Set when part of the picture is missing; outcomes still hold what arrived. */
  readonly error?: Error
  /** The relays that accepted a request event (`OK true`). */
  readonly acceptedRelays?: readonly string[]
}

export class BatchSession {
  /** The Hub's identity key: what proofs bind to and announcements are checked against. */
  readonly hub: string
  /** The token's (or connection's) relay hints, in encoded order, blanks skipped. */
  private readonly hints: readonly string[]
  private announcement: Announcement | undefined

  private constructor(
    private readonly deps: ClientDeps,
    hub: string,
    relays: readonly string[],
  ) {
    this.hub = hub
    this.hints = dedupe(relays)
  }

  /**
   * Fetches and verifies the Hub's announcement. `hub` is the identity the
   * caller already trusts, typically recovered from a bill's mint signature
   * (compressed or x-only); `relays` are where to look first.
   */
  static async open(deps: ClientDeps, hub: string, relays: readonly string[]): Promise<BatchSession> {
    if (dedupe(relays).length === 0) throw new ClientError('no_relay', 'no relays to look for the hub announcement on')
    const s = new BatchSession(deps, normalizeNodeIdentity(hub), relays)
    await s.refresh()
    return s
  }

  /**
   * Re-fetches the announcement from the relay hints and keeps the newest
   * valid one, never moving back to an older one already held.
   */
  async refresh(): Promise<void> {
    const events = await readEvents(this.deps.relays, this.hints, { kinds: [KIND_HUB_ANNOUNCEMENT], authors: [this.hub], limit: 1 }, ANNOUNCEMENT_FETCH_MS)
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
    if (this.announcement === undefined || newest.createdAt >= this.announcement.createdAt) this.announcement = newest
  }

  get limits(): Limits {
    return this.announcement!.limits
  }

  /** The key envelopes are encrypted and p-tagged to. Not the Hub identity. */
  get inbox(): string {
    return this.announcement!.inbox
  }

  /** The Hub's announced `max_request_age` (H), if any. */
  get maxRequestAge(): number | undefined {
    return this.announcement!.maxRequestAge
  }

  /** Whether bill-creating calls may go to this Hub (H announced and at least 60). */
  get usableForBills(): boolean {
    return hubUsableForBills(this.announcement!)
  }

  /** The announcement's `r` relays first, then the hints in encoded order, each once. */
  get relays(): readonly string[] {
    return dedupe([...this.announcement!.relays, ...this.hints])
  }

  /**
   * Builds the next envelope from the head of `rest`: as many items as fit
   * the limits (tested by encoding) and the signing budget. Items are signed
   * as they are added (design §3), so a slow signer just gets smaller envelopes:
   * once half the not_after window has gone on signing, the envelope closes.
   * A single item that takes the whole window is refused (`signer_too_slow`);
   * one that fits no envelope is `item_too_large`. Both before anything is sent.
   */
  private async packOne(rest: readonly ItemBuilder[], o: SendOptions): Promise<{ packed: Packed; consumed: number }> {
    try {
      validateLimits(this.limits)
    } catch (err) {
      throw new ClientError('bad_input', 'hub announced an unusable envelope policy', { cause: err })
    }
    const random = randomOf(this.deps)
    const startMs = nowMs(this.deps)
    const notAfter = o.notAfter ?? deadlineFor(this.maxRequestAge, Math.floor(startMs / 1000))
    const window = notAfter - Math.floor(startMs / 1000)
    const budgetMs = (window * 1000) / 2
    const binding: ItemBinding = { hub: this.hub, nonce: newNonce(random), notAfter }
    let env: Envelope = { notAfter, nonce: binding.nonce, replyTo: newNonce(random), items: [] }
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
        if (o.singleEnvelope === true) throw new ClientError('single_envelope_required', 'these items do not fit one envelope', { cause: err })
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
  async send(builders: readonly ItemBuilder[], o: SendOptions = {}): Promise<SendResult> {
    if (builders.length === 0) return { outcomes: [] }
    if (!this.usableForBills && builders.some((b) => b.method !== undefined && BILL_CREATING.has(b.method))) {
      throw new ClientError('hub_unusable', 'this hub announces no usable max_request_age, so no call that creates a bill may go to it')
    }
    const outcomes: ItemOutcome[] = []
    const errors: Error[] = []
    const accepted = new Set<string>()
    let rest = builders
    for (let i = 0; rest.length > 0; i++) {
      let packed: { packed: Packed; consumed: number }
      try {
        packed = await this.packOne(rest, o)
        if (o.singleEnvelope === true && packed.consumed < rest.length) throw new ClientError('single_envelope_required', 'these items do not fit one envelope')
      } catch (err) {
        // Nothing went out yet: the caller gets the error itself.
        if (i === 0) throw err
        for (const b of rest) outcomes.push({ id: b.id, state: 'error', error: { code: NOT_SENT, message: (err as Error).message }, undecodable: false, envelope: i })
        errors.push(err as Error)
        break
      }
      const p = packed.packed
      // Order: write-ahead, then mine, then the 20 s check, then publish.
      let pow: PowRequest | undefined
      try {
        if (o.beforePublish !== undefined) await o.beforePublish({ notAfter: p.envelope.notAfter, ids: p.ids, envelope: i })
        pow = await this.prepare(p)
        if (o.beforePublish !== undefined && p.envelope.notAfter - nowSeconds(this.deps) < MIN_PUBLISH_MARGIN) {
          pow.dispose()
          throw new ClientError('deadline_too_close', `less than ${MIN_PUBLISH_MARGIN} s were left before the deadline, so nothing was sent`)
        }
      } catch (err) {
        if (i === 0) throw err
        for (const b of rest) outcomes.push({ id: b.id, state: 'error', error: { code: NOT_SENT, message: (err as Error).message }, undecodable: false, envelope: i })
        errors.push(err as Error)
        break
      }
      let r = await this.sendOne(p, i, pow)
      if (r.error && isStalePolicy(r.error) && o.beforePublish === undefined) {
        try {
          await this.refresh()
          r = await this.sendOne(p, i, await this.prepare(p))
        } catch {
          // keep the first failure
        }
      }
      for (const a of r.acceptedRelays ?? []) accepted.add(a)
      if (r.outcomes.length > 0) {
        outcomes.push(...r.outcomes)
        if (r.error) errors.push(r.error)
      } else {
        outcomes.push(...notServedOutcomes(p.ids, i))
        if (r.error) errors.push(r.error)
      }
      rest = rest.slice(packed.consumed)
    }
    const acceptedRelays = [...accepted]
    if (errors.length === 1) return { outcomes, error: errors[0]!, acceptedRelays }
    if (errors.length > 1) return { outcomes, error: new AggregateError(errors, 'client: several envelopes failed'), acceptedRelays }
    return { outcomes, acceptedRelays }
  }

  private readonly powMinimums = new Map<string, number>()

  /** A relay's proof-of-work minimum for kind 23190 (NIP-11), cached; unreadable ⇒ 0 (re-mined on a `pow:` refusal). */
  private async powMinimum(relay: string, fresh = false): Promise<number> {
    if (!fresh && this.powMinimums.has(relay)) return this.powMinimums.get(relay)!
    const read = this.deps.relayInfo ?? this.deps.relays.relayInfo?.bind(this.deps.relays) ?? ((u: string) => fetchRelayInfo(u))
    let n = 0
    try {
      n = relayPowMinimum(await read(relay))
    } catch {
      n = 0
    }
    this.powMinimums.set(relay, n)
    return n
  }

  /**
   * Encodes and wraps the envelope, mined to the highest minimum of the
   * relays it will be published to (plain when all are 0). Over the mining
   * budget nothing is sent (`pow_too_hard`).
   */
  private async prepare(p: Packed): Promise<PowRequest> {
    const plaintext = encodeEnvelope(p.envelope, this.limits)
    let difficulty = 0
    for (const r of this.relays) difficulty = Math.max(difficulty, await this.powMinimum(r))
    const budget = this.deps.powBudget ?? {}
    if (budget.maxDifficulty !== undefined && difficulty > budget.maxDifficulty) throw new ClientError('pow_too_hard', `the relays ask for proof of work of difficulty ${difficulty}, above the budget`)
    const maxMs = budget.maxMs ?? Math.max((p.envelope.notAfter - MIN_PUBLISH_MARGIN) * 1000 - nowMs(this.deps), 0)
    const signal = AbortSignal.timeout(Math.max(maxMs, 1))
    try {
      return await wrapRequestPow(plaintext, this.inbox, { notAfter: p.envelope.notAfter, difficulty, now: nowSeconds(this.deps), random: randomOf(this.deps), signal })
    } catch (err) {
      if (err instanceof TransportError && err.code === 'pow_aborted') throw new ClientError('pow_too_hard', 'mining the proof of work did not finish within the budget', { cause: err })
      throw err
    }
  }

  private async sendOne(p: Packed, index: number, pow: PowRequest): Promise<SendResult> {
    const replyKey = deriveReplyKey(pow.conversationKey, p.envelope.replyTo)
    const queue = new EventQueue()
    let sub: { stop: () => void; accepted: string[] }
    try {
      sub = await this.subscribeAndPublish(p.envelope.replyTo, pow, queue, p.envelope.notAfter)
    } catch (err) {
      pow.dispose()
      return { outcomes: [], error: err as Error }
    }
    pow.dispose()
    try {
      return { ...(await this.collect(queue, replyKey, p, index)), acceptedRelays: sub.accepted }
    } finally {
      sub.stop()
    }
  }

  /**
   * Per relay, in order: subscribe for the reply, wait (bounded) for the
   * relay's EOSE, then publish. The first relay to accept wins. Every
   * subscription opened is kept until the reply is collected, since a relay
   * whose publish failed may still have delivered the request.
   */
  private async subscribeAndPublish(replyTo: string, initial: PowRequest, queue: EventQueue, notAfter: number): Promise<{ stop: () => void; accepted: string[] }> {
    let current = initial
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
        // A `pow:` refusal re-mines the same event (same envelope, same ids) and publishes it to that relay again.
        for (let attempt = 0; ; attempt++) {
          const res = await this.deps.relays.publish(relay, current.event)
          if (res.ok) return { stop: stopAll, accepted: [relay] }
          if (!isPowRejection(res.message) || attempt >= 3 || nowSeconds(this.deps) >= notAfter) {
            failures.push(`${relay}: refused${res.message ? `: ${res.message}` : ''}`)
            break
          }
          const stated = parsePowRejection(res.message) ?? (await this.powMinimum(relay, true))
          const target = Math.max(stated, current.difficulty + 1)
          current = await current.remine(target, { signal: AbortSignal.timeout(Math.max(notAfter * 1000 - nowMs(this.deps), 1)) })
        }
      } catch (err) {
        failures.push(`${relay}: ${(err as Error).message}`)
      }
    }
    stopAll()
    throw new ClientError('no_relay', `no relay took the request (${failures.join('; ')})`)
  }

  /**
   * Gathers the reply's chunks (NIP-CASH §Chunked Replies) until all `total`
   * arrived or the wait ends (at the envelope's `not_after`, or sooner with
   * `ClientDeps.replyWaitMs`). Every decided outcome is kept, whatever else
   * goes wrong: chunks disagreeing about `total`, two events with one `seq`,
   * or a `seq` out of range make the reply incomplete, never void; an item
   * answered twice (in one chunk or across chunks) is `conflicted`; an id
   * never sent is dropped; the same event from two relays is one chunk.
   * `total` is bounded by the items sent.
   */
  private async collect(queue: EventQueue, replyKey: Uint8Array, p: Packed, index: number): Promise<SendResult> {
    const decided = new Map<string, ItemResult>()
    const conflicted = new Set<string>()
    let envError: ResultError | undefined
    const seenSeq = new Set<number>()
    const seenEvents = new Set<string>()
    let declared = 0
    let malformed = false
    let chunks = 0
    const answer = (id: string, r: ItemResult) => {
      if (conflicted.has(id)) return
      if (decided.has(id)) {
        decided.delete(id)
        conflicted.add(id)
      } else decided.set(id, r)
    }
    const outcomes = () => joinOutcomes(p.ids, { results: [...decided.values()], ...(envError && { error: envError }) }, index, conflicted)
    const capMs = this.deps.replyWaitMs
    const endMs = Math.min(p.envelope.notAfter * 1000, capMs !== undefined ? nowMs(this.deps) + capMs : Infinity)
    for (;;) {
      const ev = await queue.next(endMs - nowMs(this.deps))
      if (ev === undefined) {
        if (chunks === 0) return { outcomes: [], error: new ClientError('timeout', `envelope ${index}: no reply before not_after`) }
        const why = malformed ? 'the reply was malformed' : `got ${seenSeq.size} of ${Math.min(declared, p.ids.length)} chunks${queue.closed ? ' before the relay closed' : ''}`
        return { outcomes: outcomes(), error: new ClientError('incomplete_reply', `envelope ${index}: ${why}`) }
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
      } catch {
        continue // another request's reply, or unreadable: not a chunk of this one
      }
      chunks++
      if (chunk.malformedSeq === true) malformed = true
      if (declared === 0) declared = chunk.total
      else if (chunk.total !== declared) malformed = true
      if (seenSeq.has(chunk.seq)) malformed = true
      seenSeq.add(chunk.seq)
      if (chunk.error && envError === undefined) envError = chunk.error
      for (const id of chunk.conflictedIds ?? []) {
        decided.delete(id)
        conflicted.add(id)
      }
      for (const r of chunk.results) answer(r.id, r)
      // Complete once all chunks of the bounded total arrived, or every item already has its answer.
      if (!malformed && (seenSeq.size >= Math.min(declared, p.ids.length) || decided.size === p.ids.length)) return { outcomes: outcomes() }
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

/** Relay URLs in order, each once, blanks skipped. */
function dedupe(relays: readonly string[]): string[] {
  const out: string[] = []
  for (const r of relays) {
    const t = r.trim()
    if (t !== '' && !out.includes(t)) out.push(t)
  }
  return out
}

function isStalePolicy(err: Error): boolean {
  return err instanceof TransportError && (err.code === 'envelope_too_large' || err.code === 'too_many_items' || err.code === 'verify_budget_exceeded')
}
