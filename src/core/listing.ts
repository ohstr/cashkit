// Offer listings, the wallet's side (NIP-CASH §Listing Offers): checking a
// 31190 before showing it, versions and expiry, operators (11191),
// recommendations (31191), reports (1984), curators (30000), signals and
// ranking, the at-tap check, and the fetch filters. Port of nmilat
// nipcash/listing (wallet side). The Hub side is not ported.
import { onlineCheck, type ConnVerdict } from './connection.js'
import { CoreError } from './errors.js'
import { decodeCircleHubConnection, decodeOrderConnection, verifyCircleHubConnection, verifyOrderConnection, type HubConnection } from './hubConnection.js'
import { getEventHash, verifyEvent, type EventTemplate, type NostrEvent } from './nip01.js'
import { parseCircleWalletInfo, type CircleWalletInfo } from './nipcw.js'
import { parseOrderInfo, sellsNothing, type OrderTerms } from './nipco.js'
import { LOOKALIKE_MARKS, sanitizeText } from './text.js'

export { LOOKALIKE_MARKS, sanitizeText }

export const KIND_LISTING = 31190
export const KIND_OPERATOR_OFFERS = 11191
export const KIND_RECOMMENDATION = 31191
export const KIND_REPORT = 1984
export const CURATOR_SET_KIND = 30000
export const CURATOR_SET_D = 'cash-discover'
export const REPORT_NAMESPACE = 'cash.report'
export const MAX_EXPIRY_SECS = 2_592_000
export const MAX_SKEW_SECS = 900
export const STALE_AFTER_SECS = 864_000
export const MAX_TITLE = 40
export const MAX_CONTENT = 280
export const MAX_GEOHASH = 5

export type ListingType = 'cash_order' | 'circle_wallet'
export type ListingStatus = 'open' | 'paused' | 'closed'
export interface Ref {
  readonly pubkey: string
  readonly relay: string
}
export interface Hint {
  readonly payment: 'lightning' | 'onchain'
  readonly minMillis: bigint
  readonly maxMillis: bigint
  readonly feeBase: bigint
  readonly feePpm: bigint
}

export interface Listing {
  readonly event: NostrEvent
  readonly nodeIdentity: string
  readonly d: string
  readonly type: ListingType
  readonly summary: readonly string[]
  readonly chain: string
  readonly network: string
  /** The listed string, lowercased. */
  readonly connection: string
  readonly hub: HubConnection
  readonly verdict: ConnVerdict
  /** Raw, the lister's claims: every view goes through `sanitizeText`. */
  readonly title: string
  readonly image?: string
  readonly content: string
  readonly operator?: Ref
  readonly status: ListingStatus
  readonly expiration: number
  readonly hints: readonly Hint[]
  readonly followSet?: string
  readonly languages: readonly string[]
  readonly geohashes: readonly string[]
  readonly location?: string
  readonly alt?: string
}

/** A listing that fails one of §Wallet Rules' steps 1–4: never shown, kept as a diagnostic. */
export class ListingError extends Error {
  override readonly name = 'ListingError'
  constructor(
    readonly step: 1 | 2 | 3 | 4,
    readonly reason: string,
  ) {
    super(`listing: step ${step}: ${reason}`)
  }
}

const HEX64 = /^[0-9a-f]{64}$/
const DEC = /^(0|[1-9][0-9]*)$/
const SUMMARY: Readonly<Record<ListingType, readonly string[]>> = { cash_order: ['lightning', 'onchain'], circle_wallet: ['allowlist', 'follow_set'] }

export const listingAddress = (l: Pick<Listing, 'nodeIdentity' | 'd'>): string => `${KIND_LISTING}:${l.nodeIdentity}:${l.d}`
/** `min(expiration, created_at + 30 days)`, whatever the listing says. */
export const listingExpiresAt = (l: Pick<Listing, 'expiration' | 'event'>): number => Math.min(l.expiration, l.event.created_at + MAX_EXPIRY_SECS)

/**
 * §Wallet Rules "Before showing", steps 1–4 in order (the first failure
 * wins): the signature and every count; the type and the connection's HRP
 * (no other string is decoded); the string signed by TLV 4 = `pubkey`, TLV 0
 * = `d`, TLV 6 = `n`; a held chain on mainnet (unless test networks are on).
 * Tags a type does not take, unknown hint kinds, non-https images and long
 * geohashes are dropped, not refused.
 */
export function parseListing(ev: NostrEvent, o: { chains: readonly string[]; testNetworks?: boolean }): Listing {
  if (ev.kind !== KIND_LISTING || getEventHash(ev) !== ev.id || !verifyEvent(ev)) throw new ListingError(1, 'kind, id or signature')
  const all = (k: string) => ev.tags.filter((t) => t[0] === k)
  const exactly = (k: string) => {
    const xs = all(k)
    if (xs.length !== 1 || typeof xs[0]![1] !== 'string') throw new ListingError(1, `exactly one ${k}`)
    return xs[0]![1]
  }
  const atMost = (k: string) => {
    const xs = all(k)
    if (xs.length > 1) throw new ListingError(1, `at most one ${k}`)
    return xs[0]?.[1]
  }
  const d = exactly('d')
  const chain = exactly('n')
  const network = exactly('network')
  const connectionRaw = exactly('connection')
  const status = exactly('status')
  const expirationRaw = exactly('expiration')
  if (!DEC.test(expirationRaw)) throw new ListingError(1, 'expiration is not an integer')
  const title = atMost('title') ?? ''
  const imageRaw = atMost('image')
  const location = atMost('location')
  const alt = atMost('alt')
  const pTags = all('p')
  if (pTags.length > 1) throw new ListingError(1, 'at most one p')
  const aTags = all('a')
  if (aTags.length > 1) throw new ListingError(1, 'at most one a')
  if (status !== 'open' && status !== 'paused' && status !== 'closed') throw new ListingError(1, 'status')
  const ts = all('t').map((t) => t[1] ?? '')
  const types = ts.filter((t): t is ListingType => t === 'cash_order' || t === 'circle_wallet')
  if (new Set(types).size !== types.length) throw new ListingError(1, 'a repeated type t')
  if (types.length !== 1) throw new ListingError(2, 'the type is neither or both')
  const type = types[0]!
  const hrps = all('hint').map((h) => h[1])
  if (new Set(hrps).size !== hrps.length) throw new ListingError(1, 'at most one hint per payment kind')
  const connection = connectionRaw.toLowerCase()
  const want = type === 'cash_order' ? 'cashorder1' : 'circlehub1'
  if (!connection.startsWith(want)) throw new ListingError(2, `the connection is not a ${want} string`)
  let hub: HubConnection
  try {
    hub = type === 'cash_order' ? decodeOrderConnection(connection) : decodeCircleHubConnection(connection)
  } catch (err) {
    throw new ListingError(2, (err as Error).message)
  }
  const verdict = type === 'cash_order' ? verifyOrderConnection(hub) : verifyCircleHubConnection(hub)
  if (!verdict.verified) throw new ListingError(3, 'the connection string is not signed by its Hub identity')
  if (hub.hubIdentity !== ev.pubkey) throw new ListingError(3, 'TLV 4 is not the listing’s pubkey')
  if (hub.walletPubkey !== d) throw new ListingError(3, 'TLV 0 is not d')
  if (hub.chain !== chain) throw new ListingError(3, 'TLV 6 is not n')
  if (!o.chains.includes(chain)) throw new ListingError(4, 'a chain this wallet does not hold')
  if (network !== 'mainnet' && o.testNetworks !== true) throw new ListingError(4, 'a test network, not enabled')
  const num = (v: string | undefined) => (v !== undefined && DEC.test(v) ? BigInt(v) : undefined)
  const hints: Hint[] =
    type !== 'cash_order'
      ? []
      : all('hint').flatMap((h) => {
          const [_, payment, min, max, base, ppm] = h
          const vals = [num(min), num(max), num(base), num(ppm)]
          if ((payment !== 'lightning' && payment !== 'onchain') || vals.some((v) => v === undefined)) return []
          return [{ payment, minMillis: vals[0]!, maxMillis: vals[1]!, feeBase: vals[2]!, feePpm: vals[3]! }]
        })
  const p = pTags[0]
  const followSet = type === 'circle_wallet' && aTags[0]?.[1]?.startsWith('30000:') === true ? aTags[0][1] : undefined
  return {
    event: ev,
    nodeIdentity: ev.pubkey,
    d,
    type,
    summary: ts.filter((t) => SUMMARY[type].includes(t)),
    chain,
    network,
    connection,
    hub,
    verdict,
    title,
    ...(imageRaw !== undefined && imageRaw.startsWith('https://') && { image: imageRaw }),
    content: ev.content,
    ...(p !== undefined && HEX64.test(p[1] ?? '') && { operator: { pubkey: p[1]!, relay: p[2] ?? '' } }),
    status,
    expiration: Number(expirationRaw),
    hints,
    ...(followSet !== undefined && { followSet }),
    languages: ev.tags.filter((t) => t[0] === 'l' && t[2] === 'ISO-639-1' && typeof t[1] === 'string').map((t) => t[1]!),
    geohashes: all('g').flatMap((g) => (typeof g[1] === 'string' && g[1].length > 0 && g[1].length <= MAX_GEOHASH ? [g[1]] : [])),
    ...(location !== undefined && { location }),
    ...(alt !== undefined && { alt }),
  }
}

/**
 * Versions per address (§Versions and expiry): the newest `created_at`, the
 * lowest id on a tie; the newest seen is remembered after it expires and
 * never undercut; a version more than 15 minutes ahead is ignored; a NIP-09
 * deletion by the node identity hides every version up to it.
 */
export class VersionBook {
  private readonly best = new Map<string, Listing>()
  private readonly newestSeen = new Map<string, number>()
  private readonly deletedUpTo = new Map<string, number>()

  offer(l: Listing, now: number): boolean {
    const addr = listingAddress(l)
    const c = l.event.created_at
    if (c > now + MAX_SKEW_SECS) return false
    if ((this.deletedUpTo.get(addr) ?? -1) >= c) return false
    const seen = this.newestSeen.get(addr)
    const cur = this.best.get(addr)
    if (seen !== undefined && c < seen) return false
    if (cur !== undefined && (c < cur.event.created_at || (c === cur.event.created_at && l.event.id >= cur.event.id))) return false
    this.best.set(addr, l)
    this.newestSeen.set(addr, Math.max(seen ?? 0, c))
    return true
  }

  /** A kind 5 from the node identity naming `31190:<node>:<d>` with `k` 31190. */
  applyDeletion(ev: NostrEvent): void {
    if (ev.kind !== 5 || !verifyEvent(ev) || !ev.tags.some((t) => t[0] === 'k' && t[1] === String(KIND_LISTING))) return
    for (const t of ev.tags) {
      if (t[0] !== 'a' || typeof t[1] !== 'string') continue
      const [kind, node] = t[1].split(':')
      if (kind !== String(KIND_LISTING) || node !== ev.pubkey) continue
      this.deletedUpTo.set(t[1], Math.max(this.deletedUpTo.get(t[1]) ?? 0, ev.created_at))
      const cur = this.best.get(t[1])
      if (cur !== undefined && cur.event.created_at <= ev.created_at) this.best.delete(t[1])
    }
  }

  /** Step 5: the current version, open or paused and not expired. */
  current(addr: string, now: number): Listing | undefined {
    const l = this.best.get(addr)
    if (l === undefined || l.status === 'closed' || now > listingExpiresAt(l)) return undefined
    return l
  }

  addresses(): string[] {
    return [...this.best.keys()]
  }

  snapshot(): string {
    return JSON.stringify({ seen: [...this.newestSeen], deleted: [...this.deletedUpTo] })
  }

  restore(json: string): void {
    const v = JSON.parse(json) as { seen: [string, number][]; deleted: [string, number][] }
    for (const [a, c] of v.seen) this.newestSeen.set(a, Math.max(this.newestSeen.get(a) ?? 0, c))
    for (const [a, c] of v.deleted) this.deletedUpTo.set(a, Math.max(this.deletedUpTo.get(a) ?? 0, c))
  }
}

// ---- operators

export interface OperatorOffers {
  readonly event: NostrEvent
  readonly offers: readonly string[]
  readonly nodes: readonly string[]
}

/** An operator's 11191: the public `a` and `p` items only. */
export function parseOperatorOffers(ev: NostrEvent): OperatorOffers {
  if (ev.kind !== KIND_OPERATOR_OFFERS) throw new CoreError('invalid_payload', 'not an 11191')
  return { event: ev, offers: ev.tags.filter((t) => t[0] === 'a' && typeof t[1] === 'string' && t[1].startsWith(`${KIND_LISTING}:`)).map((t) => t[1]!), nodes: ev.tags.filter((t) => t[0] === 'p' && HEX64.test(t[1] ?? '')).map((t) => t[1]!) }
}

/** The author's newest 11191 (highest `created_at`, lowest id on a tie). */
export function newestOperatorOffers(evs: readonly NostrEvent[], author: string): OperatorOffers | undefined {
  let best: NostrEvent | undefined
  for (const e of evs) {
    if (e.kind !== KIND_OPERATOR_OFFERS || e.pubkey !== author || !verifyEvent(e)) continue
    if (best === undefined || e.created_at > best.created_at || (e.created_at === best.created_at && e.id < best.id)) best = e
  }
  return best !== undefined ? parseOperatorOffers(best) : undefined
}

/** Verified only when the listing's `p` names this author and the author's newest 11191 names the listing's address. */
export const operatorVerified = (l: Listing, newest: OperatorOffers | undefined): boolean => l.operator !== undefined && newest !== undefined && newest.event.pubkey === l.operator.pubkey && newest.offers.includes(listingAddress(l))

// ---- recommendations and reports

/** An unsigned 31191: one per user per node; `content` exactly as the user typed it. */
export function newRecommendation(node: string, nodeRelay: string, offers: readonly string[], content: string): EventTemplate {
  return { kind: KIND_RECOMMENDATION, created_at: 0, content, tags: [['d', node], ['k', String(KIND_LISTING)], ['p', node, nodeRelay], ...offers.map((a) => ['a', a, nodeRelay]), ['alt', 'Recommendation of a cash offer']] }
}

export interface Recommendation {
  readonly event: NostrEvent
  readonly node: string
  readonly offers: readonly string[]
}

/** `p` ≠ `d` is ignored (undefined); an `a` of another node is dropped. */
export function parseRecommendation(ev: NostrEvent): Recommendation | undefined {
  if (ev.kind !== KIND_RECOMMENDATION) return undefined
  const d = ev.tags.find((t) => t[0] === 'd')?.[1]
  const p = ev.tags.find((t) => t[0] === 'p')?.[1]
  if (d === undefined || p !== d) return undefined
  return { event: ev, node: d, offers: ev.tags.filter((t) => t[0] === 'a' && t[1]?.split(':')[1] === d).map((t) => t[1]!) }
}

/** The offers of a node a recommendation credits: those it names, and those whose verified operator is a named offer's. */
export function creditedOffers(rec: Recommendation, offersOfNode: readonly string[], operatorOf: (addr: string) => string | undefined): string[] {
  const named = new Set(rec.offers)
  const ops = new Set(rec.offers.map(operatorOf).filter((x): x is string => x !== undefined))
  return offersOfNode.filter((a) => named.has(a) || (operatorOf(a) !== undefined && ops.has(operatorOf(a)!)))
}

/** Recommending is offered only for a used offer, never in the session of an order or join there, nor within a day of it. */
export function recommendAllowed(x: { used: boolean; lastOrderOrJoin?: number; sessionStart: number; now: number }): { allowed: boolean; reasonIfNot?: 'not_used' | 'same_session' | 'too_soon' } {
  if (!x.used) return { allowed: false, reasonIfNot: 'not_used' }
  if (x.lastOrderOrJoin !== undefined && x.lastOrderOrJoin >= x.sessionStart) return { allowed: false, reasonIfNot: 'same_session' }
  if (x.lastOrderOrJoin !== undefined && x.now - x.lastOrderOrJoin < 86400) return { allowed: false, reasonIfNot: 'too_soon' }
  return { allowed: true }
}

export type ReportReason = 'no_payout' | 'impersonation' | 'spam' | 'terms_mismatch'
const NIP56: Readonly<Record<ReportReason, string>> = { no_payout: 'other', impersonation: 'impersonation', spam: 'spam', terms_mismatch: 'other' }

/** An unsigned NIP-56 report about a node identity, labelled in `cash.report` for `no_payout` and `terms_mismatch`. */
export function newReport(r: { node: string; address?: string; listingId?: string; reason: ReportReason; content: string }): EventTemplate {
  const type = NIP56[r.reason]
  const labelled = r.reason === 'no_payout' || r.reason === 'terms_mismatch'
  return {
    kind: KIND_REPORT,
    created_at: 0,
    content: r.content,
    tags: [['p', r.node, type], ...(r.address !== undefined ? [['a', r.address]] : []), ...(r.listingId !== undefined ? [['e', r.listingId, type]] : []), ...(labelled ? [['L', REPORT_NAMESPACE], ['l', r.reason, REPORT_NAMESPACE]] : [])],
  }
}

export interface ListingReport {
  readonly event: NostrEvent
  readonly node: string
  readonly reason: ReportReason | 'other'
  readonly address?: string
}

export function parseReport(ev: NostrEvent): ListingReport | undefined {
  if (ev.kind !== KIND_REPORT) return undefined
  const p = ev.tags.find((t) => t[0] === 'p')
  if (p === undefined || !HEX64.test(p[1] ?? '')) return undefined
  const label = ev.tags.find((t) => t[0] === 'l' && t[2] === REPORT_NAMESPACE)?.[1]
  const reason = label === 'no_payout' || label === 'terms_mismatch' ? label : p[2] === 'impersonation' || p[2] === 'spam' ? p[2] : 'other'
  const a = ev.tags.find((t) => t[0] === 'a')?.[1]
  return { event: ev, node: p[1]!, reason, ...(a !== undefined && { address: a }) }
}

// ---- curators

export interface CuratorSet {
  readonly curators: readonly string[]
  readonly private: boolean
}

/** The user's curators as a NIP-51 30000 `cash-discover`, private by default (NIP-44 to self), no title. */
export async function newCuratorSet(set: CuratorSet, encryptToSelf: (plaintext: string) => Promise<string>): Promise<EventTemplate> {
  const items = set.curators.map((c) => ['p', c])
  return set.private ? { kind: CURATOR_SET_KIND, created_at: 0, tags: [['d', CURATOR_SET_D]], content: await encryptToSelf(JSON.stringify(items)) } : { kind: CURATOR_SET_KIND, created_at: 0, tags: [['d', CURATOR_SET_D], ...items], content: '' }
}

export async function parseCuratorSet(ev: NostrEvent, decryptFromSelf: (ciphertext: string) => Promise<string>): Promise<CuratorSet> {
  const pub = ev.tags.filter((t) => t[0] === 'p' && HEX64.test(t[1] ?? '')).map((t) => t[1]!)
  let priv: string[] = []
  if (ev.content !== '') {
    try {
      priv = (JSON.parse(await decryptFromSelf(ev.content)) as string[][]).filter((t) => t[0] === 'p' && HEX64.test(t[1] ?? '')).map((t) => t[1]!)
    } catch {
      priv = []
    }
  }
  return { curators: [...new Set([...pub, ...priv])], private: priv.length > 0 }
}

// ---- signals and ranking

export interface Trust {
  readonly follows: ReadonlySet<string>
  readonly curators: ReadonlySet<string>
}
/** The only gate for signals: the user's follows and curators, never global counts. */
export const trustAccepts = (t: Trust, author: string): boolean => t.follows.has(author) || t.curators.has(author)

export interface Signals {
  readonly recommendations: readonly Recommendation[]
  readonly reports: readonly ListingReport[]
  readonly operatorFollowedBy: readonly string[]
}

export function signalsFor(l: Listing, trust: Trust, recs: readonly Recommendation[], reports: readonly ListingReport[], operatorFollowers: readonly string[], operatorOf: (addr: string) => string | undefined, offersOfNode: readonly string[]): Signals {
  const addr = listingAddress(l)
  return {
    recommendations: recs.filter((r) => trustAccepts(trust, r.event.pubkey) && r.node === l.nodeIdentity && creditedOffers(r, offersOfNode, operatorOf).includes(addr)),
    reports: reports.filter((r) => trustAccepts(trust, r.event.pubkey) && r.node === l.nodeIdentity),
    operatorFollowedBy: operatorOf(addr) !== undefined ? operatorFollowers.filter((f) => trustAccepts(trust, f)) : [],
  }
}

/** Signalled before unsignalled, fresh (at most 10 days old) before stale, then newest first. */
export function rankKey(l: Listing, s: Signals, now: number): [number, number, number] {
  const signalled = s.recommendations.length > 0 || s.operatorFollowedBy.length > 0 ? 0 : 1
  const stale = now - l.event.created_at > STALE_AFTER_SECS ? 1 : 0
  return [signalled, stale, -l.event.created_at]
}

// ---- at tap

export type TapOutcome = 'show' | 'hide_for_good' | 'hide_until_newer' | 'unavailable'
export interface TapResult {
  readonly outcome: TapOutcome
  readonly reason: string
  readonly terms?: OrderTerms
  readonly circle?: CircleWalletInfo
  /** A listed hint differs from the terms `get_info` gave. */
  readonly hintDiffers: boolean
}

const xonlyOf = (k: string | undefined) => (k !== undefined && k.length === 66 ? k.slice(2) : k)

/**
 * The at-tap check (§Wallet Rules "At tap"), on the `get_info` the listed
 * connection answered: the online check and the identity equal to the
 * listing's `pubkey` (else hidden for good), the same network (else hidden
 * for good), the Hub's closed signal (hidden until a newer version); no
 * answer or any error keeps it, unavailable for now.
 */
export function checkTap(l: Listing, info: unknown, infoError: unknown): TapResult {
  if (infoError !== undefined || info === undefined || info === null || typeof info !== 'object') return { outcome: 'unavailable', reason: 'no answer', hintDiffers: false }
  const o = info as Record<string, unknown>
  let identity: string | undefined
  let circle: CircleWalletInfo | undefined
  try {
    if (l.type === 'circle_wallet') {
      circle = parseCircleWalletInfo(o)
      identity = circle?.identity
    } else identity = typeof o['pubkey'] === 'string' ? (o['pubkey'] as string) : undefined
  } catch {
    return { outcome: 'unavailable', reason: 'malformed terms', hintDiffers: false }
  }
  try {
    onlineCheck(l.hub, { ...(identity !== undefined && { identity }), chain: o['chain'] })
  } catch (err) {
    return { outcome: 'hide_for_good', reason: (err as Error).message, hintDiffers: false }
  }
  if (xonlyOf(identity) !== l.nodeIdentity) return { outcome: 'hide_for_good', reason: 'the identity is not the listing’s pubkey', hintDiffers: false }
  if (o['network'] !== l.network) return { outcome: 'hide_for_good', reason: 'another network than the listing’s', hintDiffers: false }
  if (l.type === 'cash_order') {
    let terms: OrderTerms
    try {
      terms = parseOrderInfo(o)
    } catch {
      return { outcome: 'unavailable', reason: 'malformed terms', hintDiffers: false }
    }
    if (sellsNothing(terms)) return { outcome: 'hide_until_newer', reason: 'the Hub sells nothing now', hintDiffers: false }
    const hintDiffers = l.hints.some((h) => {
      const k = terms[h.payment]
      return k === undefined || k.minMillis !== h.minMillis || k.maxMillis !== h.maxMillis || k.feeBase !== h.feeBase || k.feePpm !== h.feePpm
    })
    return { outcome: 'show', reason: 'ok', terms, hintDiffers }
  }
  if (circle === undefined) return { outcome: 'unavailable', reason: 'no circle_wallet terms', hintDiffers: false }
  if (!circle.accepting) return { outcome: 'hide_until_newer', reason: 'the circle is not accepting joins', hintDiffers: false }
  if (circle.available_millis === 0n) return { outcome: 'unavailable', reason: 'no room now', circle, hintDiffers: false }
  return { outcome: 'show', reason: 'ok', circle, hintDiffers: false }
}

/** Tap outcomes per `pubkey`, `d` and `created_at`: `hide_until_newer` lifts for a newer version. */
export class TapCache {
  private readonly m = new Map<string, { outcome: TapOutcome; createdAt: number }>()
  record(l: Listing, r: TapResult): void {
    this.m.set(listingAddress(l), { outcome: r.outcome, createdAt: l.event.created_at })
  }
  hidden(l: Listing): boolean {
    const r = this.m.get(listingAddress(l))
    if (r === undefined) return false
    if (r.outcome === 'hide_for_good') return r.createdAt === l.event.created_at
    if (r.outcome === 'hide_until_newer') return l.event.created_at <= r.createdAt
    return false
  }
  last(l: Listing): TapOutcome | undefined {
    const r = this.m.get(listingAddress(l))
    return r !== undefined && r.createdAt === l.event.created_at ? r.outcome : undefined
  }

  /** The outcomes worth keeping across restarts: every hide (an `unavailable` is tried again). */
  snapshot(): string {
    return JSON.stringify([...this.m].filter(([, r]) => r.outcome !== 'unavailable'))
  }

  restore(json: string): void {
    for (const [a, r] of JSON.parse(json) as [string, { outcome: TapOutcome; createdAt: number }][]) {
      const cur = this.m.get(a)
      if (cur === undefined || cur.createdAt <= r.createdAt) this.m.set(a, r)
    }
  }
}

// ---- fetching (informative)

export function chunkAuthors(authors: readonly string[], n = 100): string[][] {
  const out: string[][] = []
  for (let i = 0; i < authors.length; i += n) out.push(authors.slice(i, i + n))
  return out
}

/** The trusted requests, in the NIP's order: recommendations and reports by follows and curators, listings and deletions by the nodes they name. */
export function trustedFilters(x: { trusted: readonly string[]; nodes: readonly string[] }) {
  return [
    ...chunkAuthors(x.trusted).map((a) => ({ kinds: [KIND_RECOMMENDATION], authors: a, '#k': [String(KIND_LISTING)] })),
    ...(x.nodes.length > 0 ? chunkAuthors(x.trusted).map((a) => ({ kinds: [KIND_REPORT], authors: a, '#p': [...x.nodes] })) : []),
    ...chunkAuthors(x.nodes).map((a) => ({ kinds: [KIND_LISTING], authors: a })),
    ...chunkAuthors(x.nodes).map((a) => ({ kinds: [5], authors: a, '#k': [String(KIND_LISTING)] })),
  ]
}

/** The global, unreviewed request: shown apart. */
export const globalFilter = (chains: readonly string[], limit = 500) => ({ kinds: [KIND_LISTING], '#t': ['cash_order', 'circle_wallet'], '#n': [...chains], limit })
