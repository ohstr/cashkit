// Discover (NIP-CASH §Listing Offers): browse offer listings without
// contacting any Hub, rank them by the signals of the user's follows and
// curators only, and read the terms from the listed connection at tap. An
// order or a join then runs over the listed string as any other.
import {
  checkTap,
  globalFilter,
  KIND_LISTING,
  KIND_OPERATOR_OFFERS,
  listingAddress,
  ListingError,
  MAX_CONTENT,
  MAX_TITLE,
  newestOperatorOffers,
  operatorVerified,
  parseListing,
  parseRecommendation,
  parseReport,
  rankKey,
  recommendAllowed,
  sanitizeText,
  signalsFor,
  TapCache,
  trustedFilters,
  VersionBook,
  type Listing,
  type ListingReport,
  type NostrEvent,
  type OperatorOffers,
  type Recommendation,
  type TapResult,
  type Trust,
} from '../core/index.js'
import { NwcClient, readEvents } from '../client/index.js'
import type { Ctx } from './context.js'
import { CashkitError } from './errors.js'

const READ_MS = 2500

export interface DiscoverOptions {
  /** The user's read relays, plus any discovery relays. */
  readonly relays: readonly string[]
  /** Default: the identity's kind-3 follows. */
  readonly follows?: readonly string[]
  readonly curators?: readonly string[]
  /** Also run the global request; its additions are shown apart, as unreviewed. */
  readonly includeUnreviewed?: boolean
  /** Chains this wallet holds (default `bitcoin`). */
  readonly chains?: readonly string[]
  readonly testNetworks?: boolean
}

export interface OfferCard {
  readonly address: string
  readonly type: Listing['type']
  /** Sanitized, at most 40 user-perceived characters: the lister's claim. */
  readonly title: string
  /** The string's TLV 3, sanitized: the issuer's claim. */
  readonly label: string
  readonly summary: readonly string[]
  /** As listed, never terms. */
  readonly hints: Listing['hints']
  readonly operator?: { readonly pubkey: string; readonly verified: true; readonly followedBy: readonly string[] }
  readonly operatorUnknown: boolean
  readonly signals: { readonly recommendations: readonly { author: string; createdAt: number; content: string }[]; readonly reports: readonly { reporter: string; reason: string; createdAt: number; namesOtherOffer: boolean }[] }
  readonly listedAt: number
  readonly stale: boolean
  readonly status: 'open' | 'paused'
  readonly chain: string
  readonly network: string
  readonly testNetwork: boolean
  /** An identicon of the node identity until the user taps; images are never loaded by default. */
  readonly image: { readonly mode: 'identicon'; readonly seed: string } | { readonly mode: 'tap'; readonly seed: string; readonly revealed: false }
  readonly languages: readonly string[]
  readonly geohashes: readonly string[]
  readonly location?: string
  readonly tapState: 'unchecked' | 'available' | 'unavailable_for_now'
}

export interface DiscoverView {
  readonly sections: { readonly buyCash: readonly OfferCard[]; readonly circles: readonly OfferCard[]; readonly unreviewed?: readonly OfferCard[] }
  readonly unreviewedCount: number
  /** Several pubkeys list one `d`: never merged; addresses only, tap one to pick. */
  readonly contested: readonly { readonly d: string; readonly addresses: readonly string[] }[]
  readonly coldStart: 'signals' | 'curators_no_signals' | 'nothing'
  readonly diagnostics: readonly { readonly step: number; readonly reason: string }[]
}

export interface TapView {
  readonly outcome: TapResult['outcome']
  readonly reason: string
  readonly terms?: TapResult['terms']
  readonly circle?: TapResult['circle']
  readonly banners: { readonly termsDiffer: boolean; readonly testNetwork: boolean }
  readonly label: string
  readonly hubFingerprint: string
  /** A tap is anonymous but not private: the Hub and relays see a `get_info` now. */
  readonly notice: 'tap_visible'
}

interface State {
  book: VersionBook
  taps: TapCache
  listings: Map<string, Listing>
  unreviewed: Set<string>
  recs: Recommendation[]
  reports: ListingReport[]
  operators: Map<string, OperatorOffers>
  operatorFollowers: Map<string, string[]>
  trust: Trust
  diagnostics: { step: number; reason: string }[]
}

const states = new WeakMap<Ctx, State>()
const stateOf = (ctx: Ctx): State => {
  let s = states.get(ctx)
  if (s === undefined) {
    s = { book: new VersionBook(), taps: new TapCache(), listings: new Map(), unreviewed: new Set(), recs: [], reports: [], operators: new Map(), operatorFollowers: new Map(), trust: { follows: new Set(), curators: new Set() }, diagnostics: [] }
    states.set(ctx, s)
  }
  return s
}

const read = (ctx: Ctx, relays: readonly string[], f: Parameters<typeof readEvents>[2]) => readEvents(ctx.deps.relays, relays, f, READ_MS).catch(() => [] as NostrEvent[])

/**
 * Fetches listings: first everything the user's follows and curators sign
 * (recommendations, reports) and the listings of the nodes they name, so a
 * flood cannot push signalled offers out; then operators; then, only if
 * asked, the global request, shown apart. Nothing contacts a Hub.
 */
export async function refreshDiscover(ctx: Ctx, o: DiscoverOptions): Promise<void> {
  const s = stateOf(ctx)
  const me = (await ctx.signer())?.pubkey
  let follows = o.follows
  if (follows === undefined && me !== undefined) {
    const k3 = (await read(ctx, o.relays, { kinds: [3], authors: [me] })).reduce<NostrEvent | undefined>((m, e) => (m === undefined || e.created_at > m.created_at ? e : m), undefined)
    follows = k3?.tags.filter((t) => t[0] === 'p' && typeof t[1] === 'string').map((t) => t[1]!) ?? []
  }
  s.trust = { follows: new Set(follows ?? []), curators: new Set(o.curators ?? []) }
  const trusted = [...s.trust.follows, ...s.trust.curators]
  const now = ctx.nowSeconds()
  const chains = o.chains ?? ['bitcoin']
  const signals: NostrEvent[] = []
  for (const f of trustedFilters({ trusted, nodes: [] }).filter((x) => x.kinds[0] !== KIND_LISTING && x.kinds[0] !== 5)) signals.push(...(await read(ctx, o.relays, f)))
  s.recs = signals.map(parseRecommendation).filter((r): r is Recommendation => r !== undefined)
  const nodes = [...new Set(s.recs.map((r) => r.node))]
  const second: NostrEvent[] = []
  for (const f of trustedFilters({ trusted, nodes })) if (f.kinds[0] !== 31191) second.push(...(await read(ctx, o.relays, f)))
  s.reports = second.map(parseReport).filter((r): r is ListingReport => r !== undefined)
  const take = (evs: readonly NostrEvent[], unreviewed: boolean) => {
    for (const e of evs) {
      if (e.kind === 5) {
        s.book.applyDeletion(e)
        continue
      }
      if (e.kind !== KIND_LISTING) continue
      try {
        const l = parseListing(e, { chains, ...(o.testNetworks !== undefined && { testNetworks: o.testNetworks }) })
        if (s.book.offer(l, now)) s.listings.set(listingAddress(l), l)
        if (unreviewed && !nodes.includes(l.nodeIdentity)) s.unreviewed.add(listingAddress(l))
      } catch (err) {
        if (err instanceof ListingError) s.diagnostics.push({ step: err.step, reason: err.reason })
      }
    }
  }
  take(second, false)
  if (o.includeUnreviewed === true) take(await read(ctx, o.relays, globalFilter(chains)), true)
  const operators = [...new Set([...s.listings.values()].flatMap((l) => (l.operator !== undefined ? [l.operator.pubkey] : [])))]
  if (operators.length > 0) {
    const ops = await read(ctx, o.relays, { kinds: [KIND_OPERATOR_OFFERS], authors: operators })
    for (const op of operators) {
      const n = newestOperatorOffers(ops, op)
      if (n !== undefined) s.operators.set(op, n)
    }
    if (s.trust.follows.size > 0) {
      const k3 = await read(ctx, o.relays, { kinds: [3], authors: [...s.trust.follows], '#p': operators })
      for (const op of operators) s.operatorFollowers.set(op, [...new Set(k3.filter((e) => e.tags.some((t) => t[0] === 'p' && t[1] === op)).map((e) => e.pubkey))])
    }
  }
}

function operatorOf(s: State): (addr: string) => string | undefined {
  return (addr) => {
    const l = s.listings.get(addr)
    return l !== undefined && operatorVerified(l, l.operator !== undefined ? s.operators.get(l.operator.pubkey) : undefined) ? l.operator!.pubkey : undefined
  }
}

function card(ctx: Ctx, s: State, l: Listing): OfferCard {
  const addr = listingAddress(l)
  const op = operatorOf(s)(addr)
  const offersOfNode = [...s.listings.values()].filter((x) => x.nodeIdentity === l.nodeIdentity).map(listingAddress)
  const sig = signalsFor(l, s.trust, s.recs, s.reports, op !== undefined ? (s.operatorFollowers.get(op) ?? []) : [], operatorOf(s), offersOfNode)
  const last = s.taps.last(l)
  const now = ctx.nowSeconds()
  return {
    address: addr,
    type: l.type,
    title: sanitizeText(l.title, MAX_TITLE),
    label: sanitizeText(l.hub.label, MAX_TITLE),
    summary: l.summary,
    hints: l.hints,
    ...(op !== undefined && { operator: { pubkey: op, verified: true as const, followedBy: sig.operatorFollowedBy } }),
    operatorUnknown: op === undefined,
    signals: {
      recommendations: sig.recommendations.map((r) => ({ author: r.event.pubkey, createdAt: r.event.created_at, content: sanitizeText(r.event.content, MAX_CONTENT) })),
      reports: sig.reports.map((r) => ({ reporter: r.event.pubkey, reason: r.reason, createdAt: r.event.created_at, namesOtherOffer: r.address !== undefined && r.address !== addr })),
    },
    listedAt: l.event.created_at,
    stale: now - l.event.created_at > 864_000,
    status: l.status === 'paused' ? 'paused' : 'open',
    chain: l.chain,
    network: l.network,
    testNetwork: l.network !== 'mainnet',
    image: l.image !== undefined ? { mode: 'tap', seed: l.nodeIdentity, revealed: false } : { mode: 'identicon', seed: l.nodeIdentity },
    languages: l.languages,
    geohashes: l.geohashes,
    ...(l.location !== undefined && { location: sanitizeText(l.location, MAX_TITLE) }),
    tapState: last === undefined ? 'unchecked' : last === 'show' ? 'available' : 'unavailable_for_now',
  }
}

/** The ranked offers: current versions not hidden at tap; listings of different pubkeys sharing a `d` are never merged. */
export function listDiscover(ctx: Ctx): DiscoverView {
  const s = stateOf(ctx)
  const now = ctx.nowSeconds()
  const live = s.book.addresses().flatMap((a) => {
    const l = s.book.current(a, now)
    return l !== undefined && !s.taps.hidden(l) ? [l] : []
  })
  const byD = new Map<string, Listing[]>()
  for (const l of live) byD.set(l.d, [...(byD.get(l.d) ?? []), l])
  const contested: { d: string; addresses: string[] }[] = []
  const shown: Listing[] = []
  for (const [d, ls] of byD) {
    if (ls.length === 1) shown.push(ls[0]!)
    else {
      const picked = ls.filter((l) => s.taps.last(l) === 'show')
      if (picked.length === 1) shown.push(picked[0]!)
      else contested.push({ d, addresses: ls.map(listingAddress) })
    }
  }
  const cards = shown.map((l) => ({ l, c: card(ctx, s, l) }))
  const key = (x: (typeof cards)[number]) => rankKey(x.l, signalsFor(x.l, s.trust, s.recs, s.reports, [], operatorOf(s), []), now)
  const cmp = (a: (typeof cards)[number], b: (typeof cards)[number]) => {
    const ka = key(a)
    const kb = key(b)
    return ka[0] - kb[0] || ka[1] - kb[1] || ka[2] - kb[2]
  }
  const ordered = [...cards]
  // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
  ordered.sort(cmp)
  const trustedCards = ordered.filter((x) => !s.unreviewed.has(x.c.address))
  const unreviewed = ordered.filter((x) => s.unreviewed.has(x.c.address)).map((x) => x.c)
  const anySignal = trustedCards.some((x) => x.c.signals.recommendations.length > 0 || x.c.operator !== undefined)
  return {
    sections: { buyCash: trustedCards.filter((x) => x.l.type === 'cash_order').map((x) => x.c), circles: trustedCards.filter((x) => x.l.type === 'circle_wallet').map((x) => x.c), ...(unreviewed.length > 0 && { unreviewed }) },
    unreviewedCount: unreviewed.length,
    contested,
    coldStart: anySignal ? 'signals' : s.trust.curators.size > 0 ? 'curators_no_signals' : 'nothing',
    diagnostics: [...s.diagnostics],
  }
}

function listing(ctx: Ctx, address: string): Listing {
  const l = stateOf(ctx).book.current(address, ctx.nowSeconds())
  if (l === undefined) throw new CashkitError('not_found', 'no current listing at this address', { input: address })
  return l
}

/**
 * Reads the terms from the listed connection (its public secret: the tap
 * carries nothing of the user) and checks them; the outcome is cached per
 * version. No answer or any error keeps the listing, unavailable for now.
 */
export async function tapDiscover(ctx: Ctx, address: string, o: { timeoutMs?: number } = {}): Promise<TapView> {
  const l = listing(ctx, address)
  const nwc = new NwcClient({ ...ctx.clientDeps, nwcTimeoutMs: o.timeoutMs ?? 20_000 }, { walletPubkey: l.hub.walletPubkey, relays: l.hub.relays, secret: l.hub.secret, extra: {} })
  let info: unknown
  let error: unknown
  try {
    info = await nwc.request('get_info')
  } catch (err) {
    error = err
  }
  const r = checkTap(l, info, error)
  stateOf(ctx).taps.record(l, r)
  return {
    outcome: r.outcome,
    reason: r.reason,
    ...(r.terms !== undefined && { terms: r.terms }),
    ...(r.circle !== undefined && { circle: r.circle }),
    banners: { termsDiffer: r.hintDiffers, testNetwork: l.network !== 'mainnet' },
    label: sanitizeText(l.hub.label, MAX_TITLE),
    hubFingerprint: l.hub.hubIdentity.match(/.{4}/g)!.join(' '),
    notice: 'tap_visible',
  }
}

/** The listed string, for the hand-off to `orders` or `circles`, only after a tap showed the terms. */
export function listedConnection(ctx: Ctx, address: string): { type: Listing['type']; connection: string } {
  const l = listing(ctx, address)
  if (stateOf(ctx).taps.last(l) !== 'show') throw new CashkitError('usage', 'tap the offer first: its terms come from the listed connection', { reason: 'tap_first' })
  return { type: l.type, connection: l.connection }
}

/** Whether recommending this offer may be offered now. */
export async function recommendPreview(ctx: Ctx, address: string): Promise<{ allowed: boolean; reasonIfNot?: string; audience: { public: true }; revealsMembership: boolean; linksIdentity: true; delay: { minSecs: number; maxSecs: number } }> {
  const l = listing(ctx, address)
  const base = { audience: { public: true as const }, revealsMembership: l.type === 'circle_wallet', linksIdentity: true as const, delay: { minSecs: 3600, maxSecs: 21600 } }
  if ((await ctx.signer()) === undefined) return { allowed: false, reasonIfNot: 'needs_identity', ...base }
  const calls = await ctx.read((t) => t.list('pendingCalls'))
  const conns = await ctx.read((t) => t.list('connections'))
  const orders = calls.filter((c) => c.kind === 'order' && c.target === l.d)
  const used = orders.some((c) => c.order?.sawProgress === true) || conns.some((c) => c.circle?.hubPubkey === l.d)
  const last = Math.max(...orders.map((c) => Math.floor(c.createdAt / 1000)), ...conns.filter((c) => c.circle?.hubPubkey === l.d).map((c) => c.circle!.createdAt), -1)
  const r = recommendAllowed({ used, ...(last >= 0 && { lastOrderOrJoin: last }), sessionStart: Math.floor(ctx.openedAt / 1000), now: ctx.nowSeconds() })
  return { ...r, ...base }
}
