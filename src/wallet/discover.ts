// Discover (NIP-CASH §Listing Offers): browse offer listings without
// contacting any Hub, rank them by the signals of the user's follows and
// curators only, and read the terms from the listed connection at tap. An
// order or a join then runs over the listed string as any other.
import {
  checkTap,
  CURATOR_SET_D,
  CURATOR_SET_KIND,
  globalFilter,
  KIND_RECOMMENDATION,
  KIND_LISTING,
  KIND_OPERATOR_OFFERS,
  listingAddress,
  ListingError,
  newCuratorSet,
  newRecommendation,
  newReport,
  parseCuratorSet,
  parseOperatorOffers,
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
  type EventTemplate,
  type OperatorOffers,
  type Recommendation,
  type ReportReason,
  type TapResult,
  type Trust,
  verifyEvent,
} from '../core/index.js'
import { NwcClient, readEvents } from '../client/index.js'
import type { Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { newId } from './ledger.js'
import { DEFAULT_SETTINGS, type DiscoverOutboxRow, type DiscoverSettings } from './model.js'

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
  chains: readonly string[]
  testNetworks: boolean
  relays: readonly string[]
}

const states = new WeakMap<Ctx, State>()
const stateOf = (ctx: Ctx): State => {
  let s = states.get(ctx)
  if (s === undefined) {
    s = { book: new VersionBook(), taps: new TapCache(), listings: new Map(), unreviewed: new Set(), recs: [], reports: [], operators: new Map(), operatorFollowers: new Map(), trust: { follows: new Set(), curators: new Set() }, diagnostics: [], chains: ['bitcoin'], testNetworks: false, relays: [] }
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
  const curators = o.curators ?? (await ctx.settings()).discover?.curators ?? []
  s.trust = { follows: new Set(follows ?? []), curators: new Set(curators) }
  const trusted = [...s.trust.follows, ...s.trust.curators]
  const now = ctx.nowSeconds()
  const chains = o.chains ?? ['bitcoin']
  s.chains = chains
  s.testNetworks = o.testNetworks === true
  s.relays = [...o.relays]
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
    // From the discovery relays and each operator's own NIP-65 write relays, where an operator keeps its 11191.
    const ops = await read(ctx, [...new Set([...o.relays, ...(await operatorWriteRelays(ctx, operators, o.relays))])], { kinds: [KIND_OPERATOR_OFFERS], authors: operators })
    for (const op of operators) {
      const n = newestOperatorOffers(ops, op)
      if (n !== undefined) s.operators.set(op, n)
    }
    if (s.trust.follows.size > 0) {
      const k3 = await read(ctx, o.relays, { kinds: [3], authors: [...s.trust.follows], '#p': operators })
      for (const op of operators) s.operatorFollowers.set(op, [...new Set(k3.filter((e) => e.tags.some((t) => t[0] === 'p' && t[1] === op)).map((e) => e.pubkey))])
    }
  }
  await saveDiscover(ctx)
}

// ---- persistence: the book, the tap outcomes and the events behind them survive a restart

/** Writes what discover holds: version floors, tap outcomes, and the current listings and the signals behind them. */
async function saveDiscover(ctx: Ctx): Promise<void> {
  const s = stateOf(ctx)
  const now = ctx.nowSeconds()
  const rows = new Map<string, { event: NostrEvent; unreviewed: boolean }>()
  for (const a of s.book.addresses()) {
    const l = s.book.current(a, now)
    if (l !== undefined) rows.set(l.event.id, { event: l.event, unreviewed: s.unreviewed.has(a) })
  }
  for (const e of [...s.recs.map((r) => r.event), ...s.reports.map((r) => r.event), ...[...s.operators.values()].map((o) => o.event)]) rows.set(e.id, { event: e, unreviewed: false })
  await ctx.commit(async (t) => {
    const cur = await t.get('discoverBook', 'self')
    await t.put(
      'discoverBook',
      {
        id: 'self',
        book: s.book.snapshot(),
        taps: s.taps.snapshot(),
        follows: [...s.trust.follows],
        curators: [...s.trust.curators],
        operatorFollowers: [...s.operatorFollowers],
        relays: s.relays,
        chains: s.chains,
        testNetworks: s.testNetworks,
        version: (cur?.version ?? 0) + 1,
      },
      cur?.version ?? 0,
    )
    for (const old of await t.list('discoverEvents')) if (!rows.has(old.id)) await t.delete('discoverEvents', old.id)
    for (const [id, r] of rows) {
      const old = await t.get('discoverEvents', id)
      if (old === undefined || old.unreviewed !== r.unreviewed) await t.put('discoverEvents', { id, event: JSON.stringify(r.event), unreviewed: r.unreviewed, version: (old?.version ?? 0) + 1 }, old?.version ?? 0)
    }
  })
}

/** Reads back what `saveDiscover` wrote, so `list` shows the last refresh at once. */
export async function loadDiscover(ctx: Ctx): Promise<void> {
  const [book, events] = await ctx.read(async (t) => [await t.get('discoverBook', 'self'), await t.list('discoverEvents')] as const)
  if (book === undefined) return
  const s = stateOf(ctx)
  s.book.restore(book.book)
  s.taps.restore(book.taps)
  s.trust = { follows: new Set(book.follows), curators: new Set(book.curators) }
  s.operatorFollowers = new Map(book.operatorFollowers.map(([k, v]) => [k, [...v]]))
  s.relays = book.relays
  s.chains = book.chains
  s.testNetworks = book.testNetworks
  const now = ctx.nowSeconds()
  const evs = events.map((r) => ({ e: JSON.parse(r.event) as NostrEvent, unreviewed: r.unreviewed }))
  for (const { e, unreviewed } of evs) {
    if (e.kind === KIND_LISTING) {
      try {
        const l = parseListing(e, { chains: s.chains, testNetworks: s.testNetworks })
        if (s.book.offer(l, now)) s.listings.set(listingAddress(l), l)
        if (unreviewed) s.unreviewed.add(listingAddress(l))
      } catch {
        // a listing that no longer passes (a chain no longer held) is not shown
      }
    } else if (e.kind === KIND_RECOMMENDATION) {
      const r = parseRecommendation(e)
      if (r !== undefined) s.recs.push(r)
    } else if (e.kind === KIND_OPERATOR_OFFERS) {
      s.operators.set(e.pubkey, parseOperatorOffers(e))
    } else {
      const r = parseReport(e)
      if (r !== undefined) s.reports.push(r)
    }
  }
}

function operatorOf(s: State): (addr: string) => string | undefined {
  return (addr) => {
    const l = s.listings.get(addr)
    return l !== undefined && operatorVerified(l, l.operator !== undefined ? s.operators.get(l.operator.pubkey) : undefined) ? l.operator!.pubkey : undefined
  }
}

/** A listing's signals: its recommendations (one naming another offer of its node included), reports and operator's followers. */
function signalsOf(s: State, l: Listing): ReturnType<typeof signalsFor> {
  const op = operatorOf(s)(listingAddress(l))
  const offersOfNode = [...s.listings.values()].filter((x) => x.nodeIdentity === l.nodeIdentity).map(listingAddress)
  return signalsFor(l, s.trust, s.recs, s.reports, op !== undefined ? (s.operatorFollowers.get(op) ?? []) : [], operatorOf(s), offersOfNode)
}

function card(ctx: Ctx, s: State, l: Listing, sig: ReturnType<typeof signalsFor>): OfferCard {
  const addr = listingAddress(l)
  const op = operatorOf(s)(addr)
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
  // Ranked on the same signals the card shows, so a recommended offer is never below an unsignalled one.
  const cards = shown.map((l) => {
    const sig = signalsOf(s, l)
    return { l, c: card(ctx, s, l, sig), k: rankKey(l, sig, now) }
  })
  const cmp = (a: (typeof cards)[number], b: (typeof cards)[number]) => a.k[0] - b.k[0] || a.k[1] - b.k[1] || a.k[2] - b.k[2]
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
  await saveTaps(ctx)
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

async function saveTaps(ctx: Ctx): Promise<void> {
  const taps = stateOf(ctx).taps.snapshot()
  await ctx.commit(async (t) => {
    const cur = await t.get('discoverBook', 'self')
    if (cur !== undefined) await t.put('discoverBook', { ...cur, taps, version: cur.version + 1 }, cur.version)
  })
}

// ---- the user's relays

/**
 * The newest of `events` signed by `pubkey`: one whose id or signature does
 * not check is ignored, so a relay cannot stand in for the user.
 */
function newestSignedBy(events: readonly NostrEvent[], pubkey: string): NostrEvent | undefined {
  return events
    .filter((e) => e.pubkey === pubkey && verifyEvent(e, { checkPow: false }))
    .reduce<NostrEvent | undefined>((m, e) => (m === undefined || e.created_at > m.created_at || (e.created_at === m.created_at && e.id < m.id) ? e : m), undefined)
}

/** The write relays of `pubkey`'s newest signed kind 10002 (unmarked or `write`), read from `relays`. */
async function writeRelaysOf(ctx: Ctx, pubkey: string, relays: readonly string[]): Promise<string[]> {
  const newest = newestSignedBy(await read(ctx, relays, { kinds: [10002], authors: [pubkey] }), pubkey)
  return newest?.tags.filter((t) => t[0] === 'r' && typeof t[1] === 'string' && (t[2] === undefined || t[2] === 'write')).map((t) => t[1]!) ?? []
}

/** At most this many of one operator's write relays are read: an operator cannot make a refresh dial a long list. */
const MAX_OPERATOR_RELAYS = 4

/** The write relays of each operator's newest signed kind 10002, read from `relays`; ws and wss URLs only. */
async function operatorWriteRelays(ctx: Ctx, operators: readonly string[], relays: readonly string[]): Promise<string[]> {
  const lists = await read(ctx, relays, { kinds: [10002], authors: [...operators] })
  return operators.flatMap((op) =>
    (newestSignedBy(lists, op)?.tags ?? [])
      .filter((t) => t[0] === 'r' && typeof t[1] === 'string' && /^wss?:\/\/\S+$/.test(t[1]) && (t[2] === undefined || t[2] === 'write'))
      .map((t) => t[1]!)
      .slice(0, MAX_OPERATOR_RELAYS),
  )
}

async function requireIdentity(ctx: Ctx) {
  const signer = await ctx.signer()
  if (signer === undefined) throw new CashkitError('usage', 'recommending, reporting and publishing curators sign with your Nostr identity: set one up first', { reason: 'identity_required' })
  return signer
}

async function publishTo(ctx: Ctx, relays: readonly string[], ev: NostrEvent): Promise<string[]> {
  const r = await Promise.all([...new Set(relays)].map(async (url) => ((await ctx.deps.relays.publish(url, ev).catch(() => ({ ok: false }))).ok ? url : undefined)))
  return r.filter((x): x is string => x !== undefined)
}

// ---- curators (NIP-CASH §Curators)

export interface CuratorsView {
  readonly pubkeys: readonly string[]
  /** `app`: defaults an app supplied ("Curated by <sourceName>"); `user`: the user's own. */
  readonly source: 'user' | 'app'
  readonly sourceName?: string
}

async function curatorSettings(ctx: Ctx): Promise<DiscoverSettings> {
  return (await ctx.settings()).discover ?? { curators: [], curatorSource: 'user' }
}

async function writeCurators(ctx: Ctx, d: DiscoverSettings): Promise<CuratorsView> {
  await ctx.commit(async (t) => {
    const cur = await t.get('settings', 'settings')
    await t.put('settings', { ...DEFAULT_SETTINGS, ...cur, discover: d, id: 'settings', version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
  })
  return viewOf(d)
}

const viewOf = (d: DiscoverSettings): CuratorsView => ({ pubkeys: d.curators, source: d.curatorSource, ...(d.curatorSourceName !== undefined && { sourceName: d.curatorSourceName }) })
const HEX64 = /^[0-9a-f]{64}$/

export async function listCurators(ctx: Ctx): Promise<CuratorsView> {
  return viewOf(await curatorSettings(ctx))
}

/** Adds or removes a curator: the list becomes the user's own. */
export async function editCurators(ctx: Ctx, change: { add?: string; remove?: string }): Promise<CuratorsView> {
  if (change.add !== undefined && !HEX64.test(change.add)) throw new CashkitError('invalid_input', 'a curator is a 64-hex lowercase pubkey', { input: change.add })
  const d = await curatorSettings(ctx)
  const list = d.curators.filter((c) => c !== change.remove)
  if (change.add !== undefined && !list.includes(change.add)) list.push(change.add)
  const { curatorSourceName: _n, ...rest } = d
  return writeCurators(ctx, { ...rest, curators: list, curatorSource: 'user' })
}

/** An app's default curators. Ignored once the user has edited the list (the user's edits win). */
export async function setDefaultCurators(ctx: Ctx, o: { pubkeys: readonly string[]; sourceName?: string }): Promise<CuratorsView> {
  const d = (await ctx.settings()).discover
  if (d !== undefined && d.curatorSource === 'user') return viewOf(d)
  for (const p of o.pubkeys) if (!HEX64.test(p)) throw new CashkitError('invalid_input', 'a curator is a 64-hex lowercase pubkey', { input: p })
  return writeCurators(ctx, { curators: [...new Set(o.pubkeys)], curatorSource: 'app', ...(o.sourceName !== undefined && { curatorSourceName: o.sourceName }), ...(d?.curatorsPrivate !== undefined && { curatorsPrivate: d.curatorsPrivate }) })
}

/**
 * Publishes the curators as the user's NIP-51 set (kind 30000, `d`
 * `cash-discover`, no title), its items private (NIP-44 to self) unless
 * `curatorsPrivate` is false, to the user's write relays and `relays`.
 */
export async function publishCurators(ctx: Ctx, o: { relays?: readonly string[] } = {}): Promise<{ eventId: string; relays: string[] }> {
  const signer = await requireIdentity(ctx)
  const d = await curatorSettings(ctx)
  const priv = d.curatorsPrivate !== false
  const t = await newCuratorSet({ curators: d.curators, private: priv }, (pt) => signer.nip44Encrypt(signer.pubkey, pt))
  const ev = await signer.signEvent({ ...t, created_at: ctx.nowSeconds() })
  const base = o.relays ?? stateOf(ctx).relays
  const relays = [...(await writeRelaysOf(ctx, signer.pubkey, base)), ...base]
  return { eventId: ev.id, relays: await publishTo(ctx, relays, ev) }
}

/**
 * Reads the newest copy of the user's set from their write relays and
 * `relays`, and makes it the list. Only a copy signed by the user counts.
 */
export async function syncCurators(ctx: Ctx, o: { relays?: readonly string[] } = {}): Promise<CuratorsView> {
  const signer = await requireIdentity(ctx)
  const base = o.relays ?? stateOf(ctx).relays
  const relays = [...new Set([...(await writeRelaysOf(ctx, signer.pubkey, base)), ...base])]
  const newest = newestSignedBy(await read(ctx, relays, { kinds: [CURATOR_SET_KIND], authors: [signer.pubkey], '#d': [CURATOR_SET_D] }), signer.pubkey)
  if (newest === undefined) return listCurators(ctx)
  const set = await parseCuratorSet(newest, (ct) => signer.nip44Decrypt(signer.pubkey, ct))
  return writeCurators(ctx, { curators: set.curators, curatorSource: 'user', curatorsPrivate: set.private || newest.content !== '' })
}

// ---- the outbox: recommendations and reports, published later (NIP-CASH §Recommendations, §Reports)

const DELAY_MIN = 3600
const DELAY_MAX = 21_600

export interface OutboxItem {
  readonly id: string
  readonly kind: 'recommendation' | 'report'
  readonly node: string
  readonly address?: string
  readonly reason?: string
  /** Unix seconds: not published before. */
  readonly dueAt: number
  readonly createdAt: number
  /** The identity that queued it; only it publishes it. */
  readonly author?: string
}

const item = (r: DiscoverOutboxRow): OutboxItem => ({ id: r.id, kind: r.kind, node: r.node, ...(r.address !== undefined && { address: r.address }), ...(r.reason !== undefined && { reason: r.reason }), dueAt: r.dueAt, createdAt: r.createdAt, ...(r.author !== undefined && { author: r.author }) })

/** A delay drawn uniformly from [1 h, 6 h), so the publication time does not reveal when the user ordered or joined. */
function delay(ctx: Ctx): number {
  const b = ctx.random(4)
  const u = (((b[0]! << 24) >>> 0) + (b[1]! << 16) + (b[2]! << 8) + b[3]!) / 2 ** 32
  return DELAY_MIN + Math.floor(u * (DELAY_MAX - DELAY_MIN))
}

async function queue(ctx: Ctx, row: Omit<DiscoverOutboxRow, 'version' | 'dueAt' | 'createdAt' | 'relays' | 'author'>, me: string): Promise<OutboxItem> {
  const base = stateOf(ctx).relays
  const relays = [...new Set([...(await writeRelaysOf(ctx, me, base)), ...base])]
  const now = ctx.nowSeconds()
  const full = { ...row, relays, dueAt: now + delay(ctx), createdAt: now, author: me }
  await ctx.commit(async (t) => {
    const cur = await t.get('discoverOutbox', row.id)
    await t.put('discoverOutbox', { ...full, version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
  })
  return item({ ...full, version: 1 })
}

export type RecommendPreview = Awaited<ReturnType<typeof recommendPreview>>

/**
 * Recommends an offer the user has used: public, signed by the user's
 * identity. Only when `recommendPreview` allows it; `confirm` (else the
 * wallet's `confirmRecommend` question, no without a handler) is shown the
 * preview and may decline. Queued, then published 1 to 6 hours later; a
 * second recommendation of the same node replaces the first.
 */
export async function recommend(ctx: Ctx, address: string, o: { content: string; confirm?: (p: RecommendPreview) => Promise<boolean> }): Promise<{ queued: false } | { queued: true; item: OutboxItem }> {
  const signer = await requireIdentity(ctx)
  const p = await recommendPreview(ctx, address)
  if (!p.allowed) throw new CashkitError('invalid_input', `recommending this offer is not offered now: ${p.reasonIfNot}`, { reason: 'recommend_not_allowed', input: address })
  const l = listing(ctx, address)
  const yes =
    o.confirm !== undefined
      ? await o.confirm(p)
      : await ctx.confirmations.ask({ type: 'confirmRecommend', address, node: l.nodeIdentity, audience: p.audience, revealsMembership: p.revealsMembership, linksIdentity: true, delay: p.delay })
  if (!yes) return { queued: false }
  const t = newRecommendation(l.nodeIdentity, stateOf(ctx).relays[0] ?? '', [address], o.content)
  return { queued: true, item: await queue(ctx, { id: `rec:${l.nodeIdentity}`, kind: 'recommendation', node: l.nodeIdentity, address, template: JSON.stringify(t) }, signer.pubkey) }
}

export interface ReportPreview {
  readonly audience: { readonly public: true }
  /** The report names the user as the reporter. */
  readonly reporter: string
  readonly node: string
  readonly reason: ReportReason
}

/**
 * Reports a node, or one of its offers by address: public, naming the user
 * as the reporter. Queued like a recommendation; no "used" or timing rule.
 * Asks `confirm`, else the wallet's `confirmReport` question (no without a
 * handler).
 */
export async function report(ctx: Ctx, target: string, o: { reason: ReportReason; content: string; confirm?: (p: ReportPreview) => Promise<boolean> }): Promise<{ queued: false } | { queued: true; item: OutboxItem }> {
  const signer = await requireIdentity(ctx)
  let node = target
  let address: string | undefined
  let listingId: string | undefined
  if (target.includes(':')) {
    address = target
    node = target.split(':')[1] ?? ''
    listingId = stateOf(ctx).listings.get(target)?.event.id
  }
  if (!HEX64.test(node)) throw new CashkitError('invalid_input', 'report a node identity (64 hex) or a listing address', { input: target })
  const yes =
    o.confirm !== undefined
      ? await o.confirm({ audience: { public: true }, reporter: signer.pubkey, node, reason: o.reason })
      : await ctx.confirmations.ask({ type: 'confirmReport', ...(address !== undefined && { address }), node, audience: { public: true }, revealsMembership: false, linksIdentity: true, delay: { minSecs: DELAY_MIN, maxSecs: DELAY_MAX } })
  if (!yes) return { queued: false }
  const t = newReport({ node, ...(address !== undefined && { address }), ...(listingId !== undefined && { listingId }), reason: o.reason, content: o.content })
  return { queued: true, item: await queue(ctx, { id: `rep:${newId('r', ctx.random).slice(2)}`, kind: 'report', node, ...(address !== undefined && { address }), reason: o.reason, template: JSON.stringify(t) }, signer.pubkey) }
}

/**
 * Withdraws the user's recommendation of a node: its NIP-09 deletion is
 * signed and published at once (never delayed), and a recommendation still
 * queued for that node is cancelled. Asks `confirm`, else the wallet's
 * `confirmRecommend` question with `withdrawal` (no without a handler).
 */
export async function withdrawRecommendation(ctx: Ctx, node: string, o: { relays?: readonly string[]; confirm?: (p: { audience: { public: true }; node: string }) => Promise<boolean> } = {}): Promise<{ withdrawn: boolean; relays: string[] }> {
  const signer = await requireIdentity(ctx)
  if (!HEX64.test(node)) throw new CashkitError('invalid_input', 'a node identity is 64 hex', { input: node })
  const yes =
    o.confirm !== undefined
      ? await o.confirm({ audience: { public: true }, node })
      : await ctx.confirmations.ask({ type: 'confirmRecommend', node, audience: { public: true }, revealsMembership: false, linksIdentity: true, delay: { minSecs: 0, maxSecs: 0 }, withdrawal: true })
  if (!yes) return { withdrawn: false, relays: [] }
  await ctx.commit(async (t) => {
    if ((await t.get('discoverOutbox', `rec:${node}`)) !== undefined) await t.delete('discoverOutbox', `rec:${node}`)
  })
  const ev = await signer.signEvent({ kind: 5, created_at: ctx.nowSeconds(), tags: [['a', `${KIND_RECOMMENDATION}:${signer.pubkey}:${node}`], ['k', String(KIND_RECOMMENDATION)]], content: '' })
  const base = o.relays ?? stateOf(ctx).relays
  return { withdrawn: true, relays: await publishTo(ctx, [...(await writeRelaysOf(ctx, signer.pubkey, base)), ...base], ev) }
}

export async function listOutbox(ctx: Ctx): Promise<OutboxItem[]> {
  return (await ctx.read((t) => t.list('discoverOutbox'))).map(item)
}

export async function cancelOutbox(ctx: Ctx, id: string): Promise<void> {
  await ctx.commit(async (t) => {
    if ((await t.get('discoverOutbox', id)) === undefined) throw new CashkitError('not_found', 'no queued recommendation or report with this id', { input: id })
    await t.delete('discoverOutbox', id)
  })
}

/** The earliest `dueAt` still queued, in unix seconds. */
export async function nextOutboxDue(ctx: Ctx): Promise<number | undefined> {
  const rows = await ctx.read((t) => t.list('discoverOutbox'))
  return rows.length === 0 ? undefined : Math.min(...rows.map((r) => r.dueAt))
}

/**
 * Signs (now, with the identity's signer) and publishes every queued item
 * whose time has come, never before; an item no relay accepted stays queued.
 * Only the identity that queued an item publishes it: one queued by another
 * identity (the signer changed since) stays queued for it, and one stored
 * without its author is dropped unpublished (KT-10).
 */
export async function publishDue(ctx: Ctx): Promise<{ published: string[] }> {
  const signer = await ctx.signer()
  if (signer === undefined) return { published: [] }
  const now = ctx.nowSeconds()
  const rows = await ctx.read((t) => t.list('discoverOutbox'))
  const orphans = rows.filter((r) => r.author === undefined)
  if (orphans.length > 0) {
    await ctx.commit(async (tx) => {
      for (const r of orphans) {
        const cur = await tx.get('discoverOutbox', r.id)
        if (cur !== undefined && cur.author === undefined) await tx.delete('discoverOutbox', r.id)
      }
    })
  }
  const due = rows.filter((r) => r.dueAt <= now && r.author === signer.pubkey)
  const published: string[] = []
  for (const r of due) {
    const t = JSON.parse(r.template) as EventTemplate
    const ev = await signer.signEvent({ ...t, created_at: now })
    if ((await publishTo(ctx, r.relays, ev)).length === 0) continue
    await ctx.commit(async (tx) => {
      const cur = await tx.get('discoverOutbox', r.id)
      if (cur !== undefined && cur.version === r.version) await tx.delete('discoverOutbox', r.id)
    })
    published.push(r.id)
  }
  return { published }
}
