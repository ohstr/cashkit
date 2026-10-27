// listing.json: offer listings (kind 31190) and their signals — parsing,
// expiry, versions, operator verification, recommendation crediting,
// reports, the at-tap check and sanitizeText.
import { describe, expect, test } from 'vitest'
import {
  checkTap,
  creditedOffers,
  decodeCircleHubConnection,
  listingAddress,
  listingExpiresAt,
  ListingError,
  newestOperatorOffers,
  operatorVerified,
  parseListing,
  parseRecommendation,
  parseReport,
  sanitizeText,
  VersionBook,
  verifyCircleHubConnection,
  type Listing,
} from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'
import { canon } from './json-big.js'

const v = load('listing.json')

const MISMATCH = new Set([
  // nmilat's max 0 means no cap and keeps "x"; cashkit's sanitizeText(s, 0) returns "".
  'case 9 max 0',
  // "\u2714\ufe0f Alice": cashkit drops the check mark but keeps the U+FE0F variation selector after it; nmilat drops both.
  'case 2 max 40',
  // nmilat refuses two "t cash_order" tags at step 1 (a repeated type tag); cashkit counts two types and refuses at step 2.
  'step 1: two type t of one value',
  // At exactly expiresAt nmilat still shows the listing (expired only after); cashkit's VersionBook.current hides it (now >= expiresAt).
  'current at its expiry',
])

const listings = new Map<string, Listing>()
for (const c of [...v.events, ...v.parseListing]) {
  try {
    listings.set(c.event.id, parseListing(c.event, { chains: ['bitcoin'], testNetworks: true }))
  } catch {
    // a refused listing: not one the other sections name
  }
}
const kList1 = listings.get(v.events[0].event.id)!
// Three listings the cases name by id are not in the vectors; each stand-in changes K-LIST-1 only where its name says.
const STANDIN: Record<string, Listing> = {
  // "equal created_at: the lower id kept": a second version of K-LIST-1 at the same created_at.
  '5b2a606a86e2a71368d77056fc863f6f62726cb373d803380322729500c3fa99': { ...kList1, event: { ...kList1.event, id: '5b2a606a86e2a71368d77056fc863f6f62726cb373d803380322729500c3fa99' } },
  // "K-LIST-1's p naming another key".
  '9bf4f90db9614086bb251d1eebc8539e3e065630227975069475fc57cf556837': { ...kList1, operator: { pubkey: kList1.nodeIdentity, relay: 'wss://relay.example.com' } },
}
{
  // The circle listing of the tap cases: the circlehub1 string the vectors carry, under circle_wallet.
  const conn = v.parseListing.find((c: Json) => c.name === 'step 2: circlehub1 under cash_order').event.tags.find((t: string[]) => t[0] === 'connection')[1]
  const hub = decodeCircleHubConnection(conn)
  STANDIN['3f97463627ed4490df70e874d25ae2449e1c2c91b79019a7b98745c281466b64'] = { ...kList1, type: 'circle_wallet', connection: conn, hub, verdict: verifyCircleHubConnection(hub), hints: [], summary: ['allowlist'] }
}
const byId = (id: string): Listing => listings.get(id) ?? STANDIN[id]!

const shape = (l: Listing) => ({
  address: listingAddress(l),
  chain: l.chain,
  connection: l.connection,
  d: l.d,
  expiration: l.expiration,
  followSet: l.followSet ?? '',
  geohashes: l.geohashes,
  hints: l.hints.map((h) => ({ Payment: h.payment, MinMillis: h.minMillis, MaxMillis: h.maxMillis, FeeBase: h.feeBase, FeePpm: h.feePpm })),
  image: l.image ?? '',
  languages: l.languages,
  location: l.location ?? '',
  network: l.network,
  operator: l.operator === undefined ? null : { Pubkey: l.operator.pubkey, Relay: l.operator.relay },
  status: l.status,
  summary: l.summary,
  title: l.title,
  type: l.type,
})

describe('listing.json parse', () => {
  test.each(named(v.parseListing))('%s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const run = () => parseListing(c.event, { chains: c.chains, testNetworks: c.testNetworks === true })
    if (c.error !== undefined) {
      let err: unknown
      try {
        run()
      } catch (e) {
        err = e
      }
      expect(err).toBeInstanceOf(ListingError)
      expect((err as ListingError).step).toBe(c.step)
      return
    }
    const got = shape(run()) as Record<string, unknown>
    expect(canon(Object.fromEntries(Object.keys(c.want).map((k) => [k, got[k] ?? null])))).toEqual(canon(c.want))
  })
})

describe('listing.json expiry and versions', () => {
  test.each(named(v.expiresAt, (c) => `${c.id} ${c.expiration}`))('expires at: %s', (_, c: Json) => {
    expect(listingExpiresAt({ expiration: Number(c.expiration), event: kList1.event })).toBe(c.expiresAt)
  })
  test.each(named(v.versions))('versions: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const book = new VersionBook()
    c.offers.forEach((id: string, i: number) => expect(book.offer(byId(id), c.at[i])).toBe(c.accepted[i]))
    expect(book.current(listingAddress(kList1), c.currentAt)?.event.id ?? '').toBe(c.current)
  })
})

describe('listing.json signals', () => {
  test.each(named(v.operatorVerified))('operator: %s', (_, c: Json) => {
    expect(operatorVerified(byId(c.listingId), newestOperatorOffers([c.operatorOffers], c.operatorOffers.pubkey))).toBe(c.verified)
  })
  test.each(named(v.creditedOffers, (c) => c.id))('credited: %s', (_, c: Json) => {
    expect(creditedOffers(parseRecommendation(c.recommendation)!, c.ofNode, (a) => c.operators[a])).toEqual(c.credited)
  })
  test.each(named(v.reports))('report: %s', (_, c: Json) => {
    const r = parseReport(c.event)
    if (c.error !== undefined) {
      expect(r).toBeUndefined()
      return
    }
    // cashkit's report carries no listing id (the e tag): that field is not compared.
    expect({ addr: r?.address ?? '', author: r?.event.pubkey, node: r?.node, reason: r?.reason }).toEqual({ addr: c.want.addr, author: c.want.author, node: c.want.node, reason: c.want.reason })
  })
  test.each(named(v.tap))('tap: %s', (_, c: Json) => {
    const r = checkTap(byId(c.listing), c.getInfo === undefined ? undefined : JSON.parse(c.getInfo), c.infoError)
    expect({ outcome: r.outcome, hintDiffers: r.hintDiffers }).toEqual({ outcome: c.outcome, hintDiffers: c.hintDiffers })
  })
  test.each(named(v.sanitizeText, (c, i) => `${c.id ?? 'case'} ${i} max ${c.max}`))('sanitize: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    expect(sanitizeText(c.in, c.max)).toBe(c.out)
  })
})
