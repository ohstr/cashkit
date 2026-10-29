// Offer listings (NIP-CASH §Listing Offers): the before-showing steps,
// versions and expiry, recommendations, reports, the at-tap check, and
// wallet.discover end to end over a fake Order connection.
import { describe, expect, test } from 'vitest'
import {
  checkTap,
  finalizeEvent,
  getPublicKey,
  listingAddress,
  ListingError,
  newRecommendation,
  newReport,
  parseListing,
  parseRecommendation,
  parseReport,
  recommendAllowed,
  sanitizeText,
  VersionBook,
  type NostrEvent,
} from '../src/core/index.js'
import { FakeBank } from './fakeBank.js'
import { FakeOrder } from './fakeOrder.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'
import { harness } from './walletHarness.js'

const R = 'wss://social.test'
const NOW = Math.floor(Date.now() / 1000)

async function shop() {
  const pool = new MemoryRelayPool()
  const bank = new FakeBank(pool, [R])
  await bank.start()
  return { pool, bank, order: new FakeOrder(bank) }
}

function listingEvent(key: Uint8Array, o: { d: string; connection: string; created_at?: number; tags?: string[][]; drop?: string[] }): NostrEvent {
  const base: string[][] = [
    ['d', o.d],
    ['t', 'cash_order'],
    ['t', 'lightning'],
    ['n', 'bitcoin'],
    ['network', 'mainnet'],
    ['connection', o.connection],
    ['title', 'Alice’s ✓ cash counter'],
    ['status', 'open'],
    ['expiration', String(NOW + 86400 * 60)],
    ['hint', 'lightning', '1000', '1000000000', '1000', '1000'],
    ['g', 'eyc'],
    ['g', 'eyc12345'],
  ]
  return finalizeEvent({ kind: 31190, created_at: o.created_at ?? NOW - 10, tags: [...base.filter((t) => !(o.drop ?? []).includes(t[0]!)), ...(o.tags ?? [])], content: 'Cash for the meetup' }, key)
}

describe('before showing (steps 1–4)', () => {
  test('a valid listing: summary, hints and short geohashes kept, a long one dropped', async () => {
    const { bank, order } = await shop()
    const l = parseListing(listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: order.string }), { chains: ['bitcoin'] })
    expect(l).toMatchObject({ type: 'cash_order', summary: ['lightning'], status: 'open', geohashes: ['eyc'] })
    expect(l.hints).toEqual([{ payment: 'lightning', minMillis: 1000n, maxMillis: 1_000_000_000n, feeBase: 1000n, feePpm: 1000n }])
    expect(listingAddress(l)).toBe(`31190:${bank.hub.node}:${order.pubkey}`)
  })
  test.each([
    ['two titles', { tags: [['title', 'x']] }, 1],
    ['a decimal expiration', { drop: ['expiration'], tags: [['expiration', '1795305600.0']] }, 1],
    ['both types', { tags: [['t', 'circle_wallet']] }, 2],
  ] as const)('%s fails step %d', async (_, o, step) => {
    const { bank, order } = await shop()
    const ev = listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: order.string, ...(o as object) })
    expect(() => parseListing(ev, { chains: ['bitcoin'] })).toThrow(expect.objectContaining({ step }))
  })
  test('a cashhub1 is step 2; another signer, another d are step 3; an unheld chain or a test network is step 4', async () => {
    const { bank, order } = await shop()
    const hub = bank.openCashHub()
    expect(() => parseListing(listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: hub }), { chains: ['bitcoin'] })).toThrow(expect.objectContaining({ step: 2 }))
    expect(() => parseListing(listingEvent(fill(0x45, 32), { d: order.pubkey, connection: order.string }), { chains: ['bitcoin'] })).toThrow(expect.objectContaining({ step: 3 }))
    expect(() => parseListing(listingEvent(bank.hub.nodeKey, { d: 'ab'.repeat(32), connection: order.string }), { chains: ['bitcoin'] })).toThrow(expect.objectContaining({ step: 3 }))
    expect(() => parseListing(listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: order.string }), { chains: ['other'] })).toThrow(expect.objectContaining({ step: 4 }))
    const test4 = listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: order.string, drop: ['network'], tags: [['network', 'regtest']] })
    expect(() => parseListing(test4, { chains: ['bitcoin'] })).toThrow(ListingError)
    expect(parseListing(test4, { chains: ['bitcoin'], testNetworks: true }).network).toBe('regtest')
  })
})

describe('versions, signals and the tap', () => {
  test('the newest version wins and is never undercut; 15 minutes ahead is ignored; a deletion by the node hides it; the 30-day cap applies', async () => {
    const { bank, order } = await shop()
    const at = (c: number) => parseListing(listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: order.string, created_at: c }), { chains: ['bitcoin'] })
    const book = new VersionBook()
    const a = at(NOW - 100)
    const b = at(NOW - 50)
    expect(book.offer(b, NOW)).toBe(true)
    expect(book.offer(a, NOW)).toBe(false)
    expect(book.offer(at(NOW + 901), NOW)).toBe(false)
    const addr = listingAddress(b)
    expect(book.current(addr, NOW)?.event.id).toBe(b.event.id)
    expect(book.current(addr, NOW - 50 + 2_592_000)?.event.id).toBe(b.event.id)
    expect(book.current(addr, NOW - 50 + 2_592_001)).toBeUndefined()
    book.applyDeletion(finalizeEvent({ kind: 5, created_at: NOW - 40, tags: [['a', addr], ['k', '31190']], content: '' }, fill(0x45, 32)))
    expect(book.current(addr, NOW)).toBeDefined()
    book.applyDeletion(finalizeEvent({ kind: 5, created_at: NOW - 40, tags: [['a', addr], ['k', '31190']], content: '' }, bank.hub.nodeKey))
    expect(book.current(addr, NOW)).toBeUndefined()
  })
  test('recommendations, reports and the recommend rule', () => {
    const node = getPublicKey(fill(0x46, 32))
    const t = newRecommendation(node, R, [`31190:${node}:${'ab'.repeat(32)}`, `31190:${'cd'.repeat(32)}:x`], '')
    const ev = finalizeEvent({ ...t, created_at: NOW }, fill(0x47, 32))
    expect(parseRecommendation(ev)?.offers).toEqual([`31190:${node}:${'ab'.repeat(32)}`])
    const r = parseReport(finalizeEvent({ ...newReport({ node, reason: 'no_payout', content: 'never minted' }), created_at: NOW }, fill(0x47, 32)))
    expect(r).toMatchObject({ node, reason: 'no_payout' })
    expect(recommendAllowed({ used: false, sessionStart: 0, now: 10 })).toEqual({ allowed: false, reasonIfNot: 'not_used' })
    expect(recommendAllowed({ used: true, lastOrderOrJoin: 100, sessionStart: 50, now: 200 }).reasonIfNot).toBe('same_session')
    expect(recommendAllowed({ used: true, lastOrderOrJoin: 100, sessionStart: 150, now: 200 }).reasonIfNot).toBe('too_soon')
    expect(recommendAllowed({ used: true, lastOrderOrJoin: 100, sessionStart: 150, now: 100 + 86400 })).toEqual({ allowed: true })
  })
  test('at tap: another identity or network hides for good; sells nothing hides until newer; no answer keeps it', async () => {
    const { bank, order } = await shop()
    const l = parseListing(listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: order.string }), { chains: ['bitcoin'] })
    expect(checkTap(l, order.info(), undefined)).toMatchObject({ outcome: 'show', hintDiffers: false })
    expect(checkTap(l, { ...order.info(), pubkey: 'ab'.repeat(32) }, undefined).outcome).toBe('hide_for_good')
    expect(checkTap(l, { ...order.info(), network: 'regtest' }, undefined).outcome).toBe('hide_for_good')
    expect(checkTap(l, { ...order.info(), cash_order: {} }, undefined).outcome).toBe('hide_until_newer')
    expect(checkTap(l, undefined, new Error('timeout')).outcome).toBe('unavailable')
  })
})

describe('wallet.discover', () => {
  test('a recommended offer is listed with its signal; the unreviewed one apart; tap shows the terms; then an order over the listed string', async () => {
    const h = await harness({ deps: { nwcTimeoutMs: 2000 } })
    const order = new FakeOrder(h.bank)
    const friend = fill(0x48, 32)
    const listing = listingEvent(h.bank.hub.nodeKey, { d: order.pubkey, connection: order.string })
    await h.pool.publish(R, listing)
    await h.pool.publish(R, finalizeEvent({ ...newRecommendation(h.bank.hub.node, R, [`31190:${h.bank.hub.node}:${order.pubkey}`], 'fast payouts'), created_at: NOW - 5 }, friend))
    const other = new FakeOrder(h.bank)
    await h.pool.publish(R, listingEvent(h.bank.hub.nodeKey, { d: other.pubkey, connection: other.string }))
    await h.wallet.discover.refresh({ relays: [R], follows: [getPublicKey(friend)], includeUnreviewed: true })
    const v = h.wallet.discover.list()
    expect(v.sections.buyCash).toHaveLength(2)
    const card = v.sections.buyCash.find((c) => c.address.endsWith(order.pubkey))!
    expect(card).toMatchObject({ title: 'Alice’s  cash counter', operatorUnknown: true, image: { mode: 'identicon' }, tapState: 'unchecked' })
    expect(card.signals.recommendations.map((r) => r.content)).toEqual(['fast payouts'])
    expect(v.sections.buyCash[0]!.address).toBe(card.address)
    expect(v.coldStart).toBe('signals')
    expect(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? String(x) : x))).not.toContain(order.string)
    await expect(h.wallet.discover.order(card.address, { amountMillis: 5_000_000n, payment: 'lightning' })).rejects.toMatchObject({ reason: 'tap_first' })
    const tap = await h.wallet.discover.tap(card.address)
    expect(tap).toMatchObject({ outcome: 'show', notice: 'tap_visible', banners: { termsDiffer: false, testNetwork: false } })
    expect(tap.terms?.lightning?.feePpm).toBe(1000n)
    const placed = await h.wallet.discover.order(card.address, { amountMillis: 5_000_000n, payment: 'lightning' })
    expect(placed.invoice).toMatch(/^ln/)
    expect((await h.wallet.discover.recommendPreview(card.address)).reasonIfNot).toBe('not_used')
  })
})

describe('ranking (§Wallet Rules "Signals")', () => {
  test('a recommended listing ranks above a newer listing with no signal', async () => {
    const h = await harness({ deps: { nwcTimeoutMs: 2000 } })
    const friend = fill(0x48, 32)
    const recommended = new FakeOrder(h.bank)
    const unsignalled = new FakeOrder(h.bank)
    await h.pool.publish(R, listingEvent(h.bank.hub.nodeKey, { d: recommended.pubkey, connection: recommended.string, created_at: NOW - 100 }))
    await h.pool.publish(R, listingEvent(h.bank.hub.nodeKey, { d: unsignalled.pubkey, connection: unsignalled.string, created_at: NOW - 2 }))
    await h.pool.publish(R, finalizeEvent({ ...newRecommendation(h.bank.hub.node, R, [`31190:${h.bank.hub.node}:${recommended.pubkey}`], 'fast'), created_at: NOW - 5 }, friend))
    await h.wallet.discover.refresh({ relays: [R], follows: [getPublicKey(friend)] })
    const cards = h.wallet.discover.list().sections.buyCash
    expect(cards.map((c) => c.address.endsWith(recommended.pubkey))).toEqual([true, false])
    expect(cards[0]!.signals.recommendations).toHaveLength(1)
  })
  test('listings with no signal rank newest first', async () => {
    const h = await harness({ deps: { nwcTimeoutMs: 2000 } })
    const older = new FakeOrder(h.bank)
    const newer = new FakeOrder(h.bank)
    await h.pool.publish(R, listingEvent(h.bank.hub.nodeKey, { d: older.pubkey, connection: older.string, created_at: NOW - 100 }))
    await h.pool.publish(R, listingEvent(h.bank.hub.nodeKey, { d: newer.pubkey, connection: newer.string, created_at: NOW - 2 }))
    await h.wallet.discover.refresh({ relays: [R], follows: [getPublicKey(fill(0x48, 32))], includeUnreviewed: true })
    const v = h.wallet.discover.list()
    const all = [...v.sections.buyCash, ...(v.sections.unreviewed ?? [])]
    expect(all.map((c) => c.address.endsWith(newer.pubkey))).toEqual([true, false])
  })
})

describe('the listing’s connection string', () => {
  test('all uppercase is read; mixed case is step 2', async () => {
    const { bank, order } = await shop()
    expect(parseListing(listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: order.string.toUpperCase() }), { chains: ['bitcoin'] }).type).toBe('cash_order')
    const mixed = `C${order.string.slice(1)}`
    expect(() => parseListing(listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: mixed }), { chains: ['bitcoin'] })).toThrow(expect.objectContaining({ step: 2 }))
  })
})

describe('untrusted text', () => {
  test('C0 and C1 controls, DEL and directional marks are removed; breaks are one space', () => {
    expect(sanitizeText('a\u001b[31mred\u0007\u007f\u0090b', 0)).toBe('a[31mredb')
    expect(sanitizeText('x‎y‏z؜w', 0)).toBe('xyzw')
    expect(sanitizeText('one\ttwo\r\nthree\u0085four', 0)).toBe('one two three four')
  })
  test('a language that is not two lowercase letters and a geohash outside its alphabet are dropped', async () => {
    const { bank, order } = await shop()
    const l = parseListing(listingEvent(bank.hub.nodeKey, { d: order.pubkey, connection: order.string, tags: [['l', 'en', 'ISO-639-1'], ['l', 'EN\u001b', 'ISO-639-1'], ['l', 'eng', 'ISO-639-1'], ['g', 'u4pr'], ['g', 'u4pa'], ['g', 'u4\u001b']] }), { chains: ['bitcoin'] })
    expect(l.languages).toEqual(['en'])
    expect(l.geohashes).toEqual(['eyc', 'u4pr'])
  })
})
