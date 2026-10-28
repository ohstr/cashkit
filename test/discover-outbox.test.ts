// Discover beyond browsing: what survives a restart (the version book, tap
// outcomes, the events behind the last refresh), the user's curators
// (NIP-51 set, published and synced), and the outbox that publishes
// recommendations and reports later, signed by the user's identity.
import { describe, expect, test, vi } from 'vitest'
import { finalizeEvent, getPublicKey, type NostrEvent } from '../src/core/index.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { FakeOrder } from './fakeOrder.js'
import { fill } from './helpers.js'
import { harness } from './walletHarness.js'

const R = 'wss://social.test'
const yes = async () => true

function listingEvent(key: Uint8Array, o: { d: string; connection: string; created_at: number }): NostrEvent {
  return finalizeEvent(
    {
      kind: 31190,
      created_at: o.created_at,
      tags: [
        ['d', o.d],
        ['t', 'cash_order'],
        ['t', 'lightning'],
        ['n', 'bitcoin'],
        ['network', 'mainnet'],
        ['connection', o.connection],
        ['title', 'Cash counter'],
        ['status', 'open'],
        ['expiration', String(o.created_at + 86400 * 20)],
      ],
      content: '',
    },
    key,
  )
}

/** A wallet whose clock the test moves. */
async function clocked(o: { storage?: MemoryStorage } = {}) {
  let t = Date.now()
  const h = await harness({ deps: { nwcTimeoutMs: 2000, clock: () => t }, ...(o.storage !== undefined && { storage: o.storage }) })
  return { h, advance: (s: number) => (t += s * 1000), now: () => Math.floor(t / 1000) }
}

describe('a restart keeps what discover knew', () => {
  test('the listings of the last refresh, their tap outcomes and the signals are back after reopening', async () => {
    const { h, now } = await clocked()
    const order = new FakeOrder(h.bank)
    const friend = fill(0x51, 32)
    const ev = listingEvent(h.bank.hub.nodeKey, { d: order.pubkey, connection: order.string, created_at: now() - 10 })
    await h.pool.publish(R, ev)
    await h.wallet.discover.refresh({ relays: [R], follows: [getPublicKey(friend)] })
    expect(h.wallet.discover.list().sections.buyCash).toHaveLength(0)
    await h.wallet.discover.refresh({ relays: [R], follows: [getPublicKey(friend)], includeUnreviewed: true })
    const addr = h.wallet.discover.list().sections.unreviewed![0]!.address
    expect((await h.wallet.discover.tap(addr)).outcome).toBe('show')
    const again = await h.reopen()
    const v = again.discover.list()
    expect(v.sections.unreviewed?.map((c) => c.address)).toEqual([addr])
    expect(v.sections.unreviewed![0]!.tapState).toBe('available')
    // The listing at hand needs no new tap: the hand-off is allowed.
    expect((await again.discover.order(addr, { amountMillis: 5_000_000n, payment: 'lightning' })).invoice).toMatch(/^ln/)
  })
  test('an offer hidden for good at tap stays hidden after a restart; an older version cannot come back', async () => {
    const { h, now } = await clocked()
    const order = new FakeOrder(h.bank)
    order.info = () => ({ ...FakeOrder.prototype.info.call(order), pubkey: 'ab'.repeat(32) })
    const ev = listingEvent(h.bank.hub.nodeKey, { d: order.pubkey, connection: order.string, created_at: now() - 10 })
    await h.pool.publish(R, ev)
    await h.wallet.discover.refresh({ relays: [R], follows: [], includeUnreviewed: true })
    const addr = h.wallet.discover.list().sections.unreviewed![0]!.address
    expect((await h.wallet.discover.tap(addr)).outcome).toBe('hide_for_good')
    const again = await h.reopen()
    expect(again.discover.list().unreviewedCount).toBe(0)
    const older = listingEvent(h.bank.hub.nodeKey, { d: order.pubkey, connection: order.string, created_at: now() - 100 })
    await h.pool.publish(R, older)
    await again.discover.refresh({ relays: [R], follows: [], includeUnreviewed: true })
    expect(again.discover.list().unreviewedCount).toBe(0)
  })
})

describe('curators', () => {
  test("an app's defaults until the user edits; then the user's list wins", async () => {
    const h = await harness()
    const a = 'aa'.repeat(32)
    const b = 'bb'.repeat(32)
    expect(await h.wallet.discover.curators.setDefaults({ pubkeys: [a], sourceName: 'Example' })).toEqual({ pubkeys: [a], source: 'app', sourceName: 'Example' })
    expect(await h.wallet.discover.curators.add(b)).toEqual({ pubkeys: [a, b], source: 'user' })
    expect(await h.wallet.discover.curators.setDefaults({ pubkeys: [a] })).toEqual({ pubkeys: [a, b], source: 'user' })
    expect(await h.wallet.discover.curators.remove(a)).toEqual({ pubkeys: [b], source: 'user' })
    await expect(h.wallet.discover.curators.add('AB'.repeat(32))).rejects.toMatchObject({ code: 'invalid_input' })
  })
  test('published as a private NIP-51 set (no title, items NIP-44 to self) and synced back on another wallet of the same identity', async () => {
    const storage = new MemoryStorage()
    const h = await harness({ storage })
    const c = 'cc'.repeat(32)
    await h.wallet.discover.curators.add(c)
    const r = await h.wallet.discover.curators.publish({ relays: [R] })
    expect(r.relays).toEqual([R])
    const ev = h.pool.published.find((p) => p.event.kind === 30000)!.event
    expect(ev.tags).toEqual([['d', 'cash-discover']])
    expect(ev.pubkey).toBe(h.me)
    expect(ev.content).not.toContain(c)
    await h.wallet.discover.curators.remove(c)
    expect(await h.wallet.discover.curators.sync({ relays: [R] })).toEqual({ pubkeys: [c], source: 'user' })
    expect((await h.wallet.settings.get()).discover?.curatorsPrivate).toBe(true)
    // refresh ranks by the stored curators when none are passed.
    await h.wallet.discover.refresh({ relays: [R], follows: [] })
    expect(h.wallet.discover.list().coldStart).toBe('curators_no_signals')
  })
  test('a curator set or a 10002 forged under the user\'s pubkey is ignored', async () => {
    const h = await harness()
    const mine = 'cc'.repeat(32)
    await h.wallet.discover.curators.add(mine)
    await h.wallet.discover.curators.publish({ relays: [R] })
    const real = h.pool.published.find((p) => p.event.kind === 30000)!.event
    const evil = fill(0x66, 32)
    const forged: NostrEvent = { ...finalizeEvent({ kind: 30000, created_at: real.created_at + 100, tags: [['d', 'cash-discover'], ['p', 'dd'.repeat(32)]], content: '' }, evil), pubkey: h.me }
    const tampered: NostrEvent = { ...real, created_at: real.created_at + 200, tags: [['d', 'cash-discover'], ['p', 'dd'.repeat(32)]], content: '' }
    const relays: NostrEvent = { ...finalizeEvent({ kind: 10002, created_at: real.created_at + 100, tags: [['r', 'wss://evil.test']], content: '' }, evil), pubkey: h.me }
    for (const e of [forged, tampered, relays]) await h.pool.publish(R, e)
    expect(await h.wallet.discover.curators.sync({ relays: [R] })).toEqual({ pubkeys: [mine], source: 'user' })
    await h.wallet.discover.curators.publish({ relays: [R] })
    expect(h.pool.published.some((p) => p.relay === 'wss://evil.test')).toBe(false)
  })
  test('without an identity there is nothing to sign with', async () => {
    const h = await harness({ identity: false })
    await expect(h.wallet.discover.curators.publish({ relays: [R] })).rejects.toMatchObject({ code: 'usage', reason: 'identity_required' })
  })
})

describe('the outbox', () => {
  test('a report is queued, never published before its delay of 1 to 6 hours, then signed and published', async () => {
    const { h, advance, now } = await clocked()
    const node = getPublicKey(fill(0x52, 32))
    await h.wallet.discover.refresh({ relays: [R], follows: [] })
    let shown: unknown
    const r = await h.wallet.discover.report(node, { reason: 'no_payout', content: 'paid, never minted', confirm: async (p) => ((shown = p), true) })
    expect(shown).toEqual({ audience: { public: true }, reporter: h.me, node, reason: 'no_payout' })
    // Without `confirm`, the wallet asks its handler: none means no.
    expect(await h.wallet.discover.report(node, { reason: 'spam', content: 'x' })).toEqual({ queued: false })
    const asked: unknown[] = []
    const off = h.wallet.on('confirm', (q) => (asked.push(q), false))
    expect(await h.wallet.discover.report(node, { reason: 'spam', content: 'x' })).toEqual({ queued: false })
    expect(asked).toEqual([{ type: 'confirmReport', node, audience: { public: true }, revealsMembership: false, linksIdentity: true, delay: { minSecs: 3600, maxSecs: 21_600 } }])
    off()
    expect(await h.wallet.discover.outbox.list()).toHaveLength(1)
    if (!r.queued) throw new Error('not queued')
    expect(r.item.dueAt - now()).toBeGreaterThanOrEqual(3600)
    expect(r.item.dueAt - now()).toBeLessThan(21_600)
    expect(JSON.stringify(await h.wallet.discover.outbox.list())).not.toContain('never minted')
    expect((await h.wallet.discover.outbox.publishDue()).published).toEqual([])
    advance(21_600)
    expect((await h.wallet.discover.outbox.publishDue()).published).toEqual([r.item.id])
    const ev = h.pool.published.find((p) => p.event.kind === 1984)!.event
    expect(ev.pubkey).toBe(h.me)
    expect(ev.created_at).toBe(now())
    expect(ev.tags).toContainEqual(['l', 'no_payout', 'cash.report'])
    expect(await h.wallet.discover.outbox.list()).toEqual([])
  })
  test('only the identity that queued an item publishes it; one stored without its author is dropped unpublished (KT-10)', async () => {
    const { h, advance } = await clocked()
    const node = getPublicKey(fill(0x54, 32))
    await h.wallet.discover.refresh({ relays: [R], follows: [] })
    const a = await h.wallet.discover.report(node, { reason: 'spam', content: 'a', confirm: async () => true })
    const b = await h.wallet.discover.report(node, { reason: 'spam', content: 'b', confirm: async () => true })
    if (!a.queued || !b.queued) throw new Error('not queued')
    expect(a.item.author).toBe(h.me)
    await h.storage.tx('rw', async (t) => {
      const ra = (await t.get('discoverOutbox', a.item.id))!
      await t.put('discoverOutbox', { ...ra, author: 'ee'.repeat(32), version: ra.version + 1 }, ra.version)
      const rb = (await t.get('discoverOutbox', b.item.id))!
      const { author: _x, ...legacy } = rb
      await t.put('discoverOutbox', { ...legacy, version: rb.version + 1 }, rb.version)
    })
    advance(21_600)
    expect((await h.wallet.discover.outbox.publishDue()).published).toEqual([])
    expect(h.pool.published.filter((p) => p.event.kind === 1984)).toEqual([])
    expect((await h.wallet.discover.outbox.list()).map((x) => x.id)).toEqual([a.item.id])
  })
  test('declined at the confirmation, nothing is queued; a queued item can be cancelled; a due item is published at the next open', async () => {
    const storage = new MemoryStorage()
    let t = Date.now()
    const h = await harness({ storage, deps: { clock: () => t } })
    const node = getPublicKey(fill(0x53, 32))
    expect(await h.wallet.discover.report(node, { reason: 'spam', content: '', confirm: async () => false })).toEqual({ queued: false })
    const a = await h.wallet.discover.report(node, { reason: 'spam', content: 'a', confirm: yes })
    const b = await h.wallet.discover.report(`31190:${node}:${'ab'.repeat(32)}`, { reason: 'impersonation', content: 'b', confirm: yes })
    if (!a.queued || !b.queued) throw new Error('not queued')
    await h.wallet.discover.outbox.cancel(a.item.id)
    expect((await h.wallet.discover.outbox.list()).map((x) => x.id)).toEqual([b.item.id])
    // No relay read yet: publish to the user's write relays from a refresh.
    await h.wallet.discover.refresh({ relays: [R], follows: [] })
    const c = await h.wallet.discover.report(node, { reason: 'spam', content: 'c', confirm: yes })
    if (!c.queued) throw new Error('not queued')
    t += 21_600_000
    await h.reopen()
    const pub = h.pool.published.filter((p) => p.event.kind === 1984).map((p) => p.event.content)
    expect(pub).toEqual(['c'])
    // b had no relay to go to: still queued.
    expect((await (await h.reopen()).discover.outbox.list()).map((x) => x.id)).toEqual([b.item.id])
  })
  test('recommending needs a used offer outside the session of the order, a day later; one per node; a withdrawal is published at once', async () => {
    const { h, advance, now } = await clocked()
    const order = new FakeOrder(h.bank)
    await h.pool.publish(R, listingEvent(h.bank.hub.nodeKey, { d: order.pubkey, connection: order.string, created_at: now() - 10 }))
    await h.wallet.discover.refresh({ relays: [R], follows: [], includeUnreviewed: true })
    const addr = h.wallet.discover.list().sections.unreviewed![0]!.address
    await expect(h.wallet.discover.recommend(addr, { content: '' })).rejects.toMatchObject({ code: 'invalid_input', reason: 'recommend_not_allowed' })
    await h.wallet.discover.tap(addr)
    const placed = await h.wallet.discover.order(addr, { amountMillis: 5_000_000n, payment: 'lightning' })
    await order.pay(order.only(), BigInt(placed.payMillis))
    await h.wallet.orders.refresh(placed.id)
    expect((await h.wallet.discover.recommendPreview(addr)).reasonIfNot).toBe('same_session')
    advance(2 * 86400)
    const later = await h.reopen({ clock: () => now() * 1000 })
    expect((await later.discover.recommendPreview(addr)).allowed).toBe(true)
    // With no confirmation handler, nothing is queued or published.
    expect(await later.discover.recommend(addr, { content: 'fast' })).toEqual({ queued: false })
    expect(await later.discover.withdrawRecommendation(h.bank.hub.node, { relays: [R] })).toEqual({ withdrawn: false, relays: [] })
    expect(await later.discover.outbox.list()).toEqual([])
    const asked: unknown[] = []
    later.on('confirm', (r) => (asked.push(r), true))
    const first = await later.discover.recommend(addr, { content: 'fast' })
    const second = await later.discover.recommend(addr, { content: '' })
    if (!first.queued || !second.queued) throw new Error('not queued')
    expect(second.item.id).toBe(first.item.id)
    expect(await later.discover.outbox.list()).toHaveLength(1)
    expect(asked[0]).toEqual({ type: 'confirmRecommend', address: addr, node: h.bank.hub.node, audience: { public: true }, revealsMembership: false, linksIdentity: true, delay: { minSecs: 3600, maxSecs: 21_600 } })
    const w = await later.discover.withdrawRecommendation(h.bank.hub.node, { relays: [R] })
    expect(w).toEqual({ withdrawn: true, relays: [R] })
    expect(asked.at(-1)).toMatchObject({ type: 'confirmRecommend', node: h.bank.hub.node, withdrawal: true })
    expect(await later.discover.outbox.list()).toEqual([])
    const del = h.pool.published.find((p) => p.event.kind === 5)!.event
    expect(del.tags).toEqual([['a', `31191:${h.me}:${h.bank.hub.node}`], ['k', '31191']])
  })
  test('autoSettle publishes a queued item when it falls due', async () => {
    const { h, advance } = await clocked()
    await h.wallet.discover.refresh({ relays: [R], follows: [] })
    const timers: { fn: () => void; ms: number }[] = []
    const stop = h.wallet.autoSettle({ setTimeout: (fn, ms) => timers.push({ fn, ms }), clearTimeout: () => undefined })
    const r = await h.wallet.discover.report('dd'.repeat(32), { reason: 'spam', content: '', confirm: async () => true })
    if (!r.queued) throw new Error('not queued')
    await vi.waitFor(() => expect(timers.length).toBeGreaterThan(0))
    const t = timers.at(-1)!
    expect(t.ms).toBeGreaterThanOrEqual(3_600_000)
    advance(t.ms / 1000)
    t.fn()
    await vi.waitFor(() => expect(h.pool.published.some((p) => p.event.kind === 1984)).toBe(true))
    stop()
  })
  test('without an identity, recommending and reporting are refused, nothing queued', async () => {
    const h = await harness({ identity: false })
    await expect(h.wallet.discover.report('aa'.repeat(32), { reason: 'spam', content: '' })).rejects.toMatchObject({ code: 'usage', reason: 'identity_required' })
  })
})

