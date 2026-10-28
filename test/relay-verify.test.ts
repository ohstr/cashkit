// Events read from relays are trusted only once their id and signature
// verify: a relay cannot forge an author (a follow's recommendation, the
// user's own kind 3 or 10522) or shadow a real event with a forged copy.
import { describe, expect, test } from 'vitest'
import { readEvents } from '../src/client/index.js'
import { finalizeEvent, getEventHash, getPublicKey, newRecommendation, type NostrEvent } from '../src/core/index.js'
import { MemoryRelayPool } from './fakeHub.js'
import { FakeOrder } from './fakeOrder.js'
import { fill } from './helpers.js'
import { harness } from './walletHarness.js'

const R = 'wss://social.test'
const NOW = Math.floor(Date.now() / 1000)

/** `ev` claimed by `pubkey`: the id is recomputed, the signature is the original signer's. */
const forgeAuthor = (ev: NostrEvent, pubkey: string): NostrEvent => {
  const out = { ...ev, pubkey }
  return { ...out, id: getEventHash(out) }
}

describe('readEvents', () => {
  test('drops a bad signature, a wrong id and a swapped author; keeps the real one', async () => {
    const pool = new MemoryRelayPool()
    const key = fill(0x31, 32)
    const other = getPublicKey(fill(0x32, 32))
    const real = finalizeEvent({ kind: 1, created_at: NOW, tags: [], content: 'hello' }, key)
    const badSig = { ...finalizeEvent({ kind: 1, created_at: NOW, tags: [], content: 'bad sig' }, key), sig: 'ab'.repeat(64) }
    const wrongId = { ...finalizeEvent({ kind: 1, created_at: NOW, tags: [], content: 'wrong id' }, key), id: 'cd'.repeat(32) }
    const swapped = forgeAuthor(finalizeEvent({ kind: 1, created_at: NOW, tags: [], content: 'swapped' }, key), other)
    for (const e of [badSig, wrongId, swapped, real]) pool.store(R, e)
    const got = await readEvents(pool, [R], { kinds: [1] }, 1000)
    expect(got.map((e) => e.content)).toEqual(['hello'])
  })
  test('a forged copy with a real event’s id, served first, does not shadow it', async () => {
    const pool = new MemoryRelayPool()
    const real = finalizeEvent({ kind: 1, created_at: NOW, tags: [], content: 'real' }, fill(0x33, 32))
    pool.store('wss://a.test', { ...real, content: 'tampered' })
    pool.store('wss://b.test', real)
    const got = await readEvents(pool, ['wss://a.test', 'wss://b.test'], { kinds: [1] }, 1000)
    expect(got).toEqual([real])
  })
})

describe('trust read from relays', () => {
  test('a recommendation forged in a follow’s name and a forged kind 3 are ignored', async () => {
    const h = await harness({ deps: { nwcTimeoutMs: 2000 } })
    const order = new FakeOrder(h.bank)
    const friend = getPublicKey(fill(0x48, 32))
    const attacker = fill(0x49, 32)
    const listing = finalizeEvent(
      {
        kind: 31190,
        created_at: NOW - 10,
        tags: [['d', order.pubkey], ['t', 'cash_order'], ['t', 'lightning'], ['n', 'bitcoin'], ['network', 'mainnet'], ['connection', order.string], ['title', 'counter'], ['status', 'open'], ['expiration', String(NOW + 86400 * 60)]],
        content: '',
      },
      h.bank.hub.nodeKey,
    )
    h.pool.store(R, listing)
    const rec = finalizeEvent({ ...newRecommendation(h.bank.hub.node, R, [`31190:${h.bank.hub.node}:${order.pubkey}`], 'forged'), created_at: NOW - 5 }, attacker)
    h.pool.store(R, forgeAuthor(rec, friend))
    // The user's own kind 3, forged to follow the attacker.
    h.pool.store(R, forgeAuthor(finalizeEvent({ kind: 3, created_at: NOW, tags: [['p', getPublicKey(attacker)]], content: '' }, attacker), h.me))
    h.pool.store(R, finalizeEvent({ ...newRecommendation(h.bank.hub.node, R, [`31190:${h.bank.hub.node}:${order.pubkey}`], 'attacker'), created_at: NOW - 4 }, attacker))
    await h.wallet.discover.refresh({ relays: [R], follows: [friend], includeUnreviewed: true })
    expect(h.wallet.discover.list().sections.buyCash.flatMap((c) => c.signals.recommendations)).toEqual([])
    await h.wallet.discover.refresh({ relays: [R], includeUnreviewed: true })
    expect(h.wallet.discover.list().sections.buyCash.flatMap((c) => c.signals.recommendations)).toEqual([])
  })
  test('a 10522 forged in the user’s name does not make a minter trusted', async () => {
    const alice = await harness()
    const bob = await harness({ pool: alice.pool, bank: alice.bank })
    await alice.wallet.receive(alice.bank.mintToPubkey(50_000n, alice.me).token)
    await alice.wallet.zaps.send({ to: bob.me, amountMillis: 21_000n, target: { e: 'cd'.repeat(32) }, relays: [R] })
    const [z] = await bob.wallet.zaps.list({ relays: [R] })
    expect(z).toMatchObject({ valid: true, trusted: false })
    const info = finalizeEvent({ kind: 10522, created_at: NOW, tags: [['chain', z!.chain!], ['mint', z!.minter!, z!.chain!]], content: '' }, fill(0x4a, 32))
    alice.pool.store(R, forgeAuthor(info, bob.me))
    expect((await bob.wallet.zaps.list({ relays: [R] }))[0]).toMatchObject({ valid: true, trusted: false })
  })
})
