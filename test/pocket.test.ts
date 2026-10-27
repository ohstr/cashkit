// The Cash Pocket (NIP-CP): seals and wraps, entry tags, resolution, the
// balance, and the engine over relays: write-ahead before a call goes out,
// entries for kept bills, sources spent, and a second device's sync.
import { describe, expect, test } from 'vitest'
import {
  createRumor,
  createSeal,
  createWrap,
  derivedRequestId,
  fromHex,
  getPublicKey,
  localSigner,
  parsePocketEntry,
  pocketBalance,
  pocketEntryTags,
  resolveEntries,
  toHex,
  unwrap,
  wrapExpiration,
  type PocketEntry,
} from '../src/core/index.js'
import { syncPocket } from '../src/adapters/sync-pocket.js'
import { CashkitError } from '../src/wallet/index.js'
import { FakeWithdraw, PAYTO } from './fakeWithdraw.js'
import { fill } from './helpers.js'
import { harness, type Harness } from './walletHarness.js'

const R = ['wss://inbox1.test', 'wss://inbox2.test']
const rnd = (n: number) => fill(9, n)
const user = localSigner(fill(0x21, 32))
const entry = (o: Partial<PocketEntry> = {}): PocketEntry => ({ w: 'aa'.repeat(32), rev: 1, state: 'live', checkedAt: 5, wrapKey: 'bb'.repeat(32), amountMillis: 21000n, chain: 'bitcoin', cash: 'satscash1x', identity: { type: 'pubkey', value: user.pubkey }, ...o })

const cand = (id: string, created_at: number, e: Partial<PocketEntry>) => ({ rumor: { id, created_at }, entry: entry(e) })

describe('wrapping and entries', () => {
  test('seal and wrap: only the user’s own 9525 unwraps', async () => {
    const rumor = createRumor({ kind: 9525, pubkey: user.pubkey, created_at: 100, tags: pocketEntryTags(entry()), content: '' })
    const wrapKey = fill(0x31, 32)
    const wrap = createWrap(await createSeal(rumor, user, { now: 1000, random: rnd }), wrapKey, user.pubkey, { now: 1000, random: rnd })
    expect(wrap.kind).toBe(1059)
    expect(wrap.pubkey).toBe(getPublicKey(wrapKey))
    expect(wrap.created_at).toBeLessThanOrEqual(1000)
    expect((await unwrap(wrap, user))?.id).toBe(rumor.id)
    const other = localSigner(fill(0x22, 32))
    expect(await unwrap(wrap, other)).toBeUndefined()
    const forged = createRumor({ kind: 9525, pubkey: other.pubkey, created_at: 1, tags: [], content: '' })
    const bad = createWrap(await createSeal({ ...forged, pubkey: user.pubkey, id: forged.id }, user, { now: 1000000, random: rnd }), wrapKey, user.pubkey, { now: 1000000, random: rnd })
    expect(await unwrap(bad, user)).toBeUndefined()
  })
  test('tags round-trip: a pending entry with secrets by role, an order key and a notify', () => {
    const p: PocketEntry = { w: '00112233445566778899aabbccddeeff', rev: 2, state: 'pending', checkedAt: 7, wrapKey: 'cc'.repeat(32), amountMillis: 5000n, chain: 'bitcoin', requestId: '00112233445566778899aabbccddeeff', deadline: 1760000300, target: 'dd'.repeat(32), device: 'ee'.repeat(16), secrets: [{ secret: '11'.repeat(32), role: '' }, { secret: '22'.repeat(32), role: 'remainder' }], notify: 'ff'.repeat(32) }
    const tags = pocketEntryTags(p)
    expect(tags.filter((t) => t[0] === 'secret')).toEqual([['secret', '11'.repeat(32)], ['secret', '22'.repeat(32), 'remainder']])
    expect(tags.some((t) => t[0] === 'cash' || t[0] === 'identity')).toBe(false)
    expect(parsePocketEntry({ kind: 9525, tags })).toMatchObject({ ...p, recognised: true })
  })
  test('the spec’s derived ids chain', () => {
    const a = derivedRequestId('00112233445566778899aabbccddeeff')
    expect(a).toBe('1f0d61013abef39098ffb0a7c72008a17099c52aca3d5ee8d6ce8de065db5d37')
    expect(derivedRequestId(a)).toBe('c4c6d6c4893cca6283c95ea32a0b6bef6be796804e62e21e30113b63c676457e')
  })
  test('resolving: a final state wins over lower or equal revs; a higher rev supersedes it; then created_at, then the lowest id', () => {
    expect(resolveEntries([cand('b', 1, { rev: 3, state: 'live' }), cand('a', 1, { rev: 3, state: 'spent' })]).entries.get('aa'.repeat(32))!.state).toBe('spent')
    expect(resolveEntries([cand('a', 1, { rev: 2, state: 'spent' }), cand('b', 1, { rev: 3, state: 'live' })]).entries.get('aa'.repeat(32))!.state).toBe('live')
    expect(resolveEntries([cand('a', 1, { rev: 2, amountMillis: 1n }), cand('b', 2, { rev: 2, amountMillis: 2n })]).entries.get('aa'.repeat(32))!.amountMillis).toBe(2n)
    expect(resolveEntries([cand('b', 1, { rev: 2, amountMillis: 1n }), cand('a', 1, { rev: 2, amountMillis: 2n })]).entries.get('aa'.repeat(32))!.amountMillis).toBe(2n)
    expect(resolveEntries([cand('a', 1, { state: 'zombie' as never })]).entries.size).toBe(1)
  })
  test('the balance is live entries per chain; NIP-40 expiration rounds to the week', () => {
    expect(pocketBalance([entry(), entry({ w: 'cc'.repeat(32), state: 'spent' }), entry({ w: 'dd'.repeat(32), chain: 'other' })])).toEqual(new Map([['bitcoin', 21000n], ['other', 21000n]]))
    const x = wrapExpiration(1_000_000, { random: () => Uint8Array.of(0) })
    expect(x % 604800).toBe(0)
    expect(x).toBeGreaterThanOrEqual(1_000_000 + 2_592_000)
  })
})

async function withPocket(o: { pool?: Harness['pool']; bank?: Harness['bank']; relays?: readonly string[] } = {}): Promise<Harness> {
  const base = await harness({ ...(o.pool !== undefined && { pool: o.pool }), ...(o.bank !== undefined && { bank: o.bank }) })
  const pocket = syncPocket({ pool: base.pool, relays: o.relays ?? R, readTimeoutMs: 300 })
  const wallet = await base.reopen({ pocket })
  return { ...base, wallet }
}
const wraps = (h: Harness) => h.pool.published.filter((p) => p.event.kind === 1059)

describe('the pocket engine', () => {
  test('a send writes its pending entry ahead (read back), then the remainder live and the pending done, the source spent', async () => {
    const h = await withPocket()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    await h.wallet.pocket.sync()
    const seen: number[] = []
    h.bank.override = (m) => {
      if (m === 'cash_transfer') seen.push(wraps(h).length)
      return undefined
    }
    await h.wallet.send({ amount: 2000n })
    expect(seen[0]).toBeGreaterThan(R.length) // the pending entry's wraps went out before the call
    const entries = await h.wallet.pocket.entries()
    expect(entries.filter((e) => e.state === 'live').map((e) => e.amountMillis)).toEqual([3000n])
    expect(entries.filter((e) => e.state === 'done')).toHaveLength(1)
    expect(entries.filter((e) => e.state === 'spent').map((e) => e.amountMillis)).toEqual([5000n])
    expect(await h.wallet.pocket.balance()).toEqual(new Map([['flokicoin', 3000n]]))
  })
  test('a pocket that cannot store the entry stops the call: nothing is sent', async () => {
    const h = await withPocket({ relays: ['wss://inbox1.test'] })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    h.pool.relay('wss://inbox1.test').refuse = true
    const before = h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer').length
    const e = await h.wallet.send({ amount: 2000n }).then(
      () => undefined,
      (x: unknown) => x as CashkitError,
    )
    expect(e?.reason ?? e?.code).toBeDefined()
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer').length).toBe(before)
  })
  test('a second device with the same key imports the live bills, with their secrets', async () => {
    const a = await withPocket()
    const secret = '33'.repeat(32)
    await a.wallet.receive(`${a.bank.mintToCash(4000n, secret).token}#${secret}`)
    await a.wallet.pocket.sync()
    const signer = await a.storage.tx('r', (t) => t.get('identity', 'self'))
    expect(signer).toBeDefined()
    // Device two: the same storage identity, a fresh holdings table, the same relays.
    const b = await withPocket({ pool: a.pool, bank: a.bank })
    await b.storage.tx('rw', async (t) => {
      const cur = await t.get('identity', 'self')
      await t.put('identity', { ...signer!, version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
    })
    const b2 = await b.reopen({ pocket: syncPocket({ pool: a.pool, relays: R, readTimeoutMs: 300 }) })
    const rep = await b2.pocket.sync()
    expect(rep.imported).toHaveLength(1)
    const [held] = await b2.holdings()
    expect(held).toMatchObject({ amount: 4000n, mode: 'cash' })
  })
})

const now = () => Math.floor(Date.now() / 1000)
async function userSigner(h: Harness) {
  const row = (await h.storage.tx('r', (t) => t.get('identity', 'self')))!
  return localSigner(fromHex(new TextDecoder().decode(fromHex(row.priv!.data))))
}
/** Another device's write: the entry at `rev`, wrapped and stored on every pocket relay. */
async function writeElsewhere(h: Harness, e: PocketEntry) {
  const signer = await userSigner(h)
  const rumor = createRumor({ kind: 9525, pubkey: signer.pubkey, created_at: now(), tags: pocketEntryTags(e), content: '' })
  const wrap = createWrap(await createSeal(rumor, signer, { now: now(), random: rnd }), fromHex(e.wrapKey), signer.pubkey, { now: now(), random: rnd })
  for (const r of R) await h.pool.publish(r, wrap)
}
async function heldRow(h: Harness) {
  const [v] = await h.wallet.holdings()
  return (await h.storage.tx('r', (t) => t.get('holdings', v!.id)))!
}
const liveEntry = async (h: Harness, rev: number, state: PocketEntry['state'] = 'live'): Promise<PocketEntry> => {
  const b = await heldRow(h)
  const chain = (await h.wallet.pocket.entries()).find((x) => x.w === b.walletPubkey)!.chain
  return { w: b.walletPubkey, rev, state, checkedAt: now(), wrapKey: toHex(fill(0x60 + rev, 32)), amountMillis: b.amount!, chain, cash: b.token, identity: { type: 'pubkey', value: h.me } }
}

describe('the pocket engine: revs across devices', () => {
  test('a bill imported at a rev another device wrote is spent above it: the spend wins', async () => {
    const a = await withPocket()
    await a.wallet.receive(a.bank.mintToPubkey(5000n, a.me).token)
    await a.wallet.pocket.sync()
    await writeElsewhere(a, await liveEntry(a, 4))
    const w = (await heldRow(a)).walletPubkey
    // A second device with the same key and an empty store.
    const b = await withPocket({ pool: a.pool, bank: a.bank })
    const identity = await a.storage.tx('r', (t) => t.get('identity', 'self'))
    await b.storage.tx('rw', async (t) => {
      const cur = await t.get('identity', 'self')
      await t.put('identity', { ...identity!, version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
    })
    const b2 = await b.reopen({ pocket: syncPocket({ pool: a.pool, relays: R, readTimeoutMs: 300 }) })
    expect((await b2.pocket.sync()).imported).toHaveLength(1)
    await b2.send({ amount: 5000n })
    expect((await b2.pocket.entries()).find((x) => x.w === w)?.state).toBe('spent')
  })
  test('a held bill the pocket shows spent is re-checked: still unspent, it is written live above that rev', async () => {
    const a = await withPocket()
    await a.wallet.receive(a.bank.mintToPubkey(5000n, a.me).token)
    await a.wallet.pocket.sync()
    const w = (await heldRow(a)).walletPubkey
    await writeElsewhere(a, await liveEntry(a, 3, 'spent'))
    await a.wallet.pocket.sync()
    expect((await a.wallet.pocket.entries()).find((x) => x.w === w)?.state).toBe('live')
    expect(await a.wallet.holdings()).toHaveLength(1)
  })
  test('a held bill the pocket shows spent and the Hub too is marked spent here; nothing live is written', async () => {
    const a = await withPocket()
    await a.wallet.receive(a.bank.mintToPubkey(5000n, a.me).token)
    await a.wallet.pocket.sync()
    const w = (await heldRow(a)).walletPubkey
    await writeElsewhere(a, await liveEntry(a, 3, 'spent'))
    a.bank.wallets.get(w)!.spent = true
    await a.wallet.pocket.sync()
    expect((await a.wallet.pocket.entries()).find((x) => x.w === w)?.state).toBe('spent')
    expect(await a.wallet.holdings()).toEqual([])
  })
})

describe('the pocket engine: withdrawals', () => {
  test('the source is written spent once the receipt checks out, while the withdrawal stays open', async () => {
    const h = await withPocket()
    const hub = new FakeWithdraw(h.bank)
    const r = await h.wallet.receive(h.bank.mintToPubkey(21_000_000n, h.me).token)
    const id = r.received ? r.holding.id : ''
    const w = (await h.storage.tx('r', (t) => t.get('holdings', id)))!.walletPubkey
    await h.wallet.pocket.sync()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: () => Promise.resolve(true) })
    expect(v.state).toBe('queued')
    expect(hub.payouts.size).toBe(1)
    const entries = await h.wallet.pocket.entries()
    expect(entries.find((e) => e.w === w)?.state).toBe('spent')
    expect(entries.filter((e) => e.state === 'pending')).toHaveLength(1)
    expect(await h.wallet.pocket.balance()).toEqual(new Map())
  })
})

describe('the pocket engine: identities', () => {
  test('a bill under a merge key is written with that key as its identity', async () => {
    const h = await withPocket()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const b = await heldRow(h)
    const key = fill(0x71, 32)
    await h.storage.tx('rw', async (t) => {
      const row = (await t.get('holdings', b.id))!
      await t.put('holdings', { ...row, throwawayKey: { alg: 'none', data: toHex(new TextEncoder().encode(toHex(key))) }, version: row.version + 1 }, row.version)
    })
    await h.wallet.pocket.sync()
    const signer = await userSigner(h)
    const ids = []
    for (const p of wraps(h)) {
      const r = await unwrap(p.event, signer)
      if (r !== undefined) ids.push(parsePocketEntry(r).identity)
    }
    // One wrap per pocket relay.
    expect(ids).toEqual(R.map(() => ({ type: 'pubkey', value: getPublicKey(key) })))
  })
  test('a live entry bound to another pubkey or to a ConnectionKey is not imported, and is reported', async () => {
    const a = await withPocket()
    await a.wallet.receive(a.bank.mintToPubkey(5000n, a.me).token)
    await a.wallet.pocket.sync()
    const base = await liveEntry(a, 1)
    const other = { ...base, w: 'a1'.repeat(32), identity: { type: 'pubkey' as const, value: getPublicKey(fill(0x72, 32)) } }
    const ck = { ...base, w: 'a2'.repeat(32), identity: { type: 'connection_key' as const, value: 'b3'.repeat(32), ia: getPublicKey(fill(0x73, 32)) } }
    await writeElsewhere(a, other)
    await writeElsewhere(a, ck)
    const rep = await a.wallet.pocket.sync()
    expect(rep.imported).toEqual([])
    expect(new Set(rep.foreign)).toEqual(new Set([other.w, ck.w]))
    expect(await a.wallet.holdings()).toHaveLength(1)
  })
})
