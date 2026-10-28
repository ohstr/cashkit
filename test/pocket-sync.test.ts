// The Cash Pocket's upkeep (NIP-CP §Writing, §Reading, §Wrapping): the
// derived-id check before a call is placed again, NIP-40 on wraps when
// turned on, 30-day removal of final entries, a missing `expires_at` filled
// from cash_status, relay discovery (10050, then NIP-65), and NIP-42 AUTH.
import { beforeEach, describe, expect, test } from 'vitest'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  bySigning,
  connectionKeyFromAttested,
  createRumor,
  createSeal,
  createWrap,
  decodeToken,
  derivedRequestId,
  finalizeEvent,
  getPublicKey,
  newCashTarget,
  newRequestId,
  pubkeyTarget,
  toHex,
  type EventTemplate,
  type NostrEvent,
} from '../src/core/index.js'
import { billFor, CashClient, deadlineFor, transferMany } from '../src/client/index.js'
import type { PendingCall, Wallet } from '../src/wallet/index.js'
import { registerCallKind, pocketHooks, type CallKind } from '../src/wallet/runner.js'
import { markSent, prepareCall } from '../src/wallet/calls.js'
import type { Ctx } from '../src/wallet/context.js'
import { updateHolding } from '../src/wallet/ledger.js'
import { POCKET_FINAL_KEEP_SECONDS, writeEntry } from '../src/wallet/pocket.js'
import { pocketRelaysFrom, syncPocket } from '../src/adapters/sync-pocket.js'
import { RelayWs, type WebSocketLike } from '../src/adapters/relay-ws.js'
import { NostrToolsPool, type SimplePoolLike } from '../src/adapters/relay-nostr-tools.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'
import { harness, type Harness } from './walletHarness.js'

const R = ['wss://inbox1.test', 'wss://inbox2.test']
const BOB = 'ee'.repeat(32)
let skew = 0
const clock = () => Date.now() + skew
const ctxOf = (w: Wallet) => (w as unknown as { ctx: Ctx }).ctx

const kind: CallKind = {
  autoReplace: true,
  async place(ctx, call, beforePublish) {
    const h = (await ctx.read((t) => t.get('holdings', call.sources[0]!)))!
    const c = new CashClient(ctx.clientDeps, h.token)
    const r = await transferMany(
      await c.session(),
      [{ id: '1', bill: c.bill, credential: bySigning(await ctx.requireSigner()), to: pubkeyTarget(BOB), currentAmount: BigInt(call.params!['current']!), requestId: call.requestId }],
      () => ctx.nowSeconds(),
      { notAfter: call.deadline, beforePublish },
    )
    return { outcome: r.outcomes[0], ...(r.error !== undefined && { error: r.error }) }
  },
  async finish(_ctx, call) {
    return async (t) => {
      await updateHolding(t, call.sources[0]!, (x) => ({ ...x, status: 'transferred' }))
    }
  },
  async lookupTarget(ctx, call) {
    const h = (await ctx.read((t) => t.get('holdings', call.sources[0]!)))!
    return { bill: billFor(decodeToken(h.token)), authorizer: { kind: 'signer', signer: await ctx.requireSigner() } }
  },
}
registerCallKind('pocket-test-transfer', kind)

let h: Harness
beforeEach(async () => {
  skew = 0
  const base = await harness({ deps: { clock } })
  base.bank.hub.clock = clock
  const wallet = await base.reopen({ pocket: syncPocket({ pool: base.pool, relays: R, readTimeoutMs: 300 }) })
  h = { ...base, wallet }
})

const wraps = () => h.pool.published.filter((p) => p.event.kind === 1059).map((p) => p.event)
const transfers = () => h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer')
const row = (id: string) => ctxOf(h.wallet).read((t) => t.get('pendingCalls', id))

/** A transfer written ahead to the pocket and marked sent, but never delivered; the clock then passes its deadline. */
async function lostCall(): Promise<{ ctx: Ctx; call: PendingCall }> {
  const w = h.bank.mintToPubkey(5000n, h.me)
  const r = await h.wallet.receive(w.token)
  if (!r.received) throw new Error('not received')
  const ctx = ctxOf(h.wallet)
  const session = await new CashClient(ctx.clientDeps, w.token).session()
  const call = await prepareCall(ctx, {
    kind: 'pocket-test-transfer',
    requestId: newRequestId(),
    method: 'cash_transfer',
    target: w.walletPubkey,
    node: session.hub,
    relays: session.relays,
    deadline: deadlineFor(session.maxRequestAge, ctx.nowSeconds()),
    hAtSend: session.maxRequestAge!,
    amount: 5000n,
    sources: [r.holding.id],
    authorizer: { kind: 'identity' },
    outputs: [{ role: 'new', destination: { kind: 'cash', secret: newCashTarget().secret } }],
    params: { current: '5000' },
  })
  await markSent(ctx, call)
  await pocketHooks.writeAhead!(ctx, (await row(call.id))!)
  skew = (call.deadline + 2) * 1000 - Date.now()
  return { ctx, call }
}

/** Publishes a pocket entry of the user's own as raw tags (as another wallet might have written it). */
async function rawEntry(ctx: Ctx, tags: string[][]): Promise<void> {
  const signer = await ctx.requireSigner()
  const now = ctx.nowSeconds()
  const rumor = createRumor({ kind: 9525, pubkey: signer.pubkey, created_at: now, tags, content: '' })
  const wrap = createWrap(await createSeal(rumor, signer, { now, random: ctx.random }), fill(0x55, 32), signer.pubkey, { now, random: ctx.random })
  for (const url of R) await h.pool.publish(url, wrap)
}

const LIST_SK = fill(0x41, 32)
const AUTH_SK = fill(0x43, 32)
const list = (k: number, tags: string[][], at = 1): NostrEvent => finalizeEvent({ kind: k, created_at: at, tags, content: '' }, LIST_SK)
/** A list signed by someone else, to forge as the user's. */
const signedByOther = (k: number, tags: string[][], at: number) => finalizeEvent({ kind: k, created_at: at, tags, content: '' }, fill(0x44, 32))
const signAuth = async (t: EventTemplate) => finalizeEvent(t, AUTH_SK)
/** A check time over 30 days ago, on the wallet's clock. */
const oldCheck = () => Math.floor(clock() / 1000) - POCKET_FINAL_KEEP_SECONDS - 1

describe('placing a call again: the derived-id check', () => {
  test('with the old entry open and no derived entry, the call is placed again', async () => {
    const { call } = await lostCall()
    const rep = await h.wallet.settle()
    expect(rep.replaced).toEqual([call.id])
    expect(transfers().map((r) => r.params['request_id'])).toEqual([derivedRequestId(call.requestId)])
    const entries = await h.wallet.pocket.entries()
    expect(entries.find((e) => e.w === call.requestId)?.state).toBe('done')
    expect(entries.find((e) => e.w === derivedRequestId(call.requestId))?.state).toBe('done')
  })
  test('an entry carrying the derived id, even in a state this wallet does not know, stops it: the old call only closes', async () => {
    const { ctx, call } = await lostCall()
    await rawEntry(ctx, [['w', derivedRequestId(call.requestId)], ['rev', '1'], ['state', 'archived', '1']])
    await h.wallet.settle()
    expect(transfers()).toHaveLength(0)
    expect(await row(call.id)).toMatchObject({ state: 'done', outcome: 'replaced' })
    expect((await h.wallet.pocket.entries()).find((e) => e.w === call.requestId)?.state).toBe('done')
  })
  test('an old entry already closed elsewhere is not placed again', async () => {
    const { ctx, call } = await lostCall()
    // Another device closes it (the user decided): the pocket shows it `done` at a higher rev.
    await writeEntry(ctx, { w: call.requestId, state: 'done', amountMillis: 5000n, chain: 'flokicoin', requestId: call.requestId, deadline: call.deadline, target: call.target, device: 'ff'.repeat(16) }, { seenRev: 5 })
    await h.wallet.settle()
    expect(transfers()).toHaveLength(0)
    expect(await row(call.id)).toMatchObject({ state: 'done', outcome: 'not_applied' })
  })
  test('a pocket that does not show the old entry stops the re-placement; the call stays open', async () => {
    const { call } = await lostCall()
    for (const url of R) h.pool.relay(url).stored = []
    await h.wallet.settle()
    expect(transfers()).toHaveLength(0)
    expect((await row(call.id))?.state).not.toBe('done')
  })
})

describe('importing a connection-key bill', () => {
  test('held bound to its key and IA; receiving it again with the attestation makes it spendable', async () => {
    const iaKey = fill(0x51, 32)
    const ia = getPublicKey(iaKey)
    const user = '80351110224678912'
    const key = connectionKeyFromAttested('discord', user)
    const w = h.bank.mintToConnectionKey(5000n, key, ia)
    const tok = decodeToken(w.token)
    await writeEntry(ctxOf(h.wallet), { w: tok.walletPubkey, state: 'live', cash: w.token, identity: { type: 'connection_key', value: key, ia }, amountMillis: 5000n, chain: 'flokicoin' })
    const rep = await h.wallet.pocket.sync()
    expect(rep.imported).toHaveLength(1)
    const held = (await h.storage.tx('r', (t) => t.get('holdings', rep.imported[0]!)))!
    expect(held).toMatchObject({ mode: 'connection_key', connectionKey: { key, iaPubkey: ia } })
    const att = finalizeEvent(
      {
        kind: 35522,
        created_at: 1_700_000_000,
        tags: [['d', toHex(sha256(new TextEncoder().encode(`discord:${user}`)))], ['p', h.me], ['platform', 'discord'], ['evidence', JSON.stringify({ version: 1, auth_type: 'oauth', user_id: user, username: 'alice' })], ['expiration', '4000000000']],
        content: '',
      },
      iaKey,
    )
    expect(await h.wallet.receive(w.token, { attestation: att })).toMatchObject({ received: true, holding: { id: held.id, mode: 'connection_key' } })
    expect((await h.wallet.send({ to: BOB, holdings: [held.id] })).sent).toBe(5000n)
  })
})

describe('NIP-40 on wraps', () => {
  test('off by default; on, a bill with an expiry gets an expiration a week-rounded grace past it', async () => {
    const expiresAt = Math.floor(Date.now() / 1000) + 86400
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me, { expiresAt }).token)
    await h.wallet.pocket.sync()
    expect(wraps().some((w) => w.tags.some((t) => t[0] === 'expiration'))).toBe(false)
    await h.wallet.settings.update({ pocketNip40: true })
    await h.wallet.receive(h.bank.mintToPubkey(6000n, h.me, { expiresAt }).token)
    await h.wallet.pocket.sync()
    const exp = wraps().flatMap((w) => w.tags.filter((t) => t[0] === 'expiration').map((t) => Number(t[1])))
    expect(exp.length).toBeGreaterThan(0)
    for (const x of exp) {
      expect(x).toBeGreaterThanOrEqual(expiresAt + 2_592_000)
      expect(x - Math.ceil((expiresAt + 2_592_000) / 604800) * 604800).toBeLessThan(7 * 86400)
    }
  })
  test('never on an entry without expires_at', async () => {
    await h.wallet.settings.update({ pocketNip40: true })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    await h.wallet.pocket.sync()
    expect(wraps().some((w) => w.tags.some((t) => t[0] === 'expiration'))).toBe(false)
  })
})

describe('removing final entries after 30 days', () => {
  const base = { amountMillis: 1n, chain: 'flokicoin' }
  test('a final entry checked over 30 days ago is deleted; a newer one and a live one stay', async () => {
    const ctx = ctxOf(h.wallet)
    const identity = { type: 'pubkey' as const, value: h.me }
    await writeEntry(ctx, { ...base, w: 'a1'.repeat(32), state: 'spent', cash: 'x', identity, checkedAt: oldCheck() })
    await writeEntry(ctx, { ...base, w: 'a2'.repeat(32), state: 'spent', cash: 'x', identity })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const rep = await h.wallet.pocket.sync()
    expect(rep.pruned).toEqual(['a1'.repeat(32)])
    const ws = (await h.wallet.pocket.entries()).map((e) => e.w)
    expect(ws).not.toContain('a1'.repeat(32))
    expect(ws).toContain('a2'.repeat(32))
    expect(h.pool.published.some((p) => p.event.kind === 5)).toBe(true)
  })
  test('a done entry with a notify this device cannot place, and an unscrubbed withdrawal, are kept', async () => {
    const ctx = ctxOf(h.wallet)
    const done = { ...base, state: 'done' as const, checkedAt: oldCheck(), deadline: 1, target: 'cd'.repeat(32), device: 'ef'.repeat(16) }
    await writeEntry(ctx, { ...done, w: 'b1'.repeat(16), requestId: 'b1'.repeat(16), notify: 'ab'.repeat(32), orderKey: '12'.repeat(32) })
    await writeEntry(ctx, { ...done, w: 'b2'.repeat(16), requestId: 'b2'.repeat(16), notify: 'ab'.repeat(32), address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', quote: '{}' })
    await writeEntry(ctx, { ...done, w: 'b3'.repeat(16), requestId: 'b3'.repeat(16) })
    const rep = await h.wallet.pocket.sync()
    expect(rep.pruned).toEqual(['b3'.repeat(16)])
  })
  test("the source of a call another device placed and has not closed is kept, its secret included", async () => {
    const ctx = ctxOf(h.wallet)
    const identity = { type: 'cash' as const }
    await writeEntry(ctx, { ...base, w: 'c1'.repeat(32), state: 'spent', cash: 'x', identity, secrets: [{ secret: '5e'.repeat(32), role: '' }], checkedAt: oldCheck() })
    await writeEntry(ctx, { ...base, w: 'c2'.repeat(32), state: 'spent', cash: 'x', identity, checkedAt: oldCheck() })
    await writeEntry(ctx, { ...base, w: 'c3'.repeat(16), requestId: 'c3'.repeat(16), state: 'pending', deadline: 1, target: 'c1'.repeat(32), device: '0f'.repeat(16) })
    const rep = await h.wallet.pocket.sync()
    expect(rep.pruned).toEqual(['c2'.repeat(32)])
    expect((await h.wallet.pocket.entries()).map((e) => e.w)).toContain('c1'.repeat(32))
  })
})

describe('a missing expires_at filled from cash_status', () => {
  test('rewritten once the bill shows an expiry; a bill with none is asked once', async () => {
    const w = h.bank.mintToPubkey(5000n, h.me)
    await h.wallet.receive(w.token)
    await h.wallet.pocket.sync()
    const statuses = () => h.bank.hub.requests.filter((r) => r.item.method === 'cash_status').length
    // A bill without an expiry: looked up once, then remembered.
    const first = await h.wallet.pocket.sync()
    expect(first.expiryFilled).toEqual([])
    const n = statuses()
    await h.wallet.pocket.sync()
    expect(statuses()).toBe(n)
    // Another bill whose expiry this wallet has not read yet.
    const v = h.bank.mintToPubkey(3000n, h.me)
    await h.wallet.receive(v.token)
    await h.wallet.pocket.sync()
    v.expiresAt = Math.floor(clock() / 1000) + 86400
    const rep = await h.wallet.pocket.sync()
    expect(rep.expiryFilled).toEqual([v.walletPubkey])
  })
})

const authTemplate = (relay: string): EventTemplate => ({ kind: 22242, created_at: 1, tags: [['relay', relay], ['challenge', 'c']], content: '' })

describe('the sync-pocket adapter: relays and AUTH', () => {
  const user = 'aa'.repeat(32)
  test('the newest 10050 first, else NIP-65 write relays, else nothing', () => {
    const pk = list(10050, []).pubkey
    expect(pocketRelaysFrom([list(10050, [['relay', 'wss://old.test']], 1), list(10050, [['relay', 'wss://dm.test']], 2), list(10002, [['r', 'wss://w.test']])], pk)).toEqual(['wss://dm.test'])
    expect(pocketRelaysFrom([list(10002, [['r', 'wss://both.test'], ['r', 'wss://read.test', 'read'], ['r', 'wss://write.test', 'write']])], pk)).toEqual(['wss://both.test', 'wss://write.test'])
    expect(pocketRelaysFrom([list(10002, [['r', 'wss://x.test']])], user)).toEqual([])
  })
  test('a forged or tampered list is ignored: a relay cannot redirect the pocket', async () => {
    const real = list(10050, [['relay', 'wss://dm.test']], 1)
    const pk = real.pubkey
    const forged: NostrEvent = { ...signedByOther(10050, [['relay', 'wss://evil.test']], 9), pubkey: pk }
    const tampered: NostrEvent = { ...real, created_at: 10, tags: [['relay', 'wss://evil.test']] }
    expect(pocketRelaysFrom([real, forged, tampered], pk)).toEqual(['wss://dm.test'])
    const outbox: NostrEvent = { ...signedByOther(10002, [['r', 'wss://evil.test']], 5), pubkey: pk }
    expect(pocketRelaysFrom([outbox], pk)).toEqual([])
    const pool = new MemoryRelayPool()
    await pool.publish('wss://index.test', { ...list(10050, [['relay', 'wss://evil.test']], 9), pubkey: user })
    const pocket = syncPocket({ pool, relays: ['wss://fallback.test'], discovery: ['wss://index.test'], readTimeoutMs: 200 })
    const wrap = finalizeEvent({ kind: 1059, created_at: 1, tags: [['p', user]], content: 'x' }, fill(0x42, 32))
    expect(await pocket.publish(wrap)).toEqual(['wss://fallback.test'])
  })
  test('wraps go to the discovered relays plus the user’s own; configured relays only when nothing is listed', async () => {
    const pool = new MemoryRelayPool()
    const lists = list(10050, [['relay', 'wss://dm1.test'], ['relay', 'wss://dm2.test']])
    await pool.publish('wss://index.test', lists)
    const pocket = syncPocket({ pool, relays: ['wss://fallback.test'], discovery: ['wss://index.test'], ownRelays: ['wss://mine.test'], readTimeoutMs: 200 })
    const wrap = finalizeEvent({ kind: 1059, created_at: 1, tags: [['p', lists.pubkey]], content: 'x' }, fill(0x42, 32))
    expect(new Set(await pocket.publish(wrap))).toEqual(new Set(['wss://dm1.test', 'wss://dm2.test', 'wss://mine.test']))
    expect(pocket.minRelays).toBe(2)
    const other = syncPocket({ pool, relays: ['wss://fallback.test'], discovery: ['wss://index.test'], readTimeoutMs: 200 })
    const wrap2 = finalizeEvent({ kind: 1059, created_at: 1, tags: [['p', user]], content: 'x' }, fill(0x42, 32))
    expect(await other.publish(wrap2)).toEqual(['wss://fallback.test'])
  })
  test('auth is handed to the pocket\'s own isolated pool, for the pocket relays only; never to the shared pool', async () => {
    const got: ((t: EventTemplate) => Promise<NostrEvent>)[] = []
    const shared: ((t: EventTemplate) => Promise<NostrEvent>)[] = []
    const own = Object.assign(new MemoryRelayPool(), { setAuth: (s: (t: EventTemplate) => Promise<NostrEvent>) => got.push(s) })
    const pool = Object.assign(new MemoryRelayPool(), { setAuth: (s: (t: EventTemplate) => Promise<NostrEvent>) => shared.push(s), isolated: () => own })
    syncPocket({ pool, relays: R, ownRelays: ['wss://mine.test/'], auth: signAuth })
    expect(shared).toHaveLength(0)
    expect(got).toHaveLength(1)
    expect((await got[0]!(authTemplate('wss://inbox1.test'))).kind).toBe(22242)
    expect((await got[0]!(authTemplate('wss://mine.test'))).kind).toBe(22242)
    await expect(got[0]!(authTemplate('wss://hub-inbox.test'))).rejects.toThrow()
    await expect(got[0]!({ kind: 22242, created_at: 1, tags: [['challenge', 'c']], content: '' })).rejects.toThrow()
  })
})

/** A WebSocket to a relay that requires NIP-42 AUTH before serving a REQ or accepting an EVENT. */
class AuthRelaySocket implements WebSocketLike {
  readyState = 0
  readonly sent: unknown[][] = []
  authed = false
  private readonly listeners = new Map<string, ((ev?: { data: unknown }) => void)[]>()
  /** With `requireAuth` false, the relay challenges on connect but serves everyone. */
  constructor(
    readonly url: string,
    readonly requireAuth = true,
  ) {
    queueMicrotask(() => {
      this.readyState = 1
      this.emit('open')
      this.reply(['AUTH', 'challenge-1'])
    })
  }
  addEventListener(type: 'open' | 'close' | 'error', listener: () => void): void
  addEventListener(type: 'message', listener: (ev: { data: unknown }) => void): void
  addEventListener(type: string, l: (ev: { data: unknown }) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), l as (ev?: { data: unknown }) => void])
  }
  private emit(type: string, ev?: { data: unknown }) {
    for (const l of this.listeners.get(type) ?? []) l(ev)
  }
  private reply(msg: unknown[]) {
    queueMicrotask(() => this.emit('message', { data: JSON.stringify(msg) }))
  }
  send(data: string): void {
    const msg = JSON.parse(data) as unknown[]
    this.sent.push(msg)
    const [type, a] = msg
    if (type === 'AUTH') {
      const ev = a as NostrEvent
      this.authed = ev.kind === 22242 && ev.tags.some((t) => t[0] === 'challenge' && t[1] === 'challenge-1') && ev.tags.some((t) => t[0] === 'relay' && t[1] === this.url)
      this.reply(['OK', ev.id, this.authed, ''])
    } else if (type === 'REQ') {
      if (!this.authed && this.requireAuth) this.reply(['CLOSED', a, 'auth-required: this relay serves gift wraps only to their recipient'])
      else this.reply(['EOSE', a])
    } else if (type === 'EVENT') {
      const ev = a as NostrEvent
      const ok = this.authed || !this.requireAuth
      this.reply(['OK', ev.id, ok, ok ? '' : 'auth-required: sign in first'])
    }
  }
  close(): void {
    this.readyState = 3
  }
}

describe('NIP-42 AUTH in the relay adapters', () => {
  const sk = AUTH_SK
  const sign = signAuth
  test('relay-ws answers the challenge, then sends the refused REQ and EVENT once more', async () => {
    const sockets: AuthRelaySocket[] = []
    const pool = new RelayWs({ connect: (url) => (sockets.push(new AuthRelaySocket(url)), sockets.at(-1)!) })
    pool.setAuth(sign)
    const eose = new Promise<string>((res, rej) => pool.subscribe(['wss://auth.test'], { kinds: [1059] }, { onEvent: () => {}, onEose: res, onClose: (_r, why) => rej(new Error(why)) }))
    expect(await eose).toBe('wss://auth.test')
    const ev = finalizeEvent({ kind: 1, created_at: 1, tags: [], content: 'x' }, sk)
    expect(await pool.publish('wss://auth.test', ev)).toMatchObject({ ok: true })
    expect(sockets[0]!.sent.filter((m) => m[0] === 'AUTH')).toHaveLength(1)
  })
  test('relay-ws never answers a challenge alone: a relay that does not refuse learns no identity', async () => {
    const sockets: AuthRelaySocket[] = []
    const pool = new RelayWs({ connect: (url) => (sockets.push(new AuthRelaySocket(url, false)), sockets.at(-1)!) })
    pool.setAuth(sign)
    const eose = new Promise<string>((res, rej) => pool.subscribe(['wss://open.test'], { kinds: [1059] }, { onEvent: () => {}, onEose: res, onClose: (_r, why) => rej(new Error(why)) }))
    expect(await eose).toBe('wss://open.test')
    expect(await pool.publish('wss://open.test', finalizeEvent({ kind: 1, created_at: 1, tags: [], content: 'x' }, sk))).toMatchObject({ ok: true })
    expect(sockets[0]!.sent.filter((m) => m[0] === 'AUTH')).toHaveLength(0)
  })
  test('with a pocket on the pool, only a pocket relay is signed in to; another relay that refuses keeps its refusal', async () => {
    const sockets = new Map<string, AuthRelaySocket>()
    const pool = new RelayWs({ connect: (url) => (sockets.set(url, new AuthRelaySocket(url)), sockets.get(url)!) })
    const pocket = syncPocket({ pool, relays: ['wss://pocket.test'], auth: sign, minRelays: 1, readTimeoutMs: 500 })
    const wrap = finalizeEvent({ kind: 1059, created_at: 1, tags: [['p', 'bb'.repeat(32)]], content: 'x' }, sk)
    expect(await pocket.publish(wrap)).toEqual(['wss://pocket.test'])
    expect(sockets.get('wss://pocket.test')!.sent.filter((m) => m[0] === 'AUTH')).toHaveLength(1)
    // A Hub inbox (or listing, order, zap relay) on the same pool.
    const ev = finalizeEvent({ kind: 1, created_at: 1, tags: [], content: 'x' }, sk)
    expect(await pool.publish('wss://hub-inbox.test', ev)).toMatchObject({ ok: false, message: 'auth-required: sign in first' })
    const closed = new Promise<string>((res) => pool.subscribe(['wss://hub-inbox.test'], { kinds: [23195] }, { onEvent: () => {}, onEose: () => res('eose'), onClose: (_r, why) => res(why) }))
    expect(await closed).toMatch(/^auth-required:/)
    expect(sockets.get('wss://hub-inbox.test')!.sent.filter((m) => m[0] === 'AUTH')).toHaveLength(0)
  })
  test('the pocket signs in on sockets of its own: a Hub read of the same relay URL rides an unauthenticated one (R2-K5)', async () => {
    const sockets: AuthRelaySocket[] = []
    // A relay that is both the user's pocket relay and a Hub inbox; the pocket's socket is signed in.
    const strict = new RelayWs({ connect: (url) => (sockets.push(new AuthRelaySocket(url)), sockets.at(-1)!) })
    const viaStrict = syncPocket({ pool: strict, relays: ['wss://both.test'], auth: sign, minRelays: 1, readTimeoutMs: 500 })
    const wrap = finalizeEvent({ kind: 1059, created_at: 1, tags: [['p', 'bb'.repeat(32)]], content: 'x' }, sk)
    expect(await viaStrict.publish(wrap)).toEqual(['wss://both.test'])
    const pocketSocket = sockets.find((x) => x.authed)!
    expect(pocketSocket).toBeDefined()
    // The shared pool's own traffic opens another socket, which never authenticates.
    const eose = new Promise<string>((res) => strict.subscribe(['wss://both.test'], { kinds: [23195] }, { onEvent: () => {}, onEose: () => res('eose'), onClose: (_r, why) => res(why) }))
    expect(await eose).toMatch(/^auth-required:/)
    const hubSockets = sockets.filter((x) => x !== pocketSocket && x.sent.some((m) => m[0] === 'REQ' && JSON.stringify(m[2]).includes('23195')))
    expect(hubSockets).toHaveLength(1)
    expect(hubSockets[0]!.sent.filter((m) => m[0] === 'AUTH')).toHaveLength(0)
    expect(pocketSocket.sent.some((m) => m[0] === 'REQ' && JSON.stringify(m[2]).includes('23195'))).toBe(false)
  })
  test('a pool that cannot be isolated does not authenticate the pocket at all', async () => {
    const shared: unknown[] = []
    const pool = Object.assign(new MemoryRelayPool(), { setAuth: (s: unknown) => shared.push(s) })
    syncPocket({ pool, relays: R, auth: signAuth })
    expect(shared).toHaveLength(0)
  })
  test('nostr-tools isolates only with newPool', () => {
    const fake: SimplePoolLike = { subscribe: () => ({ close() {} }), publish: () => [Promise.resolve('')] }
    expect(new NostrToolsPool(fake).isolated).toBeUndefined()
    const made: SimplePoolLike[] = []
    const p = new NostrToolsPool(fake, { newPool: () => (made.push({ ...fake }), made.at(-1)!) })
    expect(p.isolated!()).toBeInstanceOf(NostrToolsPool)
    expect(made).toHaveLength(1)
  })
  test('relay-ws without a signer passes the refusal on', async () => {
    const pool = new RelayWs({ connect: (url) => new AuthRelaySocket(url) })
    const closed = new Promise<string>((res) => pool.subscribe(['wss://auth.test'], { kinds: [1059] }, { onEvent: () => {}, onEose: () => res('eose'), onClose: (_r, why) => res(why) }))
    expect(await closed).toMatch(/^auth-required:/)
    const ev = finalizeEvent({ kind: 1, created_at: 1, tags: [], content: 'x' }, sk)
    expect(await pool.publish('wss://auth.test', ev)).toMatchObject({ ok: false, message: 'auth-required: sign in first' })
  })
  test('nostr-tools gets onauth on subscribe and publish once setAuth is called', async () => {
    const seen: { sub?: unknown; pub?: unknown } = {}
    const fake: SimplePoolLike = {
      subscribe: (_r, _f, params) => ((seen.sub = params.onauth), { close() {} }),
      publish: (_r, _e, params) => ((seen.pub = params?.onauth), [Promise.resolve('')]),
    }
    const pool = new NostrToolsPool(fake)
    pool.setAuth(sign)
    pool.subscribe(['wss://a.test'], {}, { onEvent: () => {}, onEose: () => {} })
    await pool.publish('wss://a.test', finalizeEvent({ kind: 1, created_at: 1, tags: [], content: '' }, sk))
    expect(typeof seen.sub).toBe('function')
    expect(typeof seen.pub).toBe('function')
    const auth = await (seen.sub as (t: EventTemplate) => Promise<NostrEvent>)({ kind: 22242, created_at: 1, tags: [['challenge', 'c']], content: '' })
    expect(auth.kind).toBe(22242)
  })
})
