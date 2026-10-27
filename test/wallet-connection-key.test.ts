// Bills bound to a NIP-IC connection key: received with the account's
// attestation and spent with claim proofs naming it. A spec Hub answers the
// holder's cash_status NOT_FOUND (NIP-CASH §Scoping the Roster, SG-1 (a)),
// which reads as "status not readable"; a Hub that serves `scope: all` to
// the holder (SG-1 (b)/(c)) is read the same way as any other roster.
import { sha256 } from '@noble/hashes/sha2.js'
import { beforeEach, describe, expect, test } from 'vitest'
import { CashClient, ClientError, statusUnreadable, WalletError } from '../src/client/index.js'
import { bySigning, bySigningConnectionKey, connectionKeyFromAttested, finalizeEvent, getPublicKey, localSigner, parseAttestation, toHex, type NostrEvent } from '../src/core/index.js'
import type { CashkitError } from '../src/wallet/index.js'
import { fill } from './helpers.js'
import { FakeWithdraw, PAYTO } from './fakeWithdraw.js'
import { FakeNwcWallet, harness, type Harness } from './walletHarness.js'

const IA_KEY = fill(0x51, 32)
const IA = getPublicKey(IA_KEY)
const USER = '80351110224678912'
const KEY = connectionKeyFromAttested('discord', USER)
const FAR = 4_000_000_000

function attestation(p: string, o: { userId?: string; d?: string; expiration?: number | null; key?: Uint8Array } = {}): NostrEvent {
  const userId = o.userId ?? USER
  const tags = [
    ['d', o.d ?? toHex(sha256(new TextEncoder().encode(`discord:${userId}`)))],
    ['p', p],
    ['platform', 'discord'],
    ['evidence', JSON.stringify({ version: 1, auth_type: 'oauth', user_id: userId, username: 'alice' })],
    ...(o.expiration === null ? [] : [['expiration', String(o.expiration ?? FAR)]]),
  ]
  return finalizeEvent({ kind: 35522, created_at: 1_700_000_000, tags, content: '' }, o.key ?? IA_KEY)
}

const err = (p: Promise<unknown>) => p.then(() => undefined, (e: unknown) => e as CashkitError)

let h: Harness
beforeEach(async () => {
  h = await harness()
})

async function receiveCk(amount: bigint) {
  const w = h.bank.mintToConnectionKey(amount, KEY, IA)
  const r = await h.wallet.receive(w.token, { attestation: attestation(h.me) })
  if (!r.received) throw new Error('not received')
  return { w, holding: r.holding }
}

describe('connection-key slices, on a Hub that serves scope all to the holder', () => {
  beforeEach(() => {
    h.bank.ckStatusAll = true
  })
  test('received with the attestation: held in connection-key mode, its amount read with scope all', async () => {
    const { holding } = await receiveCk(5000n)
    expect(holding).toMatchObject({ status: 'held', mode: 'connection_key', amount: 5000n, verified: true })
    const row = (await h.storage.tx('r', (t) => t.get('holdings', holding.id)))!
    expect(row.connectionKey).toMatchObject({ platform: 'discord', externalId: USER, iaPubkey: IA, key: KEY })
    expect(JSON.parse(row.connectionKey!.attestation!).kind).toBe(35522)
    expect((await h.wallet.status({ holdings: [holding.id] })).outcomes[0]).toMatchObject({ ok: true, state: 'available', amount: 5000n })
  })
  test('without the attestation the Hub has no slice for the wallet', async () => {
    const w = h.bank.mintToConnectionKey(5000n, KEY, IA)
    expect(await err(h.wallet.receive(w.token))).toMatchObject({ code: 'invalid_input' })
  })
  test.each([
    ['naming another pubkey', () => attestation(getPublicKey(fill(0x77, 32)))],
    ['without an expiration', () => attestation(h.me, { expiration: null })],
    ['expired', () => attestation(h.me, { expiration: 1 })],
    ['whose d is not the hash of its user id', () => attestation(h.me, { d: 'ab'.repeat(32) })],
    ['with a non-canonical user id', () => attestation(h.me, { userId: `0${USER}` })],
  ])('an attestation %s is refused before anything is sent', async (_, make) => {
    const w = h.bank.mintToConnectionKey(5000n, KEY, IA)
    expect(await err(h.wallet.receive(w.token, { attestation: make() }))).toMatchObject({ code: 'auth', reason: 'attestation_invalid' })
  })
  test("an attestation for another account finds no slice", async () => {
    const w = h.bank.mintToConnectionKey(5000n, KEY, IA)
    const other = attestation(h.me, { userId: '80351110224678913' })
    expect(await err(h.wallet.receive(w.token, { attestation: other }))).toMatchObject({ code: 'invalid_input' })
  })
  test('a split send: the claim names the attestation, and the remainder stays bound to the same account', async () => {
    const { holding } = await receiveCk(5000n)
    const bob = getPublicKey(fill(0x66, 32))
    const r = await h.wallet.send({ amount: 2000n, to: bob, holdings: [holding.id] })
    expect(r.sent).toBe(2000n)
    expect(h.bank.ckClaims).toBe(1)
    expect(h.bank.balanceOf(bob)).toBe(2000n)
    expect(h.bank.balanceOf(KEY)).toBe(3000n)
    const rem = (await h.storage.tx('r', (t) => t.get('holdings', r.remainder!.id)))!
    expect(rem).toMatchObject({ mode: 'connection_key', status: 'held', amount: 3000n })
    expect(rem.connectionKey?.key).toBe(KEY)
    // The remainder is spendable with the same attestation.
    const all = await h.wallet.send({ to: bob, holdings: [rem.id] })
    expect(all.sent).toBe(3000n)
    expect(h.bank.balanceOf(bob)).toBe(5000n)
  })
  test('redeemed into a connection over Lightning', async () => {
    const nwc = new FakeNwcWallet(h.pool)
    await h.wallet.connections.add('main', nwc.uri)
    const { holding } = await receiveCk(5000n)
    const r = await h.wallet.redeem({ all: true })
    expect(r.firstError).toBeUndefined()
    expect(r.outcomes[0]).toMatchObject({ ok: true, holdingId: holding.id })
    expect(h.bank.redeemed).toHaveLength(1)
  })
  test('withdrawn on-chain: the quote names the key and its IA; a cancelled payout comes back bound to the same account', async () => {
    const hub = new FakeWithdraw(h.bank)
    const { holding } = await receiveCk(21_000_000n)
    const q = await h.wallet.withdraw.quote(holding.id, PAYTO)
    expect(q).toMatchObject({ amountMillis: 21_000_000n, unrecoverable: false })
    const v = await h.wallet.withdraw.send(q, { confirm: () => Promise.resolve(true) })
    expect(v).toMatchObject({ phase: 'accepted', state: 'queued' })
    hub.cancel(hub.only())
    const after = await h.wallet.withdraw.refresh(v.id)
    expect(after.phase).toBe('cancelled')
    const row = (await h.storage.tx('r', (x) => x.get('holdings', after.remintHoldingId!)))!
    expect(row).toMatchObject({ mode: 'connection_key', origin: 'reminted', amount: 21_000_000n })
    expect(row.connectionKey?.key).toBe(KEY)
  })
  test('recover: a lost connection-key withdrawal is found and followed, and its re-mint comes back bound to the same account', async () => {
    const hub = new FakeWithdraw(h.bank)
    const { holding } = await receiveCk(21_000_000n)
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(holding.id, PAYTO), { confirm: () => Promise.resolve(true) })
    const lost = (await h.storage.tx('r', (x) => x.get('pendingCalls', v.id)))!
    await h.storage.tx('rw', (x) => x.delete('pendingCalls', v.id))
    const r = await h.wallet.withdraw.recover(holding.id)
    const call = (await h.storage.tx('r', (x) => x.get('pendingCalls', r.id)))!
    expect(call).toMatchObject({ requestId: lost.requestId, params: { recovered: '1' } })
    expect(call.outputs).toEqual([{ role: 'remint', destination: { kind: 'connection_key', key: KEY, platform: 'discord', ia: IA } }])
    hub.cancel(hub.only())
    const after = await h.wallet.withdraw.refresh(r.id)
    expect(after.phase).toBe('cancelled')
    const row = (await h.storage.tx('r', (x) => x.get('holdings', after.remintHoldingId!)))!
    expect(row).toMatchObject({ mode: 'connection_key', origin: 'reminted', amount: 21_000_000n })
  })
  test('a held connection-key bill without its attestation cannot be spent, and says why', async () => {
    const { holding } = await receiveCk(5000n)
    await h.storage.tx('rw', async (t) => {
      const row = (await t.get('holdings', holding.id))!
      const { attestation: _a, ...b } = row.connectionKey!
      await t.put('holdings', { ...row, connectionKey: b, version: row.version + 1 }, row.version)
    })
    expect(await err(h.wallet.send({ to: getPublicKey(fill(0x66, 32)), holdings: [holding.id] }))).toMatchObject({ code: 'usage', reason: 'attestation_missing' })
  })
  test('an expired attestation stops spending; receiving the bill again with a fresh one for the same account restores it', async () => {
    let t = Date.now()
    const c = await harness({ deps: { clock: () => t } })
    c.bank.hub.clock = () => t
    const nowS = () => Math.floor(t / 1000)
    const w = c.bank.mintToConnectionKey(5000n, KEY, IA)
    const r = await c.wallet.receive(w.token, { attestation: attestation(c.me, { expiration: nowS() + 600 }) })
    if (!r.received) throw new Error('not received')
    t += 3600_000
    const bob = getPublicKey(fill(0x66, 32))
    expect(await err(c.wallet.send({ to: bob, holdings: [r.holding.id] }))).toMatchObject({ code: 'auth', reason: 'attestation_invalid' })
    // Another account's or another IA's attestation does not replace it.
    expect(await err(c.wallet.receive(w.token, { attestation: attestation(c.me, { userId: '80351110224678913', expiration: FAR }) }))).toMatchObject({ code: 'auth', reason: 'attestation_invalid' })
    expect(await err(c.wallet.receive(w.token, { attestation: attestation(c.me, { key: fill(0x52, 32) }) }))).toMatchObject({ code: 'auth', reason: 'attestation_invalid' })
    // Without an attestation it is still already held.
    expect(await err(c.wallet.receive(w.token))).toMatchObject({ code: 'conflict' })
    const again = await c.wallet.receive(w.token, { attestation: attestation(c.me) })
    expect(again).toMatchObject({ received: true, holding: { id: r.holding.id, status: 'held', mode: 'connection_key' } })
    expect((await c.wallet.send({ to: bob, holdings: [r.holding.id] })).sent).toBe(5000n)
    expect(c.bank.balanceOf(bob)).toBe(5000n)
  })
})

describe('connection-key slices, on a spec Hub: the status is not readable', () => {
  test('received unverified at the attested amount, and flagged', async () => {
    const w = h.bank.mintToConnectionKey(5000n, KEY, IA)
    const r = await h.wallet.receive(w.token, { attestation: attestation(h.me) })
    expect(r).toMatchObject({ received: true, statusUnreadable: true, secured: { status: 'not_applicable' } })
    if (!r.received) throw new Error('not received')
    expect(r.holding).toMatchObject({ status: 'held', mode: 'connection_key', amount: 5000n, verified: false })
    const row = (await h.storage.tx('r', (t) => t.get('holdings', r.holding.id)))!
    expect(row.connectionKey).toMatchObject({ platform: 'discord', externalId: USER, iaPubkey: IA, key: KEY })
  })
  test('status() reports it unreadable and leaves the holding as it was', async () => {
    const { holding } = await receiveCk(5000n)
    const rep = await h.wallet.status({ holdings: [holding.id] })
    expect(rep.outcomes[0]).toMatchObject({ ok: true, holdingId: holding.id, state: 'unreadable' })
    expect(rep.outcomes[0]).not.toHaveProperty('amount')
    expect((await h.storage.tx('r', (t) => t.get('holdings', holding.id)))!).toMatchObject({ status: 'held', amount: 5000n, verified: false })
  })
  test('the client reads NOT_FOUND for a connection key as unreadable, never as gone or not found', async () => {
    const w = h.bank.mintToConnectionKey(5000n, KEY, IA)
    const signer = localSigner(fill(0x44, 32))
    const att = attestation(signer.pubkey)
    const c = new CashClient({ relays: h.pool, replyWaitMs: 2000 }, w.token)
    const credential = bySigningConnectionKey(signer, 'discord', USER, parseAttestation(att))
    expect((await c.state(credential)).state).toBe('unreadable')
    const e = await c.checkClaim(credential).catch((x: unknown) => x)
    expect(e).toBeInstanceOf(ClientError)
    expect((e as ClientError).code).toBe('status_unreadable')
    // The same answer to a pubkey holder keeps its meaning.
    expect((await c.state(bySigning(signer))).state).toBe('indeterminate')
    expect(statusUnreadable(credential, new WalletError('cash_status', 'NOT_FOUND', ''))).toBe(true)
    expect(statusUnreadable(credential, { code: 'NOT_FOUND' })).toBe(true)
    expect(statusUnreadable(credential, { code: 'RESTRICTED' })).toBe(false)
    expect(statusUnreadable(bySigning(signer), { code: 'NOT_FOUND' })).toBe(false)
  })
  test('a redeem is refused before anything is sent, and the bill stays held', async () => {
    const nwc = new FakeNwcWallet(h.pool)
    await h.wallet.connections.add('main', nwc.uri)
    const { holding } = await receiveCk(5000n)
    const r = await h.wallet.redeem({ holdings: [holding.id] }).catch((x: unknown) => x as CashkitError)
    const e = 'firstError' in (r as object) ? (r as { firstError?: CashkitError }).firstError : (r as CashkitError)
    expect(e).toMatchObject({ code: 'usage', reason: 'status_unreadable', input: holding.id })
    expect(h.bank.redeemed).toHaveLength(0)
    expect(h.bank.ckClaims).toBe(0)
    expect((await h.storage.tx('r', (t) => t.get('holdings', holding.id)))!.status).toBe('held')
  })
  test('withdrawal terms and quotes are refused as unreadable; nothing is quoted', async () => {
    const hub = new FakeWithdraw(h.bank)
    const { holding } = await receiveCk(21_000_000n)
    expect(await err(h.wallet.withdraw.terms(holding.id))).toMatchObject({ code: 'usage', reason: 'status_unreadable' })
    expect(await err(h.wallet.withdraw.quote(holding.id, PAYTO))).toMatchObject({ code: 'usage', reason: 'status_unreadable' })
    expect(hub.payouts.size).toBe(0)
    expect((await h.storage.tx('r', (t) => t.get('holdings', holding.id)))!.status).toBe('held')
  })
  test('sending it whole to the own pubkey gives a bill whose status reads', async () => {
    const { holding } = await receiveCk(5000n)
    const r = await h.wallet.send({ to: h.me, holdings: [holding.id] })
    expect(r.sent).toBe(5000n)
    expect(h.bank.ckClaims).toBe(1)
    expect(h.bank.balanceOf(h.me)).toBe(5000n)
    expect((await h.storage.tx('r', (t) => t.get('holdings', holding.id)))!.status).not.toBe('held')
  })
  test('a split send works from the attested amount; the remainder stays bound to the account', async () => {
    const { holding } = await receiveCk(5000n)
    const bob = getPublicKey(fill(0x66, 32))
    const r = await h.wallet.send({ amount: 2000n, to: bob, holdings: [holding.id] })
    expect(r.sent).toBe(2000n)
    expect(h.bank.balanceOf(bob)).toBe(2000n)
    const rem = (await h.storage.tx('r', (t) => t.get('holdings', r.remainder!.id)))!
    expect(rem).toMatchObject({ mode: 'connection_key', status: 'held', amount: 3000n })
  })
  test('a connection-key bill left redeeming is never settled as redeemed on an unreadable status', async () => {
    const { holding } = await receiveCk(5000n)
    await h.storage.tx('rw', async (t) => {
      const row = (await t.get('holdings', holding.id))!
      await t.put('holdings', { ...row, status: 'redeeming', redeem: { invoice: 'lnbc1', into: 'invoice', invoiceExpiresAt: 1, since: 1 }, version: row.version + 1 }, row.version)
    })
    const rep = await h.wallet.settle()
    expect(rep.redeems).toMatchObject({ stillRedeeming: [holding.id], redeemed: [], released: [], spent: [] })
    expect((await h.storage.tx('r', (t) => t.get('holdings', holding.id)))!.status).toBe('redeeming')
  })
})
