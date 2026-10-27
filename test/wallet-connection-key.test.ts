// Bills bound to a NIP-IC connection key: received with the account's
// attestation, read with scope `all`, and spent with claim proofs naming it.
import { sha256 } from '@noble/hashes/sha2.js'
import { beforeEach, describe, expect, test } from 'vitest'
import { connectionKeyFromAttested, finalizeEvent, getPublicKey, toHex, type NostrEvent } from '../src/core/index.js'
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

describe('connection-key slices', () => {
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
  test('a held connection-key bill without its attestation cannot be spent, and says why', async () => {
    const { holding } = await receiveCk(5000n)
    await h.storage.tx('rw', async (t) => {
      const row = (await t.get('holdings', holding.id))!
      const { attestation: _a, ...b } = row.connectionKey!
      await t.put('holdings', { ...row, connectionKey: b, version: row.version + 1 }, row.version)
    })
    expect(await err(h.wallet.send({ to: getPublicKey(fill(0x66, 32)), holdings: [holding.id] }))).toMatchObject({ code: 'usage', reason: 'attestation_missing' })
  })
})
