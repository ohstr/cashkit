// Cash Zaps (NIP-CZ): identity tags, rule 2, counting, and wallet.zaps end
// to end over a fake Hub that signs zap bills. Cases follow nmilat
// nipCZ/*_test.go.
import { describe, expect, test } from 'vitest'
import {
  checkCashZapTags,
  countCashZaps,
  isTrustedMinter,
  parseCashZapInfo,
  parseIdentityTag,
  verifyCashZap,
} from '../src/core/index.js'
import { CashkitError } from '../src/wallet/index.js'
import { harness, type Harness } from './walletHarness.js'

const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )

const SOCIAL = 'wss://social.test'
const X = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const H = 'ab'.repeat(32)

describe('identity tags and rule 2', () => {
  test('[2] missing, empty or nostr is a pubkey; anything else a ConnectionKey', () => {
    expect(parseIdentityTag(['p', H])).toEqual({ value: H, kind: 'pubkey' })
    expect(parseIdentityTag(['p', H, 'nostr'])).toEqual({ value: H, kind: 'pubkey' })
    expect(parseIdentityTag(['p', H, 'discord'])).toEqual({ value: H, kind: 'connection_key', platform: 'discord' })
  })
  test('the spec’s Minter matches its x-only key, whatever the prefix', () => {
    expect(isTrustedMinter(`02${X}`, 'bitcoin', [{ minter: `03${X}`, chain: 'bitcoin' }])).toBe(true)
    expect(isTrustedMinter(`02${X}`, 'bitcoin', [{ minter: `02${X}`, chain: 'other' }])).toBe(false)
  })
  const base = [['p', H], ['amount', '21000'], ['chain', 'bitcoin'], ['cash', 'x'], ['w', H]]
  test.each([
    ['two p tags', [...base, ['p', H]]],
    ['an uppercase p', base.map((t) => (t[0] === 'p' ? ['p', H.toUpperCase()] : t))],
    ['a leading zero', base.map((t) => (t[0] === 'amount' ? ['amount', '021000'] : t))],
    ['ia on a pubkey p', [...base, ['ia', H]]],
    ['a ConnectionKey p without ia', base.map((t) => (t[0] === 'p' ? ['p', H, 'discord'] : t))],
    ['a P that is a pubkey', [...base, ['P', H]]],
  ])('refuses %s', (_, tags) => {
    expect(() => checkCashZapTags({ tags })).toThrow(expect.objectContaining({ code: 'zap_invalid' }))
  })
  test('a NIP-40 expiration tag is reported, not refused', () => {
    expect(checkCashZapTags({ tags: [...base, ['expiration', '1']] }).hasExpiration).toBe(true)
    expect(checkCashZapTags({ tags: base }).hasExpiration).toBeUndefined()
  })
  test('a 10522: a mint without a chain, or for a chain not accepted, is ignored', () => {
    const info = parseCashZapInfo({ kind: 10522, tags: [['chain', 'bitcoin'], ['mint', `02${X}`, 'bitcoin'], ['mint', `02${X}`, 'other'], ['mint', `02${X}`], ['relay', SOCIAL]] })
    expect(info).toEqual({ chains: ['bitcoin'], mints: [{ minter: `02${X}`, chain: 'bitcoin' }], relays: [SOCIAL] })
  })
})

async function pair(): Promise<{ alice: Harness; bob: Harness }> {
  const alice = await harness()
  const bob = await harness({ pool: alice.pool, bank: alice.bank })
  return { alice, bob }
}
const published = (h: Harness) => h.pool.published.filter((p) => p.event.kind === 9522).map((p) => p.event)

describe('wallet.zaps', () => {
  test('a zap on an event: a zap-signed bill, its 9522 published, rules 1–7 hold; 8 once the minter is trusted', async () => {
    const { alice, bob } = await pair()
    await alice.wallet.receive(alice.bank.mintToPubkey(50_000n, alice.me).token)
    const note = 'cd'.repeat(32)
    const r = await alice.wallet.zaps.send({ to: bob.me, amountMillis: 21_000n, target: { e: note, k: '1' }, content: 'Great post!', relays: [SOCIAL] })
    expect(r).toMatchObject({ countable: true, relays: [SOCIAL] })
    const [ev] = published(alice)
    expect(ev!.id).toBe(r.eventId)
    expect(ev!.tags.find((t) => t[0] === 'e')).toEqual(['e', note])
    expect(ev!.tags.some((t) => t[0] === 'a' || t[0] === 'expiration')).toBe(false)
    const v = verifyCashZap(ev!, { target: { pubkey: bob.me, created_at: 1 } })
    expect(v.rules).toMatchObject({ 1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: false })
    expect(v.countable).toBe(false)
    const trusted = verifyCashZap(ev!, { target: { pubkey: bob.me, created_at: 1 }, trusted: [{ minter: v.minter!, chain: v.tags!.chain }] })
    expect(trusted.countable).toBe(true)
    expect(countCashZaps([{ event: ev!, verdict: trusted }, { event: ev!, verdict: trusted }], { minLife: 0 }).totalMillis).toBe(21_000n)
    expect(countCashZaps([{ event: ev!, verdict: trusted }], { minLife: 0, deletions: new Set([ev!.id]) }).totalMillis).toBe(0n)
  })
  test('rule 9: a slice the Hub shows withdrawn is not claimed', async () => {
    const { alice, bob } = await pair()
    await alice.wallet.receive(alice.bank.mintToPubkey(50_000n, alice.me).token)
    await alice.wallet.zaps.send({ to: bob.me, amountMillis: 21_000n, target: { e: 'cd'.repeat(32) }, relays: [SOCIAL] })
    const [z] = await bob.wallet.zaps.list({ relays: [SOCIAL] })
    await bob.wallet.zaps.approveMinter(z!.minter!, z!.chain!)
    const [ev] = published(alice)
    alice.bank.wallet(ev!.tags.find((t) => t[0] === 'cash')![1]!)!.withdrawRequestId = 'ab'.repeat(32)
    expect(await failure(bob.wallet.zaps.claim(ev!))).toMatchObject({ code: 'invalid_input', reason: 'rule_9', message: expect.stringMatching(/withdrawn/) })
  })
  test('the recipient sees it issued; claims it only once the minter is approved, after rule 9; then spends it', async () => {
    const { alice, bob } = await pair()
    await alice.wallet.receive(alice.bank.mintToPubkey(50_000n, alice.me).token)
    await alice.wallet.zaps.send({ to: bob.me, amountMillis: 21_000n, target: { e: 'cd'.repeat(32) }, relays: [SOCIAL] })
    const [z] = await bob.wallet.zaps.list({ relays: [SOCIAL] })
    expect(z).toMatchObject({ status: 'issued', valid: true, trusted: false, amountMillis: 21_000n })
    const [ev] = published(alice)
    expect(await failure(bob.wallet.zaps.claim(ev!))).toMatchObject({ reason: 'minter_untrusted' })
    expect(await bob.wallet.zaps.approveMinter(z!.minter!, z!.chain!)).toEqual({ networkUnverifiable: true })
    const h = await bob.wallet.zaps.claim(ev!)
    expect(h).toMatchObject({ amount: 21_000n, mode: 'pubkey' })
    const row = (await bob.storage.tx('r', (t) => t.get('holdings', h.id)))!
    expect(row).toMatchObject({ origin: 'zap' })
    expect(row.zap?.recipient).toBe(bob.me)
    expect((await bob.wallet.zaps.list({ relays: [SOCIAL] }))[0]!.status).toBe('claimed')
    // The zap bill is spendable: its provenance comes from its stored zap fields.
    const sent = await bob.wallet.send({ amount: 1_000n, to: alice.me })
    expect(sent.sent).toBe(1_000n)
  })
  test('a profile zap is valid but never counted', async () => {
    const { alice, bob } = await pair()
    await alice.wallet.receive(alice.bank.mintToPubkey(50_000n, alice.me).token)
    const r = await alice.wallet.zaps.send({ to: bob.me, amountMillis: 1_000n, relays: [SOCIAL] })
    expect(r).toMatchObject({ countable: false, reason: 'no_target' })
  })
  test('a lost reply: the 9522 is published only once the lookup finds the bill', async () => {
    const { alice, bob } = await pair()
    await alice.wallet.receive(alice.bank.mintToPubkey(50_000n, alice.me).token)
    alice.bank.loseReplyFor.add('cash_transfer')
    expect((await failure(alice.wallet.zaps.send({ to: bob.me, amountMillis: 2_000n, target: { e: 'cd'.repeat(32) }, relays: [SOCIAL] }))).code).toBe('indeterminate')
    expect(published(alice)).toHaveLength(0)
    alice.bank.loseReplyFor.clear()
    await alice.wallet.settle()
    expect(published(alice)).toHaveLength(1)
    await alice.wallet.settle()
    expect(published(alice)).toHaveLength(1)
  })
  test('no pubkey bill covers the amount', async () => {
    const { alice, bob } = await pair()
    expect(await failure(alice.wallet.zaps.send({ to: bob.me, amountMillis: 1n, relays: [SOCIAL] }))).toMatchObject({ reason: 'no_zap_bill' })
  })
})
