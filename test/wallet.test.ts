// The wallet engine, one §6 operation at a time, against FakeBank. Cases
// port cashctl cmd/*_test.go where they cover the same behaviour (named in
// comments).
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { decodeToken, getPublicKey, newCashTarget, nip44, nip49Decrypt, toHex } from '../src/core/index.js'
import { CashkitError, toJSON, type OperationEvent, type WalletState } from '../src/wallet/index.js'
import { commitment, FakeBank } from './fakeBank.js'
import { FakeNwcWallet, harness, NWC_RELAY, type Harness } from './walletHarness.js'
import { FakeHub } from './fakeHub.js'
import { invoice } from './helpers.js'
import { CashClient, ClientError } from '../src/client/index.js'

let h: Harness
beforeEach(async () => {
  h = await harness()
})

const err = (p: Promise<unknown>) => p.then(() => undefined, (e: unknown) => e as CashkitError)

async function receivePubkey(amount: bigint, x: Harness = h) {
  const w = x.bank.mintToPubkey(amount, x.me)
  const r = await x.wallet.receive(w.token)
  if (!r.received) throw new Error('not received')
  return { w, holding: r.holding }
}

async function receiveCash(amount: bigint, o: { protect?: boolean } = {}, x: Harness = h) {
  const t = newCashTarget()
  const w = x.bank.mintToCash(amount, t.secret)
  const r = await x.wallet.receive(`${w.token}#${t.secret}`, o)
  if (!r.received) throw new Error('not received')
  return { w, t, r, holding: r.holding }
}

describe('receive (cmd/cash_receive.go)', () => {
  test('a pubkey bill is checked with its Hub and committed', async () => {
    const { holding } = await receivePubkey(5000n)
    expect(holding).toMatchObject({ status: 'held', mode: 'pubkey', protection: 'none', amount: 5000n, verified: true })
    const acts = await h.wallet.activity()
    expect(acts[0]).toMatchObject({ type: 'activity', action: 'receive', amount: 5000n, holdingId: holding.id })
  })
  test('a cash note is protected by a rekey to a fresh secret (receive_secure.go)', async () => {
    const { w, t, r } = await receiveCash(700n)
    expect(r.received && r.secured).toEqual({ status: 'rekeyed' })
    expect(r.received && r.holding).toMatchObject({ mode: 'cash', protection: 'protected' })
    expect(w.identity.value).not.toBe(commitment(t.secret))
    const exported = await h.wallet.exportHolding(r.received ? r.holding.id : '')
    expect(w.identity.value).toBe(commitment(exported.split('#')[1]!))
  })
  test('protect declined leaves it shared (TestProtectCashReceipt_Declined)', async () => {
    const { r } = await receiveCash(700n, { protect: false })
    expect(r.received && r.secured).toEqual({ status: 'declined' })
    expect(r.received && r.holding.protection).toBe('shared')
  })
  test('settings.autoProtect=false declines by default', async () => {
    await h.wallet.settings.update({ autoProtect: false })
    const { r } = await receiveCash(700n)
    expect(r.received && r.secured.status).toBe('declined')
  })
  test('a non-cash receipt is not_applicable (TestProtectCashReceipt_NonCash_NotApplicable)', async () => {
    const w = h.bank.mintToPubkey(5n, h.me)
    const r = await h.wallet.receive(w.token)
    expect(r.received && r.secured).toEqual({ status: 'not_applicable' })
  })
  test('a cash token without its secret is a read-only report (TestRunCashReceive_NoEmbeddedSecret_JSONMode)', async () => {
    const w = h.bank.mintToCash(700n, newCashTarget().secret)
    const r = await h.wallet.receive(w.token)
    expect(r).toMatchObject({ received: false, reason: 'no_embedded_secret', report: { walletPubkey: w.walletPubkey, identityRequired: false, attestedAmount: 700n } })
    expect(await h.wallet.holdings()).toHaveLength(0)
  })
  test('a token already held is a conflict', async () => {
    const { w } = await receivePubkey(5n)
    expect((await err(h.wallet.receive(w.token)))?.code).toBe('conflict')
  })
  test('a spent bill is spent, and nothing is stored', async () => {
    const w = h.bank.mintToPubkey(5n, h.me)
    w.spent = true
    expect((await err(h.wallet.receive(w.token)))?.code).toBe('spent')
    expect(await h.wallet.holdings({ includeSpent: true })).toHaveLength(0)
  })
  test('a wrong cash secret is invalid_input', async () => {
    const w = h.bank.mintToCash(700n, newCashTarget().secret)
    const e = await err(h.wallet.receive(`${w.token}#${'ab'.repeat(32)}`))
    expect(e?.code).toBe('invalid_input')
  })
  test('a bill naming someone else is invalid_input', async () => {
    const w = h.bank.mintToPubkey(5n, getPublicKey(new Uint8Array(32).fill(9)))
    expect((await err(h.wallet.receive(w.token)))?.code).toBe('invalid_input')
  })
  test('other pasted kinds are refused with a pointer (dial.Sniff routing)', async () => {
    for (const s of [invoice(5n), 'nostr+walletconnect://' + 'ab'.repeat(32) + '?relay=wss://r&secret=' + 'cd'.repeat(32), 'npub1' + 'q'.repeat(58), 'hello']) {
      expect((await err(h.wallet.receive(s)))?.code).toBe('invalid_input')
    }
  })
  test('no identity: a pubkey bill needs one (not_found)', async () => {
    const x = await harness({ identity: false, pool: h.pool, bank: h.bank })
    const w = h.bank.mintToPubkey(5n, h.me)
    expect((await err(x.wallet.receive(w.token)))?.code).toBe('not_found')
  })
})

describe('protect (cmd/wallet_protect.go)', () => {
  test('re-keys every shared cash note when nothing is named', async () => {
    await receiveCash(100n, { protect: false })
    await receiveCash(200n, { protect: false })
    const r = await h.wallet.protect()
    expect(r.outcomes.map((o) => o.ok && o.secured.status)).toEqual(['rekeyed', 'rekeyed'])
    expect((await h.wallet.holdings()).map((x) => x.protection)).toEqual(['protected', 'protected'])
  })
  test('a holding that is not a cash note is not_applicable', async () => {
    const { holding } = await receivePubkey(5n)
    const r = await h.wallet.protect({ holdings: [holding.id] })
    expect(r.outcomes[0]).toMatchObject({ ok: true, secured: { status: 'not_applicable' } })
  })
})

describe('send (cmd/cash_transfer_test.go)', () => {
  test('an amount alone splits a bill into a cash note and keeps the change', async () => {
    const { holding } = await receivePubkey(5000n)
    const r = await h.wallet.send({ amount: 2000n })
    expect(r).toMatchObject({ sent: 2000n, to: 'cash', consolidatedFirst: false, remainder: { amount: 3000n, mode: 'pubkey' } })
    expect(r.cashNote).toMatch(/^lokicash1[0-9a-z]+#[0-9a-f]{64}$/)
    const all = await h.wallet.holdings({ includeSpent: true })
    expect(all.find((x) => x.id === holding.id)?.status).toBe('transferred')
    // The note is real: another wallet receives it.
    const bob = await harness({ pool: h.pool, bank: h.bank })
    const got = await bob.wallet.receive(r.cashNote!)
    expect(got.received && got.holding.amount).toBe(2000n)
  })
  test('the whole bill to a pubkey moves in place; the recipient receives the same token', async () => {
    const bob = await harness({ pool: h.pool, bank: h.bank })
    const { w } = await receivePubkey(5000n)
    const r = await h.wallet.send({ to: bob.me })
    expect(r.recipientToken).toBe(w.token)
    expect(r.cashNote).toBeUndefined()
    expect(r.to).toMatch(/^npub1/)
    const got = await bob.wallet.receive(r.recipientToken!)
    expect(got.received).toBe(true)
  })
  test('a cash-note source keeps its secret on the remainder', async () => {
    await receiveCash(5000n)
    const r = await h.wallet.send({ amount: 1000n })
    expect(r.remainder).toMatchObject({ mode: 'cash', protection: 'protected', amount: 4000n })
    expect((await h.wallet.status({ holdings: [r.remainder!.id] })).outcomes[0]).toMatchObject({ ok: true, state: 'available', amount: 4000n })
  })
  test('auto-consolidates same-hub pubkey bills, then splits (transferWithAutoConsolidate)', async () => {
    const bob = await harness({ pool: h.pool, bank: h.bank })
    await receivePubkey(3000n)
    await receivePubkey(3000n)
    const plan = await h.wallet.planSend({ amount: 5000n, to: bob.me })
    expect(plan).toMatchObject({ consolidateFirst: true, split: true, amount: 5000n })
    const r = await h.wallet.executeSend(plan)
    expect(r).toMatchObject({ consolidatedFirst: true, sent: 5000n, remainder: { amount: 1000n } })
    expect(h.bank.balanceOf(bob.me)).toBe(5000n)
    expect(h.bank.balanceOf(h.me)).toBe(1000n)
  })
  test('auto-consolidates a cash note through a throwaway key, and the change returns to a cash note (mergeThenSend)', async () => {
    await receiveCash(3000n)
    await receivePubkey(3000n)
    const r = await h.wallet.send({ amount: 5000n })
    expect(r.consolidatedFirst).toBe(true)
    expect(r.remainder).toMatchObject({ amount: 1000n, mode: 'cash', protection: 'protected', midMerge: false })
    const held = await h.wallet.holdings()
    expect(held).toHaveLength(1)
    expect(h.wallet.state.pendingMerge).toBe(0)
  })
  test('an exact consolidated sum goes straight to the target', async () => {
    await receivePubkey(2000n)
    await receivePubkey(3000n)
    const r = await h.wallet.send({ amount: 5000n })
    expect(r.remainder).toBeUndefined()
    const bob = await harness({ pool: h.pool, bank: h.bank })
    expect((await bob.wallet.receive(r.cashNote!)).received).toBe(true)
  })
  test('not enough funds is invalid_input; fragmentation across hubs is usage', async () => {
    await receivePubkey(3000n)
    expect((await err(h.wallet.send({ amount: 9000n })))?.code).toBe('invalid_input')
    const bank2 = new FakeBank(h.pool, ['wss://bank2.test'], { seed: 0x20 })
    await bank2.start()
    await h.wallet.receive(bank2.mintToPubkey(3000n, h.me).token)
    const e = await err(h.wallet.send({ amount: 5000n }))
    expect(e?.code).toBe('usage')
    expect(e?.message).toMatch(/fragmented/)
  })
  test('auto-consolidation off refuses a plan that needs it', async () => {
    await receivePubkey(3000n)
    await receivePubkey(3000n)
    await h.wallet.settings.update({ allowAutoConsolidate: false })
    expect((await err(h.wallet.send({ amount: 5000n })))?.code).toBe('usage')
  })
  test('naming nothing to send is usage; zero is usage', async () => {
    expect((await err(h.wallet.planSend({})))?.code).toBe('usage')
    expect((await err(h.wallet.planSend({ amount: 0n })))?.code).toBe('usage')
  })
  test('a plan whose holdings changed is a conflict at execute', async () => {
    await receivePubkey(5000n)
    const plan = await h.wallet.planSend({ amount: 1000n })
    await h.wallet.status()
    expect((await err(h.wallet.executeSend(plan)))?.code).toBe('conflict')
  })
  test('an nconnection target without an IA is a usage error naming it', async () => {
    await receivePubkey(5000n)
    const { encodeNConnection } = await import('../src/core/index.js')
    const nc = encodeNConnection({ connectionKey: 'ab'.repeat(32), relays: ['wss://r'], platform: 'discord' })
    const e = await err(h.wallet.planSend({ amount: 1n, to: nc }))
    expect(e?.code).toBe('usage')
    expect(e?.message).toMatch(/Identity Authority/)
  })
  test('emits planned, sent and committed', async () => {
    await receivePubkey(5000n)
    const seen: OperationEvent[] = []
    h.wallet.on('operation', (e) => seen.push(e))
    await h.wallet.send({ amount: 1000n })
    expect(seen.map((e) => e.phase)).toEqual(['planned', 'sent', 'committed'])
  })
})

describe('consolidate (cmd/cash_consolidate_test.go)', () => {
  test('with nothing named, merges each hub group of two or more into self', async () => {
    await receivePubkey(1000n)
    await receivePubkey(2000n)
    const r = await h.wallet.consolidate()
    expect(r.outcomes).toHaveLength(1)
    expect(r.outcomes[0]).toMatchObject({ ok: true, amount: 3000n, holding: { mode: 'pubkey', amount: 3000n } })
    expect(await h.wallet.holdings()).toHaveLength(1)
  })
  test('a round that fits no envelope is halved until it does, keeping what merged (§7.3)', async () => {
    for (const a of [1000n, 2000n, 3000n, 4000n, 5000n]) await receivePubkey(a)
    const real = CashClient.prototype.cashConsolidate
    const sizes: number[] = []
    const spy = vi.spyOn(CashClient.prototype, 'cashConsolidate').mockImplementation(function (this: CashClient, cred, p) {
      sizes.push(p.sources.length)
      // As the session refuses an item that fits no envelope: locally, before sending.
      if (p.sources.length > 3) return Promise.reject(new ClientError('item_too_large', 'item does not fit any envelope the hub accepts'))
      return real.call(this, cred, p)
    })
    try {
      const r = await h.wallet.consolidate()
      expect(r.outcomes[0]).toMatchObject({ ok: true, amount: 15000n })
    } finally {
      spy.mockRestore()
    }
    expect(sizes.filter((n) => n <= 3).length).toBeGreaterThan(1)
    expect(await h.wallet.holdings()).toHaveLength(1)
    expect(h.bank.balanceOf(h.me)).toBe(15000n)
  })
  test('a lone bill per hub is reported, not merged', async () => {
    await receivePubkey(1000n)
    const r = await h.wallet.consolidate()
    expect(r.outcomes).toHaveLength(0)
    expect(r.aloneOnTheirHub).toHaveLength(1)
  })
  test('cash notes merge through a throwaway key into a fresh cash note', async () => {
    await receiveCash(1000n)
    await receivePubkey(2000n)
    const r = await h.wallet.consolidate()
    expect(r.outcomes[0]).toMatchObject({ ok: true, holding: { mode: 'cash', protection: 'protected', amount: 3000n } })
  })
  test('to someone else leaves a gift handoff and no holding (design §6.4)', async () => {
    const bob = await harness({ pool: h.pool, bank: h.bank })
    const a = await receivePubkey(1000n)
    const b = await receivePubkey(2000n)
    const r = await h.wallet.consolidate({ holdings: [a.holding.id, b.holding.id], to: bob.me })
    expect(r.outcomes[0]).toMatchObject({ ok: true, amount: 3000n })
    const first = r.outcomes[0]!
    expect(first.ok && first.holding).toBeUndefined()
    const ho = await h.wallet.handoffs()
    expect(ho[0]).toMatchObject({ kind: 'gift', status: 'sent', amount: 3000n })
    expect(h.bank.balanceOf(bob.me)).toBe(3000n)
  })
  test('fewer than two named, or one named twice, is usage; a transferred one is not_found (alreadySpentError)', async () => {
    const a = await receivePubkey(1000n)
    expect((await err(h.wallet.consolidate({ holdings: [a.holding.id] })))?.code).toBe('usage')
    expect((await err(h.wallet.consolidate({ holdings: [a.holding.id, a.holding.id] })))?.code).toBe('usage')
    await h.wallet.send({ to: getPublicKey(new Uint8Array(32).fill(7)) })
    const b = await receivePubkey(2000n)
    expect((await err(h.wallet.consolidate({ holdings: [a.holding.id, b.holding.id] })))?.code).toBe('not_found')
  })
})

describe('redeem (cmd/cash_redeem_test.go, cash_redeem_amount_select_test.go)', () => {
  let nwc: FakeNwcWallet
  beforeEach(async () => {
    nwc = new FakeNwcWallet(h.pool)
    await h.wallet.connections.add('main', nwc.uri)
  })
  test('one held bill redeems into the default connection for its net amount', async () => {
    h.bank.fee = (a) => a / 100n
    const { holding } = await receivePubkey(5000n)
    const plan = await h.wallet.planRedeem()
    expect(plan).toMatchObject({ total: 5000n, totalFee: 50n, totalNet: 4950n, destination: { kind: 'connection', name: 'main' } })
    const r = await h.wallet.executeRedeem(plan)
    expect(r.firstError).toBeUndefined()
    expect(r.outcomes[0]).toMatchObject({ ok: true, holdingId: holding.id, feesPaid: 50n })
    expect(nwc.seen.find((s) => s.method === 'make_invoice')?.params['amount']).toBe(4950)
    expect(h.bank.redeemed).toHaveLength(1)
    expect((await h.wallet.holdings({ includeSpent: true }))[0]!.status).toBe('redeemed')
  })
  test('several held and nothing named is usage', async () => {
    await receivePubkey(1n)
    await receivePubkey(2n)
    expect((await err(h.wallet.planRedeem()))?.code).toBe('usage')
    const r = await h.wallet.redeem({ all: true })
    expect(r.outcomes.filter((o) => o.ok)).toHaveLength(2)
  })
  test('an amount picks an exact same-hub subset (exactSameHubSum)', async () => {
    await receivePubkey(300n)
    await receivePubkey(200n)
    await receivePubkey(400n)
    const plan = await h.wallet.planRedeem({ amount: 500n })
    expect(plan.items.map((i) => i.amount)).toEqual([300n, 200n])
    expect((await err(h.wallet.planRedeem({ amount: 1000n })))?.code).toBe('invalid_input')
    expect((await err(h.wallet.planRedeem({ amount: 650n })))?.code).toBe('usage')
  })
  test('invoice rules: a fixed invoice refuses amount; an amount-less one needs it; one holding only (invoiceAmountOverride)', async () => {
    await receivePubkey(5000n)
    expect((await err(h.wallet.planRedeem({ invoice: invoice(100n), amount: 100n })))?.code).toBe('usage')
    expect((await err(h.wallet.planRedeem({ invoice: invoice() })))?.code).toBe('usage')
    const p = await h.wallet.planRedeem({ invoice: invoice(), amount: 1000n })
    expect(p.destination).toMatchObject({ kind: 'invoice', amount: 1000n })
    const over = await h.wallet.planRedeem({ invoice: invoice(), amount: 9000n })
    expect(over.items).toHaveLength(0)
    expect(over.refused[0]!.error.code).toBe('invalid_input')
    await receivePubkey(1n)
    expect((await err(h.wallet.planRedeem({ invoice: invoice(5n), all: true })))?.code).toBe('usage')
  })
  test('a spent bill is tombstoned during the quote, never redeemed', async () => {
    const { w } = await receivePubkey(5000n)
    w.spent = true
    const plan = await h.wallet.planRedeem()
    expect(plan.refused[0]!.error.code).toBe('spent')
    expect((await h.wallet.holdings({ includeSpent: true }))[0]!.status).toBe('spent')
  })
  test('no connection is not_found', async () => {
    await h.wallet.connections.remove('main')
    await receivePubkey(5n)
    expect((await err(h.wallet.planRedeem()))?.code).toBe('not_found')
  })
})

describe('status', () => {
  test('reports each holding and records a tombstone (cmd/spent_test.go)', async () => {
    const a = await receivePubkey(1000n)
    const b = await receivePubkey(2000n)
    b.w.spent = true
    const r = await h.wallet.status()
    expect(r.outcomes).toEqual([
      expect.objectContaining({ ok: true, holdingId: a.holding.id, state: 'available', amount: 1000n }),
      expect.objectContaining({ ok: true, holdingId: b.holding.id, state: 'spent' }),
    ])
    const acts = await h.wallet.activity()
    expect(acts.some((x) => x.type === 'activity' && x.action === 'spent')).toBe(true)
  })
})

test("status explains a cash secret the Hub no longer recognises (lokihub's NOT_FOUND)", async () => {
  const { w, holding } = await receiveCash(700n, { protect: false })
  w.identity = { type: 'cash', value: 'ff'.repeat(32) }
  const r = await h.wallet.status({ holdings: [holding.id] })
  expect(r.outcomes[0]).toMatchObject({ ok: false, error: { code: 'invalid_input' } })
  expect(r.firstError?.message).toMatch(/does not match this bill/)
})

describe('balance (cmd/wallet_balance_test.go)', () => {
  test('wallets plus unexpired held cash; expired held excluded; notes outstanding shown apart', async () => {
    const nwc = new FakeNwcWallet(h.pool)
    nwc.balance = 7000n
    await h.wallet.connections.add('main', nwc.uri)
    await receivePubkey(1000n)
    h.bank.mintToPubkey(1n, h.me)
    const exp = h.bank.mintToPubkey(500n, h.me, { expiresAt: 4_000_000_000 })
    await h.wallet.receive(exp.token)
    await h.wallet.send({ amount: 400n })
    const b = await h.wallet.balance()
    expect(b.wallets).toEqual([{ name: 'main', kind: 'nwc', balance: 7000n }])
    expect(b.outstandingCashNotes).toEqual({ count: 1, amount: 400n })
    expect(b.total).toBe(7000n + b.holdings.held)
  })
  test('an auth decline with a cached figure is stranded (strandedBalanceFallback)', async () => {
    const nwc = new FakeNwcWallet(h.pool)
    nwc.balance = 7000n
    await h.wallet.connections.add('main', nwc.uri)
    await h.wallet.balance()
    nwc.handler = () => ({ error: { code: 'EXPIRED', message: 'gone' } })
    const b = await h.wallet.balance()
    expect(b.wallets[0]).toMatchObject({ stranded: true, balance: 7000n })
    expect(b.stranded).toBe(7000n)
  })
})

describe('activity and handoffs (cmd/handoffs_test.go)', () => {
  test('an unclaimed note hides its secret unless asked; refresh marks it claimed', async () => {
    await receivePubkey(5000n)
    const r = await h.wallet.send({ amount: 2000n })
    const [masked] = await h.wallet.handoffs()
    expect(masked).toMatchObject({ kind: 'cash_note', status: 'unclaimed', secretHidden: true })
    expect(masked!.handoff).toMatch(/#<hidden>$/)
    const [shown] = await h.wallet.handoffs({ includeSecrets: true })
    expect(shown!.handoff).toBe(r.cashNote)
    const bob = await harness({ pool: h.pool, bank: h.bank })
    await bob.wallet.receive(r.cashNote!)
    const [after] = await h.wallet.handoffs({ refresh: true })
    expect(after).toMatchObject({ status: 'claimed', secretHidden: false })
  })
  test('activity never carries a secret (auditD_cli_history_secrets)', async () => {
    await receiveCash(5000n)
    const r = await h.wallet.send({ amount: 2000n })
    const secret = r.cashNote!.split('#')[1]!
    const json = toJSON(await h.wallet.activity())
    expect(json).not.toContain(secret)
    expect(json).toContain('"action":"send"')
  })
})

describe('circles (cmd/circle_test.go)', () => {
  test('joins: the key is generated locally, the connection added, the pending join deleted', async () => {
    const hub = new FakeNwcWallet(h.pool, 0x81)
    let sent: Record<string, unknown> = {}
    hub.handler = (_m, params) => {
      sent = params
      const details = JSON.stringify({ wallet_pubkey: '9a'.repeat(32), relays: ['wss://c1'], max_amount: 5000, expires_at: 1, fees_ppm: 10, budget_renewal: 'monthly' })
      return { result: { encrypted_details: nip44.encrypt(details, nip44.getConversationKey(hub.key, h.me)) } }
    }
    const r = await h.wallet.joinCircle({ hub: hub.uri, maxAmount: 5000n })
    expect(r).toMatchObject({ name: 'circle', isDefault: true, walletPubkey: '9a'.repeat(32), maxAmount: 5000n, feesPpm: 10, private: false })
    expect(r).not.toHaveProperty('fallbackReason')
    expect(sent['connection_pubkey']).toBe(r.connectionPubkey)
    expect(toJSON(r)).not.toContain('secret')
    expect(h.wallet.state.pendingJoins).toHaveLength(0)
    expect((await h.wallet.connections.list())[0]).toMatchObject({ name: 'circle', kind: 'circle', walletPubkey: '9a'.repeat(32) })
  })
  test('maxAmount 0 is invalid_input; WALLET_EXISTS is exists and forgets the key', async () => {
    const hub = new FakeNwcWallet(h.pool, 0x81)
    expect((await err(h.wallet.joinCircle({ hub: hub.uri, maxAmount: 0n })))?.code).toBe('invalid_input')
    hub.handler = (m) => (m === 'get_info' ? { result: {} } : { error: { code: 'RESTRICTED', message: 'this identity already has an active circle wallet' } })
    const e = await err(h.wallet.joinCircle({ hub: hub.uri, maxAmount: 5n }))
    expect([e?.code, e?.nwcCode]).toEqual(['exists', 'WALLET_EXISTS'])
    expect(h.wallet.state.pendingJoins).toHaveLength(0)
  })
  test('a replay-guard refusal is retried once after 1.1 s', async () => {
    const hub = new FakeNwcWallet(h.pool, 0x81)
    let calls = 0
    const slept: number[] = []
    h.wallet.sleep = async (ms) => void slept.push(ms)
    hub.handler = (m) => {
      if (m === 'get_info') return { result: {} }
      calls++
      return { error: { code: 'BAD_REQUEST', message: 'identity_event has already been used' } }
    }
    expect((await err(h.wallet.joinCircle({ hub: hub.uri, maxAmount: 5n })))?.code).toBe('conflict')
    expect([calls, slept]).toEqual([2, [1100]])
  })
  test('silence keeps the pending join', async () => {
    const hub = new FakeNwcWallet(h.pool, 0x81)
    hub.handler = (m) => (m === 'get_info' ? { result: {} } : 'silent')
    const x = await harness({ pool: h.pool, bank: h.bank, deps: { nwcTimeoutMs: 50 } })
    expect((await err(x.wallet.joinCircle({ hub: hub.uri, maxAmount: 5n })))?.code).toBe('indeterminate')
    expect(x.wallet.state.pendingJoins).toHaveLength(1)
  })
})

describe('private circle joins (NIP-CW §Private Join)', () => {
  let nwc: FakeNwcWallet
  let node: FakeHub
  let identity: string | undefined
  const sealed = (to: string) => ({ encrypted_details: nip44.encrypt(JSON.stringify({ wallet_pubkey: '9b'.repeat(32), relays: ['wss://c1'], max_amount: 5000, expires_at: 1, fees_ppm: 0, budget_renewal: 'monthly' }), nip44.getConversationKey(nwc.key, to)) })
  const standardJoins = () => nwc.seen.filter((x) => x.method === 'create_circle_wallet').length

  beforeEach(async () => {
    nwc = new FakeNwcWallet(h.pool, 0x85)
    node = new FakeHub(h.pool, [NWC_RELAY], 0x5a)
    node.handler = (_m, info) => (info.signer === info.params['pubkey'] && info.item.target === nwc.pubkey ? { result: sealed(info.params['pubkey'] as string) } : 'omit')
    await node.start()
    identity = node.node
    nwc.handler = (m, p) => {
      if (m === 'get_info') return { result: { circle_wallet: { available_millis: 5000, max_exp_secs: 0, fees_ppm: 0, circle_policy: 'allowlist', ...(identity !== undefined && { identity }) } } }
      return { result: sealed(p['pubkey'] as string) }
    }
  })

  test('joins privately when get_info reports an identity, and adds the connection', async () => {
    const r = await h.wallet.joinCircle({ hub: nwc.uri, maxAmount: 5000n })
    expect(r).toMatchObject({ name: 'circle', walletPubkey: '9b'.repeat(32), private: true })
    expect(r).not.toHaveProperty('fallbackReason')
    expect(standardJoins()).toBe(0)
    expect(h.wallet.state.pendingJoins).toHaveLength(0)
    expect((await h.wallet.connections.list())[0]).toMatchObject({ name: 'circle', kind: 'circle', walletPubkey: '9b'.repeat(32) })
  })
  test('falls back to the standard transport when no announcement verifies, and says why', async () => {
    identity = getPublicKey(new Uint8Array(32).fill(0x5c))
    const r = await h.wallet.joinCircle({ hub: nwc.uri, maxAmount: 5000n })
    expect(r.private).toBe(false)
    expect(r.fallbackReason).toMatch(/announcement/)
    expect(standardJoins()).toBe(1)
  })
  test('a Hub that refuses get_info fails the join with its code, and nothing is sent or parked', async () => {
    nwc.handler = (m) => ({ error: { code: 'NOT_IMPLEMENTED', message: m } })
    const e = await err(h.wallet.joinCircle({ hub: nwc.uri, maxAmount: 5000n }))
    expect([e?.code, e?.nwcCode]).toEqual(['internal', 'NOT_IMPLEMENTED'])
    expect(nwc.seen.map((x) => x.method)).toEqual(['get_info'])
    expect(h.wallet.state.pendingJoins).toHaveLength(0)
  })
  test('requirePrivate without an identity is not_found, and nothing is sent or parked', async () => {
    identity = undefined
    const e = await err(h.wallet.joinCircle({ hub: nwc.uri, maxAmount: 5000n, requirePrivate: true }))
    expect(e?.code).toBe('not_found')
    expect(standardJoins()).toBe(0)
    expect(h.wallet.state.pendingJoins).toHaveLength(0)
  })
  test.each([
    ['WALLET_EXISTS', 'exists'],
    ['RESTRICTED', 'auth'],
    ['NOT_READY', 'network'],
    ['RATE_LIMITED', 'conflict'],
  ])('a private refusal %s maps as on the standard path (%s), and forgets the key', async (code, want) => {
    node.handler = () => ({ error: { code, message: 'no' } })
    const e = await err(h.wallet.joinCircle({ hub: nwc.uri, maxAmount: 5000n }))
    expect([e?.code, e?.nwcCode]).toEqual([want, code])
    expect(standardJoins()).toBe(0)
    expect(h.wallet.state.pendingJoins).toHaveLength(0)
  })
  test('a private join with no reply is indeterminate and keeps the pending join', async () => {
    node.faults = { drop: true }
    const e = await err(h.wallet.joinCircle({ hub: nwc.uri, maxAmount: 5000n }))
    expect(e?.code).toBe('indeterminate')
    expect(standardJoins()).toBe(0)
    expect(h.wallet.state.pendingJoins).toHaveLength(1)
  })
})

describe('connections, identity, settings', () => {
  test('connections: first is default; names are unique; setDefault and remove', async () => {
    const a = new FakeNwcWallet(h.pool, 0x91)
    const b = new FakeNwcWallet(h.pool, 0x93)
    await h.wallet.connections.add('a', a.uri)
    await h.wallet.connections.add('b', b.uri)
    expect((await err(h.wallet.connections.add('a', b.uri)))?.code).toBe('exists')
    expect((await h.wallet.connections.list()).map((c) => [c.name, c.isDefault])).toEqual([['a', true], ['b', false]])
    await h.wallet.connections.setDefault('b')
    await h.wallet.connections.remove('b')
    expect((await h.wallet.connections.list()).map((c) => [c.name, c.isDefault])).toEqual([['a', true]])
    expect((await err(h.wallet.connections.add('x', 'not a uri')))?.code).toBe('invalid_input')
    expect(JSON.stringify(await h.wallet.connections.list())).not.toContain(toHex(a.appSecret))
  })
  test('identity: generate once, export as ncryptsec (NIP-49)', async () => {
    expect((await err(h.wallet.identity.generate()))?.code).toBe('exists')
    const enc = await h.wallet.identity.export('pw', { logN: 4 })
    expect(getPublicKey(nip49Decrypt(enc, 'pw').secretKey)).toBe(h.me)
  })
  test('identity survives reopening the same storage', async () => {
    const again = await h.reopen()
    expect((await again.identity.get())?.pubkey).toBe(h.me)
  })
  test('settings update and read back', async () => {
    expect((await h.wallet.settings.get()).autoProtect).toBe(true)
    expect((await h.wallet.settings.update({ fallbackRelays: ['wss://f'] })).fallbackRelays).toEqual(['wss://f'])
  })
})

describe('state and toJSON', () => {
  test('subscribe sees each change; the snapshot carries no secret', async () => {
    const states: WalletState[] = []
    h.wallet.subscribe((s) => states.push(s))
    const { t } = await receiveCash(700n)
    await new Promise((r) => setTimeout(r, 0))
    expect(states.length).toBeGreaterThan(0)
    expect(h.wallet.state.holdings).toHaveLength(1)
    expect(h.wallet.state.balance).toEqual({ held: 700n, count: 1, expired: 0n })
    expect(toJSON(h.wallet.state)).not.toContain(t.secret)
  })
  test('toJSON writes snake_case keys and exact integers', () => {
    expect(toJSON({ remainingAmount: 9007199254740993n, nested: { holdingId: 'h' } })).toBe('{"remaining_amount":9007199254740993,"nested":{"holding_id":"h"}}')
    expect(JSON.parse(toJSON(new CashkitError('spent', 'x', { input: 'h-1' })))).toEqual({ error: 'x', code: 'spent', input: 'h-1' })
  })
  test('a token from a decoded send is a real lokicash token', async () => {
    await receivePubkey(5000n)
    const r = await h.wallet.send({ amount: 1n })
    expect(decodeToken(r.cashNote!.split('#')[0]!).hrp).toBe('lokicash')
  })
})
