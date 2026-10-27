// NIP-CO orders: the terms, fees, tiers and mint split (the spec's
// examples), the buyer key, addresses, order replies, and wallet.orders
// against a fake Order connection. Cases follow nmilat nipCO/{terms,fees,
// order,request}_test.go and nipCO/client/client_test.go.
import { describe, expect, test } from 'vitest'
import {
  buyerKeyFromSecret,
  cashOrderRequest,
  confirmationsFor,
  CoreError,
  isOrderNotice,
  mintSplit,
  normalizeAddress,
  orderFee,
  parseOrder,
  parseOrderInfo,
  sellsNothing,
  validateTerms,
} from '../src/core/index.js'
import { CashkitError } from '../src/wallet/index.js'
import { ADDRESS, FakeOrder, TERMS } from './fakeOrder.js'
import { invoice, signedInvoice } from './helpers.js'
import { harness, type Harness } from './walletHarness.js'

const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )

const terms = parseOrderInfo({ cash_order: TERMS })

describe('terms, fees, tiers and minting (§Terms, §Response, §Minting)', () => {
  test('the spec’s example order of 21,000,000 millis', () => {
    expect(orderFee('lightning', terms.lightning!, 21_000_000n)).toEqual({ feeMillis: 22_000n, payMillis: 21_022_000n })
    expect(orderFee('onchain', terms.onchain!, 21_000_000n)).toEqual({ feeMillis: 63_000n, payMillis: 21_063_000n })
    expect(orderFee('onchain', { ...terms.onchain!, feeBase: 1n }, 21_000_000n)).toEqual({ feeMillis: 43_000n, payMillis: 21_043_000n })
    expect(() => orderFee('onchain', terms.onchain!, 1500n)).toThrow(CoreError)
  })
  test('the tier table', () => {
    const t = terms.onchain!.confirmations!
    expect([21_063_000n, 500_000_000n, 2_000_000_000n].map((v) => confirmationsFor(t, v))).toEqual([1, 3, 6])
  })
  test('mint split: three bills from 2,500,063,000 millis; nothing at or below the fee', () => {
    expect(mintSplit(2_500_063_000n, 63_000n, 1_000_000_000n)).toEqual([1_000_000_000n, 1_000_000_000n, 500_000_000n])
    expect(mintSplit(20_000_000n, 63_000n, 1_000_000_000n)).toEqual([19_937_000n])
    expect(mintSplit(50_000n, 63_000n, 1_000_000_000n)).toEqual([])
  })
  test('terms: neither kind sells nothing; tiers must ascend and end open', () => {
    expect(sellsNothing(parseOrderInfo({ cash_order: {} }))).toBe(true)
    expect(() => validateTerms(terms)).not.toThrow()
    expect(() => validateTerms(parseOrderInfo({ cash_order: { onchain: { ...TERMS.onchain, confirmations: [{ n: 1 }, { up_to_millis: 5, n: 2 }] } } }))).toThrow(CoreError)
    expect(() => validateTerms(parseOrderInfo({ cash_order: { onchain: { ...TERMS.onchain, confirmations: [{ up_to_millis: 5, n: 0 }, { n: 2 }] } } }))).toThrow(CoreError)
    expect(() => parseOrderInfo({ cash_order: { lightning: { ...TERMS.lightning, confirmations: [] } } })).toThrow(CoreError)
  })
})

describe('buyer key, request, notices, addresses', () => {
  test('the spec’s buyer key example', () => {
    const secret = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join('')
    expect(buyerKeyFromSecret(secret)).toEqual({ secretKey: 'c853759de7b777f3588569e48461ec8ad52dbea4c8829b759a05e352cf649dea', pubkey: 'a5a70781e66224a1a4e26614b36328c1a8913f1a2c80bca00fbb2e5af993c8a3' })
  })
  test('the request carries one recipient and never a secret, expiry or recipients', () => {
    const r = cashOrderRequest({ recipient: { identityType: 'cash', identityValue: 'ab'.repeat(32), amountMillis: 0n }, amountMillis: 5000n, payment: 'lightning', notify: 'cd'.repeat(32), requestId: 'ef'.repeat(16) })
    expect(new Set(Object.keys(r))).toEqual(new Set(['amount_millis', 'notify', 'payment', 'recipient', 'request_id']))
    expect(r.recipient).toEqual({ identity_type: 'cash', identity_value: 'ab'.repeat(32) })
    expect(() => cashOrderRequest({ recipient: { identityType: 'cash', identityValue: 'ab'.repeat(32), amountMillis: 0n }, amountMillis: 1500n, payment: 'onchain', notify: 'cd'.repeat(32), requestId: 'ef'.repeat(16) })).toThrow(CoreError)
  })
  test('an order notice is exactly kind 23189, one p tag, empty content', () => {
    const n = 'cd'.repeat(32)
    expect(isOrderNotice({ kind: 23189, tags: [['p', n]], content: '' }, n)).toBe(true)
    expect(isOrderNotice({ kind: 23189, tags: [['p', n], ['e', 'x']], content: '' }, n)).toBe(false)
    expect(isOrderNotice({ kind: 23189, tags: [['p', n]], content: 'x' }, n)).toBe(false)
  })
  test('addresses: segwit of the Hub’s chain and network, one case', () => {
    expect(normalizeAddress(ADDRESS.toUpperCase(), 'bitcoin', 'mainnet')).toBe(ADDRESS)
    expect(() => normalizeAddress(ADDRESS, 'bitcoin', 'regtest')).toThrow(/regtest/)
    expect(() => normalizeAddress('bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'bitcoin', 'mainnet')).toThrow(/case/)
    expect(normalizeAddress('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', 'bitcoin', 'mainnet')).toMatch(/^bc1p/)
  })
})

describe('parseOrder (§Response)', () => {
  const base = { state: 'open', payment: 'lightning', amount_millis: 21_000_000, fee_millis: 22_000, pay_millis: 21_022_000, invoice: invoice(21_022_000n), pay_by: 1720003600, bills: [] }
  const p = { request: { payment: 'lightning' as const, amount_millis: 21_000_000n }, hubIdentity: 'aa'.repeat(32) }
  test('reads a Lightning reply', () => {
    expect(parseOrder(base, p)).toMatchObject({ state: 'open', payMillis: 21_022_000n, invoice: base.invoice, payBy: 1720003600, bills: [] })
  })
  test.each([
    ['a cash_secret anywhere', { ...base, bills: [{ cash_secret: 'x' }] }],
    ['an invoice for another amount', { ...base, invoice: invoice(1n) }],
    ['an amountless invoice', { ...base, invoice: invoice() }],
    ['pay ≠ amount + fee', { ...base, pay_millis: 1 }],
    ['another payment kind', { ...base, payment: 'onchain' }],
    ['both invoice and address', { ...base, address: ADDRESS }],
    ['an unknown state', { ...base, state: 'refunded' }],
  ] as const)('refuses %s', (_, v) => {
    expect(() => parseOrder(v, p)).toThrow(CoreError)
  })
  test('an on-chain reply needs confirmations and an address of the network', () => {
    const on = { ...base, payment: 'onchain', invoice: undefined, address: ADDRESS, confirmations: 1, fee_millis: 63_000, pay_millis: 21_063_000 }
    const q = { ...p, request: { payment: 'onchain' as const, amount_millis: 21_000_000n }, chain: 'bitcoin', network: 'mainnet' }
    expect(parseOrder(on, q)).toMatchObject({ address: ADDRESS, confirmations: 1 })
    expect(() => parseOrder({ ...on, confirmations: 0 }, q)).toThrow(CoreError)
    expect(() => parseOrder(on, { ...q, network: 'regtest' })).toThrow(CoreError)
  })
})

async function setup(): Promise<{ h: Harness; shop: FakeOrder }> {
  const h = await harness({ deps: { nwcTimeoutMs: 2000 } })
  return { h, shop: new FakeOrder(h.bank) }
}

describe('wallet.orders', () => {
  test('quote: the fee, what to pay, the bill’s redeem fee; nothing written', async () => {
    const { h, shop } = await setup()
    const q = await h.wallet.orders.quote(shop.string, { amountMillis: 21_000_000n, payment: 'onchain' })
    expect(q).toMatchObject({ feeMillis: 63_000n, payMillis: 21_063_000n, confirmations: 1, billRedeemFeeMillis: 105_000n, minTransferMillis: 1000n })
    expect(await h.storage.tx('r', (t) => t.list('pendingCalls'))).toEqual([])
  })
  test('place to cash: written ahead, the invoice shown; the payment mints an ordered cash holding', async () => {
    const { h, shop } = await setup()
    const v = await h.wallet.orders.place({ connection: shop.string, amountMillis: 21_000_000n, payment: 'lightning' })
    expect(v).toMatchObject({ state: 'open', payMillis: 21_022_000n, feeMillis: 22_000n, finished: false, gift: false })
    expect(v.invoice).toMatch(/^ln/)
    expect(v.warnings).toEqual(['pay_before', 'amount_mints_bill'])
    const json = JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x))
    const call = (await h.storage.tx('r', (t) => t.get('pendingCalls', v.id)))!
    expect(call.state).toBe('open_order')
    expect(json).not.toContain(call.params!['notify']!)
    expect(json).not.toContain(call.requestId)
    // The item proof is the buyer key's, derived from the cash secret.
    const placed = shop.placed[0]!
    const secret = new TextDecoder().decode(Uint8Array.from((call.outputs[0]!.destination as { secret: { data: string } }).secret.data.match(/../g)!.map((b) => parseInt(b, 16))))
    expect(placed.signer).toBe(buyerKeyFromSecret(secret).pubkey)
    await shop.pay(shop.only(), 21_022_000n)
    const after = await h.wallet.orders.refresh(v.id)
    expect(after).toMatchObject({ state: 'minted', finished: true })
    const [held] = await h.wallet.holdings()
    expect(held).toMatchObject({ amount: 21_000_000n, mode: 'cash', ordered: true })
    expect(after.bills[0]!.holdingId).toBe(held!.id)
    // Idempotent by wallet pubkey.
    await h.wallet.orders.refresh(v.id)
    expect(await h.wallet.holdings()).toHaveLength(1)
  })
  test('a bill not stamped as ordered: another recipient’s is never kept; one with an expiry is kept unmarked', async () => {
    const { h, shop } = await setup()
    const v = await h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning', to: 'self' })
    shop.mintTo = { type: 'pubkey', value: 'ab'.repeat(32) }
    await shop.pay(shop.only(), 5_005_000n)
    const wrong = await h.wallet.orders.refresh(v.id)
    expect(wrong.bills[0]).toMatchObject({ problem: 'not_ours' })
    expect(wrong.bills[0]!.holdingId).toBeUndefined()
    expect(await h.wallet.holdings()).toEqual([])
    const w = await h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning', to: 'self' })
    shop.mintTo = undefined
    shop.mintExpiry = 4_000_000_000
    await shop.pay([...shop.orders.values()].at(-1)!, 5_005_000n)
    const exp = await h.wallet.orders.refresh(w.id)
    expect(exp.bills[0]).toMatchObject({ problem: 'expires' })
    const [held] = await h.wallet.holdings()
    expect(held).toMatchObject({ amount: 4_999_000n, expiresAt: 4_000_000_000 })
    expect(held!.ordered).toBeFalsy()
  })
  test('a gift: the bill goes to its recipient; no holding is made', async () => {
    const { h, shop } = await setup()
    const bob = await harness({ pool: h.pool, bank: h.bank })
    const v = await h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning', to: bob.me })
    expect(v.gift).toBe(true)
    await shop.pay(shop.only(), 6_000_000n)
    const after = await h.wallet.orders.refresh(v.id)
    expect(after.bills.map((b) => b.amountMillis)).toEqual([6_000_000n - 6_000n])
    expect(await h.wallet.holdings()).toEqual([])
    expect(h.bank.balanceOf(bob.me)).toBe(6_000_000n - 6_000n)
  })
  test('on-chain: the address and confirmations; two outputs mint two bills', async () => {
    const { h, shop } = await setup()
    const v = await h.wallet.orders.place({ connection: shop.string, amountMillis: 21_000_000n, payment: 'onchain', to: 'self' })
    expect(v).toMatchObject({ address: ADDRESS, confirmations: 1, payMillis: 21_063_000n })
    expect(v.warnings).toEqual(['pay_before', 'amount_mints_bill', 'late_payment_kept', 'per_output_fee', 'fee_floor'])
    await shop.pay(shop.only(), 10_000_000n)
    await shop.pay(shop.only(), 10_000_000n)
    const after = await h.wallet.orders.refresh(v.id)
    expect(after.bills.map((b) => b.amountMillis)).toEqual([9_937_000n, 9_937_000n])
    expect((await h.wallet.holdings()).map((x) => [x.amount, x.mode, x.ordered])).toEqual([
      [9_937_000n, 'pubkey', true],
      [9_937_000n, 'pubkey', true],
    ])
  })
  test('an invoice for another amount: the order stays open, flagged, and its invoice is never shown', async () => {
    const { h, shop } = await setup()
    shop.invoiceFor = () => invoice(1n)
    const v = await h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning' })
    expect(v.invalidReply).toMatch(/invoice/)
    expect(v.invoice).toBeUndefined()
  })
  test('the deadline shown is pay_by, or the invoice’s own expiry when that comes first', async () => {
    const { h, shop } = await setup()
    const at = (expiry: number) => (pay: bigint) => signedInvoice({ amountMillis: pay, nodeKey: h.bank.hub.nodeKey, timestamp: Math.floor(h.bank.hub.clock() / 1000), expiry })
    shop.invoiceFor = at(7200)
    const late = await h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning' })
    expect(late.payDeadline).toBe(late.payBy)
    shop.invoiceFor = at(600)
    const early = await h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning' })
    expect(early.payDeadline).toBe(early.payBy - 3000)
    expect(early.invoice).toMatch(/^ln/)
  })
  test('a retired connection sells nothing: not_selling, nothing written; amounts out of range are refused locally', async () => {
    const { h, shop } = await setup()
    expect(await failure(h.wallet.orders.place({ connection: shop.string, amountMillis: 1n, payment: 'onchain' }))).toMatchObject({ code: 'invalid_input', reason: 'amount_out_of_range' })
    shop.terms = {}
    expect(await failure(h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning' }))).toMatchObject({ code: 'not_found', reason: 'not_selling' })
    expect(await h.storage.tx('r', (t) => t.list('pendingCalls'))).toEqual([])
  })
  test('a lost reply: the order is found by lookup and opened', async () => {
    const { h, shop } = await setup()
    shop.loseReply = true
    const x = await harness({ pool: h.pool, bank: h.bank, deps: { replyWaitMs: 300, nwcTimeoutMs: 2000 } })
    const e = await failure(x.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning' }))
    expect(e.code).toBe('indeterminate')
    const rep = await x.wallet.settle()
    expect(rep.applied).toEqual([e.pendingCallId])
    const [o] = await x.wallet.orders.list()
    expect(o).toMatchObject({ id: e.pendingCallId, state: 'open' })
    expect(o!.invoice).toMatch(/^ln/)
  }, 20_000)
  test('an order never placed is placed again only on confirmation, with a fresh notify', async () => {
    let skew = 0
    const clock = () => Date.now() + skew
    const h = await harness({ deps: { clock, replyWaitMs: 300, nwcTimeoutMs: 2000 } })
    h.bank.hub.clock = clock
    const shop = new FakeOrder(h.bank)
    shop.dropOrder = true
    const e = await failure(h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning' }))
    const id = e.pendingCallId!
    const first = (await h.storage.tx('r', (t) => t.get('pendingCalls', id)))!
    skew = (first.deadline + 2) * 1000 - Date.now()
    await h.wallet.settle()
    expect(await h.storage.tx('r', (t) => t.get('pendingCalls', id))).toMatchObject({ needsUser: 'confirm_replace' })
    shop.dropOrder = false
    await h.wallet.pendingCalls.confirmReplace(id)
    const next = (await h.storage.tx('r', (t) => t.list('pendingCalls'))).find((c) => c.derivedFrom === id)!
    expect(next.params!['notify']).toMatch(/^[0-9a-f]{64}$/)
    expect(next.params!['notify']).not.toBe(first.params!['notify'])
    expect(shop.placed.at(-1)!.params['notify']).toBe(next.params!['notify'])
    expect(next.state).toBe('open_order')
  }, 20_000)
  test('watch: a notice reads the order', async () => {
    const { h, shop } = await setup()
    const v = await h.wallet.orders.place({ connection: shop.string, amountMillis: 5_000_000n, payment: 'lightning' })
    const updates: string[] = []
    const done = new Promise<void>((resolve) => {
      void h.wallet.orders.watch(v.id, { pollMs: 60_000, onUpdate: (u) => (updates.push(u.state), u.finished && resolve()) })
    })
    await new Promise((r) => setTimeout(r, 50))
    await shop.pay(shop.only(), 5_006_000n)
    await done
    expect(updates.at(-1)).toBe('minted')
  }, 20_000)
})
