// Holding lokicash (loki) and satscash (sat) bills in one wallet without ever
// summing, selecting or redeeming them together (ohstr/cashkit#6). A second
// FakeBank mints satscash, so one wallet ends up with bills of both coins.
import { describe, expect, test } from 'vitest'
import { FakeBank } from './fakeBank.js'
import { FakeNwcWallet, harness, type Harness } from './walletHarness.js'
import { invoice } from './helpers.js'

/** A wallet holding loki bills from one Hub and sat bills from a Bitcoin Hub. */
async function mixed(): Promise<{ h: Harness; sat: FakeBank }> {
  const h = await harness() // the default bank mints lokicash (loki)
  const sat = new FakeBank(h.pool, ['wss://satbank.test'], { seed: 0x30, hrp: 'satscash' })
  await sat.start()
  await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token) // loki
  await h.wallet.receive(h.bank.mintToPubkey(3000n, h.me).token) // loki
  await h.wallet.receive(sat.mintToPubkey(7000n, h.me).token) // sat
  await h.wallet.receive(sat.mintToPubkey(2000n, h.me).token) // sat
  return { h, sat }
}

describe('multi-currency wallet (#6)', () => {
  test('a Hub can mint satscash, and its bills read as sat from the HRP', async () => {
    const h = await harness()
    const sat = new FakeBank(h.pool, ['wss://satbank.test'], { seed: 0x31, hrp: 'satscash' })
    await sat.start()
    const r = await h.wallet.receive(sat.mintToPubkey(4200n, h.me).token)
    expect(r.received && r.holding.unit).toBe('sat')
    const loki = await h.wallet.receive(h.bank.mintToPubkey(1000n, h.me).token)
    expect(loki.received && loki.holding.unit).toBe('loki')
  })

  test('balance is reported per currency, never summed', async () => {
    const { h } = await mixed()
    const bal = await h.wallet.balance({ refresh: false })
    expect(bal.holdings.loki?.held).toBe(8000n)
    expect(bal.holdings.sat?.held).toBe(9000n)
    // The live snapshot keeps them apart too.
    expect(h.wallet.state.balance.loki?.held).toBe(8000n)
    expect(h.wallet.state.balance.sat?.held).toBe(9000n)
    // There is no single cross-currency total to read.
    expect(new Set(Object.keys(bal.holdings))).toEqual(new Set(['loki', 'sat']))
  })

  test('an amount send needs a unit when two currencies are held, and spends only that one', async () => {
    const { h } = await mixed()
    await expect(h.wallet.send({ amount: 1000n })).rejects.toMatchObject({ code: 'usage', reason: 'ambiguous_unit' })
    const r = await h.wallet.send({ amount: 1000n, unit: 'sat' })
    expect(r.sent).toBe(1000n)
    const bal = await h.wallet.balance({ refresh: false })
    expect(bal.holdings.loki?.held).toBe(8000n) // untouched
    expect(bal.holdings.sat?.held).toBe(8000n) // 9000 held - 1000 handed off
  })

  test('consolidate merges within one currency only', async () => {
    const { h } = await mixed()
    const rep = await h.wallet.consolidate()
    expect(rep.firstError).toBeUndefined()
    const merged = rep.outcomes.flatMap((o) => (o.ok && o.holding !== undefined ? [[o.holding.unit, o.holding.amount] as const] : []))
    // Two merges, one per currency; loki and sat were never combined.
    expect(new Set(merged.map(([u]) => u))).toEqual(new Set(['loki', 'sat']))
    expect(new Set(merged.map(([, a]) => a))).toEqual(new Set([8000n, 9000n]))
    const bal = await h.wallet.balance({ refresh: false })
    expect(bal.holdings.loki?.held).toBe(8000n)
    expect(bal.holdings.sat?.held).toBe(9000n)
  })

  test('a named consolidation across currencies is refused', async () => {
    const { h } = await mixed()
    const hs = await h.wallet.holdings()
    const loki = hs.find((x) => x.unit === 'loki')!
    const sat = hs.find((x) => x.unit === 'sat')!
    await expect(h.wallet.consolidate({ holdings: [loki.id, sat.id] })).rejects.toMatchObject({ code: 'invalid_input' })
  })

  test('a wrong-network invoice is refused before anything is paid', async () => {
    const { h } = await mixed()
    const loki = (await h.wallet.holdings()).find((x) => x.unit === 'loki')!
    // A Bitcoin (bc) invoice cannot be paid from a loki bill.
    const bitcoinInvoice = invoice(1000n, 0x42, 'bc')
    await expect(h.wallet.redeem({ invoice: bitcoinInvoice, holdings: [loki.id] })).rejects.toMatchObject({ code: 'invalid_input', reason: 'wrong_network' })
    // The right coin's invoice is accepted into the matching bill (not refused for the network).
    const sat = (await h.wallet.holdings()).find((x) => x.unit === 'sat' && x.amount === 2000n)!
    const bitcoinAmountless = invoice(undefined, 0x43, 'bcrt')
    const plan = await h.wallet.planRedeem({ invoice: bitcoinAmountless, holdings: [sat.id], amount: 2000n })
    expect(plan.items).toHaveLength(1)
    expect(plan.refused).toHaveLength(0)
  })

  test('redeeming into a Lightning wallet checks the make_invoice coin before paying', async () => {
    const { h } = await mixed()
    const btc = new FakeNwcWallet(h.pool)
    btc.invoiceCurrency = 'bcrt' // a Bitcoin regtest wallet
    await h.wallet.connections.add('btc', btc.uri)
    const hs = await h.wallet.holdings()
    // A sat bill redeems fine: the wallet answers with a bcrt (sat) invoice.
    const sat = hs.find((x) => x.unit === 'sat' && x.amount === 2000n)!
    const ok = await h.wallet.redeem({ holdings: [sat.id], into: 'btc' })
    expect(ok.firstError).toBeUndefined()
    // A loki bill is refused: the bcrt invoice the wallet makes is the wrong coin.
    const loki = hs.find((x) => x.unit === 'loki')!
    const bad = await h.wallet.redeem({ holdings: [loki.id], into: 'btc' })
    expect(bad.firstError?.reason).toBe('wrong_network')
    expect(btc.seen.filter((s) => s.method === 'pay_invoice')).toHaveLength(0)
  })
})
