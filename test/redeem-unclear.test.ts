// Redeems whose outcome is unclear: one cash_status read decides, a claimed
// row is `redeeming` until settle() sees it unclaimed, gone, or paid.
import { describe, expect, test } from 'vitest'
import { FakeNwcWallet, harness, type Harness } from './walletHarness.js'

async function setup(): Promise<{ h: Harness; nwc: FakeNwcWallet; token: string }> {
  const h = await harness()
  const nwc = new FakeNwcWallet(h.pool)
  await h.wallet.connections.add('main', nwc.uri)
  const w = h.bank.mintToPubkey(5000n, h.me)
  await h.wallet.receive(w.token)
  return { h, nwc, token: w.token }
}

/** The Hub answers INTERNAL; `claim` says whether it left the row claimed. */
function internalOnce(h: Harness, token: string, claim: boolean) {
  let done = false
  h.bank.override = (m) => {
    if (m !== 'cash_redeem' || done) return undefined
    done = true
    h.bank.wallet(token)!.claimed = claim
    return { error: { code: 'INTERNAL', message: 'payout stalled' } }
  }
}

describe('unclear redeems', () => {
  test('invoices are asked for with expiry 3600', async () => {
    const { h, nwc } = await setup()
    await h.wallet.redeem()
    expect(nwc.seen.find((x) => x.method === 'make_invoice')?.params['expiry']).toBe(3600)
  })
  test('INTERNAL with the row unclaimed: nothing was paid, the bill stays live, nothing is resent', async () => {
    const { h, token } = await setup()
    internalOnce(h, token, false)
    const r = await h.wallet.redeem()
    expect(r.firstError?.code).toBe('network')
    expect(r.firstError?.message).toMatch(/nothing was paid/)
    expect(h.bank.hub.requests.filter((x) => x.item.method === 'cash_redeem')).toHaveLength(1)
    expect((await h.wallet.holdings()).map((x) => x.status)).toEqual(['held'])
  })
  test('INTERNAL with the row claimed: redeeming, in no balance or plan; the invoice settling makes it redeemed', async () => {
    const { h, nwc, token } = await setup()
    internalOnce(h, token, true)
    const r = await h.wallet.redeem()
    expect(r.firstError).toMatchObject({ code: 'indeterminate', reason: 'redeem_in_flight' })
    expect(await h.wallet.holdings()).toEqual([])
    expect((await h.wallet.holdings({ includeSpent: true })).map((x) => x.status)).toEqual(['redeeming'])
    expect((await h.wallet.balance({ refresh: false })).holdings.held).toBe(0n)
    let rep = await h.wallet.settle()
    expect(rep.redeems.stillRedeeming).toHaveLength(1)
    nwc.handler = (method, params) => (method === 'lookup_invoice' ? { result: { invoice: params['invoice'], settled_at: 1 } } : { error: { code: 'NOT_IMPLEMENTED', message: method } })
    rep = await h.wallet.settle()
    expect(rep.redeems.redeemed).toHaveLength(1)
    expect((await h.wallet.holdings({ includeSpent: true })).map((x) => x.status)).toEqual(['redeemed'])
  })
  test('a claimed row that comes back unclaimed is released; a tombstone makes it spent', async () => {
    const a = await setup()
    internalOnce(a.h, a.token, true)
    await a.h.wallet.redeem()
    a.h.bank.wallet(a.token)!.claimed = false
    expect((await a.h.wallet.settle()).redeems.released).toHaveLength(1)
    expect((await a.h.wallet.holdings()).map((x) => x.status)).toEqual(['held'])

    const b = await setup()
    internalOnce(b.h, b.token, true)
    await b.h.wallet.redeem()
    b.h.bank.wallet(b.token)!.spent = true
    expect((await b.h.wallet.settle()).redeems.spent).toHaveLength(1)
  })
  test('PAYMENT_FAILED is retried once with a fresh invoice and proof', async () => {
    const { h, nwc } = await setup()
    let first = true
    h.bank.override = (m) => {
      if (m !== 'cash_redeem' || !first) return undefined
      first = false
      return { error: { code: 'PAYMENT_FAILED', message: 'no route' } }
    }
    const r = await h.wallet.redeem()
    expect(r.firstError).toBeUndefined()
    const invoices = h.bank.hub.requests.filter((x) => x.item.method === 'cash_redeem').map((x) => x.params['invoice'])
    expect(invoices).toHaveLength(2)
    expect(invoices[0]).not.toBe(invoices[1])
    expect(nwc.seen.filter((x) => x.method === 'make_invoice')).toHaveLength(2)
  })
})
