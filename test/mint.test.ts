// Minting through a stored Cash Hub connection, as a pending call.
import { describe, expect, test } from 'vitest'
import { splitCashString } from '../src/core/index.js'
import { CashkitError } from '../src/wallet/index.js'
import { commitment } from './fakeBank.js'
import { FakeNwcWallet, harness, type Harness } from './walletHarness.js'

const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )

async function withHub(o: { nwcTimeoutMs?: number } = {}): Promise<{ h: Harness; hub: string }> {
  const h = await harness({ deps: { nwcTimeoutMs: o.nwcTimeoutMs ?? 2000 } })
  const hub = h.bank.openCashHub()
  await h.wallet.connections.add('hub', hub)
  return { h, hub }
}

const openCalls = (h: Harness) => h.storage.tx('r', async (t) => (await t.list('pendingCalls')).filter((c) => c.state !== 'done'))

describe('Cash Hub connections', () => {
  test('a cashhub1 is verified, checked online and stored as given; never the default wallet', async () => {
    const { h, hub } = await withHub()
    const [c] = await h.wallet.connections.list()
    expect(c).toMatchObject({ name: 'hub', kind: 'cashhub', isDefault: false, hubIdentity: h.bank.hub.node, verified: true, chain: 'bitcoin' })
    const row = (await h.storage.tx('r', (t) => t.get('connections', 'hub')))!
    expect(row.uri).toBeUndefined()
    expect(new TextDecoder().decode(Uint8Array.from(row.connection!.data.match(/../g)!.map((b) => parseInt(b, 16))))).toBe(hub)
    expect((await failure(h.wallet.lightning('hub'))).code).toBe('usage')
    expect((await failure(h.wallet.lightning())).code).toBe('not_found')
  })
  test('a URI given as a Cash Hub is connection_invalid; a get_info naming another node is connection_mismatch', async () => {
    const h = await harness()
    const nwc = new FakeNwcWallet(h.pool)
    expect(await failure(h.wallet.connections.add('x', nwc.uri, { kind: 'cashhub' }))).toMatchObject({ code: 'invalid_input', reason: 'connection_invalid' })
    h.bank.cashHubInfo = { pubkey: 'ab'.repeat(32) }
    expect(await failure(h.wallet.connections.add('y', h.bank.openCashHub()))).toMatchObject({ code: 'invalid_input', reason: 'connection_mismatch' })
    expect(await h.wallet.connections.list()).toEqual([])
  })
})

describe('wallet.mint', () => {
  test('to cash: the secret is written ahead, the note is returned and another wallet receives it', async () => {
    const { h } = await withHub()
    const r = await h.wallet.mint({ hub: 'hub', amount: 21000n })
    expect(r.amount).toBe(21000n)
    const { token, cashSecret } = splitCashString(r.cashNote!)
    expect(h.bank.wallet(token)?.identity).toEqual({ type: 'cash', value: commitment(cashSecret) })
    const calls = await h.storage.tx('r', (t) => t.list('pendingCalls'))
    expect(calls.map((c) => [c.kind, c.method, c.state, c.outcome])).toEqual([['mint', 'mint_cash', 'done', 'applied']])
    expect(calls[0]!.outputs[0]!.destination.kind).toBe('cash')
    const bob = await harness({ pool: h.pool, bank: h.bank })
    expect((await bob.wallet.receive(r.cashNote!)).received).toBe(true)
  })
  test('to self: a held, verified bill of origin minted', async () => {
    const { h } = await withHub()
    const r = await h.wallet.mint({ hub: 'hub', amount: 5000n, to: 'self' })
    const [held] = await h.wallet.holdings()
    expect(held).toMatchObject({ id: r.holdingId, amount: 5000n, mode: 'pubkey' })
    const row = (await h.storage.tx('r', (t) => t.get('holdings', r.holdingId!)))!
    expect(row).toMatchObject({ origin: 'minted', verified: true, minterXonly: h.bank.hub.node })
    expect(h.bank.balanceOf(h.me)).toBe(5000n)
  })
  test('a lost reply leaves the mint open; settle() applies it from the lookup', async () => {
    const { h } = await withHub({ nwcTimeoutMs: 300 })
    h.bank.loseMintReply = true
    const e = await failure(h.wallet.mint({ hub: 'hub', amount: 3000n, to: 'self' }))
    expect(e.code).toBe('indeterminate')
    expect(e.pendingCallId).toBeDefined()
    expect(await h.wallet.holdings()).toEqual([])
    h.bank.loseMintReply = false
    const rep = await h.wallet.settle()
    expect(rep.applied).toEqual([e.pendingCallId])
    expect((await h.wallet.holdings()).map((x) => x.amount)).toEqual([3000n])
    expect(await openCalls(h)).toEqual([])
  }, 20_000)
  test('a malformed request is refused before anything is written', async () => {
    const { h } = await withHub()
    expect((await failure(h.wallet.mint({ hub: 'hub', amount: 0n }))).code).toBe('invalid_input')
    expect((await failure(h.wallet.mint({ hub: 'hub', recipients: [{ to: 'cash', amount: 1n }] }))).code).toBe('usage')
    expect((await failure(h.wallet.mint({ hub: 'nope', amount: 1n }))).code).toBe('not_found')
    expect(await h.storage.tx('r', (t) => t.list('pendingCalls'))).toEqual([])
  })
  test('BAD_REQUEST from the Hub closes the mint not applied', async () => {
    const { h } = await withHub()
    // An expiration the Hub refuses: the wallet's clock runs far behind the Hub's.
    const skew = await harness({ pool: h.pool, bank: h.bank, deps: { nwcTimeoutMs: 2000, clock: () => Date.now() - 3_600_000 } })
    await skew.wallet.connections.add('hub', h.bank.openCashHub())
    const e = await failure(skew.wallet.mint({ hub: 'hub', amount: 1000n }))
    expect(e.code).toBe('invalid_input')
    expect(await openCalls(skew)).toEqual([])
  })
})
