// The wallet engine against lokihub's regtest dev stack (design §11.3): a
// mint over a signed cashhub1, lost replies settled by lookup, Lightning and
// on-chain orders paid by the stack's payer, withdrawals mined to final, a
// Cash Zap, a Cash Pocket read on a second device and a listed circle joined.
// Lost replies are made with a reply wait of 1 ms: a mint, a transfer, an
// order and a withdrawal, each settled by lookup on a reopened wallet.
// Opt-in, like wallet.test.ts:
//
//   CASHKIT_E2E_CONFIG=<lokihub>/integration/config.local.yaml   admin_api and relay_url
//   (or CASHKIT_E2E_ADMIN_URL + CASHKIT_E2E_ADMIN_TOKEN [+ CASHKIT_E2E_RELAY])
//
// The order, withdrawal and chain steps need the stack's test hooks
// (/api/test, a testhooks build on regtest); they skip without them.
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { RelayWs } from '../../src/adapters/relay-ws.js'
import { MemoryStorage } from '../../src/adapters/storage-memory.js'
import { NoneVault } from '../../src/adapters/vault-none.js'
import { syncPocket } from '../../src/adapters/sync-pocket.js'
import { localSigner } from '../../src/core/index.js'
import { readEvents, type RelayPool } from '../../src/client/index.js'
import type { NostrEvent } from '../../src/core/index.js'
import { Wallet, CashkitError } from '../../src/wallet/index.js'
import type { WalletDeps } from '../../src/wallet/ports.js'
import { admin, api, createCashHub, deleteCashHub, hooks, relayUrl, until, type CreatedApp } from './admin.js'

const hasHooks = await hooks.available()
const pool = new RelayWs()
const opened: Wallet[] = []

async function openWallet(o: Partial<WalletDeps> = {}, settle = true): Promise<Wallet> {
  const w = await Wallet.open({ storage: new MemoryStorage(), vault: new NoneVault(), relays: pool, ...o }, { settle })
  opened.push(w)
  return w
}

async function withHub(w: Wallet, hub: CreatedApp, name = 'hub'): Promise<void> {
  expect(hub.cashHubToken).toMatch(/^cashhub1/)
  await w.connections.add(name, hub.cashHubToken!, { confirmUnverified: async () => false })
}

/** settle() until no call is open, for up to about 100 s. */
async function settleAll(w: Wallet) {
  let report = await w.settle()
  for (let i = 0; i < 20 && report.open.length > 0; i++) {
    await new Promise((r) => setTimeout(r, 5000))
    report = await w.settle()
  }
  return report
}

/** pool, except that the NIP-47 responses (kind 23195) to calls carrying a deadline (an `expiration` tag: mint_cash, not get_info) never arrive. */
function dropDeadlineReplies(inner: RelayPool): RelayPool {
  const dropped = new Set<string>()
  const lost = (e: NostrEvent) => e.kind === 23195 && e.tags.some((t) => t[0] === 'e' && dropped.has(t[1]!))
  return {
    subscribe: (relays, filter, h) =>
      inner.subscribe(relays, filter, {
        // Delegated one by one: a handler object may keep its methods on a prototype.
        onEose: (r) => h.onEose(r),
        ...(h.onClose && { onClose: (r: string, why: string) => h.onClose!(r, why) }),
        onEvent: (e, r) => (lost(e) ? undefined : h.onEvent(e, r)),
      }),
    publish: (relay, e) => {
      if (e.kind === 23194 && e.tags.some((t) => t[0] === 'expiration')) dropped.add(e.id)
      return inner.publish(relay, e)
    },
    ...(inner.relayInfo && { relayInfo: (relay: string) => inner.relayInfo!(relay) }),
  }
}

afterAll(() => {
  for (const w of opened) w.close()
  pool.close()
})

describe.skipIf(admin === undefined)('lokihub: cashhub1 mint and lost replies', () => {
  let hub: CreatedApp
  beforeAll(async () => {
    hub = await createCashHub({ name: 'cashkit-e2e mint' })
  }, 60_000)
  afterAll(() => deleteCashHub(hub), 120_000)

  test('mints to itself over a signed cashhub1 string and reads the bill', async () => {
    const w = await openWallet()
    await w.identity.generate()
    await withHub(w, hub)
    const m = await w.mint({ hub: 'hub', amount: 30_000n, to: 'self' })
    expect(m.amount).toBe(30_000n)
    expect(m.holdingId).toBeDefined()
    const st = await w.status()
    expect(st.firstError).toBeUndefined()
    expect(st.outcomes).toMatchObject([{ ok: true, state: 'available', amount: 30_000n }])
  }, 300_000)

  // A reply wait of 1 ms: the call is published, then given up on before the
  // Hub can answer. Reopened over the same storage, settle() looks it up.
  const lose = async (act: (w: Wallet) => Promise<unknown>) => {
    const storage = new MemoryStorage()
    const vault = new NoneVault()
    const w = await openWallet({ storage, vault })
    await w.identity.generate()
    await withHub(w, hub)
    const outcome = await act(w).catch((e: unknown) => e)
    return { storage, vault, w, outcome }
  }

  test('a mint whose reply was lost is found by settle() and held once', async () => {
    const storage = new MemoryStorage()
    const vault = new NoneVault()
    const first = await openWallet({ storage, vault })
    await first.identity.generate()
    await withHub(first, hub)
    first.close()
    // A mint goes over NIP-47 on the cashhub1 connection, not the private
    // transport. The online check (get_info) has to be answered, so the reply
    // is lost at the relay instead: the mint's response (its request carries
    // the deadline as an expiration tag) is dropped, and it gives up after 5 s.
    const lossy = await openWallet({ storage, vault, relays: dropDeadlineReplies(pool), nwcTimeoutMs: 5_000 }, false)
    const lost = await lossy.mint({ hub: 'hub', amount: 12_000n, to: 'self' }).catch((e: unknown) => e)
    expect(lost).toBeInstanceOf(CashkitError)
    expect((lost as CashkitError).code).toBe('indeterminate')
    lossy.close()

    const w = await openWallet({ storage, vault }, false)
    const report = await settleAll(w)
    expect(report.open).toEqual([])
    expect(report.applied.length).toBeGreaterThanOrEqual(1)
    expect((await w.balance()).holdings.held).toBe(12_000n)
  }, 600_000)

  test('a transfer whose reply was lost is settled: the remainder is held, nothing twice', async () => {
    const { storage, vault, w: first } = await lose(async (w) => w.mint({ hub: 'hub', amount: 40_000n, to: 'self' }))
    first.close()
    const lossy = await openWallet({ storage, vault, replyWaitMs: 1 }, false)
    const lost = await lossy.send({ amount: 15_000n }).catch((e: unknown) => e)
    expect(lost).toBeInstanceOf(CashkitError)
    lossy.close()

    const w = await openWallet({ storage, vault }, false)
    const report = await settleAll(w)
    expect(report.open).toEqual([])
    expect((await w.balance()).holdings.held).toBe(25_000n)
    const [handoff] = await w.handoffs({ includeSecrets: true })
    expect(handoff).toBeDefined()
  }, 600_000)
})

describe.skipIf(admin === undefined || !hasHooks)('lokihub: orders paid by the payer', () => {
  let hub: CreatedApp
  let cashorder: string
  beforeAll(async () => {
    hub = await createCashHub({ name: 'cashkit-e2e orders' })
    await api('PUT', `/api/cash-hubs/${hub.id}/order-terms`, {
      terms: {
        lightning: { min_millis: 1000, max_millis: 1_000_000, fee_base: 1000, fee_ppm: 1000, window: 600 },
        onchain: { min_millis: 10_000, max_millis: 5_000_000, fee_base: 21_000, fee_ppm: 2000, window: 3600, confirmations: [{ n: 1 }] },
        bill: { redeem_fee_base: 0, redeem_fee_ppm: 0, min_transfer_millis: 0 },
      },
      openCeilingLightningMillis: 5_000_000,
      openCeilingOnchainMillis: 5_000_000,
      openOnchainMax: 5,
    })
    const conn = await api<{ connectionString: string }>('POST', `/api/cash-hubs/${hub.id}/order-connections`, { label: 'cashkit e2e' })
    cashorder = conn.connectionString
    expect(cashorder).toMatch(/^cashorder1/)
  }, 60_000)
  afterAll(() => deleteCashHub(hub), 120_000)

  test('a Lightning order is minted once after the payer pays its invoice', async () => {
    const w = await openWallet()
    await w.identity.generate()
    const o = await w.orders.place({ connection: cashorder, amountMillis: 5_000n, payment: 'lightning' })
    expect(o.invoice).toMatch(/^ln/)
    const paid = await hooks.payInvoice(o.invoice!)
    expect(paid.status).toBe('SUCCEEDED')
    await until('order finished', async () => (await w.orders.refresh(o.id)).finished)
    const done = await w.orders.get(o.id)
    expect(done.bills).toHaveLength(1)
    expect((await w.balance()).holdings.held).toBe(5_000n)
  }, 300_000)

  test('an order whose reply was lost is found by settle(), then minted once after payment', async () => {
    const storage = new MemoryStorage()
    const vault = new NoneVault()
    const first = await openWallet({ storage, vault })
    await first.identity.generate()
    first.close()
    const lossy = await openWallet({ storage, vault, replyWaitMs: 1 }, false)
    const lost = await lossy.orders.place({ connection: cashorder, amountMillis: 6_000n, payment: 'lightning' }).catch((e: unknown) => e)
    expect(lost).toBeInstanceOf(CashkitError)
    expect((lost as CashkitError).code).toBe('indeterminate')
    lossy.close()

    const w = await openWallet({ storage, vault }, false)
    const report = await settleAll(w)
    expect(report.open).toEqual([])
    const orders = await w.orders.list()
    expect(orders).toHaveLength(1)
    const [o] = orders
    expect(o).toMatchObject({ id: (lost as CashkitError).pendingCallId, state: 'open' })
    expect(o!.invoice).toMatch(/^ln/)
    expect((await hooks.payInvoice(o!.invoice!)).status).toBe('SUCCEEDED')
    await until('order finished', async () => (await w.orders.refresh(o!.id)).finished)
    expect((await w.orders.get(o!.id)).bills).toHaveLength(1)
    expect((await w.balance()).holdings.held).toBe(6_000n)
  }, 600_000)

  test('an on-chain order is minted after one confirmation', async () => {
    const w = await openWallet()
    await w.identity.generate()
    // Large enough that its single output is not dust on the chain.
    const o = await w.orders.place({ connection: cashorder, amountMillis: 1_000_000n, payment: 'onchain' })
    expect(o.address).toBeDefined()
    // One output, rounded up to whole loki: more mints more, never a refund.
    const pay = ((o.payMillis + 999n) / 1000n) * 1000n
    const txid = await hooks.payAddress(o.address!, pay)
    expect(txid).toMatch(/^[0-9a-f]{64}$/)
    // An on-chain order stays open (not finished) until it expires or closes,
    // and may gain more bills (NIP-CO §Client Behavior): wait for the bill.
    await until('on-chain order minted', async () => (await w.orders.refresh(o.id)).bills.length > 0, { mine: true, tries: 20 })
    const done = await w.orders.get(o.id)
    expect(done.bills).toHaveLength(1)
    expect(done.finished).toBe(false)
  }, 600_000)
})

describe.skipIf(admin === undefined || !hasHooks)('lokihub: on-chain withdrawals', () => {
  let hub: CreatedApp
  let offered = false
  beforeAll(async () => {
    // Four withdrawals of a 21,000-loki bill each, plus a re-mint.
    hub = await createCashHub({ name: 'cashkit-e2e withdraw', perWalletMaxMloki: 50_000_000, fundLoki: 120_000 })
    try {
      await api('PUT', '/api/cash-withdraw/node', { enabled: true })
      const v = await api<{ offered: boolean }>('PUT', `/api/cash-hubs/${hub.id}/withdraw-terms`, { enabled: true, fee_base_millis: 1000, fee_ppm: 1000 })
      offered = v.offered
    } catch {
      offered = false
    }
  }, 60_000)
  afterAll(() => deleteCashHub(hub), 120_000)

  const fresh = async () => {
    const w = await openWallet()
    await w.identity.generate()
    await withHub(w, hub)
    const m = await w.mint({ hub: 'hub', amount: 21_000_000n, to: 'self' })
    const q = await w.withdraw.quote(m.holdingId!, await hooks.payerAddress())
    const sent = await w.withdraw.send(q, { confirm: async () => true })
    return { w, sent }
  }

  test('a payout is mined to final', async (ctx) => {
    if (!offered) ctx.skip()
    const { w, sent } = await fresh()
    await until('payout final', async () => (await w.withdraw.refresh(sent.id)).state === 'final', { mine: true, tries: 40 })
    const v = await w.withdraw.get(sent.id)
    expect(v.txid).toMatch(/^[0-9a-f]{64}$/)
    expect((await hooks.tx(v.txid!)).depth).toBeGreaterThanOrEqual(v.finalDepth)
  }, 900_000)

  test('a withheld payout stays unconfirmed, then confirms once released', async (ctx) => {
    if (!offered) ctx.skip()
    const { w, sent } = await fresh()
    let txid: string | undefined
    await until('payout broadcast', async () => {
      txid = (await w.withdraw.refresh(sent.id)).txid
      return txid !== undefined
    })
    await hooks.withhold(txid!, true)
    try {
      await hooks.mine(3)
      const st = (await w.withdraw.refresh(sent.id)).state
      expect(st === 'confirmed' || st === 'final').toBe(false)
    } finally {
      await hooks.withhold(txid!, false)
    }
    await until('payout final after release', async () => (await w.withdraw.refresh(sent.id)).state === 'final', { mine: true, tries: 40 })
  }, 900_000)

  test('a withdrawal whose reply was lost is found by settle(): the bill is spent once and the payout followed to final', async (ctx) => {
    if (!offered) ctx.skip()
    const storage = new MemoryStorage()
    const vault = new NoneVault()
    const first = await openWallet({ storage, vault })
    await first.identity.generate()
    await withHub(first, hub)
    const m = await first.mint({ hub: 'hub', amount: 21_000_000n, to: 'self' })
    const q = await first.withdraw.quote(m.holdingId!, await hooks.payerAddress())
    first.close()
    const lossy = await openWallet({ storage, vault, replyWaitMs: 1 }, false)
    const lost = await lossy.withdraw.send(q, { confirm: async () => true }).catch((e: unknown) => e)
    expect(lost).toBeInstanceOf(CashkitError)
    expect((lost as CashkitError).code).toBe('indeterminate')
    lossy.close()

    const w = await openWallet({ storage, vault }, false)
    const report = await settleAll(w)
    expect(report.open).toEqual([])
    const all = await w.withdraw.list()
    expect(all).toHaveLength(1)
    const v = all[0]!
    expect(v.id).toBe((lost as CashkitError).pendingCallId)
    expect(['accepted', 'broadcast', 'confirmed', 'final']).toContain(v.phase)
    expect((await w.balance()).holdings.held).toBe(0n)
    await until('payout final', async () => (await w.withdraw.refresh(v.id)).state === 'final', { mine: true, tries: 40 })
  }, 900_000)

  test('a cancel before broadcast re-mints the bill', async (ctx) => {
    if (!offered) ctx.skip()
    const { w, sent } = await fresh()
    const c = await w.withdraw.cancel(sent.id).catch((e: unknown) => e)
    if (c instanceof Error) ctx.skip() // already broadcast: the race is the Hub's to win
    await until('cancelled', async () => (await w.withdraw.refresh(sent.id)).state === 'cancelled', { mine: true, tries: 40 })
    await until('re-minted bill held', async () => (await w.balance({ refresh: true })).holdings.held > 0n, { mine: true, tries: 20 })
  }, 900_000)
})

describe.skipIf(admin === undefined || relayUrl === undefined)('lokihub: zaps, pocket and discovery on the Hub relay', () => {
  let hub: CreatedApp
  beforeAll(async () => {
    hub = await createCashHub({ name: 'cashkit-e2e social' })
  }, 60_000)
  afterAll(() => deleteCashHub(hub), 120_000)

  test('a Cash Zap is sent as a zap transfer and claimed by its recipient', async () => {
    const alice = await openWallet()
    await alice.identity.generate()
    await withHub(alice, hub)
    await alice.mint({ hub: 'hub', amount: 30_000n, to: 'self' })
    const bob = await openWallet()
    const bobId = await bob.identity.generate()
    const target = { e: 'ab'.repeat(32), k: '1' }
    const sent = await alice.zaps.send({ to: bobId.pubkey, amountMillis: 10_000n, target, relays: [relayUrl!] })
    expect(sent.eventId).toMatch(/^[0-9a-f]{64}$/)
    let zaps: Awaited<ReturnType<typeof bob.zaps.list>> = []
    await until('zap on the relay', async () => {
      zaps = await bob.zaps.list({ relays: [relayUrl!] })
      return zaps.length > 0
    })
    expect(zaps.length).toBeGreaterThanOrEqual(1)
    // Rule 9 against the Hub: approve the minter, then claim; the bill becomes Bob's holding.
    const zap = zaps.find((z) => z.amountMillis === 10_000n && z.status === 'issued') ?? zaps[0]!
    expect(zap.minter).toBeDefined()
    expect(zap.chain).toBeDefined()
    await bob.zaps.approveMinter(zap.minter!, zap.chain!)
    const [event] = await readEvents(pool, [relayUrl!], { ids: [zap.id] }, 5_000)
    expect(event).toBeDefined()
    const held = await bob.zaps.claim(event!, { relays: [relayUrl!] })
    expect(held.amount).toBe(10_000n)
    expect((await bob.balance()).holdings.held).toBe(10_000n)
    expect((await bob.zaps.list({ relays: [relayUrl!] })).find((z) => z.id === zap.id)?.status).toBe('claimed')
  }, 300_000)

  test('a second device with the same key reads the bill from the Cash Pocket', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32))
    const a = await openWallet({ signer: localSigner(key), pocket: syncPocket({ pool, relays: [relayUrl!] }) })
    await withHub(a, hub)
    await a.mint({ hub: 'hub', amount: 9_000n, to: 'self' })
    await a.pocket.sync()
    const b = await openWallet({ signer: localSigner(key), pocket: syncPocket({ pool, relays: [relayUrl!] }) })
    await until('pocket imported', async () => {
      const r = await b.pocket.sync()
      return r.imported.length > 0
    })
    expect((await b.balance()).holdings.held).toBe(9_000n)
  }, 300_000)

  test('a listed circle is found, tapped and joined', async (ctx) => {
    const w = await openWallet()
    const me = await w.identity.generate()
    const circle = await api<CreatedApp>('POST', '/api/apps', {
      name: 'cashkit-e2e listed circle',
      kind: 'circle_hub',
      maxAmount: 0,
      scopes: ['circle_wallet', 'get_info'],
      circleIdentityName: 'cashkit-e2e listed circle',
      circlePolicy: 'allowlist',
      circleMaxExpSecs: 86_400,
      circlePerWalletMaxMloki: 1_000_000,
    })
    try {
      await api('POST', '/api/transfers', { toAppId: circle.id, amountLoki: 100 })
      await api('PUT', `/api/apps/${circle.id}/circle/allowlist`, { pubkeys: [me.pubkey] })
      const before = await api<{ configured: string[] }>('GET', '/api/listing-relays').catch(() => undefined)
      if (before === undefined) ctx.skip()
      await api('PUT', '/api/listing-relays', { relays: [relayUrl] })
      const title = `cashkit e2e ${Date.now() % 1_000_000}`
      const l = await api<{ id: number; address: string }>('POST', '/api/listings', { circle_hub_app_id: circle.id, title, content: 'e2e' })
      try {
        let address: string | undefined
        await until('listing found', async () => {
          await w.discover.refresh({ relays: [relayUrl!], includeUnreviewed: true, chains: ['flokicoin'], testNetworks: true })
          const v = w.discover.list()
          const cards = [...v.sections.circles, ...(v.sections.unreviewed ?? [])]
          address = cards.find((c) => c.title === title)?.address
          return address !== undefined
        })
        const tap = await w.discover.tap(address!)
        expect(tap.outcome).toBe('show')
        const joined = await w.discover.join(address!, { maxAmount: 50_000n, maxReceive: 50_000n }, { confirmNoRecovery: async () => true, confirmUnverified: async () => false })
        expect(joined).toBeDefined()
      } finally {
        await api('POST', `/api/listings/${l.id}/unlist`).catch(() => undefined)
        await api('PUT', '/api/listing-relays', { relays: before!.configured }).catch(() => undefined)
      }
    } finally {
      const { children } = await api<{ children: { appId: number }[] }>('GET', `/api/apps/${circle.id}/circle/children?limit=0`).catch(() => ({ children: [] }))
      for (const c of children ?? []) await api('DELETE', `/api/apps/${circle.id}/circle/children/${c.appId}`).catch(() => undefined)
      await api('DELETE', `/api/apps/${circle.id}`).catch(() => undefined)
    }
  }, 300_000)
})
