// The wallet engine end to end against a live Hub over real relays (design
// §11.3). Opt-in, and it moves real value on the test Hub:
//
//   CASHKIT_E2E_ADMIN_URL=http://...   the Hub's admin API
//   CASHKIT_E2E_ADMIN_TOKEN=...        an admin API token (never logged)
//
// or CASHKIT_E2E_CONFIG=<path to cashctl/integration/config.local.yaml>,
// which carries both under admin_api.
//
//   just e2e
//
// Like cashctl's integration suite (integration/cash_test.go setUpCashHub),
// it provisions a throwaway self-funded cash_hub, mints a cash bill on it,
// and deletes every child wallet and then the hub when it is done.
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { NwcClient } from '../../src/client/index.js'
import { RelayWs } from '../../src/adapters/relay-ws.js'
import { MemoryStorage } from '../../src/adapters/storage-memory.js'
import { NoneVault } from '../../src/adapters/vault-none.js'
import { Wallet } from '../../src/wallet/index.js'
import { admin, api, type CreatedApp } from './admin.js'

interface MintResult {
  readonly cash_token: string
  readonly recipients: readonly { readonly cash_secret?: string }[]
}

const MINT = 50_000n // millis
const SEND = 20_000n

describe.skipIf(admin === undefined)('live hub: wallet engine', () => {
  const pool = new RelayWs()
  let hub: CreatedApp
  const wallets: Wallet[] = []

  const openWallet = async (): Promise<Wallet> => {
    const w = await Wallet.open({ storage: new MemoryStorage(), vault: new NoneVault(), relays: pool })
    await w.identity.generate()
    await w.connections.add('hub', hub.pairingUri)
    wallets.push(w)
    return w
  }

  beforeAll(async () => {
    // cashctl integration/cash_test.go setUpCashHubOpts, with its defaults.
    hub = await api<CreatedApp>('POST', '/api/apps', {
      name: 'cashkit-e2e cash_hub',
      kind: 'cash_hub',
      maxAmount: 0,
      scopes: ['cash_hub', 'pay_invoice', 'make_invoice', 'get_balance'],
      cashPerWalletMaxMloki: 10_000_000,
      cashMaxExpSecs: 3600,
    })
    await api('POST', '/api/transfers', { toAppId: hub.id, amountLoki: 2000 })
  }, 60_000)

  afterAll(async () => {
    for (const w of wallets) w.close()
    pool.close()
    if (hub === undefined) return
    // Every child wallet first: a cash_hub with children cannot be deleted.
    try {
      const { claims } = await api<{ claims: { wallet_app_id: number }[] }>('GET', `/api/apps/${hub.id}/cash-wallets?limit=0`)
      for (const id of new Set(claims.map((c) => c.wallet_app_id))) {
        await api('DELETE', `/api/apps/${hub.id}/cash-wallets/${id}`).catch(() => undefined)
      }
    } finally {
      await api('DELETE', `/api/apps/${hub.id}`)
    }
  }, 120_000)

  test('mint, receive, status, send as cash, receive the note, redeem everything back', async () => {
    // cashctl integration/campaign_helpers_test.go mintCashGift.
    const minter = new NwcClient({ relays: pool }, hub.pairingUri)
    const res = await minter.call('mint_cash', { recipients: [{ identity_type: 'cash', amount_millis: Number(MINT) }] })
    expect(res.error).toBeUndefined()
    const minted = res.result as MintResult
    const secret = minted.recipients[0]?.cash_secret
    expect(secret).toMatch(/^[0-9a-f]{64}$/)

    const alice = await openWallet()
    const got = await alice.receive(`${minted.cash_token}#${secret}`)
    expect(got.received).toBe(true)
    if (!got.received) return
    expect(got.holding.amount).toBe(MINT)

    const st = await alice.status()
    expect(st.firstError).toBeUndefined()
    expect(st.outcomes).toMatchObject([{ ok: true, state: 'available', amount: MINT }])

    const sent = await alice.send({ amount: SEND })
    expect(sent.sent).toBe(SEND)
    expect(sent.cashNote).toMatch(/#[0-9a-f]{64}$/)
    expect(sent.remainder?.amount).toBe(MINT - SEND)

    const bob = await openWallet()
    const note = await bob.receive(sent.cashNote!)
    expect(note.received).toBe(true)
    expect((await bob.balance()).holdings.held).toBe(SEND)

    // The Hub now reports the sender's note as claimed.
    const [handoff] = await alice.handoffs({ refresh: true })
    expect(handoff?.status).toBe('claimed')

    for (const w of [alice, bob]) {
      const r = await w.redeem({ all: true, into: 'hub' })
      expect(r.firstError).toBeUndefined()
      expect((await w.balance()).holdings.held).toBe(0n)
    }
  }, 600_000)
})
