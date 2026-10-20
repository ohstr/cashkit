// A private circle join end to end against a live Hub over real relays
// (design §11.3, NIP-CW §Private Join). Opt-in, with the admin API of
// test/e2e/admin.ts, and it commits real value on the test Hub:
//
//   just e2e
//
// Like cashctl's integration suite (integration/circle_fee_budget_test.go),
// it provisions a throwaway, self-funded, allowlist circle_hub, joins it,
// and deletes every child wallet and then the hub when it is done.
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { RelayWs } from '../../src/adapters/relay-ws.js'
import { MemoryStorage } from '../../src/adapters/storage-memory.js'
import { NoneVault } from '../../src/adapters/vault-none.js'
import { CashkitError, Wallet } from '../../src/wallet/index.js'
import { admin, api, type CreatedApp } from './admin.js'

const MAX = 100_000n // millis, within the hub's per-wallet cap and funding

describe.skipIf(admin === undefined)('live hub: private circle join', () => {
  const pool = new RelayWs()
  let hub: CreatedApp
  let wallet: Wallet

  beforeAll(async () => {
    // get_info carries the circle_wallet block, identity included, only with its own scope.
    hub = await api<CreatedApp>('POST', '/api/apps', {
      name: 'cashkit-e2e circle_hub',
      kind: 'circle_hub',
      maxAmount: 0,
      scopes: ['circle_wallet', 'get_info'],
      circleIdentityName: 'cashkit-e2e circle',
      circlePolicy: 'allowlist',
      circleMaxExpSecs: 86400,
      circlePerWalletMaxMloki: 1_000_000,
    })
    await api('POST', '/api/transfers', { toAppId: hub.id, amountLoki: 100 })
    wallet = await Wallet.open({ storage: new MemoryStorage(), vault: new NoneVault(), relays: pool })
    const me = await wallet.identity.generate()
    await api('PUT', `/api/apps/${hub.id}/circle/allowlist`, { pubkeys: [me.pubkey] })
  }, 60_000)

  afterAll(async () => {
    wallet?.close()
    pool.close()
    if (hub === undefined) return
    // Every child first: a circle_hub with children cannot be deleted.
    try {
      const { children } = await api<{ children: { appId: number }[] }>('GET', `/api/apps/${hub.id}/circle/children?limit=0`)
      for (const c of children) await api('DELETE', `/api/apps/${hub.id}/circle/children/${c.appId}`).catch(() => undefined)
    } finally {
      await api('DELETE', `/api/apps/${hub.id}`)
    }
  }, 120_000)

  test('joins over the private transport, then a second join is WALLET_EXISTS', async () => {
    expect(hub.circleHubToken).toMatch(/^circlehub1/)
    const joined = await wallet.joinCircle({ hub: hub.circleHubToken!, maxAmount: MAX, requirePrivate: true })
    expect(joined).toMatchObject({ private: true, maxAmount: MAX })
    expect(joined).not.toHaveProperty('fallbackReason')
    expect(joined.walletPubkey).toMatch(/^[0-9a-f]{64}$/)

    // The wallet it pairs over answers on its own connection.
    const ln = await wallet.lightning(joined.name)
    expect((await ln.getBalance()).balance).toBeGreaterThanOrEqual(0)

    const again = await wallet.joinCircle({ hub: hub.circleHubToken!, maxAmount: MAX, name: 'again', requirePrivate: true }).catch((e: unknown) => e)
    expect(again).toBeInstanceOf(CashkitError)
    expect([(again as CashkitError).code, (again as CashkitError).nwcCode]).toEqual(['exists', 'WALLET_EXISTS'])
  }, 300_000)
})
