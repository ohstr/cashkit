// NIP-CW member requests end to end against lokihub's regtest dev stack:
// the member signs (circles.memberRequest), the host submits through its own
// administration (lokihub: POST /api/circle-hubs/:id/member-requests {event}),
// and the wallet follows on its own keys (circles.watch for the
// notifications, circles.refresh for an unfreeze, circles.recover on a
// second device), then deletes the wallet with delete_circle_wallet.
// Opt-in, like circle.test.ts:
//
//   CASHKIT_E2E_CONFIG=<lokihub>/integration/config.local.yaml   admin_api and relay_url
//
// The rotation delay is 20 s; lokihub completes due rotations every 10 s, so
// the rotation takes up to about 30 s.
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { RelayWs } from '../../src/adapters/relay-ws.js'
import { MemoryStorage } from '../../src/adapters/storage-memory.js'
import { NoneVault } from '../../src/adapters/vault-none.js'
import { localSigner, type NostrEvent } from '../../src/core/index.js'
import { CashkitError, Wallet } from '../../src/wallet/index.js'
import { admin, api, until, type CreatedApp } from './admin.js'

const MAX = 100_000n
const DELAY = 20
const yes = () => Promise.resolve(true)

interface Submitted {
  readonly code?: string
  readonly message: string
  readonly action?: string
  readonly completes_at?: number
}

describe.skipIf(admin === undefined)('lokihub: member requests (rotate, freeze, unfreeze) and delete_circle_wallet', () => {
  const pool = new RelayWs()
  const key = crypto.getRandomValues(new Uint8Array(32))
  const opened: Wallet[] = []
  const stops: (() => void)[] = []
  let hub: CreatedApp
  let a: Wallet
  let name: string
  const alerts: string[] = []

  const submit = (ev: NostrEvent) => api<Submitted>('POST', `/api/circle-hubs/${hub.id}/member-requests`, { event: ev })
  const open = async () => {
    const w = await Wallet.open({ storage: new MemoryStorage(), vault: new NoneVault(), relays: pool, signer: localSigner(key) })
    opened.push(w)
    return w
  }

  beforeAll(async () => {
    hub = await api<CreatedApp>('POST', '/api/apps', {
      name: 'cashkit-e2e member requests',
      kind: 'circle_hub',
      maxAmount: 0,
      scopes: ['circle_wallet', 'get_info'],
      circleIdentityName: 'cashkit-e2e member requests',
      circlePolicy: 'allowlist',
      circleMaxExpSecs: 86_400,
      circlePerWalletMaxMloki: 1_000_000,
      circleRotationEnabled: true,
      circleRotationDelaySecs: DELAY,
    })
    await api('POST', '/api/transfers', { toAppId: hub.id, amountLoki: 100 })
    a = await open()
    await api('PUT', `/api/apps/${hub.id}/circle/allowlist`, { pubkeys: [(await a.identity.get())!.pubkey] })
    const joined = await a.circles.join(hub.circleHubToken!, { maxAmount: MAX, maxReceive: MAX }, { confirmUnverified: yes })
    name = joined.name
    expect(joined.rotatable).toBe(true)
    stops.push(await a.circles.watch(name, { onAlert: (x) => alerts.push(x) }))
  }, 300_000)

  afterAll(async () => {
    for (const s of stops) s()
    for (const w of opened) w.close()
    pool.close()
    if (hub === undefined) return
    try {
      const { children } = await api<{ children: { appId: number }[] }>('GET', `/api/apps/${hub.id}/circle/children?limit=0`)
      for (const c of children ?? []) await api('DELETE', `/api/apps/${hub.id}/circle/children/${c.appId}`).catch(() => undefined)
    } finally {
      await api('DELETE', `/api/apps/${hub.id}`).catch(() => undefined)
    }
  }, 120_000)

  test('freeze: wallet_frozen arrives, payments stop, the Hub answers FROZEN; an unfreeze is read back by refresh', async () => {
    const frozen = await submit(await a.circles.memberRequest(name, 'freeze'))
    expect(frozen.code).toBeUndefined()
    await until('wallet_frozen applied', () => Promise.resolve(alerts.includes('frozen_alert')), { tries: 20 })
    const refused = await a.lightning(name).catch((e: unknown) => e)
    expect(refused).toBeInstanceOf(CashkitError)
    expect((refused as CashkitError).nwcCode).toBe('FROZEN')
    expect(await a.circles.refresh(name)).toMatchObject({ frozen: true })

    const ev = await a.circles.memberRequest(name, 'unfreeze')
    expect((await submit(ev)).code).toBeUndefined()
    // Single use: the same request again is spent.
    expect((await submit(ev)).code).toBe('REQUEST_REUSED')
    expect(await a.circles.refresh(name)).toMatchObject({ frozen: false })
    expect((await (await a.lightning(name)).getBalance()).balance).toBeGreaterThanOrEqual(0)
  }, 300_000)

  test('rotate from the device that holds the wallet: rotation_pending on the old key, rotation_completed on the new one, which then answers', async () => {
    const ev = await a.circles.memberRequest(name, 'rotate')
    const newKey = ev.tags.find((t) => t[0] === 'connection')![1]!
    const r = await submit(ev)
    expect(r.code).toBeUndefined()
    expect(r.completes_at).toBeGreaterThan(0)
    // Nothing may be sent over the old key now: any request by it cancels the rotation.
    expect((await a.circles.refresh(name).catch((e: unknown) => e)) as CashkitError).toMatchObject({ code: 'usage', reason: 'rotation_pending' })
    await until('rotation_pending applied', () => Promise.resolve(alerts.includes('rotation_alert')), { tries: 20 })
    expect((await a.circles.list())[0]!.rotation).toMatchObject({ newConnectionPubkey: newKey, completesAt: r.completes_at })
    await until('rotation_completed applied', () => Promise.resolve(alerts.includes('rotation_completed')), { tries: 30 })
    const [c] = await a.circles.list()
    expect(c).toMatchObject({ connectionPubkey: newKey, frozen: false, moved: false })
    expect(c!.rotation).toBeUndefined()
    expect((await (await a.lightning(name)).getBalance()).balance).toBeGreaterThanOrEqual(0)
  }, 300_000)

  test('a lost device: a new device with the same identity rotates the wallet by its pubkey and recovers it; the old one is alerted and marked moved', async () => {
    const walletPubkey = (await a.circles.list())[0]!.walletPubkey
    const b = await open()
    const { event, newConnectionSecret } = await b.circles.memberRequestFor(hub.circleHubToken!, walletPubkey, 'rotate', { confirmUnverified: yes })
    expect(newConnectionSecret).toMatch(/^[0-9a-f]{64}$/)
    const before = alerts.length
    const r = await submit(event)
    expect(r.code).toBeUndefined()
    await until('the old device alerted', () => Promise.resolve(alerts.slice(before).includes('rotation_alert')), { tries: 20 })
    expect(await b.circles.recover(hub.circleHubToken!, newConnectionSecret!, { confirmUnverified: yes })).toMatchObject({ state: 'pending', retryAt: r.completes_at })
    let done: Awaited<ReturnType<typeof b.circles.recover>> | undefined
    await until('recovered', async () => {
      done = await b.circles.recover(hub.circleHubToken!, newConnectionSecret!, { confirmUnverified: yes })
      return done.state === 'done'
    }, { tries: 30 })
    expect(done).toMatchObject({ state: 'done', wallet: { walletPubkey } })
    const bn = (await b.circles.list())[0]!.name
    expect((await (await b.lightning(bn)).getBalance()).balance).toBeGreaterThanOrEqual(0)
    await until('the old device marks it moved', async () => (await a.circles.list())[0]!.moved, { tries: 10 })
  }, 300_000)

  test('delete_circle_wallet at dust from the device that holds it: the connection goes, and the Hub holds the wallet no more', async () => {
    const b = opened[1]!
    const [c] = await b.circles.list()
    let dust = -1n
    await b.circles.delete(c!.name, ({ dust: d }) => {
      dust = d
      return yes()
    })
    expect(dust).toBeGreaterThanOrEqual(0n)
    expect(await b.circles.list()).toEqual([])
    // A member request for it now names a wallet the Hub no longer holds.
    const { event } = await b.circles.memberRequestFor(hub.circleHubToken!, c!.walletPubkey, 'freeze', { confirmUnverified: yes })
    expect((await submit(event)).code).toBe('NOT_FOUND')
  }, 300_000)
})
