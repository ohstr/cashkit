// A bill bound to a NIP-IC connection key, end to end against lokihub's
// regtest dev stack (NIP-CASH §Scoping the Roster, SG-1 (a)): the Hub
// answers the holder's cash_status NOT_FOUND, so the bill is received
// unverified at its attested amount (statusUnreadable), status() reads it
// `unreadable`, a redeem or an on-chain withdrawal is refused before
// anything is sent, and a send still works. Opt-in, like lokihub.test.ts:
//
//   CASHKIT_E2E_CONFIG=<lokihub>/integration/config.local.yaml
//
// The Identity Authority is a throwaway key the test registers as trusted
// (POST /api/identity-authorities) and revokes after; its attestation
// (kind 35522) is built here, as cashctl's integration/local_ia_test.go does.
import { sha256 } from '@noble/hashes/sha2.js'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { RelayWs } from '../../src/adapters/relay-ws.js'
import { MemoryStorage } from '../../src/adapters/storage-memory.js'
import { NoneVault } from '../../src/adapters/vault-none.js'
import { connectionKeyFromAttested, finalizeEvent, getPublicKey, toHex, type NostrEvent } from '../../src/core/index.js'
import { CashkitError, Wallet } from '../../src/wallet/index.js'
import type { WalletDeps } from '../../src/wallet/ports.js'
import { admin, api, createCashHub, deleteCashHub, hooks, type CreatedApp } from './admin.js'

const pool = new RelayWs()
const opened: Wallet[] = []

async function openWallet(o: Partial<WalletDeps> = {}): Promise<Wallet> {
  const w = await Wallet.open({ storage: new MemoryStorage(), vault: new NoneVault(), relays: pool, ...o })
  opened.push(w)
  return w
}

/** A canonical Discord user id (a snowflake: no leading zero). */
const userId = () => `7${Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b % 10).join('')}`

function attestation(iaKey: Uint8Array, user: string, holder: string): NostrEvent {
  const now = Math.floor(Date.now() / 1000)
  return finalizeEvent(
    {
      kind: 35522,
      created_at: now,
      tags: [
        ['d', toHex(sha256(new TextEncoder().encode(`discord:${user}`)))],
        ['p', holder],
        ['platform', 'discord'],
        ['evidence', JSON.stringify({ version: 1, auth_type: 'integration_test', user_id: user, username: 'cashkit-e2e', verified_at: now })],
        ['expiration', String(now + 30 * 86_400)],
      ],
      content: '',
    },
    iaKey,
  )
}

afterAll(() => {
  for (const w of opened) w.close()
  pool.close()
})

describe.skipIf(admin === undefined)('lokihub: a connection-key holder (SG-1: status not readable)', () => {
  let hub: CreatedApp
  const iaKey = crypto.getRandomValues(new Uint8Array(32))
  const ia = getPublicKey(iaKey)
  beforeAll(async () => {
    hub = await createCashHub({ name: 'cashkit-e2e connection key', perWalletMaxMloki: 50_000_000, fundLoki: 30_000 })
    await api('POST', '/api/identity-authorities', { pubkey: ia, name: 'cashkit-e2e IA' })
  }, 60_000)
  afterAll(async () => {
    await api('DELETE', `/api/identity-authorities/${ia}`).catch(() => undefined)
    await deleteCashHub(hub)
  }, 120_000)

  /** alice mints and sends `amount` to a fresh Discord account; bob, attested for it, receives the bill. */
  async function delivered(amount: bigint) {
    const alice = await openWallet()
    await alice.identity.generate()
    await alice.connections.add('hub', hub.cashHubToken!, { confirmUnverified: async () => false })
    await alice.mint({ hub: 'hub', amount, to: 'self' })
    const user = userId()
    expect(connectionKeyFromAttested('discord', user)).toMatch(/^[0-9a-f]{64}$/)
    const sent = await alice.send({ amount, to: `connection:discord:${user}:${ia}` })
    expect(sent.sent).toBe(amount)
    expect(sent.recipientToken).toBeDefined()
    const bob = await openWallet()
    const me = await bob.identity.generate()
    const r = await bob.receive(sent.recipientToken!, { attestation: attestation(iaKey, user, me.pubkey) })
    if (!r.received) throw new Error('not received')
    return { bob, r }
  }

  test('received unverified at its attested amount; status() reads it unreadable, never spent or gone', async () => {
    const { bob, r } = await delivered(20_000n)
    expect(r).toMatchObject({ received: true, statusUnreadable: true })
    expect(r.holding).toMatchObject({ status: 'held', mode: 'connection_key', amount: 20_000n, verified: false })
    const st = await bob.status({ holdings: [r.holding.id] })
    expect(st.outcomes[0]).toMatchObject({ ok: true, holdingId: r.holding.id, state: 'unreadable' })
  }, 300_000)

  test('a redeem is refused before anything is sent, and the bill stays held', async () => {
    const { bob, r } = await delivered(20_000n)
    await bob.connections.add('ln', hub.pairingUri)
    const out = await bob.redeem({ holdings: [r.holding.id] }).catch((x: unknown) => x as CashkitError)
    const e = 'firstError' in (out as object) ? (out as { firstError?: CashkitError }).firstError : (out as CashkitError)
    expect(e).toMatchObject({ code: 'usage', reason: 'status_unreadable' })
    expect((await bob.balance()).holdings.held).toBe(20_000n)
  }, 300_000)

  test('an on-chain withdrawal is refused before anything is quoted', async (ctx) => {
    // A valid regtest address comes from the payer hook.
    if (!(await hooks.available())) ctx.skip()
    const { bob, r } = await delivered(21_000_000n)
    expect(await bob.withdraw.terms(r.holding.id).catch((x: unknown) => x)).toMatchObject({ code: 'usage', reason: 'status_unreadable' })
    const e = await bob.withdraw.quote(r.holding.id, await hooks.payerAddress()).catch((x: unknown) => x)
    expect(e).toBeInstanceOf(CashkitError)
    expect(e).toMatchObject({ code: 'usage', reason: 'status_unreadable' })
    expect((await bob.balance()).holdings.held).toBe(21_000_000n)
  }, 300_000)

  test('a send still works: split to a pubkey, the remainder stays bound to the account, the recipient reads its bill', async () => {
    const { bob, r } = await delivered(20_000n)
    const carol = await openWallet()
    const c = await carol.identity.generate()
    const sent = await bob.send({ amount: 8_000n, to: c.pubkey, holdings: [r.holding.id] })
    expect(sent.sent).toBe(8_000n)
    expect(sent.remainder).toMatchObject({ mode: 'connection_key', status: 'held', amount: 12_000n })
    const got = await carol.receive(sent.recipientToken!)
    expect(got).toMatchObject({ received: true, holding: { amount: 8_000n } })
    expect((await carol.status()).outcomes).toMatchObject([{ ok: true, state: 'available', amount: 8_000n }])
  }, 300_000)
})
