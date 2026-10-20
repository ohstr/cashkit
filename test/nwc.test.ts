// NWC and Circle clients against an in-memory wallet service. Cases follow
// nmilat relay/client/nwc_test.go, nwc_relay_failover_test.go and
// nipcw/client/create_circle_wallet_test.go.
import { beforeEach, describe, expect, test } from 'vitest'
import {
  buildPairingURI,
  finalizeEvent,
  getPublicKey,
  KIND_CIRCLE_IDENTITY_PROOF,
  localSigner,
  nip04,
  nip44,
  toHex,
  verifyEvent,
  type NostrEvent,
} from '../src/core/index.js'
import { CircleClient, ClientError, NwcClient, WalletError } from '../src/client/index.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const R1 = 'wss://n1.test'
const R2 = 'wss://n2.test'
const walletKey = fill(0x21, 32)
const WALLET = getPublicKey(walletKey)
const appSecret = fill(0x22, 32)

type Handler = (method: string, params: unknown) => { result?: unknown; error?: { code: string; message: string } } | 'silent'

/** A wallet service: answers kind 23194 requests addressed to it. */
function startWallet(pool: MemoryRelayPool, handler: Handler, opts: { forge?: boolean } = {}) {
  const seen: { method: string; params: unknown; event: NostrEvent }[] = []
  pool.subscribe([R1, R2], { kinds: [23194], '#p': [WALLET] }, {
    onEvent: (e, relay) => {
      const ck = nip44.getConversationKey(walletKey, e.pubkey)
      const legacy = e.tags.some((t) => t[0] === 'encryption' && t[1] === 'nip04')
      const open = (c: string) => (legacy ? nip04.decrypt(c, walletKey, e.pubkey) : nip44.decrypt(c, ck))
      const seal = (body: string) => (legacy ? nip04.encrypt(body, walletKey, e.pubkey) : nip44.encrypt(body, ck))
      const req = JSON.parse(open(e.content)) as { method: string; params?: unknown }
      seen.push({ method: req.method, params: req.params, event: e })
      const a = handler(req.method, req.params)
      if (a === 'silent') return
      const body = JSON.stringify({ result_type: req.method, ...a })
      if (opts.forge) {
        // Someone else answering with the request's e tag, encrypted under their own key.
        const imposter = fill(0x33, 32)
        const fake = finalizeEvent({ kind: 23195, created_at: e.created_at, tags: [['p', e.pubkey], ['e', e.id]], content: nip44.encrypt(JSON.stringify({ result_type: req.method, result: { balance: 999 } }), nip44.getConversationKey(imposter, e.pubkey)) }, imposter)
        void pool.publish(relay, fake)
      }
      // Like most real wallets, a nip04 reply carries no encryption tag.
      const tags = legacy ? [['p', e.pubkey], ['e', e.id]] : [['p', e.pubkey], ['e', e.id], ['encryption', 'nip44_v2']]
      const reply = finalizeEvent({ kind: 23195, created_at: e.created_at, tags, content: seal(body) }, walletKey)
      void pool.publish(relay, reply)
    },
    onEose: () => {},
  })
  return seen
}

let pool: MemoryRelayPool
beforeEach(() => {
  pool = new MemoryRelayPool()
})

const pairing = (relays = [R1, R2]) => buildPairingURI(WALLET, relays, toHex(appSecret))

describe('NwcClient', () => {
  test('get_balance round trip over nip44_v2, signed by the connection key', async () => {
    const seen = startWallet(pool, () => ({ result: { balance: 21000 } }))
    const c = new NwcClient({ relays: pool }, pairing())
    expect(await c.getBalance()).toEqual({ balance: 21000 })
    expect(seen[0]!.method).toBe('get_balance')
    expect(seen[0]!.event.pubkey).toBe(getPublicKey(appSecret))
    expect(verifyEvent(seen[0]!.event)).toBe(true)
    expect(seen[0]!.event.tags).toEqual([['p', WALLET], ['encryption', 'nip44_v2']])
  })
  test('get_info types the circle_wallet block and keeps the other fields', async () => {
    startWallet(pool, () => ({ result: { alias: 'hub', methods: ['create_circle_wallet'], circle_wallet: { available_millis: 7, max_exp_secs: 60, fees_ppm: 1, circle_policy: 'follow_set', identity: '79'.repeat(32) } } }))
    expect(await new NwcClient({ relays: pool }, pairing()).getInfo()).toEqual({
      alias: 'hub',
      methods: ['create_circle_wallet'],
      circle_wallet: { available_millis: 7n, max_exp_secs: 60, fees_ppm: 1, circle_policy: 'follow_set', identity: '79'.repeat(32) },
    })
  })
  test('get_info without a circle_wallet block has none', async () => {
    startWallet(pool, () => ({ result: { alias: 'plain' } }))
    expect(await new NwcClient({ relays: pool }, pairing()).getInfo()).toEqual({ alias: 'plain' })
  })
  test('get_info refuses a malformed circle_wallet block', async () => {
    startWallet(pool, () => ({ result: { circle_wallet: { fees_ppm: 'lots' } } }))
    await expect(new NwcClient({ relays: pool }, pairing()).getInfo()).rejects.toThrow(/circle_wallet/)
  })
  test('bigint params travel as exact JSON numbers', async () => {
    const seen = startWallet(pool, () => ({ result: { invoice: 'lnfc1x' } }))
    await new NwcClient({ relays: pool }, pairing()).makeInvoice({ amount: 9007199254740993n, description: 'coffee' })
    expect(nip44.decrypt(seen[0]!.event.content, nip44.getConversationKey(walletKey, getPublicKey(appSecret)))).toBe(
      '{"method":"make_invoice","params":{"amount":9007199254740993,"description":"coffee"}}',
    )
  })
  test('a wallet error is a WalletError', async () => {
    startWallet(pool, () => ({ error: { code: 'INSUFFICIENT_BALANCE', message: 'no' } }))
    await expect(new NwcClient({ relays: pool }, pairing()).payInvoice('lnfc1x')).rejects.toMatchObject({ walletCode: 'INSUFFICIENT_BALANCE' })
    await expect(new NwcClient({ relays: pool }, pairing()).payInvoice('lnfc1x')).rejects.toBeInstanceOf(WalletError)
  })
  test('a forged reply from another key is ignored', async () => {
    startWallet(pool, () => ({ result: { balance: 21000 } }), { forge: true })
    expect(await new NwcClient({ relays: pool }, pairing()).getBalance()).toEqual({ balance: 21000 })
  })
  test('fails over when the first relay is down', async () => {
    pool.relay(R1).down = true
    startWallet(pool, () => ({ result: { balance: 1 } }))
    expect(await new NwcClient({ relays: pool }, pairing()).getBalance()).toEqual({ balance: 1 })
  })
  test('no response times out', async () => {
    startWallet(pool, () => 'silent')
    await expect(new NwcClient({ relays: pool }, pairing()).call('get_info', undefined, 200)).rejects.toMatchObject({ code: 'timeout' })
  })
  test('refuses pairing data with no usable relay', () => {
    expect(() => new NwcClient({ relays: pool }, { walletPubkey: WALLET, relays: [' '], secret: toHex(appSecret), extra: {} })).toThrow(ClientError)
  })
})

/** Publishes the wallet's kind 13194 info event with this encryption tag (none when undefined). */
async function publishInfo(encryption: string | undefined, key = walletKey) {
  const tags = encryption === undefined ? [] : [['encryption', encryption]]
  const info = finalizeEvent({ kind: 13194, created_at: 1_700_000_000, tags, content: 'get_balance pay_invoice' }, key)
  for (const r of [R1, R2]) await pool.publish(r, info)
}

describe('NwcClient encryption negotiation (NIP-47 §Encryption)', () => {
  const cases: [string, string | undefined, string][] = [
    ['both listed: nip44_v2', 'nip44_v2 nip04', 'nip44_v2'],
    ['nip44_v2 only', 'nip44_v2', 'nip44_v2'],
    ['nip04 only', 'nip04', 'nip04'],
    ['no encryption tag means nip04-only', undefined, 'nip04'],
  ]
  for (const [name, tag, want] of cases) {
    test(name, async () => {
      await publishInfo(tag)
      const seen = startWallet(pool, () => ({ result: { balance: 7 } }))
      const c = new NwcClient({ relays: pool }, pairing())
      expect(await c.encryption()).toBe(want)
      expect(await c.getBalance()).toEqual({ balance: 7 })
      expect(seen[0]!.event.tags).toContainEqual(['encryption', want])
    })
  }
  test('no info event at all: nip44_v2', async () => {
    startWallet(pool, () => ({ result: { balance: 1 } }))
    expect(await new NwcClient({ relays: pool }, pairing()).encryption()).toBe('nip44_v2')
  })
  test('an info event from anyone but the wallet is ignored', async () => {
    await publishInfo('nip04', fill(0x99, 32))
    startWallet(pool, () => ({ result: { balance: 1 } }))
    expect(await new NwcClient({ relays: pool }, pairing()).encryption()).toBe('nip44_v2')
  })
  test('a wallet listing neither scheme is refused', async () => {
    await publishInfo('nip99')
    await expect(new NwcClient({ relays: pool }, pairing()).getBalance()).rejects.toMatchObject({ code: 'bad_input' })
  })
  test('an explicit scheme skips negotiation', async () => {
    await publishInfo('nip04')
    const seen = startWallet(pool, () => ({ result: { balance: 1 } }))
    await new NwcClient({ relays: pool }, pairing(), 'nip44_v2').getBalance()
    expect(seen[0]!.event.tags).toContainEqual(['encryption', 'nip44_v2'])
  })
})

describe('CircleClient', () => {
  const member = localSigner(fill(0x24, 32))
  test('generates the connection key locally and sends only its pubkey', async () => {
    let request: Record<string, unknown> = {}
    startWallet(pool, (_m, params) => {
      request = params as Record<string, unknown>
      const details = JSON.stringify({ wallet_pubkey: '9a'.repeat(32), relays: ['wss://c1'], max_amount: 5000, expires_at: 1, fees_ppm: 0, budget_renewal: 'monthly' })
      return { result: { encrypted_details: nip44.encrypt(details, nip44.getConversationKey(walletKey, member.pubkey)) } }
    })
    const c = new CircleClient({ relays: pool }, pairing())
    const { wallet, connection } = await c.createCircleWallet({ signer: member, maxAmountMillis: 5000n, expirySeconds: 3600, budgetRenewal: 'monthly' })
    expect(request['connection_pubkey']).toBe(connection.pubkey)
    expect(JSON.stringify(request)).not.toContain(connection.secret)
    const proof = JSON.parse(request['identity_event'] as string) as NostrEvent
    expect(proof.kind).toBe(KIND_CIRCLE_IDENTITY_PROOF)
    expect(proof.tags).toEqual([['d', WALLET], ['connection', connection.pubkey]])
    expect(wallet.pairingUri).toBe(buildPairingURI('9a'.repeat(32), ['wss://c1'], connection.secret))
    expect(wallet.maxAmountMillis).toBe(5000n)
  })
  test('a refusal surfaces as WalletError', async () => {
    startWallet(pool, () => ({ error: { code: 'RESTRICTED', message: 'not a member' } }))
    await expect(new CircleClient({ relays: pool }, pairing()).createCircleWallet({ signer: member, maxAmountMillis: 1n, expirySeconds: 0 })).rejects.toMatchObject({ walletCode: 'RESTRICTED' })
  })
})
