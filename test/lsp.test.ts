// NIP-LSP announcements. Each case mirrors nmilat niplsp's T23 case named;
// K-LSP-1..6 are the ids frozen in niplsp/parse_test.go and build_test.go.
import { describe, expect, test } from 'vitest'
import { finalizeEvent, getEventHash, type NostrEvent } from '../src/core/index.js'
import {
  AnnouncementError,
  checkLive,
  fromLspsInfo,
  fromLspsName,
  LspSeen,
  newAnnouncement,
  newestAnnouncements,
  nodeIds,
  parseAnnouncement,
  parseLsps1Info,
  parseLsps2Menu,
  signingPayload,
  toLspsName,
  type LspFields,
} from '../src/client/index.js'

const KEY1 = Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0))
const KEY1_PUB = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const KEY2_PUB = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
const CREATED = 1792713600
const NOW = CREATED + 10
const K_LSP_1 = 'd87841c795e01ba75208a603bc0bdfe7f2015ab3876860501e2f09d0c257a45b'
const K_LSP_2 = '4888cfb893cec3cd2ab49f26504f9914e841933a8e3f3e5725eb27313b951158'
const K_LSP_3 = '9e63298039c075dc61ff438ff8b642ed7463d15f6d9e10b14f738f9cddf1c0ba'
const K_LSP_4 = 'b9d668ad9b8dc89a01df7fe8f8c429204e946110c9a8768bafbf76c9503d4b8c'
const K_LSP_5 = 'c49b0d6188e1829ffd507ee217589a05cd4eeaed22014bcf3a57d41c58b9adff'
const K_LSP_6 = 'b9601b6f837a62e054285d0b2c62ece02d3db65be8f1d27c2ea107806ed3b974'
const mainnet = { chains: ['bitcoin'], networks: ['mainnet'], now: NOW }

const example = (): LspFields => ({
  nodeKey: KEY1_PUB,
  addrs: ['vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:9735', '203.0.113.7:9735'],
  chain: 'bitcoin',
  network: 'mainnet',
  status: 'open',
  expiration: 1795305600,
  title: "Alice's Liquidity",
  content: 'Inbound channels and just-in-time channels.',
  website: 'https://lsp.example.com',
  operator: { pubkey: KEY2_PUB, relay: 'wss://relay.example.com' },
  languages: ['en'],
  relays: ['wss://relay.example.com'],
  protocols: [1, 2, 5],
  lsps1: [
    { name: 'min_required_channel_confirmations', value: '0' },
    { name: 'min_funding_confirms_within_blocks', value: '6' },
    { name: 'supports_zero_channel_reserve', value: 'false' },
    { name: 'max_channel_expiry_blocks', value: '12960' },
    { name: 'min_initial_client_balance', value: '0' },
    { name: 'max_initial_client_balance', value: '1000000' },
    { name: 'min_initial_lsp_balance', value: '0' },
    { name: 'max_initial_lsp_balance', value: '10000000' },
    { name: 'min_channel_balance', value: '100000' },
    { name: 'max_channel_balance', value: '10000000' },
  ],
  lsps2: [{ minFeeMillis: 2000000n, proportional: 4000n, minLifetime: 4320n, maxClientToSelfDelay: 2016n, minPaymentSizeMillis: 10000000n, maxPaymentSizeMillis: 4000000000n }],
  lsps5: [{ name: 'max_webhooks', value: '10' }],
})

const signed = (f: LspFields): NostrEvent => {
  const u = newAnnouncement(f, CREATED)
  return finalizeEvent({ kind: u.kind, created_at: u.created_at, tags: u.tags, content: u.content }, KEY1)
}
const withTags = (change: (t: string[][]) => string[][]): NostrEvent => {
  const u = newAnnouncement(example(), CREATED)
  return finalizeEvent({ kind: u.kind, created_at: CREATED, tags: change(u.tags.map((t) => [...t])), content: u.content }, KEY1)
}
const set = (k: string, v: string) => (t: string[][]) => t.map((x) => (x[0] === k ? [k, v] : x))
const stepOf = (f: () => unknown): number => {
  try {
    f()
  } catch (err) {
    if (err instanceof AnnouncementError) return err.step
    throw err
  }
  return 0
}

describe('building (T23-01, T23-02)', () => {
  test('K-LSP-1: the NIP example, byte for byte; a node id gives the same event', () => {
    const ev = newAnnouncement(example(), CREATED)
    expect(ev.id).toBe(K_LSP_1)
    expect(ev.tags.find((t) => t[0] === 'alt')).toEqual(['alt', "Lightning service provider: Alice's Liquidity"])
    expect(newAnnouncement({ ...example(), nodeKey: `02${KEY1_PUB.toUpperCase()}` }, CREATED).id).toBe(K_LSP_1)
    expect(getEventHash(ev)).toBe(K_LSP_1)
  })
  test.each([
    ['protocol 2 without a fee row', { lsps2: [] }],
    ['lsps1 without protocol 1', { protocols: [2, 5] }],
    ['an option twice', { lsps1: [{ name: 'max_webhooks', value: '1' }, { name: 'max_webhooks', value: '2' }] }],
    ['an http website', { website: 'http://x.example' }],
    ['a bad addr', { addrs: ['example.com:9735'] }],
    ['an expiration past 30 days', { expiration: CREATED + 2_592_001 }],
    ['content over 280', { content: 'x'.repeat(281) }],
  ] as const)('refuses %s', (_, change) => {
    expect(() => newAnnouncement({ ...example(), ...(change as Partial<LspFields>) }, CREATED)).toThrow()
  })
  test('the node key signs only kind 10735', () => {
    expect(() => signingPayload({ kind: 1, pubkey: KEY1_PUB, created_at: 1, tags: [], content: '' })).toThrow(/only kind 10735/)
  })
})

describe('parsing (T23-03..T23-09)', () => {
  test('K-LSP-2: closed parses and is not shown; paused is shown but not selling', () => {
    const ev = signed({ ...example(), status: 'closed' })
    expect(ev.id).toBe(K_LSP_2)
    expect(parseAnnouncement(ev, mainnet)).toMatchObject({ shown: false, selling: false })
    expect(parseAnnouncement(signed({ ...example(), status: 'paused' }), mainnet)).toMatchObject({ shown: true, selling: false })
    expect(parseAnnouncement(signed(example()), mainnet)).toMatchObject({ shown: true, selling: true, displayTitle: "Alice's Liquidity" })
  })
  test('K-LSP-3..6: one fixture per step', () => {
    const k3 = withTags((t) => t.filter((x) => x[0] !== 'network'))
    const k4 = withTags((t) => {
      const i = t.findIndex((x) => x[0] === 'lsps1' && x[1] === 'max_channel_balance')
      return [...t.slice(0, i + 1), ['lsps1', 'max_channel_balance', '20000000'], ...t.slice(i + 1)]
    })
    const k5 = withTags(set('expiration', '1795305601'))
    const k6 = withTags(set('network', 'regtest'))
    expect([k3.id, k4.id, k5.id, k6.id]).toEqual([K_LSP_3, K_LSP_4, K_LSP_5, K_LSP_6])
    expect([k3, k4, k5, k6].map((e) => stepOf(() => parseAnnouncement(e, mainnet)))).toEqual([2, 3, 4, 5])
  })
  test('step 1: a tampered event or another kind', () => {
    const ev = signed(example())
    expect(stepOf(() => parseAnnouncement({ ...ev, content: 'Cheaper than anyone.' }, mainnet))).toBe(1)
    expect(stepOf(() => parseAnnouncement(finalizeEvent({ kind: 10736, created_at: CREATED, tags: ev.tags, content: '' }, KEY1), mainnet))).toBe(1)
    expect(stepOf(() => parseAnnouncement(ev, { ...mainnet, now: 1795305601 }))).toBe(4)
  })
  test('unknown tags, unknown options and step data without its protocol are ignored (T23-08)', () => {
    const ev = withTags((t) => [...t, ['lsps1', 'future_option', '7'], ['unknown', 'x'], ['l', 'xx-long', 'other-ns']])
    const a = parseAnnouncement(ev, mainnet)
    expect(a.lsps1.map((o) => o.name)).not.toContain('future_option')
    const no5 = withTags((t) => t.filter((x) => !(x[0] === 'protocol' && x[1] === '5')))
    expect(parseAnnouncement(no5, mainnet).lsps5).toEqual([])
  })
  test('newest only, never a fallback to an older one (T23-09)', () => {
    const seen = new LspSeen({ chains: ['bitcoin'], networks: ['mainnet'], now: () => NOW })
    const older = signed(example())
    const newerBad = finalizeEvent({ kind: 10735, created_at: CREATED + 1, tags: older.tags.filter((t) => t[0] !== 'network'), content: '' }, KEY1)
    expect(newestAnnouncements(seen, [older]).size).toBe(1)
    seen.offer(newerBad)
    expect(seen.current(KEY1_PUB)).toBeUndefined()
    expect(seen.offer(older)).toBeUndefined()
    expect(seen.current(KEY1_PUB)).toBeUndefined()
  })
})

describe('LSPS answers and the live check (T23-10..T23-12)', () => {
  test('both unit dialects map to the announced names', () => {
    expect(fromLspsName('max_channel_balance_sat')).toEqual({ name: 'max_channel_balance', unit: 'base' })
    expect(fromLspsName('min_fee_mloki')).toEqual({ name: 'min_fee', unit: 'millis' })
    expect(toLspsName('min_fee', 'millis', 'loki')).toBe('min_fee_mloki')
    expect(parseLsps1Info({ options: { min_channel_balance_loki: '100000', supports_zero_channel_reserve: true } })).toEqual([
      { name: 'supports_zero_channel_reserve', value: 'true' },
      { name: 'min_channel_balance', value: '100000' },
    ])
    const raw = { opening_fee_params_menu: [{ min_fee_msat: '2000000', proportional: 4000, min_lifetime: 4320, max_client_to_self_delay: 2016, min_payment_size_msat: '10000000', max_payment_size_msat: '4000000000', valid_until: 'x', promise: 'y' }] }
    expect(parseLsps2Menu(raw)).toEqual(example().lsps2)
    const f = fromLspsInfo({ protocols: [1, 2], lsps1Info: { min_channel_balance_sat: 100000 }, lsps2Menu: raw, meta: { nodeKey: KEY1_PUB, addrs: ['203.0.113.7:9735'], chain: 'bitcoin', network: 'mainnet' } })
    expect(f.lsps1).toEqual([{ name: 'min_channel_balance', value: '100000' }])
    expect(() => fromLspsInfo({ protocols: [2], meta: { nodeKey: KEY1_PUB, addrs: [], chain: 'bitcoin', network: 'mainnet' } })).toThrow()
  })
  test('checkLive: a missing protocol makes it unusable; worse and better values for the buyer', () => {
    const a = parseAnnouncement(signed(example()), mainnet)
    expect(checkLive(a, { protocols: [1, 2] })).toMatchObject({ usable: false, missingProtocol: [5] })
    const live = checkLive(a, { lsps1: [...example().lsps1!.filter((o) => o.name !== 'min_channel_balance'), { name: 'min_channel_balance', value: '200000' }], lsps2Menu: [{ ...example().lsps2![0]!, proportional: 3000n }] })
    expect(live.worse).toBe(true)
    expect(live.fields.find((f) => f.field === 'min_channel_balance')?.verdict).toBe('worse')
    expect(live.fields.find((f) => f.field === 'lsps2_fee[0].proportional')?.verdict).toBe('better')
  })
  test('node ids are 02 and 03 followed by the key', () => {
    expect(nodeIds(KEY1_PUB)).toEqual([`02${KEY1_PUB}`, `03${KEY1_PUB}`])
  })
})
