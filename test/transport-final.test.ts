// The private transport on the final NIP-CASH rules: the tag-form
// announcement, servable methods and bearer shapes, the verification
// budget, padding capped at max_bytes, freshness by max_request_age,
// response chunks that never throw for a bad item, `detail`, and proof of
// work. Literals are the NIP's (§The Hub Announcement, §Envelopes, §Bearer
// Items, §Proof of Work). Cases follow nmilat nipcash/transport
// {announcement,envelope,validate,response,pow}_test.go.
import { describe, expect, test } from 'vitest'
import { finalizeEvent, getPublicKey, localSigner, nip44, powDifficulty, toHex, type NostrEvent } from '../src/core/index.js'
import {
  announcementTags,
  bearerShapeOK,
  buildBillProof,
  buildItemProof,
  checkFreshness,
  conversationKeyFor,
  decodeResponse,
  decodeResponseChunk,
  DEFAULT_LIMITS,
  encodeEnvelope,
  encodeResponse,
  hubUsableForBills,
  isPowRejection,
  isServableMethod,
  MAX_POW_AHEAD,
  paddedSize,
  paramsHash,
  parseAnnouncement,
  parsePowRejection,
  relayPowMinimum,
  toJSONText,
  validAddr,
  validateEnvelope,
  verificationCost,
  wrapRequestPow,
  type Item,
  type Limits,
  type ProofBinding,
} from '../src/transport/index.js'
import { fill } from './helpers.js'

const NOW = 1_760_000_000
const nodeKey = fill(0x0a, 32)
const NODE = getPublicKey(nodeKey)
const INBOX = getPublicKey(fill(0x0b, 32))
const LIMITS: Limits = { maxEnvelopeBytes: 16384, maxItems: 16, maxConsolidateSources: 8, padBucketBytes: 2048, maxVerifyBudget: 64 }
const ONION = `${'a'.repeat(56)}.onion:9735`

const announce = (tags: string[][], key = nodeKey, createdAt = NOW): NostrEvent => finalizeEvent({ kind: 11190, created_at: createdAt, tags, content: '' }, key)
const nipExample = () => announcementTags({ inbox: INBOX, limits: LIMITS, maxRequestAge: 300, relays: ['wss://relay.example.com'], addrs: [ONION] })

describe('T-302 the tag-form announcement', () => {
  test('the NIP example parses: inbox, limits, H, relays in order, addr for display', () => {
    const a = parseAnnouncement(announce(nipExample()), NODE)
    expect(a).toEqual({ inbox: INBOX, limits: LIMITS, maxRequestAge: 300, relays: ['wss://relay.example.com'], addrs: [ONION], createdAt: NOW })
    expect(hubUsableForBills(a)).toBe(true)
  })
  test('the inbox may be the author itself', () => {
    const tags = nipExample().map((t) => (t[0] === 'inbox' ? ['inbox', NODE] : t))
    expect(parseAnnouncement(announce(tags), NODE).inbox).toBe(NODE)
  })
  test.each<[string, (t: string[][]) => string[][]]>([
    ['no inbox', (t) => t.filter((x) => x[0] !== 'inbox')],
    ['two inbox tags', (t) => [...t, ['inbox', INBOX]]],
    ['a malformed inbox', (t) => t.map((x) => (x[0] === 'inbox' ? ['inbox', INBOX.toUpperCase()] : x))],
    ['two limits of one name', (t) => [...t, ['limit', 'max_items', '8']]],
    ['a limit with a leading zero', (t) => t.map((x) => (x[1] === 'max_items' ? ['limit', 'max_items', '016'] : x))],
    ['a negative limit', (t) => t.map((x) => (x[1] === 'max_items' ? ['limit', 'max_items', '-1'] : x))],
    ['a malformed r', (t) => [...t, ['r', 'not a url']]],
    ['a missing max_items (no default)', (t) => t.filter((x) => x[1] !== 'max_items')],
    ['pad bucket 2047', (t) => t.map((x) => (x[1] === 'pad_bucket_bytes' ? ['limit', 'pad_bucket_bytes', '2047'] : x))],
  ])('rejects %s', (_, change) => {
    expect(() => parseAnnouncement(announce(change(nipExample())), NODE)).toThrow()
  })
  test('ignores an unknown tag, an unknown limit, a malformed addr and the content', () => {
    const tags = [...nipExample(), ['x', 'y'], ['limit', 'max_future', '7'], ['addr', 'example.com:9735']]
    const ev = finalizeEvent({ kind: 11190, created_at: NOW, tags, content: '{"v":2,"inbox":"zz"}' }, nodeKey)
    const a = parseAnnouncement(ev, NODE)
    expect(a.addrs).toEqual([ONION])
    expect(a.limits).toEqual(LIMITS)
  })
  test('pad bucket 2048 is accepted', () => {
    expect(parseAnnouncement(announce(nipExample()), NODE).limits.padBucketBytes).toBe(2048)
  })
  test('a foreign signature is rejected', () => {
    expect(() => parseAnnouncement(announce(nipExample(), fill(0x0c, 32)), NODE)).toThrow(expect.objectContaining({ code: 'announcement_author' }))
  })
  test.each<[string, string | undefined, boolean]>([
    ['absent', undefined, false],
    ['0', '0', false],
    ['59', '59', false],
    ['60', '60', true],
    ['86401', '86401', true],
  ])('max_request_age %s: parses; usable for bill-creating calls = %s', (_, h, usable) => {
    const tags = nipExample().filter((t) => t[1] !== 'max_request_age')
    if (h !== undefined) tags.push(['limit', 'max_request_age', h])
    const a = parseAnnouncement(announce(tags), NODE)
    expect(hubUsableForBills(a)).toBe(usable)
  })
  test('a max_request_age as a non-number is a malformed limit', () => {
    const tags = [...nipExample().filter((t) => t[1] !== 'max_request_age'), ['limit', 'max_request_age', 'soon']]
    expect(() => parseAnnouncement(announce(tags), NODE)).toThrow()
  })
  test('max_bytes 70000 reads as 65535, the NIP-44 ceiling', () => {
    const tags = nipExample().map((t) => (t[1] === 'max_bytes' ? ['limit', 'max_bytes', '70000'] : t))
    expect(parseAnnouncement(announce(tags), NODE).limits.maxEnvelopeBytes).toBe(65535)
  })
  test('addr forms: IPv4, bracketed IPv6, onion; a port out of range or a hostname is dropped', () => {
    for (const ok of ['192.0.2.1:9735', '[2001:db8::1]:9735', ONION]) expect(validAddr(ok)).toBe(true)
    for (const bad of ['example.com:9735', '192.0.2.1', '192.0.2.1:0', '192.0.2.1:65536', '256.0.0.1:1', '[::1]', 'a.onion:1']) expect(validAddr(bad)).toBe(false)
  })
})

const HUB = NODE
const holder = localSigner(fill(2, 32))
const billSecret = fill(9, 32)
const NONCE = '11'.repeat(32)
async function item(method: string, params: object, o: { proof?: boolean } = {}): Promise<Item> {
  const target = toHex(fill(0xa0, 32))
  const text = toJSONText(params)
  const b: ProofBinding = { target, hub: HUB, method, paramsHash: paramsHash(text), nonce: NONCE, notAfter: NOW + 60 }
  return { id: '1', target, method, params: text, ...(o.proof !== false && { proof: await buildItemProof(holder, b, NOW) }), billProof: buildBillProof(billSecret, b, NOW) }
}
const ev = '{"kind":23198}'
const secret = { cash_secret: 'ab'.repeat(32) }

describe('T-301 / T-314 servable methods and bearer shapes', () => {
  test('the allowlist', () => {
    for (const m of ['cash_status', 'cash_redeem', 'cash_withdraw_quote', 'cash_withdraw', 'cash_transfer', 'cash_consolidate', 'cash_lookup', 'cash_order', 'create_circle_wallet']) expect(isServableMethod(m)).toBe(true)
    for (const m of ['mint_cash', 'get_info', 'pay_invoice', 'get_balance', '']) expect(isServableMethod(m)).toBe(false)
  })
  test.each<[string, string, string | undefined, boolean, boolean, boolean]>([
    ['cash-mode status: neither', 'cash_status', '{}', false, false, true],
    ['status with a secret', 'cash_status', undefined, false, true, false],
    ['signed status', 'cash_status', undefined, true, false, true],
    ['cash-mode quote: neither', 'cash_withdraw_quote', undefined, false, false, true],
    ['quote with a secret', 'cash_withdraw_quote', undefined, false, true, false],
    ['quote with proof and secret', 'cash_withdraw_quote', undefined, true, true, false],
    ['bearer withdraw', 'cash_withdraw', '{}', false, true, true],
    ['withdraw with neither', 'cash_withdraw', '{}', false, false, false],
    ['cancel request, bearer without secret (as a lookup)', 'cash_withdraw', '{"cancel":true,"request_id":"00112233445566778899aabbccddeeff"}', false, false, true],
    ['a malformed cancel request is never well shaped', 'cash_withdraw', '{"cancel":true}', true, false, false],
    ['bearer lookup without secret', 'cash_lookup', undefined, false, false, true],
    ['bearer lookup with secret', 'cash_lookup', undefined, false, true, true],
    ['redeem by secret', 'cash_redeem', undefined, false, true, true],
    ['redeem with both', 'cash_redeem', undefined, true, true, false],
    ['transfer with neither', 'cash_transfer', undefined, false, false, false],
    ['an order without proof', 'cash_order', undefined, false, false, false],
    ['a join with proof', 'create_circle_wallet', undefined, true, false, true],
  ])('%s', (_, method, params, p, s, ok) => {
    expect(bearerShapeOK(method, params, p, s)).toBe(ok)
  })
  test('a cash-mode status envelope validates without a proof; one carrying a secret is refused at encode', async () => {
    const it = await item('cash_status', {}, { proof: false })
    const e = { notAfter: NOW + 60, nonce: NONCE, replyTo: '22'.repeat(32), items: [it] }
    expect(() => encodeEnvelope(e, DEFAULT_LIMITS)).not.toThrow()
    expect(() => validateEnvelope(e, HUB, NOW)).not.toThrow()
    const bad = await item('cash_status', secret, { proof: false })
    expect(() => encodeEnvelope({ ...e, items: [bad] }, DEFAULT_LIMITS)).toThrow()
  })
  test('a cash-mode quote validates without a proof', async () => {
    const it = await item('cash_withdraw_quote', { address: 'bc1q' }, { proof: false })
    expect(() => validateEnvelope({ notAfter: NOW + 60, nonce: NONCE, replyTo: '22'.repeat(32), items: [it] }, HUB, NOW)).not.toThrow()
  })
})

describe('T-305 envelope build', () => {
  test('never two calls with one request_id; a lookup may repeat it', async () => {
    const rid = '00112233445566778899aabbccddeeff'
    const a = await item('cash_transfer', { identity_event: ev, request_id: rid })
    const b = { ...(await item('cash_transfer', { identity_event: ev, request_id: rid, amount_millis: 1 })), id: '2' }
    const e = { notAfter: NOW + 60, nonce: NONCE, replyTo: '22'.repeat(32), items: [a, b] }
    expect(() => encodeEnvelope(e, DEFAULT_LIMITS)).toThrow(/request_id/)
    const lookup = { ...(await item('cash_lookup', { request_id: rid, deadline: NOW })), id: '3' }
    expect(() => encodeEnvelope({ ...e, items: [a, lookup] }, DEFAULT_LIMITS)).not.toThrow()
  })
})

describe('T-304 / T-315 verification cost (K-VB-1, K-VB-2)', () => {
  const src = (ck = false) => ({ wallet_pubkey: 'aa'.repeat(32), identity_event: ev, ...(ck && { attestation_event: ev }) })
  test.each<[string, string, object, boolean, number]>([
    ['pubkey redeem', 'cash_redeem', { identity_event: ev }, true, 3],
    ['bearer redeem', 'cash_redeem', secret, false, 1],
    ['CK transfer', 'cash_transfer', { identity_event: ev, attestation_event: ev }, true, 4],
    ['consolidate 3 pubkey sources', 'cash_consolidate', { sources: [src(), src(), src()] }, true, 5],
    ['consolidate 2 pubkey + 1 CK', 'cash_consolidate', { sources: [src(), src(), src(true)] }, true, 6],
    ['signed status', 'cash_status', {}, true, 2],
    ['cash-mode status', 'cash_status', {}, false, 1],
    ['private join', 'create_circle_wallet', { identity_event: ev }, true, 3],
    ['pubkey quote', 'cash_withdraw_quote', {}, true, 2],
    ['CK quote', 'cash_withdraw_quote', { attestation_event: ev }, true, 3],
    ['cash-mode quote', 'cash_withdraw_quote', {}, false, 1],
    ['pubkey withdraw', 'cash_withdraw', { identity_event: ev, quote: ev }, true, 4],
    ['CK withdraw', 'cash_withdraw', { identity_event: ev, attestation_event: ev, quote: ev }, true, 5],
    ['bearer withdraw', 'cash_withdraw', { ...secret, quote: ev }, false, 2],
    ['cancel by pubkey', 'cash_withdraw', { cancel: true }, true, 2],
    ['bearer cancel', 'cash_withdraw', { cancel: true }, false, 1],
  ])('%s = %i', async (_, method, params, proof, cost) => {
    expect(verificationCost(await item(method, params, { proof }))).toBe(cost)
  })
  test('the S-CASH-136 envelope (pubkey redeem + CK transfer + cash-mode status) costs 8', async () => {
    const items = [await item('cash_redeem', { identity_event: ev }), await item('cash_transfer', { identity_event: ev, attestation_event: ev }), await item('cash_status', {}, { proof: false })]
    expect(items.reduce((n, i) => n + verificationCost(i), 0)).toBe(8)
  })
})

describe('T-303 padding (K-PAD-1)', () => {
  test('bucket 4096, L 5000 ⇒ 8192; with max_bytes 6000 ⇒ 6000', () => {
    expect(paddedSize({ ...LIMITS, padBucketBytes: 4096, maxEnvelopeBytes: 16384 }, 5000)).toBe(8192)
    expect(paddedSize({ ...LIMITS, padBucketBytes: 4096, maxEnvelopeBytes: 6000 }, 5000)).toBe(6000)
  })
  test('the NIP example: bucket 2048, max 16384: 900 ⇒ 2048, 2100 ⇒ 4096; exact boundary stays', () => {
    expect(paddedSize(LIMITS, 900)).toBe(2048)
    expect(paddedSize(LIMITS, 2100)).toBe(4096)
    expect(paddedSize(LIMITS, 2048)).toBe(2048)
  })
  test('L above max_bytes is refused locally', () => {
    expect(() => paddedSize(LIMITS, 16385)).toThrow(expect.objectContaining({ code: 'envelope_too_large' }))
  })
  test('an encoded envelope is exactly T bytes and carries no v', async () => {
    const e = { notAfter: NOW + 60, nonce: NONCE, replyTo: '22'.repeat(32), items: [await item('cash_status', {})] }
    const text = encodeEnvelope(e, LIMITS)
    expect(new TextEncoder().encode(text).length).toBe(2048)
    expect(JSON.parse(text)).not.toHaveProperty('v')
  })
})

describe('T-1805 freshness by max_request_age', () => {
  test.each([60, 86401])('H = %i: H ahead accepted, H+1 refused, 0 accepted, −1 dropped', (h) => {
    expect(() => checkFreshness({ notAfter: NOW + h }, NOW, h)).not.toThrow()
    expect(() => checkFreshness({ notAfter: NOW + h + 1 }, NOW, h)).toThrow(expect.objectContaining({ code: 'envelope_too_far_ahead' }))
    expect(() => checkFreshness({ notAfter: NOW }, NOW, h)).not.toThrow()
    expect(() => checkFreshness({ notAfter: NOW - 1 }, NOW, h)).toThrow(expect.objectContaining({ code: 'envelope_expired' }))
  })
})

const plain = (o: object) => JSON.stringify({ req_nonce: NONCE, seq: 1, total: 1, ...o })

describe('T-308 / T-315 response chunks', () => {
  test('the strict single-event decoder refuses what the chunk decoder reports', () => {
    const cases = [
      plain({ results: [{ id: 'x', result: {} }, { id: '1', result: {} }] }),
      plain({ results: [{ id: '1', result: {} }, { id: '1', result: {} }] }),
      plain({ results: [{ id: '1', result: {}, error: { code: 'X' } }] }),
      JSON.stringify({ req_nonce: NONCE, seq: 0, total: 2, results: [] }),
    ]
    for (const text of cases) expect(() => decodeResponse(text, NONCE, ['1'], DEFAULT_LIMITS)).toThrow()
    expect(decodeResponse(plain({ results: [{ id: '1', result: null, error: { code: 'X' } }] }), NONCE, ['1'], DEFAULT_LIMITS).results).toHaveLength(1)
  })
  test('an unknown id is dropped and reported; the others keep their outcome', () => {
    const r = decodeResponseChunk(plain({ results: [{ id: 'x', result: {} }, { id: '1', result: {} }] }), NONCE, ['1'], DEFAULT_LIMITS)
    expect(r.results.map((x) => x.id)).toEqual(['1'])
    expect(r.unknownIds).toEqual(['x'])
  })
  test('an id answered twice, or with a result and an error, has no outcome', () => {
    const r = decodeResponseChunk(plain({ results: [{ id: '1', result: {} }, { id: '1', result: {} }, { id: '2', result: {}, error: { code: 'X' } }, { id: '3', result: {} }] }), NONCE, ['1', '2', '3'], DEFAULT_LIMITS)
    expect(r.results.map((x) => x.id)).toEqual(['3'])
    expect(r.conflictedIds).toEqual(['1', '2'])
  })
  test('every result a duplicate, plus an envelope error: nothing decided, the error kept', () => {
    const r = decodeResponseChunk(plain({ results: [{ id: '1', result: {} }, { id: '1', error: { code: 'X' } }], error: { code: 'QUOTA_EXCEEDED' } }), NONCE, ['1'], DEFAULT_LIMITS)
    expect(r.results).toEqual([])
    expect(r.error?.code).toBe('QUOTA_EXCEEDED')
  })
  test('seq 0 or above total is flagged malformed, results kept', () => {
    for (const [seq, total] of [[0, 2], [3, 2]]) {
      const r = decodeResponseChunk(JSON.stringify({ req_nonce: NONCE, seq, total, results: [{ id: '1', result: {} }] }), NONCE, ['1'], DEFAULT_LIMITS)
      expect(r.malformedSeq).toBe(true)
      expect(r.results).toHaveLength(1)
    }
  })
  test('a req_nonce mismatch still rejects the chunk', () => {
    expect(() => decodeResponse(plain({ req_nonce: '33'.repeat(32), results: [] }), NONCE, ['1'], DEFAULT_LIMITS)).toThrow(expect.objectContaining({ code: 'response_mismatch' }))
  })
  test('detail is decoded and round-trips; absent stays absent (K-WDET-1..3)', () => {
    const text = encodeResponse({ reqNonce: NONCE, results: [{ id: '1', error: { code: 'RESTRICTED', message: 'x', detail: 'own_address' } }, { id: '2', error: { code: 'NOT_FOUND' } }], seq: 1, total: 1 }, DEFAULT_LIMITS)
    expect(JSON.parse(text)).not.toHaveProperty('v')
    const r = decodeResponse(text, NONCE, ['1', '2'], DEFAULT_LIMITS)
    expect(r.results[0]!.error).toEqual({ code: 'RESTRICTED', message: 'x', detail: 'own_address' })
    expect(r.results[1]!.error).toEqual({ code: 'NOT_FOUND' })
  })
})

describe('T-310..T-313 proof of work (K-POW-1..4)', () => {
  test('K-POW-1: the fixed id has difficulty 21', () => {
    expect(powDifficulty('000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358')).toBe(21)
  })
  test('relayPowMinimum from NIP-11', () => {
    expect(relayPowMinimum({ limitation: { min_pow_difficulty: 20 } })).toBe(20)
    for (const bad of [undefined, {}, { limitation: {} }, { limitation: { min_pow_difficulty: 0 } }, { limitation: { min_pow_difficulty: -3 } }, { limitation: { min_pow_difficulty: 2.5 } }, { limitation: { min_pow_difficulty: '20' } }]) {
      expect(relayPowMinimum(bad)).toBe(0)
    }
  })
  test('K-POW-2: parsePowRejection', () => {
    expect(parsePowRejection('pow: difficulty 20 required')).toBe(20)
    expect(parsePowRejection('pow: too weak')).toBeUndefined()
    expect(isPowRejection('pow: too weak')).toBe(true)
    expect(parsePowRejection('blocked: spam')).toBeUndefined()
    expect(isPowRejection('blocked: spam')).toBe(false)
  })
  test('K-POW-3: a mined request carries exactly p, nonce (target third) and expiration = not_after', async () => {
    const r = await wrapRequestPow('{"items":[]}', INBOX, { notAfter: NOW + 60, difficulty: 8, now: NOW })
    expect(r.event.tags.map((t) => t[0])).toEqual(['p', 'nonce', 'expiration'])
    expect(r.event.tags[1]![2]).toBe('8')
    expect(r.event.tags[2]).toEqual(['expiration', String(NOW + 60)])
    expect(powDifficulty(r.event.id)).toBeGreaterThanOrEqual(8)
  })
  test('difficulty 0 adds neither tag', async () => {
    const r = await wrapRequestPow('{"items":[]}', INBOX, { notAfter: NOW + 60, difficulty: 0, now: NOW })
    expect(r.event.tags).toEqual([['p', INBOX]])
  })
  test('a not_after more than a day ahead is refused locally', async () => {
    await expect(wrapRequestPow('x', INBOX, { notAfter: NOW + MAX_POW_AHEAD + 1, difficulty: 0, now: NOW })).rejects.toThrow()
    await expect(wrapRequestPow('x', INBOX, { notAfter: NOW + MAX_POW_AHEAD, difficulty: 0, now: NOW })).resolves.toBeDefined()
  })
  test('T-312 remine: same key, content and created_at; new nonce and id; the Hub opens the same envelope', async () => {
    const r = await wrapRequestPow('{"items":["same"]}', INBOX, { notAfter: NOW + 60, difficulty: 0, now: NOW })
    const m = await r.remine(10)
    expect([m.event.pubkey, m.event.content, m.event.created_at]).toEqual([r.event.pubkey, r.event.content, r.event.created_at])
    expect(m.event.id).not.toBe(r.event.id)
    expect(powDifficulty(m.event.id)).toBeGreaterThanOrEqual(10)
    expect(nip44.decrypt(m.event.content, conversationKeyFor(m.event.pubkey, fill(0x0b, 32)))).toBe('{"items":["same"]}')
    m.dispose()
    await expect(m.remine(4)).rejects.toThrow()
  })
  test('T-313 mining honours an abort signal', async () => {
    const c = new AbortController()
    c.abort()
    await expect(wrapRequestPow('x', INBOX, { notAfter: NOW + 60, difficulty: 30, now: NOW, signal: c.signal })).rejects.toThrow(expect.objectContaining({ code: 'pow_aborted' }))
  })
})
