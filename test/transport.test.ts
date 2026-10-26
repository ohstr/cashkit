// Unit tests for src/transport. Cases follow nmilat nipcash/transport tests:
// request_test, response_test, envelope_test, proof_test, proof_window_test,
// bill_proof_test, announcement_test, auditB_priv_padding_test,
// auditD_privacy_padding_test, auditB_duplicate_item_test, validate_test.
import { describe, expect, test } from 'vitest'
import { getPublicKey, localSigner, nip44, toHex } from '../src/core/index.js'
import { compactGo, goString, parseGo, parseGoStream } from '../src/transport/gojson.js'
import {
  buildBillProof,
  buildItemProof,
  conversationKeyFor,
  decodeEnvelope,
  decodeResponse,
  DEFAULT_LIMITS,
  deriveReplyKey,
  encodeEnvelope,
  encodeResponse,
  KIND_PRIVATE_REQUEST,
  MAX_CREATED_AT_BACKDATE,
  newNonce,
  normalizeNodeIdentity,
  omittedIds,
  openReply,
  paramsHash,
  randomizedCreatedAt,
  sealReply,
  toJSONText,
  TransportError,
  validateEnvelope,
  verifyBillProof,
  verifyItemProof,
  wrapRequest,
  type Envelope,
  type Item,
  type ProofBinding,
} from '../src/transport/index.js'
import { fill } from './helpers.js'

const NOW = 1_760_000_000
const inboxKey = fill(0x0b, 32)
const INBOX = getPublicKey(inboxKey)
const hubKey = fill(0x07, 32)
const HUB = getPublicKey(hubKey)
const holder = localSigner(fill(2, 32))
const billSecret = fill(9, 32)
const NONCE = '11'.repeat(32)
const REPLY = '22'.repeat(32)

async function item(i: number, method = 'cash_status', params: unknown = { scope: 'mine' }): Promise<Item> {
  const target = toHex(fill(0xa0 + i, 32))
  const text = toJSONText(params)
  const b: ProofBinding = { target, hub: HUB, method, paramsHash: paramsHash(text), nonce: NONCE, notAfter: NOW + 60 }
  return { id: `i${i}`, target, method, params: text, proof: await buildItemProof(holder, b, NOW), billProof: buildBillProof(billSecret, b, NOW) }
}
const envelope = (items: Item[]): Envelope => ({ notAfter: NOW + 60, nonce: NONCE, replyTo: REPLY, items })

describe('request wrap (request_test.go)', () => {
  test('the Hub opens what the client wraps', () => {
    const { event, conversationKey } = wrapRequest('{"v":1}', INBOX, { now: NOW })
    expect(event.kind).toBe(KIND_PRIVATE_REQUEST)
    expect(event.tags).toEqual([['p', INBOX]])
    expect(conversationKeyFor(event.pubkey, inboxKey)).toEqual(conversationKey)
    expect(nip44.decrypt(event.content, conversationKey)).toBe('{"v":1}')
  })
  test('every request has a fresh ephemeral author and a backdated created_at', () => {
    const a = wrapRequest('x', INBOX, { now: NOW }).event
    const b = wrapRequest('x', INBOX, { now: NOW }).event
    expect(a.pubkey).not.toBe(b.pubkey)
    for (const e of [a, b]) {
      expect(e.created_at).toBeLessThanOrEqual(NOW)
      expect(e.created_at).toBeGreaterThan(NOW - MAX_CREATED_AT_BACKDATE)
    }
  })
  test('randomizedCreatedAt stays within two days', () => {
    expect(randomizedCreatedAt(NOW, () => new Uint8Array(8))).toBe(NOW)
    expect(randomizedCreatedAt(NOW, () => fill(0xff, 8))).toBeGreaterThan(NOW - MAX_CREATED_AT_BACKDATE)
  })
  test('refuses an empty payload and a bad inbox', () => {
    expect(() => wrapRequest('', INBOX, { now: NOW })).toThrow(TransportError)
    expect(() => wrapRequest('x', INBOX.toUpperCase(), { now: NOW })).toThrow(TransportError)
    expect(() => wrapRequest('x', 'ff'.repeat(32), { now: NOW })).toThrow(/valid point/)
  })
})

describe('reply (response_test.go)', () => {
  test('the reply key depends on the label and reply_to (TestAuditC_DeriveReplyKey_LabelIsLoadBearing)', () => {
    const ck = fill(1, 32)
    expect(deriveReplyKey(ck, REPLY)).not.toEqual(deriveReplyKey(ck, NONCE))
    expect(deriveReplyKey(ck, REPLY)).not.toEqual(ck)
  })
  test('a full exchange: wrap, Hub decrypts, Hub seals the reply, client opens it', () => {
    const { event, conversationKey } = wrapRequest('req', INBOX, { now: NOW })
    const hubCk = conversationKeyFor(event.pubkey, inboxKey)
    const reply = encodeResponse({ reqNonce: NONCE, results: [{ id: 'i0', resultType: 'cash_status', result: '{"recipients":[]}' }], seq: 1, total: 1 }, DEFAULT_LIMITS)
    const content = sealReply(reply, hubCk, REPLY)
    const opened = decodeResponse(openReply(content, conversationKey, REPLY), NONCE, ['i0', 'i1'], DEFAULT_LIMITS)
    expect(opened.results[0]).toEqual({ id: 'i0', resultType: 'cash_status', result: '{"recipients":[]}' })
    expect(omittedIds(opened, ['i0', 'i1'])).toEqual(['i1'])
  })
  test('responses pad to the bucket too', () => {
    expect(encodeResponse({ reqNonce: NONCE, results: [], seq: 0, total: 0 }, DEFAULT_LIMITS)).toHaveLength(8192)
  })
})

describe('envelope (envelope_test.go, padding tests)', () => {
  test('encode then decode round-trips real items', async () => {
    const e = envelope([await item(0), await item(1, 'cash_redeem', { invoice: 'lnfc1x', cash_secret: '' })])
    const { envelope: back, rejected } = decodeEnvelope(encodeEnvelope(e, DEFAULT_LIMITS), DEFAULT_LIMITS)
    expect(rejected).toEqual([])
    expect(back.items.map((i) => i.id)).toEqual(['i0', 'i1'])
    expect(back.items[0]!.params).toBe(e.items[0]!.params)
  })
  test('padding hides batch size: 1 to 8 real items fall into few buckets (TestEnvelope_EncodePadsToBuckets)', async () => {
    const sizes = new Set<number>()
    for (let n = 1; n <= 8; n++) {
      const items = await Promise.all(Array.from({ length: n }, (_, i) => item(i)))
      sizes.add(encodeEnvelope(envelope(items), DEFAULT_LIMITS).length)
    }
    expect(sizes.size).toBeLessThanOrEqual(3)
    for (const s of sizes) expect(s % DEFAULT_LIMITS.padBucketBytes).toBe(0)
  })
  test('32 cash_status items still fit the default envelope', async () => {
    const items = await Promise.all(Array.from({ length: 32 }, (_, i) => item(i)))
    expect(encodeEnvelope(envelope(items), DEFAULT_LIMITS).length).toBeLessThanOrEqual(DEFAULT_LIMITS.maxEnvelopeBytes)
  })
  test('a re-serialized duplicate is still a duplicate (auditB_duplicate_item_test.go)', async () => {
    const a = await item(0)
    const b = { ...a, id: 'other', params: '{ "scope" : "mine" }' }
    expect(() => encodeEnvelope(envelope([a, b]), DEFAULT_LIMITS)).toThrow(/identical/)
  })
  test('decode drops a forged item but serves its co-items', async () => {
    const good = await item(0)
    const text = encodeEnvelope(envelope([good]), DEFAULT_LIMITS).replace('"items":[', `"items":[{"id":"bad","target":"nope","method":"cash_status","bill_proof":{}},`)
    const { envelope: e, rejected } = decodeEnvelope(text, DEFAULT_LIMITS)
    expect(e.items.map((i) => i.id)).toEqual(['i0'])
    expect(rejected.map((r) => r.index)).toEqual([0])
  })
  test('newNonce is 64 lowercase hex and fresh', () => {
    expect(newNonce()).toMatch(/^[0-9a-f]{64}$/)
    expect(newNonce()).not.toBe(newNonce())
  })
})

describe('params text', () => {
  test('bigint amounts are written exactly and hash by their literal', () => {
    const text = toJSONText({ amount_millis: 18446744073709551615n, memo: '<&>' })
    expect(text).toBe('{"amount_millis":18446744073709551615,"memo":"\\u003c\\u0026\\u003e"}')
    expect(paramsHash(text)).toBe(paramsHash('{"memo":"<&>","amount_millis":18446744073709551615}'))
  })
  test('undefined fields are omitted', () => {
    expect(toJSONText({ a: 1, b: undefined })).toBe('{"a":1}')
  })
  test('the same value written two ways hashes alike', () => {
    expect(paramsHash('{"a":1,"b":[true,null]}')).toBe(paramsHash(' { "b" : [ true , null ] , "a" : 1 } '))
    expect(paramsHash('{"n":1.0}')).not.toBe(paramsHash('{"n":1}'))
  })
})

describe('proofs (proof_test.go, proof_window_test.go, bill_proof_test.go)', () => {
  const b: ProofBinding = { target: 'a1'.repeat(32), hub: HUB, method: 'cash_redeem', paramsHash: 'c3'.repeat(32), nonce: NONCE, notAfter: NOW + 60 }
  test('a slice proof verifies to the holder, a bill proof to the bill key', async () => {
    expect(verifyItemProof(await buildItemProof(holder, b, NOW), b, NOW)).toBe(holder.pubkey)
    expect(verifyBillProof(buildBillProof(billSecret, b, NOW), b, NOW)).toBe(getPublicKey(billSecret))
  })
  test('the kinds are not interchangeable', async () => {
    const slice = await buildItemProof(holder, b, NOW)
    expect(() => verifyBillProof(slice, b, NOW)).toThrow(TransportError)
    expect(() => verifyItemProof(buildBillProof(billSecret, b, NOW), b, NOW)).toThrow(TransportError)
  })
  test.each<[string, Partial<ProofBinding>, string]>([
    ['target', { target: 'b2'.repeat(32) }, 'proof_wrong_target'],
    ['hub', { hub: holder.pubkey }, 'proof_wrong_hub'],
    ['method', { method: 'cash_transfer' }, 'proof_wrong_method'],
    ['params', { paramsHash: 'c4'.repeat(32) }, 'proof_wrong_params'],
    ['envelope', { nonce: REPLY }, 'proof_wrong_envelope'],
  ])('a substituted %s is refused with its own code', async (_, change, code) => {
    const proof = await buildItemProof(holder, b, NOW)
    expect(() => verifyItemProof(proof, { ...b, ...change }, NOW)).toThrow(expect.objectContaining({ code }))
  })
  test('freshness: 5 minutes back and 1 minute ahead', async () => {
    const proof = await buildItemProof(holder, b, NOW)
    expect(() => verifyItemProof(proof, b, NOW + 300)).not.toThrow()
    expect(() => verifyItemProof(proof, b, NOW + 301)).toThrow(expect.objectContaining({ code: 'proof_stale' }))
    expect(() => verifyItemProof(proof, b, NOW - 60)).not.toThrow()
    expect(() => verifyItemProof(proof, b, NOW - 61)).toThrow(expect.objectContaining({ code: 'proof_stale' }))
  })
  test('every binding field is required', async () => {
    await expect(buildItemProof(holder, { ...b, nonce: '' }, NOW)).rejects.toThrow(TransportError)
    expect(() => buildBillProof(billSecret, { ...b, hub: '' }, NOW)).toThrow(TransportError)
  })
})

describe('validateEnvelope (validate_test.go)', () => {
  test('an envelope built from real proofs is coherent', async () => {
    const e = envelope([await item(0), await item(1)])
    expect(() => validateEnvelope(e, HUB, NOW)).not.toThrow()
  })
  test('a proof for another hub reads as mixed hubs', async () => {
    const it = await item(0)
    expect(() => validateEnvelope(envelope([it]), holder.pubkey, NOW)).toThrow(expect.objectContaining({ code: 'mixed_hubs' }))
  })
  test('mint_cash is not servable', async () => {
    const mint = envelope([await item(0, 'mint_cash')])
    expect(() => validateEnvelope(mint, HUB, NOW)).toThrow(expect.objectContaining({ code: 'method_not_servable' }))
  })
})

describe('announcement (announcement_test.go)', () => {
  const nodeKey = fill(0x0a, 32)
  const node = getPublicKey(nodeKey)
  test('normalizeNodeIdentity takes a compressed key from a mint signature', () => {
    expect(normalizeNodeIdentity('03' + node.toUpperCase())).toBe(node)
    expect(() => normalizeNodeIdentity('04' + node)).toThrow(TransportError)
  })
})

describe('Go JSON', () => {
  test('parse refuses what encoding/json refuses', () => {
    for (const bad of ['{', '{"a":1,}', '[01]', '{"s":"a\u0001"}', "{'a':1}", '{"a":1} x', 'nul']) expect(() => parseGo(bad)).toThrow()
  })
  test('a lone surrogate escape decodes to U+FFFD; a pair to the character', () => {
    expect(parseGo('"\\ud800"')).toMatchObject({ value: '�' })
    expect(parseGo('"\\ud83d\\ude00"')).toMatchObject({ value: '😀' })
  })
  test('a stream value may be followed by ] or } (Decoder.More), not by other content', () => {
    expect(() => parseGoStream('{} ]')).not.toThrow()
    expect(() => parseGoStream('{} {}')).toThrow()
  })
  test('goString and compactGo escape as json.Marshal does', () => {
    expect(goString('<a&b> \u0001"\\')).toBe('"\\u003ca\\u0026b\\u003e\\u2028\\u0001\\"\\\\"')
    expect(compactGo('{ "a" : "<x>" ,\n "b" : [ 1 , 2 ] }')).toBe('{"a":"\\u003cx\\u003e","b":[1,2]}')
    expect(compactGo('{"a":"\\/é"}')).toBe('{"a":"\\/é"}')
  })
})
