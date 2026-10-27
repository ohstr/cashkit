// envelope.json: the private-transport envelope, items, freshness,
// responses, coherence validation and the serving classification.
import { describe, expect, test } from 'vitest'
import {
  bearerShapeOK,
  checkFreshness,
  decodeEnvelope,
  decodeResponse,
  DEFAULT_LIMITS,
  encodeEnvelope,
  encodeResponse,
  hasBillProof,
  hasCashSecret,
  hasProof,
  isCancelRequest,
  isServableMethod,
  normalizeNodeIdentity,
  omittedIds,
  sourceCount,
  validateEnvelope,
  verificationCost,
  type Envelope,
  type Item,
  type ResponseEnvelope,
} from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

// Genuine differences from nmilat, skipped and reported.
const MISMATCH = new Set<string>([
  // decodeEnvelope applies the Hub's per-item rules (target, bill proof, I8 shape, duplicate items)
  // and drops a bad item before the budget; nmilat's decode is structural and keeps every item.
  'one bad item is dropped, its co-items kept',
  'a duplicate item: the first is kept',
  'no item survives: the first rejection is the error',
  'budget counts surviving items only',
  'explicit null proof on a bearer item',
  // nmilat refuses the whole envelope when two items share an id; cashkit drops both and keeps the rest.
  'every item sharing an id is dropped',
  // encodeResponse writes `results` before `seq`/`total`/`pad`; nmilat writes it last (same JSON, same size).
  'results and an error',
  'chunk 2 of 3',
  // decodeResponse keeps the chunk and flags these (unknownIds, conflictedIds, malformedSeq); nmilat refuses it.
  'an unknown id',
  'a duplicate result',
  'result and error together',
  'seq 0 of 2',
  // nmilat refuses a malformed cash_withdraw cancel (shape not OK); cashkit's isCancelRequest and bearerShapeOK accept it.
  'cash_withdraw cancel with a deadline',
  'cash_withdraw cancel without request_id',
  'cash_withdraw malformed cancel',
])

const v = load('envelope.json')

const toItem = (i: Json): Item => ({
  id: i.id,
  target: i.target,
  method: i.method,
  ...(i.params !== null && i.params !== undefined && { params: i.params }),
  ...(i.proof !== null && i.proof !== undefined && { proof: i.proof }),
  ...(i.bill_proof !== null && i.bill_proof !== undefined && { billProof: i.bill_proof }),
})
const toEnvelope = (e: Json): Envelope => ({ notAfter: e.not_after, nonce: e.nonce, replyTo: e.reply_to, items: (e.items ?? []).map(toItem) })
const toResponse = (r: Json): ResponseEnvelope => ({
  reqNonce: r.req_nonce,
  ...(r.error && { error: r.error }),
  results: (r.results ?? []).map((x: Json) => ({
    id: x.id,
    ...(x.result_type && { resultType: x.result_type }),
    ...(x.result !== undefined && { result: JSON.stringify(x.result) }),
    ...(x.error && { error: x.error }),
  })),
  seq: r.seq ?? 0,
  total: r.total ?? 0,
})

describe('envelope.json', () => {
  test.each(named(v.encode))('encode: %s', (name: string, c: Json) => {
    if (MISMATCH.has(name)) return
    const e = toEnvelope(c.envelope)
    if (c.error) {
      expect(() => encodeEnvelope(e, c.limits)).toThrow()
      return
    }
    expect(encodeEnvelope(e, c.limits)).toBe(c.plaintext)
  })
  test.each(named(v.decode))('decode: %s', (name: string, c: Json) => {
    if (MISMATCH.has(name)) return
    if (c.error) {
      expect(() => decodeEnvelope(c.plaintext, c.limits)).toThrow()
      return
    }
    const { envelope, rejected } = decodeEnvelope(c.plaintext, c.limits)
    expect(envelope.items.map((i) => i.id)).toEqual(c.kept)
    if (c.rejected !== undefined) expect(rejected.map((r) => r.index)).toEqual(c.rejected)
  })
  test.each(named(v.items))('item: %s', (_: string, c: Json) => {
    const it = toItem(c.item)
    expect({ hasProof: hasProof(it), hasBillProof: hasBillProof(it), isBearer: hasCashSecret(it), sourceCount: sourceCount(it), verificationCost: verificationCost(it) }).toEqual({
      hasProof: c.hasProof,
      hasBillProof: c.hasBillProof,
      isBearer: c.isBearer,
      sourceCount: c.sourceCount,
      verificationCost: c.verificationCost,
    })
  })
  test.each(named(v.freshness, (c) => `not_after ${c.notAfter} at ${c.now}, H ${c.horizon}`))('freshness %s', (_: string, c: Json) => {
    if (c.error) expect(() => checkFreshness({ notAfter: c.notAfter }, c.now, c.horizon)).toThrow()
    else expect(() => checkFreshness({ notAfter: c.notAfter }, c.now, c.horizon)).not.toThrow()
  })
  test.each(named(v.encodeResponse))('encodeResponse: %s', (name: string, c: Json) => {
    if (MISMATCH.has(name)) {
      // Field order differs; the content and the padded size agree.
      const got = encodeResponse(toResponse(c.response), c.limits)
      expect(JSON.parse(got)).toEqual(JSON.parse(c.plaintext))
      expect(got.length).toBe(c.plaintext.length)
      return
    }
    if (c.error) {
      expect(() => encodeResponse(toResponse(c.response), c.limits)).toThrow()
      return
    }
    expect(encodeResponse(toResponse(c.response), c.limits)).toBe(c.plaintext)
  })
  test.each(named(v.decodeResponse))('decodeResponse: %s', (name: string, c: Json) => {
    if (MISMATCH.has(name)) return
    const go = () => decodeResponse(c.plaintext, c.reqNonce, c.requestedIds, DEFAULT_LIMITS)
    if (c.error) {
      expect(go).toThrow()
      return
    }
    const r = go()
    expect([r.seq, r.total]).toEqual([c.seq, c.total])
    expect(omittedIds(r, c.requestedIds)).toEqual(c.omitted ?? [])
    if (name === 'an error with detail') expect(r.results[0]?.error).toMatchObject({ code: 'RESTRICTED', detail: 'own_address' })
  })
  test.each(named(v.validate))('validate: %s', (name: string, c: Json) => {
    if (MISMATCH.has(name)) return
    const go = () => validateEnvelope(toEnvelope(c.envelope), c.hub, c.now)
    if (c.error) expect(go).toThrow()
    else expect(go).not.toThrow()
  })
  test('servable methods', () => {
    for (const [m, ok] of Object.entries(v.servable)) expect(isServableMethod(m), m).toBe(ok)
  })
  test.each(named(v.normalizeNodeIdentity, (c) => JSON.stringify(c.input)))('normalizeNodeIdentity %s', (_: string, c: Json) => {
    if (c.error) expect(() => normalizeNodeIdentity(c.input)).toThrow()
    else expect(normalizeNodeIdentity(c.input)).toBe(c.want)
  })
  test.each(named(v.serving))('serving: %s', (name: string, c: Json) => {
    if (MISMATCH.has(name)) return
    const item = { method: c.method, params: c.params }
    const cancel = isCancelRequest(item)
    const params = JSON.parse(c.params) as Record<string, unknown>
    const hasSecret = typeof params['cash_secret'] === 'string' && params['cash_secret'] !== ''
    if (c.error) {
      expect(bearerShapeOK(c.method, c.params, c.hasProof, hasSecret)).toBe(false)
      return
    }
    expect(cancel ? 'cash_lookup' : c.method).toBe(c.serving)
    expect(bearerShapeOK(c.method, c.params, c.hasProof, hasSecret)).toBe(c.shapeOk)
    expect(isServableMethod(cancel ? 'cash_lookup' : c.method)).toBe(c.servable)
  })
  test.each(named(v.verificationCost, (c) => `${c.id} ${c.name}`))('verificationCost %s', (_: string, c: Json) => {
    const it: Item = { id: 'i0', target: '00'.repeat(32), method: 'cash_status', params: c.params, ...(c.hasProof && { proof: '{}' }), billProof: '{}' }
    expect(verificationCost(it)).toBe(c.cost)
  })
})
