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
  servingMethod,
  sourceCount,
  validateEnvelope,
  verificationCost,
  type Envelope,
  type Item,
  type ResponseEnvelope,
} from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

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
  test.each(named(v.encode))('encode: %s', (_: string, c: Json) => {
    const e = toEnvelope(c.envelope)
    if (c.error) {
      expect(() => encodeEnvelope(e, c.limits)).toThrow()
      return
    }
    expect(encodeEnvelope(e, c.limits)).toBe(c.plaintext)
  })
  test.each(named(v.decode))('decode: %s', (_: string, c: Json) => {
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
  test.each(named(v.encodeResponse))('encodeResponse: %s', (_: string, c: Json) => {
    if (c.error) {
      expect(() => encodeResponse(toResponse(c.response), c.limits)).toThrow()
      return
    }
    expect(encodeResponse(toResponse(c.response), c.limits)).toBe(c.plaintext)
  })
  test.each(named(v.decodeResponse))('decodeResponse: %s', (name: string, c: Json) => {
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
  test.each(named(v.validate))('validate: %s', (_: string, c: Json) => {
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
  test.each(named(v.serving))('serving: %s', (_: string, c: Json) => {
    const params = JSON.parse(c.params) as Record<string, unknown>
    const hasSecret = typeof params['cash_secret'] === 'string' && params['cash_secret'] !== ''
    if (c.error) {
      expect(() => servingMethod(c.method, c.params)).toThrow(expect.objectContaining({ code: 'bad_cancel' }))
      expect(bearerShapeOK(c.method, c.params, c.hasProof, hasSecret)).toBe(false)
      return
    }
    const serving = servingMethod(c.method, c.params)
    expect(serving).toBe(c.serving)
    expect(isCancelRequest({ method: c.method, params: c.params })).toBe(serving === 'cash_lookup' && c.method === 'cash_withdraw')
    expect(bearerShapeOK(c.method, c.params, c.hasProof, hasSecret)).toBe(c.shapeOk)
    expect(isServableMethod(serving)).toBe(c.servable)
  })
  test.each(named(v.verificationCost, (c) => `${c.id} ${c.name}`))('verificationCost %s', (_: string, c: Json) => {
    const it: Item = { id: 'i0', target: '00'.repeat(32), method: 'cash_status', params: c.params, ...(c.hasProof && { proof: '{}' }), billProof: '{}' }
    expect(verificationCost(it)).toBe(c.cost)
  })
})
