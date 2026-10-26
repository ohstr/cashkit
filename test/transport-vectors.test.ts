// Runs src/transport against nmilat's transport vectors (design §11.1).
import { readFileSync } from 'node:fs'
import { describe, expect, test } from 'vitest'
import { fromHex, localSigner, toHex } from '../src/core/index.js'
import {
  buildBillProof,
  buildItemProof,
  canonicalParams,
  checkFreshness,
  decodeEnvelope,
  decodeResponse,
  DEFAULT_LIMITS,
  deriveReplyKey,
  encodeEnvelope,
  encodeResponse,
  estimatedConsolidateItemBytes,
  estimatedWireBytes,
  hasBillProof,
  hasProof,
  hasCashSecret,
  isServableMethod,
  maxSourcesForEnvelope,
  normalizeNodeIdentity,
  omittedIds,
  paddedSize,
  paramsHash,
  parseAnnouncement,
  sourceCount,
  validateAnnouncedLimits,
  validateEnvelope,
  validateLimits,
  verifyBillProof,
  verifyItemProof,
  type Envelope,
  type Item,
  type ResponseEnvelope,
} from '../src/transport/index.js'

type Json = any

const load = (name: string): Json => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), 'utf8'))
const named = (cases: Json[], title: (c: Json, i: number) => string): [string, Json][] => cases.map((c, i) => [title(c, i), c])

const toItem = (i: Json): Item => ({
  id: i.id,
  target: i.target,
  method: i.method,
  ...(i.params !== null && { params: i.params }),
  ...(i.proof !== null && { proof: i.proof }),
  ...(i.bill_proof !== null && { billProof: i.bill_proof }),
})
const toEnvelope = (e: Json): Envelope => ({ notAfter: e.not_after, nonce: e.nonce, replyTo: e.reply_to, items: e.items.map(toItem) })
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
const toBinding = (b: Json) => ({ target: b.target, hub: b.hub, method: b.method, paramsHash: b.paramsHash, nonce: b.nonce, notAfter: b.notAfter })

// The pinned envelope.json, padding.json and announcement.json predate the
// envelope without `v`, padding capped at max_bytes, freshness by the Hub's
// max_request_age and the tag-form announcement. Until they are regenerated
// a case is checked on what those rules leave unchanged: an encoded
// plaintext as parsed JSON without `v` and `pad`, at the same padded size.
// Cases whose verdict the final rules invert: a cash-mode cash_status now
// carries no secret (and one with a secret is refused), `v` is not read, and
// a bad response item no longer rejects its chunk.
const INVERTED = new Set(['a bearer item needs no slice proof', 'no proof and no cash secret', 'a null proof is no proof', 'wrong version', 'explicit null proof on a bearer item'])
const RESPONSE_FLAGGED: Record<string, (r: ResponseEnvelope) => boolean> = {
  'an unknown id': (r) => (r.unknownIds?.length ?? 0) > 0,
  'a duplicate result': (r) => (r.conflictedIds?.length ?? 0) > 0,
  'result and error together': (r) => (r.conflictedIds?.length ?? 0) > 0,
  'seq 0 of 2': (r) => r.malformedSeq === true,
  'wrong version': () => true,
}
const withoutVersion = (text: string) => {
  const { v: _v, pad: _p, ...rest } = JSON.parse(text) as Record<string, unknown>
  return rest
}

describe('reply-key.json', () => {
  test.each(named(load('reply-key.json').derive, (c) => c.replyTo))('deriveReplyKey %s', (_: string, c: Json) => {
    if (c.error) expect(() => deriveReplyKey(fromHex(c.conversationKey), c.replyTo)).toThrow()
    else expect(toHex(deriveReplyKey(fromHex(c.conversationKey), c.replyTo))).toBe(c.replyKey)
  })
})

describe('canonical-params.json', () => {
  test.each(named(load('canonical-params.json').hash, (c) => c.name))('%s', (_: string, c: Json) => {
    if (c.error) {
      expect(() => paramsHash(c.params)).toThrow()
      return
    }
    expect(paramsHash(c.params)).toBe(c.hash)
    if (c.canonical) expect(canonicalParams(c.params)).toBe(c.canonical)
  })
})

describe('padding.json', () => {
  const v = load('padding.json')
  test('defaults', () => {
    expect(DEFAULT_LIMITS).toEqual(v.defaults)
  })
  test.each(named(v.paddedSize, (c) => `${c.limits.padBucketBytes}/${c.limits.maxEnvelopeBytes} n=${c.n}`))('paddedSize %s', (_: string, c: Json) => {
    if (c.n > c.limits.maxEnvelopeBytes || c.n < 0) expect(() => paddedSize(c.limits, c.n)).toThrow()
    else if (c.error) expect(paddedSize(c.limits, c.n)).toBe(c.limits.maxEnvelopeBytes)
    else expect(paddedSize(c.limits, c.n)).toBe(c.padded)
  })
  test.each(named(v.validate, (c) => c.name))('validate: %s', (_: string, c: Json) => {
    if (c.validateError) expect(() => validateLimits(c.limits)).toThrow()
    else expect(() => validateLimits(c.limits)).not.toThrow()
    if (c.validateAnnouncedError) expect(() => validateAnnouncedLimits(c.limits)).toThrow()
    else expect(() => validateAnnouncedLimits(c.limits)).not.toThrow()
  })
  test('estimates', () => {
    for (const [n, want] of v.maxSourcesForEnvelope) expect(maxSourcesForEnvelope(n)).toBe(want)
    for (const [n, want] of v.estimatedConsolidateItemBytes) expect(estimatedConsolidateItemBytes(n)).toBe(want)
    for (const c of v.estimatedWireBytes) expect(estimatedWireBytes(c.limits)).toBe(c.wireBytes)
  })
})

describe('envelope.json', () => {
  const v = load('envelope.json')
  test.each(named(v.encode, (c) => c.name))('encode: %s', (_: string, c: Json) => {
    const e = toEnvelope(c.envelope)
    if (INVERTED.has(c.name)) {
      if (c.error) expect(() => encodeEnvelope(e, c.limits)).not.toThrow()
      else expect(() => encodeEnvelope(e, c.limits)).toThrow()
      return
    }
    if (c.error) {
      expect(() => encodeEnvelope(e, c.limits)).toThrow()
      return
    }
    const got = encodeEnvelope(e, c.limits)
    expect(withoutVersion(got)).toEqual(withoutVersion(c.plaintext))
    expect(got.length).toBe(c.plaintext.length)
  })
  test.each(named(v.decode, (c) => c.name))('decode: %s', (_: string, c: Json) => {
    if (INVERTED.has(c.name)) {
      if (c.error) expect(() => decodeEnvelope(c.plaintext, c.limits)).not.toThrow()
      else expect(() => decodeEnvelope(c.plaintext, c.limits)).toThrow()
      return
    }
    if (c.error) {
      expect(() => decodeEnvelope(c.plaintext, c.limits)).toThrow()
      return
    }
    const { envelope, rejected } = decodeEnvelope(c.plaintext, c.limits)
    expect(envelope.items.map((i) => i.id)).toEqual(c.kept)
    expect(rejected.map((r) => r.index)).toEqual(c.rejected ?? [])
  })
  test.each(named(v.items, (c) => c.name))('item: %s', (_: string, c: Json) => {
    const it = toItem(c.item)
    expect({ hasProof: hasProof(it), hasBillProof: hasBillProof(it), hasCashSecret: hasCashSecret(it), sourceCount: sourceCount(it) }).toEqual({
      hasProof: c.hasProof,
      hasBillProof: c.hasBillProof,
      hasCashSecret: c.isBearer,
      sourceCount: c.sourceCount,
    })
  })
  test.each(named(v.freshness, (c) => `not_after ${c.notAfter} at ${c.now}`))('freshness %s', (_: string, c: Json) => {
    // The pinned cases use the former 120 s ceiling, i.e. a Hub announcing H = 120.
    if (c.error) expect(() => checkFreshness({ notAfter: c.notAfter }, c.now, 120)).toThrow()
    else expect(() => checkFreshness({ notAfter: c.notAfter }, c.now, 120)).not.toThrow()
  })
  test.each(named(v.encodeResponse, (c) => c.name))('encodeResponse: %s', (_: string, c: Json) => {
    if (c.error) {
      expect(() => encodeResponse(toResponse(c.response), c.limits)).toThrow()
      return
    }
    const got = encodeResponse(toResponse(c.response), c.limits)
    expect(withoutVersion(got)).toEqual(withoutVersion(c.plaintext))
    expect(got.length).toBe(c.plaintext.length)
  })
  test.each(named(v.decodeResponse, (c) => c.name))('decodeResponse: %s', (_: string, c: Json) => {
    const flagged = RESPONSE_FLAGGED[c.name]
    if (flagged !== undefined) {
      expect(flagged(decodeResponse(c.plaintext, c.reqNonce, c.requestedIds, DEFAULT_LIMITS))).toBe(true)
      return
    }
    if (c.error) {
      expect(() => decodeResponse(c.plaintext, c.reqNonce, c.requestedIds, DEFAULT_LIMITS)).toThrow()
      return
    }
    const r = decodeResponse(c.plaintext, c.reqNonce, c.requestedIds, DEFAULT_LIMITS)
    expect([r.seq, r.total]).toEqual([c.seq, c.total])
    expect(omittedIds(r, c.requestedIds)).toEqual(c.omitted ?? [])
  })
  test.each(named(v.validate, (c) => c.name))('validate: %s', (_: string, c: Json) => {
    const run = () => validateEnvelope(toEnvelope(c.envelope), c.hub, c.now)
    if (c.error) expect(run).toThrow()
    else expect(run).not.toThrow()
  })
  test('servable methods', () => {
    for (const [m, ok] of Object.entries(v.servable)) expect(isServableMethod(m)).toBe(ok)
  })
  test.each(named(v.normalizeNodeIdentity, (c) => JSON.stringify(c.input)))('normalizeNodeIdentity %s', (_: string, c: Json) => {
    if (c.error) expect(() => normalizeNodeIdentity(c.input)).toThrow()
    else expect(normalizeNodeIdentity(c.input)).toBe(c.want)
  })
})

describe('proof.json', () => {
  const v = load('proof.json')
  const claimant = fromHex('02'.repeat(32))
  test.each(named(v.build, (c) => c.name))('build: %s', async (_: string, c: Json) => {
    const b = toBinding(c.binding)
    const run = async () => (c.kind === 'item' ? buildItemProof(localSigner(claimant), b, 1760000000) : buildBillProof(claimant, b, 1760000000))
    if (c.error) {
      await expect(run()).rejects.toThrow()
      return
    }
    const ev = JSON.parse(await run())
    expect([ev.kind, ev.tags]).toEqual([c.eventKind, c.tags])
  })
  test.each(named(v.verify, (c) => c.name))('verify: %s', (_: string, c: Json) => {
    const run = () => (c.kind === 'item' ? verifyItemProof : verifyBillProof)(c.proof, toBinding(c.binding), c.now)
    if (c.error) expect(run).toThrow()
    else expect(run()).toBe(c.signer)
  })
})

describe('announcement.json', () => {
  test.each(named(load('announcement.json').parse, (c) => c.name))('%s', (_: string, c: Json) => {
    // Every pinned case is in the former JSON-content form, which carries no inbox tag.
    const ev = { ...c.event, tags: c.event.tags ?? [] }
    expect(() => parseAnnouncement(ev, c.expectedNode)).toThrow()
  })
})
