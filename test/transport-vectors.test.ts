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
  isBearer,
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
  verificationCost,
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
const toEnvelope = (e: Json): Envelope => ({ v: e.v, notAfter: e.not_after, nonce: e.nonce, replyTo: e.reply_to, items: e.items.map(toItem) })
const toResponse = (r: Json): ResponseEnvelope => ({
  v: r.v,
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
    if (c.error) expect(() => paddedSize(c.limits, c.n)).toThrow()
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
    if (c.error) expect(() => encodeEnvelope(e, c.limits)).toThrow()
    else expect(encodeEnvelope(e, c.limits)).toBe(c.plaintext)
  })
  test.each(named(v.decode, (c) => c.name))('decode: %s', (_: string, c: Json) => {
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
    expect({ hasProof: hasProof(it), hasBillProof: hasBillProof(it), isBearer: isBearer(it), sourceCount: sourceCount(it), verificationCost: verificationCost(it) }).toEqual({
      hasProof: c.hasProof,
      hasBillProof: c.hasBillProof,
      isBearer: c.isBearer,
      sourceCount: c.sourceCount,
      verificationCost: c.verificationCost,
    })
  })
  test.each(named(v.freshness, (c) => `not_after ${c.notAfter} at ${c.now}`))('freshness %s', (_: string, c: Json) => {
    if (c.error) expect(() => checkFreshness({ notAfter: c.notAfter }, c.now)).toThrow()
    else expect(() => checkFreshness({ notAfter: c.notAfter }, c.now)).not.toThrow()
  })
  test.each(named(v.encodeResponse, (c) => c.name))('encodeResponse: %s', (_: string, c: Json) => {
    if (c.error) expect(() => encodeResponse(toResponse(c.response), c.limits)).toThrow()
    else expect(encodeResponse(toResponse(c.response), c.limits)).toBe(c.plaintext)
  })
  test.each(named(v.decodeResponse, (c) => c.name))('decodeResponse: %s', (_: string, c: Json) => {
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
    const ev = { ...c.event, tags: c.event.tags ?? [] }
    if (c.error) {
      expect(() => parseAnnouncement(ev, c.expectedNode)).toThrow()
      return
    }
    const a = parseAnnouncement(ev, c.expectedNode)
    expect({ inbox: a.inbox, limits: a.limits, relays: a.relays, createdAt: a.createdAt }).toEqual(c.want)
  })
})
