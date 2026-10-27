// proof.json: item (23192) and bill (23193) proofs, the params hash, and
// verification order, freshness and kind separation.
import { describe, expect, test } from 'vitest'
import { finalizeEvent, fromHex, localSigner } from '../../src/core/index.js'
import { buildBillProof, buildItemProof, paramsHash, verifyBillProof, verifyItemProof } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('proof.json')
const KEY1 = Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0))
const toBinding = (b: Json) => ({ target: b.target, hub: b.hub, method: b.method, paramsHash: b.paramsHash, nonce: b.nonce, notAfter: b.notAfter })

describe('proof.json', () => {
  test.each(named(v.kats))('%s', async (_: string, c: Json) => {
    const b = toBinding(c.binding)
    const json = c.kind === 23192 ? await buildItemProof(localSigner(KEY1), b, c.createdAt) : buildBillProof(KEY1, b, c.createdAt)
    const ev = JSON.parse(json)
    expect([ev.kind, ev.pubkey, ev.created_at, ev.tags, ev.id]).toEqual([c.kind, c.pubkey, c.createdAt, c.tags, c.eventId])
    expect(finalizeEvent({ kind: c.kind, created_at: c.createdAt, tags: c.tags, content: '' }, KEY1).id).toBe(c.eventId)
  })
  test.each(named(v.ph, (c, i) => `${c.id || 'ph'} #${i}${c.note ? ` (${c.note})` : ''}`))('%s', (_: string, c: Json) => {
    if (c.error) {
      expect(() => paramsHash(c.params)).toThrow()
      return
    }
    // A note names a wrong serialization: its hash is the one a correct implementation must not produce.
    if (c.note) expect(paramsHash(c.params)).not.toBe(c.hash)
    else expect(paramsHash(c.params)).toBe(c.hash)
  })
  test.each(named(v.build))('build: %s', async (_: string, c: Json) => {
    const b = toBinding(c.binding)
    const claimant = fromHex('02'.repeat(32))
    const go = async () => (c.kind === 'item' ? buildItemProof(localSigner(claimant), b, 1760000000) : buildBillProof(claimant, b, 1760000000))
    if (c.error) {
      await expect(go()).rejects.toThrow()
      return
    }
    const ev = JSON.parse(await go())
    expect([ev.kind, ev.tags]).toEqual([c.eventKind, c.tags])
  })
  test.each(named(v.verify))('verify: %s', (_: string, c: Json) => {
    const go = () => (c.kind === 'item' ? verifyItemProof : verifyBillProof)(c.proof, toBinding(c.binding), c.now)
    if (c.error) expect(go).toThrow()
    else expect(go()).toBe(c.signer)
  })
})
