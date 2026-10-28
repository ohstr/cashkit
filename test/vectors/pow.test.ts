// pow.json: proof of work on kind-23190 requests.
import { describe, expect, test } from 'vitest'
import { powDifficulty } from '../../src/core/index.js'
import { isPowRejection, MAX_POW_AHEAD, mineNonce, parsePowRejection } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('pow.json')

describe('pow.json', () => {
  test.each(named(v.difficulty, (c) => c.id ?? c.eventId))('difficulty of %s', (_: string, c: Json) => {
    if (c.error !== undefined) expect(() => powDifficulty(c.eventId)).toThrow()
    else expect(powDifficulty(c.eventId)).toBe(c.difficulty)
  })
  test.each(named(v.parseRejection, (c) => JSON.stringify(c.message)))('rejection %s', (_: string, c: Json) => {
    expect(isPowRejection(c.message)).toBe(c.powRefusal)
    expect(parsePowRejection(c.message) ?? 0).toBe(c.difficulty)
  })
  test('the nonce and expiration tags: the example is the nonce mined to its target', async () => {
    const ex = v.tags.example
    const base = ex.tags.filter((t: string[]) => t[0] !== 'nonce')
    expect(v.tags.shape.map((t: string[]) => t[0])).toEqual(['expiration', 'nonce'])
    const target = Number(ex.tags.find((t: string[]) => t[0] === 'nonce')[2])
    const mined = await mineNonce({ pubkey: ex.pubkey, created_at: ex.created_at, kind: ex.kind, tags: base, content: ex.content }, target)
    expect(powDifficulty(mined.id)).toBeGreaterThanOrEqual(target)
    expect(new Set(mined.tags.map((t) => t[0]))).toEqual(new Set(ex.tags.map((t: string[]) => t[0])))
  })
  test('the relay bound on expiration is one day', () => {
    expect(MAX_POW_AHEAD).toBe(v.maxPowAhead)
  })
})
