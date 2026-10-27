// connection-key.json: canonical platform user ids (K-IDNA-1..6 among them)
// and the generated IDNA corpus, against cashkit's UTS #46 port.
import { describe, expect, test } from 'vitest'
import { canonicalUserId, connectionKeyFromAttested, connectionKeyFromTyped, punycodeDecode, punycodeEncode } from '../../src/core/idna.js'
import { load, named, type Json } from './helpers.js'

const v = load('connection-key.json')
const run = (platform: string, input: string): string => {
  try {
    return canonicalUserId(platform, input)
  } catch (err) {
    return `error: ${(err as Error).message}`
  }
}

describe('connection-key.json canonicalUserId', () => {
  test.each(named(v.canonicalUserId, (c: Json, i) => `${c.id ?? i} ${c.platform} ${JSON.stringify(c.input)}`))('%s', (_, c: Json) => {
    expect(run(c.platform, c.input)).toBe(c.error !== undefined ? `error: ${c.error}` : c.output)
  })
})

const derive = (c: Json): string => {
  try {
    return c.mode === 'typed' ? connectionKeyFromTyped(c.platform, c.input) : connectionKeyFromAttested(c.platform, c.input)
  } catch (err) {
    return `error: ${(err as Error).message}`
  }
}

describe('connection-key.json kats and legacy (typed and attested derivations)', () => {
  test.each(named(v.kats, (c: Json) => `${c.id} ${c.mode}`))('%s', (_, c: Json) => {
    expect(derive(c)).toBe(c.error !== undefined ? `error: ${c.error}` : c.key)
    if (c.mode === 'typed' && c.canonical !== undefined) expect(canonicalUserId(c.platform, c.input)).toBe(c.canonical)
  })
  test.each(named(v.legacy, (c: Json) => `${c.platform}:${c.externalId}`))('legacy %s is refused', (_, c: Json) => {
    expect(run(c.platform, c.externalId)).toBe(`error: ${c.error}`)
  })
})

describe('connection-key.json idna_corpus', () => {
  test(`all ${v.idna_corpus.length} domains agree`, () => {
    const off = (v.idna_corpus as Json[]).filter((c) => run('dns', c.input) !== (c.error !== undefined ? `error: ${c.error}` : c.output))
    expect(off.map((c) => c.input)).toEqual([])
  })
  test('accepted domains round-trip through punycode', () => {
    for (const c of (v.idna_corpus as Json[]).filter((x) => x.error === undefined)) {
      for (const label of (c.output as string).split('.')) {
        if (!label.startsWith('xn--')) continue
        const u = punycodeDecode(label.slice(4))!
        expect(`xn--${punycodeEncode(u)}`).toBe(label)
      }
    }
  })
  test('a ConnectionKey hashes the canonical form', () => {
    expect(connectionKeyFromTyped('dns', 'BüCHER.example')).toBe(connectionKeyFromTyped('dns', 'xn--bcher-kva.example'))
  })
})
