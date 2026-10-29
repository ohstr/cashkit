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

const NOT_CANONICAL = 'nipIC: user id is not in canonical form'
const long = ['a'.repeat(63), 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(59), 'ex'].join('.') // 254 characters

describe('canonical user ids at their edges (§Canonical Platform User IDs)', () => {
  test.each([
    ['email', '@alice@example.com'],
    ['email', ' @alice@example.com'],
    ['email', '@example.com'],
    // A decomposed é: the local part is not NFC.
    ['email', 'e\u0301@x.example'],
    ['dns', long],
    ['email', `a@${long}`],
    ['dns', '@example.com'],
  ])('%s %j is refused, never repaired', (platform, input) => {
    expect(() => canonicalUserId(platform, input)).toThrow(NOT_CANONICAL)
  })
  test.each([
    ['email', ' Alice@Example.COM ', 'alice@example.com'],
    ['email', 'a@b.example', 'a@b.example'],
    ['email', 'e\u0301@x.example'.normalize('NFC'), 'é@x.example'],
    ['dns', long.slice(1), long.slice(1)],
    ['email', `a@${long.slice(1)}`, `a@${long.slice(1)}`],
  ])('%s %j is %j', (platform, input, want) => {
    expect(canonicalUserId(platform, input)).toBe(want)
  })
  test('the tables are Unicode 15.0.0, as nmilat on its pinned toolchain: a 15.0 ideograph is valid, a 15.1 one is not', () => {
    expect(canonicalUserId('dns', '\u{31350}.example')).toMatch(/^xn--[a-z0-9]+\.example$/)
    expect(() => canonicalUserId('dns', '\u{2EBF0}.example')).toThrow(NOT_CANONICAL)
  })
})
