// Unit tests for NIP-01 events. Cases follow nmilat nip01/event_test.go and
// nip13 tests; the escaping cases pin nmilat's behaviour, which the Hub uses
// to recompute ids.
import { describe, expect, test } from 'vitest'
import {
  CoreError,
  finalizeEvent,
  getEventHash,
  getPublicKey,
  powDifficulty,
  serializeEvent,
  verifyEvent,
  type NostrEvent,
} from '../src/core/index.js'
import { fill } from './helpers.js'

const sk = fill(1, 32)
const template = { kind: 23198, created_at: 1760000000, tags: [['d', 'ab'.repeat(32)], ['amount_millis', '21000']], content: '' }

describe('nip01', () => {
  test('a signed event verifies and carries the right pubkey and id', () => {
    const e = finalizeEvent(template, sk)
    expect(e.pubkey).toBe(getPublicKey(sk))
    expect(e.id).toBe(getEventHash(e))
    expect(verifyEvent(e)).toBe(true)
  })
  test('signing does not keep a reference to the caller’s tags', () => {
    const tags = [['t', 'a']]
    const e = finalizeEvent({ ...template, tags }, sk)
    tags[0]![1] = 'b'
    expect(verifyEvent(e)).toBe(true)
  })
  test('the same aux randomness gives the same signature', () => {
    const aux = fill(9, 32)
    expect(finalizeEvent(template, sk, aux).sig).toBe(finalizeEvent(template, sk, aux).sig)
  })
  test.each<[string, (e: NostrEvent) => NostrEvent]>([
    ['content changed', (e) => ({ ...e, content: 'x' })],
    ['a tag changed', (e) => ({ ...e, tags: [['d', 'cd'.repeat(32)]] })],
    ['created_at changed', (e) => ({ ...e, created_at: e.created_at + 1 })],
    ['kind changed', (e) => ({ ...e, kind: 1 })],
    ['signature byte flipped', (e) => ({ ...e, sig: (e.sig[0] === '0' ? '1' : '0') + e.sig.slice(1) })],
    ['id uppercased', (e) => ({ ...e, id: e.id.toUpperCase() })],
    ['another key’s signature', (e) => ({ ...e, sig: finalizeEvent(template, fill(2, 32)).sig })],
    ['kind out of range', (e) => ({ ...e, kind: 70000 })],
    ['short pubkey', (e) => ({ ...e, pubkey: e.pubkey.slice(2) })],
    ['empty signature', (e) => ({ ...e, sig: '' })],
  ])('verification fails when %s', (_, mutate) => {
    expect(verifyEvent(mutate(finalizeEvent(template, sk)))).toBe(false)
  })
  test('an uppercase pubkey or signature still verifies, as in nmilat', () => {
    const e = finalizeEvent(template, sk)
    expect(verifyEvent({ ...e, pubkey: e.pubkey.toUpperCase(), sig: e.sig.toUpperCase() })).toBe(true)
  })
  test('serialization lowercases the pubkey and writes empty tags as []', () => {
    const s = serializeEvent({ pubkey: 'AB'.repeat(32), created_at: 1, kind: 1, tags: [], content: '' })
    expect(s).toBe(`[0,"${'ab'.repeat(32)}",1,1,[],""]`)
  })
  test('escaping: tags escape U+2028 and content does not; controls become \\u00xx', () => {
    const s = serializeEvent({ pubkey: 'ab'.repeat(32), created_at: 1, kind: 1, tags: [['t', 'a \u0001']], content: 'a \u0001"\\' })
    expect(s).toBe(`[0,"${'ab'.repeat(32)}",1,1,[["t","a\\u2028\\u0001"]],"a \\u0001\\"\\\\"]`)
  })
  test('html characters and slashes are not escaped', () => {
    expect(serializeEvent({ pubkey: 'ab'.repeat(32), created_at: 1, kind: 1, tags: [['t', '<&>/']], content: '<&>/' })).toContain('[["t","<&>/"]],"<&>/"')
  })
  test('refuses a non-integer created_at or kind and an invalid secret key', () => {
    expect(() => finalizeEvent({ ...template, created_at: 1.5 }, sk)).toThrow(CoreError)
    expect(() => finalizeEvent({ ...template, kind: 1.5 }, sk)).toThrow(CoreError)
    expect(() => finalizeEvent(template, new Uint8Array(32))).toThrow(CoreError)
  })
})

describe('nip13 nonce check', () => {
  test('difficulty counts leading zero bits', () => {
    expect(powDifficulty('00'.repeat(32))).toBe(256)
    expect(powDifficulty('0f' + 'ff'.repeat(31))).toBe(4)
    expect(powDifficulty('007f' + 'ff'.repeat(30))).toBe(9)
    expect(powDifficulty('ff'.repeat(32))).toBe(0)
  })
  test.each([
    [['nonce', '1', '0'], true],
    [['nonce', '1', '-3'], true],
    [['nonce', '1', '+0'], true],
    [['nonce', '1', '250'], false],
    [['nonce', '1'], false],
    [['nonce', '1', 'x'], false],
    [['nonce', '1', ' 1'], false],
  ])('a nonce tag %j verifies: %s', (nonce, ok) => {
    expect(verifyEvent(finalizeEvent({ ...template, tags: [nonce] }, sk))).toBe(ok)
  })
  test('two nonce tags fail', () => {
    expect(verifyEvent(finalizeEvent({ ...template, tags: [['nonce', '1', '0'], ['nonce', '2', '0']] }, sk))).toBe(false)
  })
})
