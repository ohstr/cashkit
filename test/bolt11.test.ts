// Unit tests for bolt11 decoding. Cases follow nmilat nip57/bolt11 tests and
// the invoices cashctl's redeem tests use.
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { describe, expect, test } from 'vitest'
import { bech32Encode, toWords } from '../src/core/bech32.js'
import { CoreError, decodeBolt11, invoiceExpiresAt, toHex } from '../src/core/index.js'
import { fill, signedInvoice } from './helpers.js'

type Field = [type: number, words: Uint8Array]

/** A structurally valid invoice with a zero signature, as nmilat never checks it. */
function invoice(hrp: string, ...fields: Field[]): string {
  const w: number[] = Array.from({ length: 7 }, () => 0)
  for (const [type, data] of fields) w.push(type, data.length >> 5, data.length & 31, ...data)
  w.push(...Array.from({ length: 104 }, () => 0))
  return bech32Encode(hrp, Uint8Array.from(w))
}
const hashField = (type: number, b: Uint8Array): Field => [type, toWords(b)]
const PH = hashField(1, fill(0xaa, 32))

const REAL_LNFC =
  'lnfc10u1p4dqm55pp55aq08rgfwhrrdpy5z5jhyd0v2p6ddlurxzj6q6gdx0a5j7c5hnyqdqdw3exzmnnvejhycqzeqxqyz5vqrzjq0uu9vvap7vzzlt63829ht853lrzuzuxgw76qe7l6qf6u5fsm2qjlapyqqqqqqqq9cqqqqlgqqqqqeqpjqsp5uv65wj7xp88qlul2pk5uymnfq2wedpn3g4545mswfmj0df4pup7q9qxpqysgqnwdkm8xuwgq4cp5ukw4kfmz6pz0zcwxtr77n05ls0ljk2rsmg46rmfdnfycwl0p26dyk0ufvmtlyxejn9sm4jp2t8ua663qnufqyhxqplfddnp'

describe('decodeBolt11', () => {
  test('a real flokicoin invoice', () => {
    const inv = decodeBolt11(REAL_LNFC)
    expect(inv.currency).toBe('fc')
    expect(inv.amountMillis).toBe(1_000_000n)
    expect(inv.paymentHash).toMatch(/^[0-9a-f]{64}$/)
  })
  test.each([
    ['lnfc', 0n],
    ['lnfc1', 100_000_000_000n],
    ['lnfc25m', 2_500_000_000n],
    ['lnfc10u', 1_000_000n],
    ['lnfc2500n', 250_000n],
    ['lnfc10p', 1n],
    ['lnfc007u', 700_000n],
  ])('amount in %s is %s millis', (hrp, millis) => {
    expect(decodeBolt11(invoice(hrp, PH)).amountMillis).toBe(millis)
  })
  test('a multiplier with no digits is part of the currency', () => {
    expect(decodeBolt11(invoice('lnfcu', PH))).toMatchObject({ currency: 'fcu', amountMillis: 0n })
  })
  test.each(['lnfc15p', 'lnfc7x', 'lnfc99999999999', 'lnfc92233720368547758m', 'lnfc99999999999999999999999u'])(
    'refuses amount %s (bad pico, unknown multiplier, or beyond int64 where nmilat wraps)',
    (hrp) => {
      expect(() => decodeBolt11(invoice(hrp, PH))).toThrow(CoreError)
    },
  )
  test('reads the description and its hash', () => {
    const inv = decodeBolt11(invoice('lnfc1u', PH, [13, toWords(new TextEncoder().encode('coffee ☕'))], hashField(23, fill(0xdd, 32))))
    expect(inv.description).toBe('coffee ☕')
    expect(inv.descriptionHash).toBe('dd'.repeat(32))
  })
  test('skips unknown fields and malformed hashes; the last valid payment hash wins', () => {
    expect(decodeBolt11(invoice('lnfc1u', [9, Uint8Array.of(1, 2, 3)], PH)).paymentHash).toBe('aa'.repeat(32))
    expect(decodeBolt11(invoice('lnfc1u', PH, hashField(1, fill(0xbb, 32)))).paymentHash).toBe('bb'.repeat(32))
    expect(decodeBolt11(invoice('lnfc1u', [1, toWords(fill(0xaa, 31))], PH)).paymentHash).toBe('aa'.repeat(32))
  })
  test.each<[string, string]>([
    ['no payment hash', invoice('lnfc1u', [13, toWords(new TextEncoder().encode('x'))])],
    ['only a short payment hash', invoice('lnfc1u', [1, toWords(fill(0xaa, 31))])],
    ['a truncated field', bech32Encode('lnfc1u', Uint8Array.from([...Array(7).fill(0), 1, 1, 20, 0, 0, ...Array(104).fill(0)]))],
    ['data shorter than timestamp and signature', bech32Encode('lnfc1u', new Uint8Array(100))],
    ['a non-lightning HRP', invoice('lokicash', PH)],
    ['not bech32', 'lnfc1notaninvoice'],
  ])('refuses %s', (_, s) => {
    expect(() => decodeBolt11(s)).toThrow(CoreError)
  })
  test('accepts an all-uppercase invoice', () => {
    expect(decodeBolt11(invoice('lnfc1u', PH).toUpperCase()).paymentHash).toBe('aa'.repeat(32))
  })
})

describe('decodeBolt11: creation time, expiry and payee', () => {
  const node = fill(0x5a, 32)
  const nodeKey = toHex(secp256k1.getPublicKey(node, true))
  test('the payee recovers from the signature; the expiry defaults to an hour', () => {
    const i = decodeBolt11(signedInvoice({ amountMillis: 21000n, nodeKey: node, timestamp: 1_700_000_000 }))
    expect(i).toMatchObject({ amountMillis: 21000n, timestamp: 1_700_000_000, expirySeconds: 3600, payee: nodeKey })
    expect(invoiceExpiresAt(i)).toBe(1_700_003_600)
  })
  test('an x field sets the expiry; an n field names the payee', () => {
    const other = toHex(secp256k1.getPublicKey(fill(0x6b, 32), true))
    const i = decodeBolt11(signedInvoice({ nodeKey: node, timestamp: 1_700_000_000, expiry: 600, payeeField: other }))
    expect(i).toMatchObject({ expirySeconds: 600, payee: other })
  })
  test('a zero signature recovers no payee', () => {
    expect(decodeBolt11(invoice('lnfc10n', PH)).payee).toBeUndefined()
  })
})
