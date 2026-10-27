// tlv.json: cash token decode and encode (TLV 0-3, the provenance pair 5/6
// and its scheme TLV 8, the hub group TLV 7) and bech32 framing.
import { describe, expect, test } from 'vitest'
import { decodeToken, encodeToken, fromHex, toHex, type Token, type TokenScheme } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('tlv.json')

const MISMATCH = new Set<string>()

const SCHEME_NUM: Record<TokenScheme, number> = { none: 0, mint_v1: 1, zap_v1: 2, malformed: 255 }
const SCHEME_NAME: Record<number, TokenScheme> = { 0: 'none', 1: 'mint_v1', 2: 'zap_v1', 255: 'malformed' }
const utf8 = new TextDecoder('utf-8', { ignoreBOM: true })

/** A decoded token in vector form: every TLV 1 entry as encoded, hex bytes, decimal amount, null for absent. */
const tokenToJSON = (t: Token) => ({
  hrp: t.hrp,
  walletPubkey: t.walletPubkey,
  secret: t.secret,
  relays: (t.relayBytes ?? []).map((b) => utf8.decode(b)),
  identityRequired: t.identityRequired ?? null,
  mintSignature: t.mintSignature ? toHex(t.mintSignature) : null,
  attestedAmountMillis: t.attestedAmountMillis?.toString() ?? null,
  hubGroup: t.hubGroup ? toHex(t.hubGroup) : null,
  scheme: SCHEME_NUM[t.scheme],
})

const fieldsOf = (f: Json) => ({
  hrp: f.hrp,
  walletPubkey: f.walletPubkey,
  secret: f.secret,
  relays: f.relays,
  ...(f.identityRequired !== null && { identityRequired: f.identityRequired }),
  ...(f.mintSignature !== null && { mintSignature: fromHex(f.mintSignature.toLowerCase()) }),
  ...(f.attestedAmountMillis !== null && { attestedAmountMillis: BigInt(f.attestedAmountMillis) }),
  ...(f.hubGroup !== null && { hubGroup: fromHex(f.hubGroup) }),
  scheme: SCHEME_NAME[f.scheme] ?? 'none',
})

describe('tlv.json', () => {
  const decode = named(v.decode, (c) => `${c.kind}: ${c.name}`)
  test.each(decode.filter(([, c]) => !MISMATCH.has(c.name)))('decode %s', (_: string, c: Json) => {
    if (c.error) expect(() => decodeToken(c.input)).toThrow()
    else expect(tokenToJSON(decodeToken(c.input))).toEqual(c.want)
  })
  test.skip.each(decode.filter(([, c]) => MISMATCH.has(c.name)))('decode (mismatch) %s', (_: string, c: Json) => {
    expect(tokenToJSON(decodeToken(c.input))).toEqual(c.want)
  })
  const encode = named(v.encode, (c) => `${c.kind}: ${c.name}`)
  test.each(encode.filter(([, c]) => !MISMATCH.has(c.name)))('encode %s', (_: string, c: Json) => {
    if (c.error) expect(() => encodeToken(fieldsOf(c.fields))).toThrow()
    else expect(encodeToken(fieldsOf(c.fields))).toBe(c.output)
  })
  test.skip.each(encode.filter(([, c]) => MISMATCH.has(c.name)))('encode (mismatch) %s', (_: string, c: Json) => {
    expect(() => encodeToken(fieldsOf(c.fields))).toThrow()
  })
})
