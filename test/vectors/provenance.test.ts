// provenance.json: the cash-mint:v1 and cash-zap:v1 payloads, the per-HRP
// signed-message prefix, and minter recovery from the compact signature.
// reservedSignText is not covered: refusing those labels is a Hub's sign-message rule, not a client's.
import { describe, expect, test } from 'vitest'
import {
  CHAIN_TABLE,
  chainForHrp,
  decodeToken,
  fromHex,
  mintPayloadV1,
  relayHashOf,
  signCompact,
  signedMessageDigest,
  signedMessagePrefix,
  toHex,
  verifyProvenance,
  verifyZapProvenance,
  zapPayloadV1,
  zapTargetHash,
  type TokenScheme,
} from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('provenance.json')

const MISMATCH = new Set<string>()

const enc = new TextEncoder()
const SCHEME: Record<number, TokenScheme> = { 0: 'none', 1: 'mint_v1', 2: 'zap_v1', 255: 'malformed' }
const split = (rows: [string, Json][]) => [rows.filter(([n]) => !MISMATCH.has(n)), rows.filter(([n]) => MISMATCH.has(n))] as const

const zapPayloadOf = (c: Json) =>
  zapPayloadV1({
    hrp: c.hrp,
    walletPubkey: c.walletPubkey,
    amountMillis: BigInt(c.amountMillis),
    relayHash: c.relayHash,
    recipient: c.zap.recipient,
    sender: c.zap.sender,
    zapTarget: c.zap.zapTarget,
    issuedAt: c.zap.issuedAt,
    expiresAt: c.zap.expiresAt,
  })

describe('provenance.json', () => {
  test.each(named(v.mintPayload))('mintPayload %s', (_: string, c: Json) => {
    const relayHash = relayHashOf(c.relays.map((r: string) => enc.encode(r)), c.secret)
    expect(relayHash).toBe(c.relayHash)
    expect(mintPayloadV1({ hrp: c.hrp, walletPubkey: c.walletPubkey, amountMillis: BigInt(c.amountMillis), relayHash })).toBe(c.payload)
  })

  const [zapOk, zapSkip] = split(named(v.zapPayload))
  test.each(zapOk)('zapPayload %s', (_: string, c: Json) => {
    if (c.error) {
      expect(() => zapPayloadOf(c)).toThrow()
      return
    }
    expect(zapTargetHash(c.zap.zapTarget)).toBe(c.targetHash)
    expect(zapPayloadOf(c)).toBe(c.payload)
  })
  test.skip.each(zapSkip)('zapPayload (mismatch) %s', (_: string, c: Json) => {
    expect(() => zapPayloadOf(c)).toThrow()
  })

  test('specToken', () => {
    const s = v.specToken
    const t = decodeToken(s.token)
    expect(signedMessagePrefix(t.hrp)).toBe(s.prefix)
    const digest = signedMessageDigest(t.hrp, s.payload)!
    expect(toHex(digest)).toBe(s.digest)
    expect(toHex(t.mintSignature!)).toBe(s.signature)
    expect(t.mintSignature![0]).toBe(s.header)
    expect(toHex(signCompact(digest, fromHex(s.minterSecret)))).toBe(s.signature)
    expect(verifyProvenance(t)).toEqual({ minter: s.minter, xonly: s.minterXOnly })
  })

  const [prefixOk, prefixSkip] = split(named(v.signedMessagePrefix, (c) => c.hrp || '(empty)'))
  test.each(prefixOk)('signedMessagePrefix %s', (_: string, c: Json) => {
    expect(signedMessagePrefix(c.hrp) ?? null).toBe(c.prefix)
    expect(chainForHrp(c.hrp) ?? null).toBe(c.chain)
  })
  test.skip.each(prefixSkip)('signedMessagePrefix (mismatch) %s', (_: string, c: Json) => {
    expect(chainForHrp(c.hrp) ?? null).toBe(c.chain)
  })

  // No chain → prefix function in cashkit; CHAIN_TABLE holds the same mapping.
  test.each(named(v.chainSignedMessagePrefix, (c) => c.chain || '(empty)'))('chainSignedMessagePrefix %s', (_: string, c: Json) => {
    expect(Object.values(CHAIN_TABLE).find((r) => r.chain === c.chain)?.prefix ?? null).toBe(c.prefix)
  })

  test.each(named(v.verify))('verify %s', (_: string, c: Json) => {
    const t = {
      hrp: c.hrp,
      walletPubkey: c.walletPubkey,
      secret: c.secret,
      relays: c.relays,
      relayBytes: c.relays.map((r: string) => enc.encode(r)),
      scheme: SCHEME[c.scheme] ?? 'malformed',
      ...(c.mintSignature !== null && { mintSignature: fromHex(c.mintSignature) }),
      ...(c.attestedAmountMillis !== null && { attestedAmountMillis: BigInt(c.attestedAmountMillis) }),
    }
    const got = c.zap ? verifyZapProvenance(t, c.zap) : verifyProvenance(t)
    expect(got?.minter ?? null).toBe(c.minter)
  })
})
