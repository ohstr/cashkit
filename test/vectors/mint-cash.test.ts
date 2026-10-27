// mint-cash.json: the cash commitment, the mint_cash request and its result
// (a lookup may answer a tombstone where the token was).
import { describe, expect, test } from 'vitest'
import { cashCommitment, decodeLookupDone, mintCashRequest, newConnectionKey, parseMintCashResult, type MintRecipient, type Tombstone } from '../../src/core/index.js'
import { parseJSONValue } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('mint-cash.json')
const PUBKEY = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
const K_CMT_1 = v.commitment[0]

const pubkey = (amount: number): MintRecipient => ({ identityType: 'pubkey', identityValue: PUBKEY, amountMillis: BigInt(amount) })
// The error cases name their recipients in words.
const SHORTHAND: Record<string, MintRecipient[]> = {
  'cash + pubkey': [{ identityType: 'cash', identityValue: K_CMT_1.commit, amountMillis: 21000n }, pubkey(1000)],
  pubkey: [pubkey(21000)],
  'pubkey 0': [pubkey(0)],
}
function recipient(r: Json): MintRecipient {
  const amountMillis = BigInt(r.amount)
  if (r.pubkey !== undefined) return { identityType: 'pubkey', identityValue: r.pubkey, amountMillis }
  if (r.cashSecret !== undefined) return { identityType: 'cash', identityValue: cashCommitment(r.cashSecret), amountMillis }
  const [platform] = Object.keys(r).filter((k) => k !== 'amount' && k !== 'ia')
  return { identityType: 'connection_key', identityValue: newConnectionKey(platform!, r[platform!]), iaPubkey: r.ia, amountMillis }
}
const recipients = (x: Json): MintRecipient[] => (x === undefined ? [] : typeof x === 'string' ? SHORTHAND[x]! : x.map(recipient))
const plainRequest = (r: Json): Json => JSON.parse(JSON.stringify(r, (_k, y) => (typeof y === 'bigint' ? Number(y) : y)))
const wire = (t: Tombstone): Json => ({ status: t.status, ...(t.reason !== undefined && { reason: t.reason }), ...(t.retainedUntil !== undefined && { retained_until: t.retainedUntil }) })

// Parsed as cashkit reads each: a direct reply arrives over NIP-47 (JSON.parse), a lookup's
// result over the private transport (parseJSONValue, integers as bigints).
const parse = (c: Json): unknown => (c.lookup ? parseJSONValue(c.result) : JSON.parse(c.result))
const MISMATCH = new Set<string>()

// Every result case answers a one-recipient request.
const SENT = mintCashRequest({ recipients: [pubkey(21000)], requestId: '00112233445566778899aabbccddeeff' })

describe('mint-cash.json', () => {
  test.each(named(v.commitment, (c, i) => `${c.id ?? 'commitment'} #${i}${c.note ? ` (${c.note})` : ''}`))('%s', (_: string, c: Json) => {
    if (c.error) expect(() => cashCommitment(c.secret)).toThrow()
    else if (c.note) expect(cashCommitment(c.secret)).not.toBe(c.commit)
    else expect(cashCommitment(c.secret)).toBe(c.commit)
  })

  test.each(named(v.requests))('request: %s', (_: string, c: Json) => {
    const i = c.inputs
    const go = () => mintCashRequest({ recipients: recipients(i.recipients), ...(i.expirySeconds !== undefined && { expirySeconds: i.expirySeconds }), requestId: i.requestId ?? '' })
    if (c.error) expect(go).toThrow()
    else expect(plainRequest(go())).toEqual(c.request)
  })

  test.each(named(v.results, (c) => `${c.name}${c.lookup ? ' (lookup)' : ''}`))('result: %s', (title: string, c: Json) => {
    if (MISMATCH.has(title)) return
    if (c.error) {
      expect(() => {
        const raw = parse(c)
        parseMintCashResult(c.lookup ? decodeLookupDone(raw).result : raw, SENT)
      }).toThrow()
      return
    }
    const raw = parse(c)
    if (c.lookup) {
      const { result, tombstones } = decodeLookupDone(raw)
      if (tombstones.cash_token !== undefined) {
        // The bill is gone: the lookup answers its tombstone where the token was.
        expect(wire(tombstones.cash_token)).toEqual(c.want.cash_token)
        expect([result['wallet_pubkey'], plainRequest(result['recipients'])]).toEqual([c.want.wallet_pubkey, c.want.recipients])
        return
      }
    }
    const r = parseMintCashResult(raw, SENT)
    expect({
      cash_token: r.cashToken,
      ...(r.expiresAt !== undefined && { expires_at: r.expiresAt }),
      recipients: r.recipients.map((x) => ({ amount_millis: Number(x.amountMillis), identity_type: x.identityType, identity_value: x.identityValue })),
      wallet_pubkey: r.walletPubkey,
    }).toEqual(c.want)
    expect(r.cashToken).toBe(c.token)
  })
})
