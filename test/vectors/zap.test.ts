// zap.json: NIP-CZ Cash Zaps — the recipient's 10522, the tag rules
// (K-CZ-1..6), verification rules 1-8, and counting.
import { describe, expect, test } from 'vitest'
import { countCashZaps, isTrustedMinter, parseCashZapInfo, verifyCashZap, type CashZapVerdict, type NostrEvent } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('zap.json')

const MISMATCH = new Set([
  // nmilat reads a 9522 with a NIP-40 expiration tag (shown, never counted); cashkit's rule 2 refuses it, so it is not valid.
  'an expiration tag is kept, listed never counted',
  'an expiration tag: listed, never counted',
  // cashkit's rule 7 checks the target's author and time but not that e names the target event's id: it holds; nmilat fails it.
  'retargeted: another e (rule 7)',
])

describe('zap.json 10522', () => {
  test.each(named(v.info))('%s', (_, c: Json) => {
    if (c.error !== undefined) {
      expect(() => parseCashZapInfo(c.event)).toThrow()
      return
    }
    const info = parseCashZapInfo(c.event)
    for (const [chain, ok] of Object.entries(c.accepts)) expect(info.chains.length === 0 || info.chains.includes(chain)).toBe(ok)
    for (const [key, ok] of Object.entries(c.listsMinter)) {
      const [minter, chain] = key.split('/')
      expect(isTrustedMinter(minter!, chain!, info.mints)).toBe(ok)
    }
    expect(info.relays).toEqual(c.relays ?? [])
  })
})

describe('zap.json parse (rules 1-3)', () => {
  test.each(named(v.parse))('%s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const r = verifyCashZap(c.event)
    if (c.error !== undefined) {
      expect(r.valid).toBe(false)
      expect(r.failed).toBe(c.rule)
      return
    }
    expect([r.rules[1], r.rules[2], r.rules[3]]).toEqual([true, true, true])
  })
})

const info = parseCashZapInfo(v.info[0].event)
const verdict = (c: Json): CashZapVerdict => verifyCashZap(c.event, { target: v.target, ...(c.withInfo && { zapInfo: info }), trusted: c.trustedMinters.map((m: string) => ({ minter: m, chain: 'bitcoin' })) })

describe('zap.json verify (rules 1-8)', () => {
  test.each(named(v.verify))('%s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const r = verdict(c)
    // nmilat reports a skipped rule as not ok; cashkit leaves it undefined.
    expect(c.rules.map((x: Json) => r.rules[x.n as 1] ?? false)).toEqual(c.rules.map((x: Json) => x.ok))
    expect(r.minter ?? '').toBe(c.minter)
    // nmilat calls a token zap-signed once its Minter is recovered over the zap payload.
    expect(r.minter !== undefined && r.token?.scheme === 'zap_v1').toBe(c.zapSigned)
    expect(r.valid).toBe(c.valid)
    expect(r.countable).toBe(c.countable)
  })
})

describe('zap.json count', () => {
  const byName = new Map<string, Json>(v.verify.map((c: Json) => [c.name, c]))
  test.each(named(v.count))('%s', (_, c: Json) => {
    const zaps = c.zaps.map((n: string) => byName.get(n)!)
    const deletions = new Set<string>(c.deletedBySender.map((n: string) => byName.get(n)!.event.id))
    const got = countCashZaps(
      zaps.map((z: Json) => ({ event: z.event as NostrEvent, verdict: verdict(z) })),
      { minLife: c.minLifeSeconds, deletions, collapseRepeated: c.collapse },
    )
    expect(got).toEqual({ totalMillis: BigInt(c.total), counted: c.counted })
  })
})
