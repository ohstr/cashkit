// lookup.json: the Hub's lookup decision, the client's deadline, lookup
// params and done results. The deadline, recordRetained,
// tombstoneAnswerable and answersWithTombstone sections are Hub-side rules
// with no cashkit counterpart.
import { describe, expect, test } from 'vitest'
import { deadlineFor } from '../../src/client/session.js'
import { cashLookupParams, decodeLookupDone, decideLookup, parseCashLookupResult, parseTombstone } from '../../src/core/index.js'
import { parseJSONValue } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('lookup.json')
// A join lookup by connection_pubkey runs on a fixed 360 s window, whatever H.
const JOIN_HORIZON = 360
/** JSON with bigints as numbers: every amount here is a safe integer. */
const numeric = (x: unknown): unknown => JSON.parse(JSON.stringify(x, (_k, y) => (typeof y === 'bigint' ? Number(y) : y)))

describe('lookup.json', () => {
  test.each(named(v.decideLookup, (c, i) => `${c.id ?? 'decide'} #${i}`))('decideLookup %s', (_: string, c: Json) => {
    const got = decideLookup({ now: c.now, deadline: c.deadline, horizon: c.join ? JOIN_HORIZON : c.horizon, hasRecord: c.haveRecord })
    const g = typeof got === 'string' ? { status: got, retryAfter: 0 } : got
    expect(g).toEqual({ status: c.status, retryAfter: c.retryAfter })
  })
  test.each(named(v.deadlineWindow, (c) => `H=${c.horizon}`))('deadline window %s', (_: string, c: Json) => {
    expect(deadlineFor(c.horizon, 1720000000) - 1720000000).toBe(c.window)
  })
  test.each(named(v.params))('params: %s', (_: string, c: Json) => {
    const p = c.params
    const by = { ...(p.request_id !== undefined && { requestId: p.request_id }), ...(p.connection_pubkey !== undefined && { connectionPubkey: p.connection_pubkey }) } as { requestId: string }
    const go = () => cashLookupParams(by, p.deadline, p.cash_secret)
    if (c.error) expect(go).toThrow()
    else expect(go()).toEqual(p)
  })
  test.each(named(v.results))('result: %s', (_: string, c: Json) => {
    const go = () => parseCashLookupResult(parseJSONValue(c.result))
    if (c.error) {
      expect(go).toThrow()
      return
    }
    const r = go()
    expect(r.status).toBe(c.status)
    if (r.status === 'pending') expect(r.retryAfter).toBe(c.retryAfter)
    if (r.status !== 'done') return
    if (c.gone) {
      const g = c.gone
      expect(parseTombstone(r.result)).toEqual({
        status: g.status,
        ...(g.reason !== undefined && { reason: g.reason }),
        ...(g.retained_until !== undefined && { retainedUntil: g.retained_until }),
        ...(g.withdraw_request_id !== undefined && { withdrawRequestId: g.withdraw_request_id }),
      })
      return
    }
    expect(parseTombstone(r.result)).toBeUndefined()
    expect(numeric(decodeLookupDone(r.result))).toEqual({ result: c.inner, tombstones: {} })
  })
})
