// lsp-announcement.json: NIP-LSP announcements (kind 10735) — K-LSP-1..6,
// parsing in step order, the live check and the fields from LSPS answers.
import { describe, expect, test } from 'vitest'
import { AnnouncementError, checkLive, fromLspsInfo, nodeIds, parseAnnouncement, parseListProtocols, parseLsps1Info, parseLsps2Menu, type FeeRow, type LspAnnouncement, type LspOption } from '../../src/client/lsp.js'
import { load, named, type Json } from './helpers.js'
import { canon } from './json-big.js'

const v = load('lsp-announcement.json')

const stepOf = (run: () => unknown): number => {
  try {
    run()
  } catch (e) {
    return e instanceof AnnouncementError ? e.step : -1
  }
  return 0
}

const options = (xs: readonly LspOption[]) => xs.map((o) => ({ Name: o.name, Value: o.value }))
const rows = (xs: readonly FeeRow[]) => xs.map((r) => ({ MaxClientToSelfDelay: r.maxClientToSelfDelay, MaxPaymentSizeMillis: r.maxPaymentSizeMillis, MinFeeMillis: r.minFeeMillis, MinLifetime: r.minLifetime, MinPaymentSizeMillis: r.minPaymentSizeMillis, Proportional: r.proportional }))

const shape = (a: LspAnnouncement) => ({
  Addrs: a.addrs,
  Chain: a.chain,
  Display: { Content: a.content ?? '', Image: a.image ?? '', Languages: a.languages, Operator: a.operator === undefined ? null : { Pubkey: a.operator.pubkey, Relay: a.operator.relay ?? '' }, Title: a.title ?? '', Website: a.website ?? '' },
  Expiration: a.expiration,
  LSPS1: options(a.lsps1),
  LSPS2: rows(a.lsps2),
  LSPS5: options(a.lsps5),
  Network: a.network,
  NodeKey: a.nodeKey,
  Protocols: a.protocols,
  Relays: a.relays,
  Status: a.status,
  displayTitle: a.displayTitle,
  nodeIds: nodeIds(a.nodeKey),
  selling: a.selling,
  shown: a.shown,
})

describe('lsp-announcement.json events', () => {
  test.each(named(v.events, (c) => c.id))('%s', (_, c: Json) => {
    expect(stepOf(() => parseAnnouncement(c.event, v.client))).toBe(c.step)
  })
})

describe('lsp-announcement.json parse', () => {
  test.each(named(v.parse))('%s', (_, c: Json) => {
    const client = c.client ?? v.client
    expect(stepOf(() => parseAnnouncement(c.event, client))).toBe(c.step)
    // Go writes an empty list as null.
    if (c.want !== undefined) expect(canon(shape(parseAnnouncement(c.event, client)))).toEqual(canon({ ...c.want, LSPS1: c.want.LSPS1 ?? [], LSPS2: c.want.LSPS2 ?? [], LSPS5: c.want.LSPS5 ?? [] }))
  })
})

const VERDICT: Record<string, number> = { same: 0, worse: 1, better: 2 }
const kLsp1 = parseAnnouncement(v.events[0].event, v.client)

describe('lsp-announcement.json live check', () => {
  test.each(named(v.checkLive))('%s', (_, c: Json) => {
    const d = checkLive(kLsp1, {
      protocols: parseListProtocols(c.protocols),
      ...(c.lsps1 != null && { lsps1: parseLsps1Info(c.lsps1) }),
      ...(c.lsps2 != null && { lsps2Menu: parseLsps2Menu(c.lsps2) }),
    })
    const changed = d.fields.filter((f) => f.verdict !== 'same').map((f) => ({ Field: f.field, Announced: f.announced, Live: f.live, Verdict: VERDICT[f.verdict] }))
    expect({ missingProtocol: d.missingProtocol, changed, same: changed.length === 0 && d.missingProtocol.length === 0, worse: d.worse, usable: d.usable }).toEqual({ missingProtocol: c.missingProtocol, changed: c.changed, same: c.same, worse: c.worse, usable: c.usable })
  })
})

describe('lsp-announcement.json from LSPS answers', () => {
  const meta = { nodeKey: kLsp1.nodeKey, addrs: kLsp1.addrs, chain: kLsp1.chain, network: kLsp1.network }
  test.each(named(v.fromLSPSInfo))('%s', (_, c: Json) => {
    const run = () => fromLspsInfo({ protocols: [1, 2, 5], lsps1Info: c.lsps1, lsps2Menu: c.lsps2, lsps5: c.lsps5, meta })
    if (c.error !== undefined) {
      expect(run).toThrow()
      return
    }
    const f = run()
    expect(canon({ Protocols: f.protocols, LSPS1: options(f.lsps1 ?? []), LSPS2: rows(f.lsps2 ?? []), LSPS5: options(f.lsps5 ?? []) })).toEqual(canon({ Protocols: c.fields.Protocols, LSPS1: c.fields.LSPS1, LSPS2: c.fields.LSPS2, LSPS5: c.fields.LSPS5 }))
  })
})
