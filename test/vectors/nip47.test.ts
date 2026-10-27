// nip47.json: pairing URIs, info events, request and response events,
// notifications and get_info's network, chain and circle_wallet block.
import { describe, expect, test } from 'vitest'
import {
  buildPairingURI,
  fromHex,
  nip44,
  nwcRequestEvent,
  parseCircleWalletInfo,
  parseInfoEvent,
  parseNotificationEvent,
  parsePairingURI,
  parseResponseEvent,
  readNetworkChain,
  validNetwork,
  verifyEvent,
} from '../../src/core/index.js'
import { load, named, plain, type Json } from './helpers.js'

const v = load('nip47.json')
const appSecret = fromHex('04'.repeat(32))
const walletSecret = fromHex('05'.repeat(32))

describe('nip47.json', () => {
  test.each(named(v.pairingBuild, (c) => c.uri))('build %s', (_: string, c: Json) => {
    expect(buildPairingURI(c.walletPubkey, c.relays, c.secret, c.extra)).toBe(c.uri)
  })
  test.each(named(v.pairingParse))('parse: %s', (_: string, c: Json) => {
    if (c.error !== undefined) expect(() => parsePairingURI(c.uri)).toThrow()
    else expect({ ...parsePairingURI(c.uri) }).toEqual(c.want)
  })
  test.each(named(v.info))('info: %s', (_: string, c: Json) => {
    const e = { ...c.event, tags: c.event.tags ?? [] }
    if (c.error !== undefined) expect(() => parseInfoEvent(e)).toThrow()
    else expect({ ...parseInfoEvent(e) }).toEqual(c.want)
  })
  test.each(named(v.requests))('request: %s', (_: string, c: Json) => {
    const e = c.event
    expect(verifyEvent(e)).toBe(true)
    expect(JSON.parse(nip44.decrypt(e.content, nip44.getConversationKey(walletSecret, e.pubkey)))).toEqual(JSON.parse(c.plaintext))
    // Re-encrypting with nmilat's nonce must give nmilat's bytes.
    const nonce = Uint8Array.from(atob(e.content), (ch) => ch.charCodeAt(0)).subarray(1, 33)
    const exp = e.tags.find((t: string[]) => t[0] === 'expiration')?.[1]
    const ours = nwcRequestEvent({ connectionSecret: appSecret, walletPubkey: e.tags[0][1], method: c.method, ...(c.params !== null && { params: c.params }), createdAt: e.created_at, nonce, ...(exp !== undefined && { expiration: Number(exp) }) })
    expect(ours).toEqual({ pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content })
  })
  test.each(named(v.responses))('response: %s', (_: string, c: Json) => {
    const e = { ...c.event, tags: c.event.tags ?? [] }
    if (c.error !== undefined) {
      expect(() => parseResponseEvent(e, appSecret, c.fallback)).toThrow()
      return
    }
    const { request_event_id, sub_payment_id, result_type, error, result } = c.want
    expect(parseResponseEvent(e, appSecret, c.fallback)).toEqual({
      resultType: result_type,
      ...(error && { error }),
      ...(result !== undefined && { result }),
      requestEventId: request_event_id,
      subPaymentId: sub_payment_id,
    })
  })
  test.each(named(v.notifications))('notification: %s', (_: string, c: Json) => {
    expect(verifyEvent(c.event)).toBe(true)
    expect(parseNotificationEvent(c.event, appSecret)).toEqual({ type: c.type, notification: c.payload })
  })
  test.each(named(v.getInfo))('get_info: %s', (_: string, c: Json) => {
    const raw = JSON.parse(c.result)
    const nc = readNetworkChain(raw)
    const network = nc.network ?? nc.networkRaw
    expect(network === '' ? undefined : network).toBe(c.want.network)
    expect(nc.chain).toBe(c.want.chain)
    expect(validNetwork(raw.network)).toBe(c.validNetwork)
    const cw = parseCircleWalletInfo(raw)
    if (c.want.circle_wallet === undefined) {
      expect(cw).toBeUndefined()
      return
    }
    const w = c.want.circle_wallet
    expect(plain({ available_millis: cw!.available_millis, max_exp_secs: cw!.max_exp_secs, fees_ppm: cw!.fees_ppm, circle_policy: cw!.circle_policy })).toEqual({ available_millis: String(w.available_millis), max_exp_secs: w.max_exp_secs, fees_ppm: w.fees_ppm, circle_policy: w.circle_policy })
    if (w.fee_reserve !== null) expect(plain(cw!.fee_reserve)).toEqual({ ppm: w.fee_reserve.ppm, min_millis: String(w.fee_reserve.min_millis) })
    if (w.dust_threshold_millis !== null) expect(cw!.dust_threshold_millis).toBe(BigInt(w.dust_threshold_millis))
    // A missing accepting reads as false.
    expect(cw!.accepting).toBe(c.accepting === true)
    if (c.missingAlways.includes('identity')) expect(cw!.identity).toBeUndefined()
  })
})
