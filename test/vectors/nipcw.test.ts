// nipcw.json: the terms tag, the join proof and request, the join's details,
// get_info's circle_wallet block, member requests, notifications and get_budget.
// The Hub's own checks (verifyJoinProof, the member-request checks) are not the
// member's and are not run here.
import { describe, expect, test } from 'vitest'
import {
  buildMemberRequest,
  connectionKeyFromSecret,
  createCircleWalletRequest,
  fromHex,
  localSigner,
  parseCircleWalletInfo,
  parseCreateCircleWalletResult,
  parseNotificationEvent,
  readNetworkChain,
  termsTag,
  verifyEvent,
  type JoinTerms,
  type NostrEvent,
  type Renewal,
} from '../../src/core/index.js'
import { CircleWalletClient } from '../../src/client/index.js'
import { named, plain, type Json } from './helpers.js'
import { canon, loadExact } from './json-big.js'

const v = loadExact('nipcw.json')
const big = (x: unknown) => BigInt(x as number | bigint)
const termsOf = (t: Json): JoinTerms => ({ maxAmount: big(t.maxAmount), maxReceive: big(t.maxReceive), expiry: Number(t.expiry), ...(t.renewal !== '' && { budgetRenewal: t.renewal as Renewal }) })
const member = localSigner(fromHex('02'.repeat(32)))
const HUB = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
const CONN = connectionKeyFromSecret('00'.repeat(31) + '02').pubkey

/** The request as the vector shows it: the identity event without id and sig, and its signature checked. */
function requestShape(r: Awaited<ReturnType<typeof createCircleWalletRequest>>['request']) {
  const ev = JSON.parse(r.identity_event) as NostrEvent
  return plain({ ...r, identity_event: { content: ev.content, kind: ev.kind, pubkey: ev.pubkey, tags: ev.tags, valid: verifyEvent(ev) } })
}

describe('nipcw.json terms', () => {
  test.each(named(v.terms, (c, i) => c.id ?? `case ${i}`))('termsTag: %s', (_, c: Json) => {
    if (c.error !== undefined) expect(() => termsTag(termsOf(c.terms))).toThrow()
    else expect(termsTag(termsOf(c.terms))).toBe(c.tag)
  })
  // cashkit has no terms-tag parser (the Hub reads it); a valid tag must be what termsTag writes back.
  test.each(named(v.parseTerms.filter((c: Json) => c.error === undefined), (c) => c.input))('parseTerms round trip: %s', (_, c: Json) => {
    expect(termsTag(termsOf(c.terms))).toBe(c.input)
  })
})

describe('nipcw.json join proof and requests', () => {
  test('K-JOIN-1', async () => {
    const j = v.joinProof
    const p = await createCircleWalletRequest({ signer: localSigner(fromHex(j.signerSecret)), connectionPubkey: connectionKeyFromSecret(j.connectionSecret).pubkey, hubPubkey: j.hub, terms: { maxAmount: 100000n, maxReceive: 200000n, budgetRenewal: 'monthly' }, now: j.createdAt })
    expect(p.proofId).toBe(j.proofId)
    expect(p.deadline).toBe(j.deadline)
    expect(canon(requestShape(p.request))).toEqual(canon(j.request))
  })
  test.each(named(v.requests))('request: %s', async (_, c: Json) => {
    const i = c.inputs
    const run = () =>
      createCircleWalletRequest({
        signer: localSigner(fromHex(i.memberSecret)),
        connectionPubkey: i.connectionSecret === '' ? '' : connectionKeyFromSecret(i.connectionSecret).pubkey,
        hubPubkey: i.hub,
        terms: { maxAmount: big(i.maxAmountMillis), maxReceive: big(i.maxReceiveMillis), expiry: Number(i.expirySeconds), ...(i.budgetRenewal !== '' && { budgetRenewal: i.budgetRenewal }) },
        now: i.now,
      })
    if (c.error !== undefined) {
      await expect(run()).rejects.toThrow()
      return
    }
    expect(canon(requestShape((await run()).request))).toEqual(canon(c.request))
  })
})

describe('nipcw.json results', () => {
  test.each(named(v.results))('details: %s', async (_, c: Json) => {
    let parsed: unknown
    try {
      parsed = JSON.parse(c.result)
    } catch {
      expect(c.error).toBeDefined()
      return
    }
    const run = () => parseCreateCircleWalletResult(parsed, { signer: member, hubPubkey: HUB, connectionPubkey: CONN, requested: { maxAmount: 100000n, maxReceive: 50000n } })
    if (c.error !== undefined) {
      await expect(run()).rejects.toThrow()
      return
    }
    const d = await run()
    const w = c.want
    expect(canon({
      BudgetRenewal: d.budgetRenewal,
      CapsRaised: d.capsRaised,
      ConnectionPubkey: d.connectionPubkey,
      DustThresholdMillis: d.dustThresholdMillis,
      ExpiresAt: d.expiresAt,
      FeesPpm: d.feesPpm,
      LeakedFields: d.leakedFields.length > 0 ? d.leakedFields : null,
      MaxAmountMillis: d.maxAmount,
      MaxReceiveMillis: d.maxReceive,
      MissingTerms: d.missingTerms.length > 0 ? d.missingTerms : null,
      Relays: d.relays,
      RotationDelaySecs: d.rotationDelaySecs ?? null,
      WalletPubkey: d.walletPubkey,
    })).toEqual(canon({ ...w, BudgetRenewal: w.BudgetRenewal === '' ? 'never' : w.BudgetRenewal }))
  })
})

describe('nipcw.json circle_wallet', () => {
  test.each(named(v.circleWallet))('get_info: %s', (_, c: Json) => {
    const info = JSON.parse(c.result) as Record<string, unknown>
    const cw = parseCircleWalletInfo(info)
    expect(readNetworkChain(info).networkUnknown).toBe(!c.validNetwork)
    if (c.want.circle_wallet === undefined) {
      expect(cw).toBeUndefined()
      return
    }
    const w = c.want.circle_wallet
    expect(cw!.accepting).toBe(c.accepting === true)
    for (const [k, x] of Object.entries(w)) {
      if (x === null) continue
      expect(canon((cw as unknown as Record<string, unknown>)[k])).toEqual(canon(x))
    }
    for (const k of c.missingAlways as string[]) if (k === 'identity') expect(cw!.identity).toBeUndefined()
  })
})

describe('nipcw.json member requests', () => {
  // Built by the member; the Hub's refusals (time window, reuse, malformed tags) are the Hub's checks.
  test.each(named(v.memberRequests.filter((c: Json) => c.error === undefined)))('build: %s', async (_, c: Json) => {
    const e = c.event as NostrEvent
    const tag = (k: string) => e.tags.find((t) => t[0] === k)?.[1]
    const action = tag('action') as 'rotate' | 'freeze' | 'unfreeze'
    const conn = tag('connection')
    const built = await buildMemberRequest(member, { hubPubkey: tag('d')!, action, walletPubkey: tag('wallet')!, ...(conn !== undefined && { newConnectionPubkey: conn }), now: e.created_at })
    expect(built.id).toBe(e.id)
    expect({ Action: action, Connection: conn ?? '', CreatedAt: built.created_at, ID: built.id, Pubkey: built.pubkey, Wallet: tag('wallet') }).toEqual(c.want)
  })
})

describe('nipcw.json notifications', () => {
  test.each(named(v.notifications))('%s', (_, c: Json) => {
    const n = parseNotificationEvent(c.event, fromHex('02'.repeat(32)))
    expect(n.type).toBe(c.type)
    expect(canon(n.notification)).toEqual(canon(c.payload))
  })
})

const room = (t: bigint, u: bigint) => (u > t ? 0n : t - u)

describe('nipcw.json get_budget', () => {
  test.each(named(v.getBudget))('%s', async (_, c: Json) => {
    const client = new CircleWalletClient({ relays: {} as never }, { walletPubkey: HUB, relays: ['wss://x'], secret: '02'.repeat(32) })
    Object.defineProperty(client, 'nwc', { value: { request: async () => JSON.parse(c.result) } })
    if (c.error !== undefined) {
      await expect(client.getBudget()).rejects.toThrow()
      return
    }
    const b = await client.getBudget()
    expect(room(b.totalBudget, b.usedBudget)).toBe(big(c.remainingSend))
    const hasReceive = 'total_receive_budget' in JSON.parse(c.result)
    expect(hasReceive ? room(b.totalReceiveBudget, b.usedReceiveBudget) : null).toBe(c.remainingReceive === null ? null : big(c.remainingReceive))
  })
})
