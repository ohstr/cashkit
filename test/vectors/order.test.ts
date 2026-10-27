// order.json: NIP-CO terms, the buyer key, the order fee, confirmation tiers,
// the mint split, order notices, cash_order requests and order replies. The
// Hub's own decisions (requestRefusals, placement, states, retention) are not
// the buyer's and are not run here.
import { describe, expect, test } from 'vitest'
import {
  buyerKeyFromSecret,
  cashCommitment,
  cashOrderRequest,
  confirmationsFor,
  decodeToken,
  isOrderNotice,
  mintSplit,
  orderFee,
  orderNoticeFilter,
  parseOrder,
  parseOrderInfo,
  sellsNothing,
  validateTerms,
  verifyEvent,
  verifyProvenance,
  type KindTerms,
  type MintRecipient,
  type Payment,
} from '../../src/core/index.js'
import { named, type Json } from './helpers.js'
import { canon, loadExact } from './json-big.js'

const v = loadExact('order.json')
const title = (c: Json, i: number) => c.name ?? c.id ?? `case ${i}`

const MISMATCH = new Set([
  // JSON.parse reads 1e3 as 1000: cashkit cannot tell the exponent form apart and accepts it; nmilat refuses it.
  'min_millis 1e3',
  // cashkit's validateTerms does not check window > 0.
  'window 0',
  // cashkit's orderFee works in bigint: an amount of 2^64-1 plus a fee does not overflow, so it is not refused.
  'fee lightning 18446744073709551615',
  // cashkit's orderFee takes any payment string as Lightning; nmilat refuses "card".
  'fee card 1000',
  // The vector's invoice "lnbc210220n1..." is a placeholder: cashkit's parseOrder decodes the invoice and requires it to be for exactly pay_millis.
  'Lightning, open (reply)',
  'Lightning, open (lookup)',
  // cashkit's parseOrder reads replies and lookups alike: it does not refuse a direct reply whose order is not open.
  'on-chain, minted (a lookup\'s done result) (reply)',
  'a minted bill already destroyed (reply)',
])

const kindTerms = (k: Json): KindTerms => ({ minMillis: 0n, maxMillis: 0n, feeBase: BigInt(k.feeBase), feePpm: BigInt(k.feePpm), window: 0 })

/** A kind's terms in the vector's snake case. */
const k = (x: Json) => (x === undefined ? undefined : { fee_base: x.feeBase, fee_ppm: x.feePpm, max_millis: x.maxMillis, min_millis: x.minMillis, window: x.window, ...(x.confirmations !== undefined && { confirmations: x.confirmations.map((y: Json) => ({ n: y.n, ...(y.upToMillis !== undefined && { up_to_millis: y.upToMillis }) })) }) })

describe('order.json terms', () => {
  test.each(named(v.getInfo, title))('get_info: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    let info: unknown
    try {
      info = JSON.parse(c.getInfo)
    } catch {
      expect(c.error).toBeDefined()
      return
    }
    if (c.error !== undefined) {
      expect(() => parseOrderInfo(info)).toThrow()
      return
    }
    const t = parseOrderInfo(info)
    expect(sellsNothing(t)).toBe(c.sellsNothing)
    expect(canon({ bill: { min_transfer_millis: t.bill.minTransferMillis, redeem_fee_base: t.bill.redeemFeeBase, redeem_fee_ppm: t.bill.redeemFeePpm }, ...(t.lightning && { lightning: k(t.lightning) }), ...(t.onchain && { onchain: k(t.onchain) }) })).toEqual(canon(c.terms))
    if (c.validate !== undefined) expect(() => validateTerms(t, 1_000_000_000n)).toThrow()
    else if (!sellsNothing(t)) expect(() => validateTerms(t, 1_000_000_000n)).not.toThrow()
  })
})

describe('order.json buyer key, fee, tiers, split', () => {
  test.each(named(v.buyerKey, (c, i) => c.id ?? `case ${i}`))('buyer key: %s', (_, c: Json) => {
    if (c.error !== undefined) {
      expect(() => buyerKeyFromSecret(c.cashSecret)).toThrow()
      return
    }
    expect(cashCommitment(c.cashSecret)).toBe(c.commitment)
    expect(buyerKeyFromSecret(c.cashSecret)).toEqual({ secretKey: c.buyerSk, pubkey: c.buyerPk })
  })
  test.each(named(v.orderFee, (c) => c.id ?? `fee ${c.payment} ${c.amountMillis}`))('order fee: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const run = () => orderFee(c.payment as Payment, kindTerms(c), BigInt(c.amountMillis))
    if (c.error !== undefined) expect(run).toThrow()
    else expect(run()).toEqual({ feeMillis: BigInt(c.feeMillis), payMillis: BigInt(c.payMillis) })
  })
  test.each(named(v.confirmations, (c) => c.id ?? `value ${c.valueMillis}`))('confirmations: %s', (_, c: Json) => {
    const tiers = c.tiers.map((t: Json) => ({ n: t.n, ...(t.up_to_millis !== undefined && { upToMillis: BigInt(t.up_to_millis) }) }))
    if (c.error !== undefined) expect(() => confirmationsFor(tiers, BigInt(c.valueMillis))).toThrow()
    else expect(confirmationsFor(tiers, BigInt(c.valueMillis))).toBe(c.n)
  })
  test.each(named(v.mintSplit, (c) => c.id ?? `received ${c.receivedMillis}`))('mint split: %s', (_, c: Json) => {
    expect(mintSplit(BigInt(c.receivedMillis), BigInt(c.feeMillis), BigInt(c.maxMillis))).toEqual(c.bills.map(BigInt))
  })
})

describe('order.json notice', () => {
  const n = v.notice
  test('K-ON-1 filter', () => {
    expect(orderNoticeFilter(n.notify)).toEqual(n.filter)
  })
  test.each(named(n.isOrderNotice))('is order notice: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    // A notice is a signed event; cashkit reads only those whose signature verifies, then checks the shape.
    expect(verifyEvent(c.event) && isOrderNotice(c.event, c.notify)).toBe(c.notice)
  })
})

const EXAMPLE = { recipient: { identity_type: 'cash', identity_value: '630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd' }, amount_millis: 21000000, payment: 'lightning', notify: '0123456789abcdef'.repeat(4), request_id: '00112233445566778899aabbccddeeff' }
/** The refused requests carry no input: each is the NIP example with the one change its name says. */
const REFUSED: Record<string, Json> = {
  'amount 0': { ...EXAMPLE, amount_millis: 0 },
  'on-chain 21,000,500': { ...EXAMPLE, amount_millis: 21000500, payment: 'onchain' },
  'payment bitcoin': { ...EXAMPLE, payment: 'bitcoin' },
  'notify uppercase': { ...EXAMPLE, notify: EXAMPLE.notify.toUpperCase() },
  'no recipient': { ...EXAMPLE, recipient: undefined },
}

function build(input: Json) {
  const r = input.recipient
  const recipient = r === undefined ? undefined : ({ identityType: r.identity_type, identityValue: r.identity_value, ...(r.ia_pubkey !== undefined && { iaPubkey: r.ia_pubkey }), amountMillis: 0n } as MintRecipient)
  return cashOrderRequest({ recipient: recipient!, amountMillis: BigInt(input.amount_millis), payment: input.payment, notify: input.notify, requestId: input.request_id })
}

describe('order.json requests', () => {
  test.each(named(v.requests))('request: %s', (name, c: Json) => {
    if (c.error !== undefined) {
      expect(REFUSED[name]).toBeDefined()
      expect(() => build(REFUSED[name])).toThrow()
      return
    }
    const input = JSON.parse(c.input)
    expect(canon(build(input))).toEqual(canon(input))
  })
})

describe('order.json replies', () => {
  test.each(named(v.replies, (c) => `${c.name} (${c.lookup ? 'lookup' : 'reply'})`))('%s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const raw = JSON.parse(c.reply)
    const token = raw.bills?.find((b: Json) => typeof b.cash_token === 'string')?.cash_token
    let hubIdentity = '00'.repeat(32)
    try {
      hubIdentity = verifyProvenance(decodeToken(token))?.xonly ?? hubIdentity
    } catch {
      // a bad token: the reply is refused anyway
    }
    const run = () => parseOrder(raw, { request: { payment: c.payment, amount_millis: BigInt(raw.amount_millis ?? 0) }, hubIdentity, chain: 'bitcoin', network: 'mainnet' })
    if (c.error !== undefined) {
      expect(run).toThrow()
      return
    }
    const o = run()
    const w = c.want
    expect(o.state).toBe(w.state)
    expect(canon({ amount: o.amountMillis, fee: o.feeMillis, pay: o.payMillis, payBy: o.payBy, address: o.address ?? null, confirmations: o.confirmations ?? null })).toEqual(canon({ amount: w.amount_millis, fee: w.fee_millis, pay: w.pay_millis, payBy: w.pay_by, address: w.address ?? null, confirmations: w.confirmations ?? null }))
    expect(canon(o.bills.map((b) => ({ amount_millis: b.amountMillis, cash_token: b.token, outpoint: b.outpoint, paid_millis: b.paidMillis, wallet_pubkey: b.walletPubkey })))).toEqual(canon(w.bills.map((b: Json) => (typeof b.cash_token === 'string' ? b : { ...b, cash_token: { status: b.cash_token.status, reason: b.cash_token.reason, retainedUntil: b.cash_token.retained_until } }))))
  })
})
