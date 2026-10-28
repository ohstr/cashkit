// cw-fees.json: NIP-CW §Fees and §Own Funds and Caps: the fee skim, the routing-fee reserve, a payment's most cost, the send cap.
import { describe, expect, test } from 'vitest'
import { maxPaymentCost } from '../../src/core/index.js'
import { CircleWalletClient } from '../../src/client/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('cw-fees.json')
const reserve = { ppm: Number(v.feeReserve.ppm), min_millis: BigInt(v.feeReserve.min_millis) }
const noReserve = { ppm: 0, min_millis: 0n }
const title = (c: Json) => `${c.id ?? 'case'} amount ${c.amount}`

describe('cw-fees.json', () => {
  test.each(named(v.feeSkim, title))('fee skim: %s', (_, c: Json) => {
    expect(maxPaymentCost(BigInt(c.amount), v.feesPpm, noReserve) - BigInt(c.amount)).toBe(BigInt(c.want))
  })
  test.each(named(v.routingFeeReserve, title))('routing-fee reserve: %s', (_, c: Json) => {
    expect(maxPaymentCost(BigInt(c.amount), 0, reserve) - BigInt(c.amount)).toBe(BigInt(c.want))
  })
  test.each(named(v.maxCost, title))('max cost: %s', (_, c: Json) => {
    expect(maxPaymentCost(BigInt(c.amount), v.feesPpm, reserve)).toBe(BigInt(c.want))
  })
  test.each(named(v.sendCap, title))('send cap: %s', (_, c: Json) => {
    const p = CircleWalletClient.previewPayment(BigInt(c.amount), {
      feesPpm: v.feesPpm,
      feeReserve: reserve,
      balance: 1n << 60n,
      active: true,
      budget: { totalBudget: BigInt(c.cap), usedBudget: BigInt(c.used), totalReceiveBudget: 0n, usedReceiveBudget: 0n },
    })
    expect(p.maxCost).toBe(BigInt(c.maxCost))
    expect(p.withinSendRoom).toBe(c.allowed)
  })
})
