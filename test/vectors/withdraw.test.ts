// withdraw.json: on-chain withdrawal quotes and receipts, request_hash, the
// claim proof, the withdraw fee, witness addresses, refusal details, the
// cash_withdraw request, payouts, cancel requests and the withdraw terms. The
// Hub's own decisions (cancel, remintExpiry, retention, quoteRefusals,
// payoutRefusals, payoutStates, cancel request reading) are not run here.
import { describe, expect, test } from 'vitest'
import {
  bySecret,
  bySigning,
  cashWithdrawCancelRequest,
  cashWithdrawRequest,
  classifyAddress,
  classifyAddressAmong,
  CoreError,
  fromHex,
  getEventHash,
  localSigner,
  normalizeAddressText,
  parseDetail,
  parsePayout,
  parseWithdrawQuote,
  paysScriptType,
  quoteFeeMillis,
  quoteValidAt,
  requestHash,
  validateWithdrawTerms,
  verifyWithdrawQuote,
  verifyWithdrawReceipt,
  withdrawFee,
  type Payout,
  type ScriptType,
} from '../../src/core/index.js'
import { verificationCost } from '../../src/transport/index.js'
import { named, type Json } from './helpers.js'
import { canon, loadExact } from './json-big.js'

const v = loadExact('withdraw.json')
const inp = v.inputs
const PAYS: ScriptType[] = [
  [0, 20],
  [0, 32],
  [1, 32],
]
const label = (c: Json, i: number) => c.name ?? (c.id ? `${c.id} ${c.address ?? c.input ?? i}` : `case ${i} ${c.address ?? c.input ?? ''}`)

const MISMATCH = new Set<string>([
  // cashkit's withdrawFee works in bigint: a network fee of 2^64-1 does not overflow, so it is not refused.
  'amount 10 network 18446744073709551615',
  // nmilat's hrp "" accepts any HRP; cashkit's classifyAddress requires exactly the HRP given and refuses "bc" under "".
  'case 16 bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
  // cashkit's parsePayout does not refuse a txid on a queued payout.
  'queued with a txid',
  // cashkit's parsePayout does not refuse a tx on an unsigned payout.
  'tx while unsigned',
  // nmilat accepts an empty script_types list; cashkit's validateWithdrawTerms refuses it.
  'no script type',
  // cashkit's validateWithdrawTerms takes any program length 2..40; nmilat refuses a version-0 length other than 20 or 32.
  'an invalid script type',
])

const CLASS: Record<string, string> = { address_network: 'network', address_malformed: 'malformed', address_no_witness: 'script_type' }
const classOf = (run: () => unknown): string => {
  try {
    run()
  } catch (e) {
    return e instanceof CoreError ? (CLASS[e.code] ?? e.code) : String(e)
  }
  return 'none'
}

describe('withdraw.json quotes and receipts', () => {
  test.each(named(v.quotes, (c) => c.id))('quote: %s', (_, c: Json) => {
    const q = parseWithdrawQuote(JSON.stringify(c.event))
    verifyWithdrawQuote(q, inp.hub)
    expect(q.wallet).toBe(inp.wallet)
    expect(q.address).toBe(inp.address)
    expect(quoteFeeMillis(q)).toBe(BigInt(c.feeMillis))
  })
  test.each(named(v.requestHash, (c) => c.id))('request_hash: %s', (_, c: Json) => {
    // A "negative" note gives the hash over some other bytes, which request_hash must not be.
    if (c.note?.startsWith('negative') === true) expect(requestHash(c.requestIdHex)).not.toBe(c.hash)
    else expect(requestHash(c.requestIdHex)).toBe(c.hash)
  })
  test.each(named(v.receipts, (c) => c.id))('receipt: %s', (_, c: Json) => {
    const tag = (k: string) => c.event.tags.find((t: string[]) => t[0] === k)[1]
    const requestId = v.requestHash.find((r: Json) => r.hash === tag('request_hash')).requestIdHex
    verifyWithdrawReceipt(JSON.stringify(c.event), { hubXOnly: inp.hub, target: inp.wallet, quoteId: tag('q'), requestId, address: inp.address, payoutMillis: 19258000n, sentBy: 1720003600 })
  })
  test('K-CLAIM-5 claim proof id', () => {
    const p = v.claimProof
    expect(getEventHash({ kind: p.kind, pubkey: p.pubkey, created_at: p.createdAt, tags: p.tags, content: '' })).toBe(p.want)
  })
  test.each(named(v.parseQuote))('parse quote: %s', (_, c: Json) => {
    const run = () => verifyWithdrawQuote(parseWithdrawQuote(c.input), inp.hub)
    if (c.error !== undefined) expect(run).toThrow()
    else expect(run).not.toThrow()
  })
  test.each(named(v.verifyReceipt))('verify receipt: %s', (_, c: Json) => {
    const x = c.want.expectation
    const run = () => verifyWithdrawReceipt(c.input, { hubXOnly: x.HubXOnly, target: x.Target, quoteId: x.QuoteID, requestId: x.RequestID, address: x.Address, payoutMillis: BigInt(x.PayoutMillis), sentBy: x.SentBy })
    if (c.error !== undefined) expect(run).toThrow()
    else expect(run).not.toThrow()
  })
})

describe('withdraw.json fee and addresses', () => {
  test.each(named(v.withdrawFee, (c) => c.id || `amount ${c.amountMillis} network ${c.networkFeeMillis}`))('withdraw fee: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const run = () => withdrawFee(BigInt(c.amountMillis), BigInt(c.networkFeeMillis), BigInt(c.withdrawFeeBase), BigInt(c.withdrawFeePpm), BigInt(c.redeemFeeMillis))
    if (c.error !== undefined) expect(run).toThrow()
    else expect(run()).toEqual({ hubFee: BigInt(c.hubFeeMillis), fee: BigInt(c.feeMillis), payout: BigInt(c.payoutMillis) })
  })
  test.each(named(v.address, label))('address: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    if (c.error !== undefined) {
      expect(classOf(() => classifyAddress(c.address, c.hrp))).toBe(c.class)
      return
    }
    const st = classifyAddress(c.address, c.hrp)
    expect(st).toEqual(c.scriptType)
    expect(classOf(() => paysScriptType(PAYS, st)) === 'none').toBe(c.paidByHub)
  })
  test.each(named(v.normalizeAddress, label))('normalize: %s', (_, c: Json) => {
    if (c.error !== undefined) expect(() => normalizeAddressText(c.input)).toThrow()
    else expect(normalizeAddressText(c.input)).toBe(c.output)
  })
  test.each(named(v.classifyAddressAmong, label))('classify among: %s', (_, c: Json) => {
    if (c.error !== undefined) expect(classOf(() => classifyAddressAmong(c.address, c.hrps))).toBe(c.class)
    else expect(classifyAddressAmong(c.address, c.hrps)).toEqual({ scriptType: c.scriptType, hrp: c.hrp })
  })
  test.each(named(v.detail, (c, i) => `${c.id || 'case'} ${i}`))('detail: %s', (_, c: Json) => {
    expect(parseDetail(JSON.parse(c.error).detail) ?? '').toBe(c.detail)
  })
  test.each(named(v.quoteValidAt, (c) => `${c.id} tip ${c.tip}`))('quote valid at: %s', (_, c: Json) => {
    expect(quoteValidAt(c.holdsUntil, c.tip)).toBe(c.valid)
  })
  test.each(named(v.verificationCost))('verification cost: %s', (_, c: Json) => {
    expect(verificationCost({ id: 'x', target: inp.wallet, method: 'cash_withdraw', params: c.params, ...(c.hasProof && { proof: '{}' }), billProof: '{}' })).toBe(c.cost)
  })
})

describe('withdraw.json requests', () => {
  const signer = localSigner(fromHex(inp.sliceSecret))
  test.each(named(v.withdrawRequestRefusals))('cash_withdraw: %s', async (_, c: Json) => {
    const i = JSON.parse(c.input)
    const run = async () =>
      cashWithdrawRequest({
        walletPubkey: inp.wallet,
        quote: parseWithdrawQuote(i.quote),
        credential: c.slice.CashMode ? bySecret(i.cash_secret) : bySigning(signer),
        requestId: i.request_id,
        notify: i.notify,
        ...(i.remint_commitment !== undefined && { remintCommitment: i.remint_commitment }),
        ...(c.slice.Commitment !== '' && { sliceCommitment: c.slice.Commitment }),
        now: 1720000050,
      })
    if (c.error !== undefined) {
      await expect(run()).rejects.toThrow()
      return
    }
    const got = await run()
    // The vector stands a literal "{}" in for the signed claim proof: compare it apart.
    if (c.want.identity_event !== undefined) {
      const proof = JSON.parse(got['identity_event'] as string)
      expect(proof.kind).toBe(23198)
      expect(proof.tags).toEqual([
        ['d', inp.wallet],
        ['m', 'cash_withdraw'],
        ['q', parseWithdrawQuote(i.quote).id],
      ])
      got['identity_event'] = c.want.identity_event
    }
    expect(got).toEqual(c.want)
  })
  test.each(named(v.cancelShapes))('cancel: %s', (_, c: Json) => {
    // Reading a cancel request is the Hub's; cashkit only writes the two valid shapes.
    if (c.want.request === undefined) return
    const i = JSON.parse(c.input)
    expect(cashWithdrawCancelRequest({ requestId: i.request_id, ...(i.cash_secret !== undefined && { cashSecret: i.cash_secret }) })).toEqual(c.want.request)
  })
})

const snake = (p: Payout) => ({
  address: p.address,
  amount_millis: p.amountMillis,
  fee_millis: p.feeMillis,
  final_depth: p.finalDepth,
  payout_millis: p.payoutMillis,
  receipt: p.receipt,
  sent_by: p.sentBy,
  signed: p.signed,
  state: p.state,
  ...(p.tx !== undefined && { tx: p.tx }),
  ...(p.txid !== undefined && { txid: p.txid }),
  ...(p.vout !== undefined && { vout: p.vout }),
  ...(p.depth !== undefined && { depth: p.depth }),
  ...(p.newWalletPubkey !== undefined && { new_wallet_pubkey: p.newWalletPubkey }),
  ...(p.newWalletToken !== undefined && { new_wallet_token: typeof p.newWalletToken === 'string' ? p.newWalletToken : { status: p.newWalletToken.status, ...(p.newWalletToken.reason !== undefined && { reason: p.newWalletToken.reason }) } }),
})

describe('withdraw.json payouts and terms', () => {
  test.each(named(v.payouts))('payout: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const run = () => parsePayout(JSON.parse(c.input))
    if (c.error !== undefined) expect(run).toThrow()
    else expect(canon(snake(run()))).toEqual(canon(c.want))
  })
  test.each(named(v.withdrawObject))('withdraw terms: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const t = validateWithdrawTerms(JSON.parse(c.input))
    if (c.error !== undefined) {
      expect(t).toBeUndefined()
      return
    }
    expect(t?.scriptTypes).toEqual(c.want.scriptTypes)
    const w = c.want.terms
    expect(canon({ base: t?.withdrawFeeBase, ppm: t?.withdrawFeePpm, min: t?.minMillis ?? null, max: t?.maxMillis ?? null, depth: t?.finalDepth })).toEqual(canon({ base: w.withdraw_fee_base, ppm: w.withdraw_fee_ppm, min: w.min_millis ?? null, max: w.max_millis ?? null, depth: w.final_depth }))
  })
})
