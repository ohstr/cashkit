// On-chain withdrawals: addresses, transactions, the fee and its spec
// example, quote and receipt checks, and wallet.withdraw against a fake Hub.
// Cases follow nmilat nipcash/withdraw_*_test.go.
import { describe, expect, test } from 'vitest'
import {
  classifyAddress,
  classifyAddressAmong,
  CoreError,
  decodeWitnessAddress,
  finalizeEvent,
  getPublicKey,
  nearMatch,
  normalizeAddressText,
  parsePayout,
  parseTx,
  parseWithdrawQuote,
  requestHash,
  toHex,
  txid,
  verifyPayoutTx,
  verifyWithdrawReceipt,
  withdrawFee,
} from '../src/core/index.js'
import { CashkitError } from '../src/wallet/index.js'
import { FakeWithdraw, PAYTO, payoutTx } from './fakeWithdraw.js'
import { fill } from './helpers.js'
import { harness, type Harness } from './walletHarness.js'

const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )

describe('addresses (withdraw_address_test.go)', () => {
  test('BIP-173/350: v0 bech32, v1 bech32m, HRP exact; another HRP is address_network', () => {
    expect(classifyAddress(PAYTO, 'bc')).toEqual([0, 20])
    expect(classifyAddress('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', 'bc')).toEqual([1, 32])
    expect(() => decodeWitnessAddress(PAYTO, 'tb')).toThrow(expect.objectContaining({ code: 'address_network' }))
    expect(classifyAddressAmong(PAYTO, ['bc', 'tb', 'bcrt'])).toEqual({ scriptType: [0, 20], hrp: 'bc' })
  })
  test('a v1 address with a bech32 checksum, a legacy address and mixed case are refused', () => {
    expect(() => decodeWitnessAddress('bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx', 'bc')).toThrow(CoreError)
    expect(() => decodeWitnessAddress('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 'bc')).toThrow(expect.objectContaining({ code: 'address_no_witness' }))
    expect(() => normalizeAddressText('bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).toThrow(expect.objectContaining({ code: 'address_malformed' }))
    expect(normalizeAddressText(` ${PAYTO.toUpperCase()} `)).toBe(PAYTO)
  })
  test('a look-alike: same HRP, same first and last six characters, not equal', () => {
    const fake = `${PAYTO.slice(0, 10)}zzzz${PAYTO.slice(14)}`
    expect(nearMatch(PAYTO, fake)).toBe(true)
    expect(nearMatch(PAYTO, PAYTO)).toBe(false)
  })
})

describe('payout transactions (withdraw_tx_test.go)', () => {
  test('the id and the output are checked; another value or script is a mismatch', () => {
    const tx = payoutTx(PAYTO, 19_258n)
    const id = txid(parseTx(tx))
    expect(() => verifyPayoutTx(tx, id, 0, PAYTO, '', 19_258_000n)).not.toThrow()
    expect(() => verifyPayoutTx(tx, id, 0, PAYTO, '', 19_259_000n)).toThrow(expect.objectContaining({ code: 'tx_mismatch' }))
    expect(() => verifyPayoutTx(tx, 'ab'.repeat(32), 0, PAYTO, '', 19_258_000n)).toThrow(CoreError)
    expect(() => verifyPayoutTx(tx, id, 1, PAYTO, '', 19_258_000n)).toThrow(CoreError)
    expect(() => parseTx(`${tx}00`)).toThrow(CoreError)
  })
})

describe('the fee (§The Withdraw Fee)', () => {
  test('the spec example: 21,000,000 millis pays out 19,258,000', () => {
    expect(withdrawFee(21_000_000n, 1_200_000n, 500_000n, 2000n, 105_000n)).toEqual({ hubFee: 542_000n, fee: 1_742_000n, payout: 19_258_000n })
  })
  test('the redeem fee floors it, the amount caps it, and the payout is whole base units', () => {
    expect(withdrawFee(1_000_000n, 0n, 0n, 0n, 300_500n).payout).toBe(699_000n)
    expect(withdrawFee(1_000n, 5_000n, 0n, 0n, 0n)).toEqual({ hubFee: 0n, fee: 1_000n, payout: 0n })
    expect(() => withdrawFee(1n, 0n, 0n, 1_000_001n, 0n)).toThrow(expect.objectContaining({ code: 'withdraw_fee_invalid' }))
  })
})

describe('quotes, receipts and payouts', () => {
  const node = fill(0x61, 32)
  const NODE = getPublicKey(node)
  const sign = (kind: number, tags: string[][], content = '') => JSON.stringify(finalizeEvent({ kind, created_at: 1, tags, content }, node))
  const quoteTags = [['d', 'aa'.repeat(32)], ['i', 'bb'.repeat(32)], ['address', PAYTO], ['amount_millis', '21000000'], ['network_fee_millis', '1200000'], ['hub_fee_millis', '542000'], ['payout_millis', '19258000'], ['sent_by', '1720003600'], ['holds_until', '870413']]
  test('a quote in any tag order parses; a leading zero, a repeated tag or content is malformed', () => {
    expect(parseWithdrawQuote(sign(23187, [quoteTags[8]!, ...quoteTags.slice(0, 8)]))).toMatchObject({ payoutMillis: 19_258_000n, holdsUntil: 870413 })
    expect(() => parseWithdrawQuote(sign(23187, quoteTags.map((t) => (t[0] === 'sent_by' ? ['sent_by', '01720003600'] : t))))).toThrow(expect.objectContaining({ code: 'quote_malformed' }))
    expect(() => parseWithdrawQuote(sign(23187, [...quoteTags, ['d', 'aa'.repeat(32)]]))).toThrow(CoreError)
    expect(() => parseWithdrawQuote(sign(23187, quoteTags, 'x'))).toThrow(CoreError)
    expect(() => parseWithdrawQuote(sign(23188, quoteTags))).toThrow(CoreError)
  })
  test('a receipt binds the bill, quote, request hash, address, payout and sent_by', () => {
    const rid = 'cd'.repeat(16)
    const r = sign(23188, [['d', 'aa'.repeat(32)], ['q', 'ee'.repeat(32)], ['request_hash', requestHash(rid)], ['address', PAYTO], ['payout_millis', '19258000'], ['sent_by', '1720003600']])
    const x = { hubXOnly: NODE, target: 'aa'.repeat(32), quoteId: 'ee'.repeat(32), requestId: rid, address: PAYTO, payoutMillis: 19_258_000n, sentBy: 1720003600 }
    expect(() => verifyWithdrawReceipt(r, x)).not.toThrow()
    expect(() => verifyWithdrawReceipt(r, { ...x, requestId: 'ab'.repeat(16) })).toThrow(expect.objectContaining({ code: 'receipt_invalid' }))
    expect(() => verifyWithdrawReceipt(r, { ...x, quoteId: '' })).not.toThrow()
    expect(() => verifyWithdrawReceipt(r, { ...x, hubXOnly: 'ab'.repeat(32) })).toThrow(CoreError)
  })
  test('a payout: an unknown state, broadcast fields under cancelled, no receipt are malformed', () => {
    const base = { state: 'queued', address: PAYTO, amount_millis: 1, fee_millis: 0, payout_millis: 1, sent_by: 1, final_depth: 6, signed: false, receipt: '{}' }
    expect(parsePayout(base).state).toBe('queued')
    expect(() => parsePayout({ ...base, state: 'paid' })).toThrow(CoreError)
    expect(() => parsePayout({ ...base, state: 'cancelled', txid: 'ab'.repeat(32) })).toThrow(CoreError)
    expect(() => parsePayout({ ...base, receipt: undefined })).toThrow(CoreError)
  })
})

async function setup(): Promise<{ h: Harness; hub: FakeWithdraw; id: string }> {
  const h = await harness()
  const hub = new FakeWithdraw(h.bank)
  const r = await h.wallet.receive(h.bank.mintToPubkey(21_000_000n, h.me).token)
  return { h, hub, id: r.received ? r.holding.id : '' }
}
const yes = () => Promise.resolve(true)

describe('wallet.withdraw', () => {
  test('terms from one status read; quote checked; nothing written', async () => {
    const { h, id } = await setup()
    const t = await h.wallet.withdraw.terms(id)
    expect(t).toMatchObject({ offered: true, amountMillis: 21_000_000n, inRange: 'ok', privacy: [{ kind: 'known_amount', splitFirst: true }] })
    const q = await h.wallet.withdraw.quote(id, PAYTO.toUpperCase())
    expect(q).toMatchObject({ address: PAYTO, amountMillis: 21_000_000n, payoutMillis: 19_258_000n, feeMillis: 1_742_000n, finalDepth: 6, highFee: false, irreversible: true, unrecoverable: false })
    expect(await h.storage.tx('r', (x) => x.list('pendingCalls'))).toEqual([])
  })
  test('local refusals before any quote is asked', async () => {
    const { h, hub, id } = await setup()
    void hub
    expect(await failure(h.wallet.withdraw.quote(id, 'bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'))).toMatchObject({ code: 'invalid_input', reason: 'address_invalid' })
    expect(await failure(h.wallet.withdraw.quote(id, '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'))).toMatchObject({ reason: 'address_invalid', input: 'no_witness' })
    h.bank.withdrawTerms = { ...h.bank.withdrawTerms, script_types: [[0, 32]] }
    expect(await failure(h.wallet.withdraw.quote(id, PAYTO))).toMatchObject({ reason: 'address_invalid', input: 'script_type_not_paid' })
  })
  test('a refusal with a detail keeps it as the reason, with the public wording', async () => {
    const { h, hub, id } = await setup()
    hub.refuseQuote = { code: 'RESTRICTED', detail: 'below_min' }
    expect(await failure(h.wallet.withdraw.quote(id, PAYTO))).toMatchObject({ code: 'auth', reason: 'below_min', message: 'Too small to send on-chain.' })
    hub.refuseQuote = { code: 'NOT_IMPLEMENTED' }
    expect(await failure(h.wallet.withdraw.quote(id, PAYTO))).toMatchObject({ reason: 'withdraw_not_offered' })
  })
  test('send needs a confirmation; the receipt ends the bill and the call follows the payout to final', async () => {
    const { h, hub, id } = await setup()
    const q = await h.wallet.withdraw.quote(id, PAYTO)
    expect(await failure(h.wallet.withdraw.send(q))).toMatchObject({ reason: 'not_confirmed' })
    const q2 = await h.wallet.withdraw.quote(id, PAYTO)
    const v = await h.wallet.withdraw.send(q2, { confirm: yes })
    expect(v).toMatchObject({ phase: 'accepted', state: 'queued', payoutMillis: 19_258_000n, address: PAYTO })
    expect(await failure(h.wallet.withdraw.send(q2, { confirm: yes }))).toMatchObject({ reason: 'quote_used' })
    expect(await h.wallet.holdings()).toEqual([])
    const call = (await h.storage.tx('r', (x) => x.get('pendingCalls', v.id)))!
    expect(call.state).toBe('open_withdraw')
    expect(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? String(x) : x))).not.toContain(call.requestId)
    const p = hub.only()
    hub.broadcast(p)
    expect(await h.wallet.withdraw.refresh(v.id)).toMatchObject({ phase: 'broadcast', txCheck: 'ok', txid: p.txid })
    hub.confirm(p, 1)
    expect((await h.wallet.withdraw.refresh(v.id)).phase).toBe('confirmed')
    hub.confirm(p, 6)
    const fin = await h.wallet.withdraw.refresh(v.id)
    expect(fin.phase).toBe('final')
    expect(fin.address).toBeUndefined()
    expect((await h.storage.tx('r', (x) => x.get('pendingCalls', v.id)))!.state).toBe('done')
  })
  test('a transaction paying another value is a warning, never a failure, and is not offered', async () => {
    const { h, hub, id } = await setup()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
    hub.broadcast(hub.only(), payoutTx(PAYTO, 1n))
    expect((await h.wallet.withdraw.refresh(v.id)).txCheck).toBe('mismatch')
    expect(await failure(h.wallet.withdraw.signedTx(v.id))).toMatchObject({ reason: 'tx_not_offered' })
  })
  test('cancelled: the whole amount comes back as a re-minted holding', async () => {
    const { h, hub, id } = await setup()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
    expect(await failure(h.wallet.withdraw.cancel(v.id))).toMatchObject({ reason: 'cancel_not_due' })
    hub.cancel(hub.only())
    const after = await h.wallet.withdraw.refresh(v.id)
    expect(after.phase).toBe('cancelled')
    const [held] = await h.wallet.holdings()
    expect(held).toMatchObject({ id: after.remintHoldingId, amount: 21_000_000n })
    const row = (await h.storage.tx('r', (x) => x.get('holdings', held!.id)))!
    expect(row.origin).toBe('reminted')
  })
  test('a cash note withdraws with a fresh remint secret, and its re-mint comes back under it', async () => {
    const h = await harness()
    const hub = new FakeWithdraw(h.bank)
    const secret = toHex(fill(0x33, 32))
    const r = await h.wallet.receive(`${h.bank.mintToCash(5_000_000n, secret).token}#${secret}`)
    const id = r.received ? r.holding.id : ''
    const q = await h.wallet.withdraw.quote(id, PAYTO)
    expect(q.unrecoverable).toBe(true)
    const v = await h.wallet.withdraw.send(q, { confirm: yes })
    expect(v.phase).toBe('accepted')
    hub.cancel(hub.only())
    const after = await h.wallet.withdraw.refresh(v.id)
    const row = (await h.storage.tx('r', (x) => x.get('holdings', after.remintHoldingId!)))!
    expect(row).toMatchObject({ mode: 'cash', origin: 'reminted', amount: 5_000_000n })
  })
})

describe('wallet.withdraw: checks against what was confirmed', () => {
  test('a bill held under a merge key is refused before any quote', async () => {
    const { h, id } = await setup()
    await h.storage.tx('rw', async (t) => {
      const row = (await t.get('holdings', id))!
      await t.put('holdings', { ...row, throwawayKey: { alg: 'none', data: toHex(fill(0x44, 32)) }, version: row.version + 1 }, row.version)
    })
    expect(await failure(h.wallet.withdraw.quote(id, PAYTO))).toMatchObject({ code: 'conflict', reason: 'mid_merge' })
  })
  test('a payout naming another address or payout than the quote is not applied, even with a tx that pays it', async () => {
    const { h, hub, id } = await setup()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
    const p = hub.only() as { address: string; payout: bigint } & ReturnType<typeof hub.only>
    const other = 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'
    p.address = other
    hub.broadcast(p, payoutTx(other, p.payout / 1000n))
    const after = await h.wallet.withdraw.refresh(v.id)
    expect(after).toMatchObject({ phase: 'accepted', state: 'queued', address: PAYTO })
    expect(after.txCheck).toBeUndefined()
    p.address = PAYTO
    p.payout -= 1000n
    hub.broadcast(p, payoutTx(PAYTO, p.payout / 1000n))
    expect((await h.wallet.withdraw.refresh(v.id)).txCheck).toBeUndefined()
  })
})
