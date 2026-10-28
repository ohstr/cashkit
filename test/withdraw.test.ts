// On-chain withdrawals: addresses, transactions, the fee and its spec
// example, quote and receipt checks, and wallet.withdraw against a fake Hub.
// Cases follow nmilat nipcash/withdraw_*_test.go.
import { describe, expect, test } from 'vitest'
import {
  classifyAddress,
  classifyAddressAmong,
  CoreError,
  decodeWitnessAddress,
  derivedRequestId,
  finalizeEvent,
  getPublicKey,
  nearMatch,
  nip44,
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
import { FakeBank } from './fakeBank.js'
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
// sent_by follows the clock, so a second may pass between two quotes.
const noClock = (f: readonly string[] | undefined) => (f ?? []).filter((x) => x !== 'sentBy')

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
  test('requote: a new handle listing what changed; the old one can no longer be sent', async () => {
    const { h, hub, id } = await setup()
    const q = await h.wallet.withdraw.quote(id, PAYTO)
    const same = await h.wallet.withdraw.requote(q)
    expect(noClock(same.quoteChanged)).toEqual([])
    expect(same.handle).not.toBe(q.handle)
    expect(await failure(h.wallet.withdraw.send(q, { confirm: yes }))).toMatchObject({ reason: 'quote_used' })
    hub.networkFee = 1_500_000n
    const moved = await h.wallet.withdraw.requote(same)
    expect(noClock(moved.quoteChanged)).toEqual(['networkFeeMillis', 'feeMillis', 'payoutMillis'])
    let shown: readonly string[] | undefined
    const v = await h.wallet.withdraw.send(moved, { confirm: (x) => ((shown = x.quoteChanged), Promise.resolve(true)) })
    expect(noClock(shown)).toEqual(['networkFeeMillis', 'feeMillis', 'payoutMillis'])
    expect(v.payoutMillis).toBe(moved.payoutMillis)
  })
  test('recover: a withdrawal whose record was lost is found from the bill’s tombstone and followed, never placed again', async () => {
    const { h, hub, id } = await setup()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
    const lost = (await h.storage.tx('r', (x) => x.get('pendingCalls', v.id)))!
    await h.storage.tx('rw', (x) => x.delete('pendingCalls', v.id))
    const placed = h.bank.hub.requests.filter((r) => r.item.method === 'cash_withdraw').length
    const r = await h.wallet.withdraw.recover(id)
    expect(r).toMatchObject({ phase: 'accepted', state: 'queued', payoutMillis: 19_258_000n, holdingId: id })
    const call = (await h.storage.tx('r', (x) => x.get('pendingCalls', r.id)))!
    expect(call).toMatchObject({ requestId: lost.requestId, state: 'open_withdraw', params: { recovered: '1' } })
    expect(h.bank.hub.requests.filter((x) => x.item.method === 'cash_withdraw')).toHaveLength(placed)
    // Known now: recovering again returns it.
    expect((await h.wallet.withdraw.recover(id)).id).toBe(r.id)
    hub.broadcast(hub.only())
    expect((await h.wallet.withdraw.refresh(r.id)).phase).toBe('broadcast')
  })
  test('recover: an earlier recovery that closed not_sent does not hide the withdrawal', async () => {
    const { h, id } = await setup()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
    const lost = (await h.storage.tx('r', (x) => x.get('pendingCalls', v.id)))!
    await h.storage.tx('rw', async (x) => {
      await x.delete('pendingCalls', v.id)
      await x.put('pendingCalls', { ...lost, id: 'pc-dead', state: 'done', outcome: 'not_sent', params: { recovered: '1' }, version: 1 }, 0)
    })
    const r = await h.wallet.withdraw.recover(id)
    expect(r.id).not.toBe('pc-dead')
    expect(r).toMatchObject({ phase: 'accepted', state: 'queued' })
  })
  test('recover: a recovered call is never placed again, and nothing is written when asked to', async () => {
    const { h, id } = await setup()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
    await h.storage.tx('rw', (x) => x.delete('pendingCalls', v.id))
    const r = await h.wallet.withdraw.recover(id)
    // As if a lookup had answered unknown and the call waited on a confirmation.
    await h.storage.tx('rw', async (x) => {
      const c = (await x.get('pendingCalls', r.id))!
      await x.put('pendingCalls', { ...c, needsUser: 'confirm_replace', version: c.version + 1 }, c.version)
    })
    const before = await h.storage.tx('r', async (x) => ({ calls: (await x.list('pendingCalls')).length, derived: (await x.list('derivedIds')).length }))
    expect(await failure(h.wallet.pendingCalls.confirmReplace(r.id))).toMatchObject({ code: 'usage', reason: 'recovered_call' })
    expect(await h.storage.tx('r', async (x) => ({ calls: (await x.list('pendingCalls')).length, derived: (await x.list('derivedIds')).length }))).toEqual(before)
    expect((await h.storage.tx('r', (x) => x.get('pendingCalls', r.id)))!.state).toBe('open_withdraw')
  })
  test('recover: a bill no withdrawal ended is not_found', async () => {
    const { h, id } = await setup()
    expect(await failure(h.wallet.withdraw.recover(id))).toMatchObject({ code: 'not_found', reason: 'no_withdrawal' })
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
  test('a cancelled payout whose re-minted bill names another wallet or another minter is not imported', async () => {
    const { h, hub, id } = await setup()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
    const p = hub.only()
    hub.cancel(p)
    const real = p.newWallet!
    const me = { type: 'pubkey' as const, value: h.me }
    const sealedFor = (from: { walletKey: Uint8Array }, token: string) => nip44.encrypt(token, nip44.getConversationKey(from.walletKey, h.me))
    // Decrypts under the named wallet, but the token inside is another wallet's.
    const named = h.bank.mint(p.amount, me)
    p.newWallet = { pubkey: named.walletPubkey, token: sealedFor(named, h.bank.mint(p.amount, me).token) }
    expect((await h.wallet.withdraw.refresh(v.id)).phase).toBe('accepted')
    // The named wallet's own token, minted by another Hub.
    const elsewhere = new FakeBank(h.pool, ['wss://elsewhere.test'], { seed: 0x0b })
    await elsewhere.start()
    const foreign = elsewhere.mint(p.amount, me)
    p.newWallet = { pubkey: foreign.walletPubkey, token: sealedFor(foreign, foreign.token) }
    expect((await h.wallet.withdraw.refresh(v.id)).phase).toBe('accepted')
    expect(await h.wallet.holdings()).toEqual([])
    p.newWallet = real
    expect((await h.wallet.withdraw.refresh(v.id)).phase).toBe('cancelled')
    expect(await h.wallet.holdings()).toHaveLength(1)
  })
})

describe('wallet.withdraw: a cancelled payout', () => {
  test('without its re-minted bill is malformed', () => {
    const base = { state: 'cancelled', address: PAYTO, amount_millis: 1, fee_millis: 0, payout_millis: 1, sent_by: 1, final_depth: 6, signed: false, receipt: '{}' }
    expect(() => parsePayout(base)).toThrow(expect.objectContaining({ code: 'invalid_payload' }))
    expect(() => parsePayout({ ...base, new_wallet_pubkey: 'ab'.repeat(32) })).toThrow(expect.objectContaining({ code: 'invalid_payload' }))
  })
  test('whose re-minted bill is a tombstone closes and tells the user once, asking nothing', async () => {
    const { h, hub, id } = await setup()
    const v = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes })
    const p = hub.only()
    hub.cancel(p)
    p.newWallet = { pubkey: p.newWallet!.pubkey, token: { status: 'spent', reason: 'redeemed' } as unknown as string }
    const seen: unknown[] = []
    h.wallet.on('confirm', (r) => {
      seen.push(r)
      return false
    })
    const after = await h.wallet.withdraw.refresh(v.id)
    expect(after.phase).toBe('cancelled')
    expect(after.remintGone).toEqual({ reason: 'redeemed' })
    expect(await h.wallet.holdings()).toEqual([])
    // A notice, told once; nothing waits for the user.
    expect(await h.wallet.pendingCalls.list()).toEqual([])
    await h.wallet.withdraw.refresh(v.id)
    expect(seen).toEqual([expect.objectContaining({ type: 'withdrawCancelled', id: v.id, remintGone: { reason: 'redeemed' } })])
  })
})

describe('wallet.withdraw: a lost withdrawal is placed again (NIP-CP §Lookups)', () => {
  let skew = 0
  const clock = () => Date.now() + skew
  async function lost(o: { reused?: boolean; refusedDetail?: string } = {}) {
    skew = 0
    const h = await harness({ deps: { clock } })
    h.bank.hub.clock = clock
    const hub = new FakeWithdraw(h.bank)
    const r = await h.wallet.receive(h.bank.mintToPubkey(21_000_000n, h.me).token)
    const id = r.received ? r.holding.id : ''
    const prev = h.bank.override
    // The call never reaches the Hub (or is answered REQUEST_REUSED, or refused): its lookup then answers unknown.
    h.bank.override = (m, info) =>
      m === 'cash_withdraw' && (info.params as Record<string, unknown>)['cancel'] !== true
        ? o.reused === true
          ? { error: { code: 'REQUEST_REUSED', message: 'used' } }
          : o.refusedDetail !== undefined
            ? { error: { code: 'RESTRICTED', message: 'x', detail: o.refusedDetail } }
            : 'omit'
        : prev?.(m, info)
    const e = await h.wallet.withdraw.send(await h.wallet.withdraw.quote(id, PAYTO), { confirm: yes }).then(
      () => undefined,
      (x: unknown) => x as CashkitError,
    )
    const pc = (await h.storage.tx('r', (x) => x.list('pendingCalls'))).find((c) => c.kind === 'withdraw')!
    h.bank.override = prev
    skew = (pc.deadline + 2) * 1000 - Date.now()
    return { h, hub, id, e, pc }
  }
  test('after no answer and an unknown lookup: automatically, under the derived id, with the same quote and notify', async () => {
    const { h, pc } = await lost()
    const rep = await h.wallet.settle()
    expect(rep.replaced).toEqual([pc.id])
    const all = await h.storage.tx('r', (x) => x.list('pendingCalls'))
    const next = all.find((c) => c.derivedFrom === pc.id)!
    expect(next).toMatchObject({ requestId: derivedRequestId(pc.requestId), attempts: 2, state: 'open_withdraw' })
    expect(next.params).toMatchObject({ quote: pc.params!['quote'], notify: pc.params!['notify'] })
    expect(all.find((c) => c.id === pc.id)).toMatchObject({ outcome: 'replaced' })
    const sent = h.bank.hub.requests.filter((r) => r.item.method === 'cash_withdraw').map((r) => r.params['request_id'])
    expect(sent.at(-1)).toBe(next.requestId)
  })
  test('after REQUEST_REUSED: waits for the user (confirm_replace), never automatically', async () => {
    const { h, pc } = await lost({ reused: true })
    const before = h.bank.hub.requests.filter((r) => r.item.method === 'cash_withdraw').length
    await h.wallet.settle()
    expect(await h.storage.tx('r', (x) => x.get('pendingCalls', pc.id))).toMatchObject({ needsUser: 'confirm_replace', sawReused: true })
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_withdraw')).toHaveLength(before)
  })
  test('a call refused quote_expired is closed refused, never placed again', async () => {
    const { h, pc } = await lost({ refusedDetail: 'quote_expired' })
    await h.wallet.settle()
    expect(await h.storage.tx('r', (x) => x.get('pendingCalls', pc.id))).toMatchObject({ state: 'done', outcome: 'not_applied', needsUser: 'refused', lastDetail: 'quote_expired' })
    expect((await h.storage.tx('r', (x) => x.list('pendingCalls'))).some((c) => c.derivedFrom === pc.id)).toBe(false)
  })
  test('a re-placement of a chain whose earlier call was refused quote_expired is closed refused', async () => {
    const { h, pc } = await lost()
    // As if this call replaced one the Hub refused quote_expired.
    await h.storage.tx('rw', async (x) => {
      await x.put('pendingCalls', { ...pc, id: 'pc-parent', state: 'done', outcome: 'replaced', lastCode: 'RESTRICTED', lastDetail: 'quote_expired', version: 1 }, 0)
      const c = (await x.get('pendingCalls', pc.id))!
      await x.put('pendingCalls', { ...c, derivedFrom: 'pc-parent', version: c.version + 1 }, c.version)
    })
    await h.wallet.settle()
    expect(await h.storage.tx('r', (x) => x.get('pendingCalls', pc.id))).toMatchObject({ state: 'done', outcome: 'not_applied', lastDetail: 'quote_expired' })
    expect((await h.storage.tx('r', (x) => x.list('pendingCalls'))).some((c) => c.derivedFrom === pc.id)).toBe(false)
  })
})
