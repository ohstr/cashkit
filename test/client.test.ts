// Client behaviour against FakeHub. Cases follow nmilat nipcash/client
// tests: batch_session, batch_pack, batch_send (chunking, failover, relay
// close), batch_outcome, bill_state, client (oneItemOutcome), check_claim,
// transfer_from_sources and rekey_cash_slice.
import { beforeEach, describe, expect, test } from 'vitest'
import {
  bySecret,
  bySigning,
  cashTargetFromSecret,
  decodeToken,
  getPublicKey,
  localSigner,
  pubkeyTarget,

} from '../src/core/index.js'
import {
  BatchSession,
  billFor,
  CashClient,
  ClientError,
  NotServedError,
  PartialProgressError,
  safeToResend,
  NOT_SENT,
  statusMany,
  WalletError,

} from '../src/client/index.js'
import { DEFAULT_LIMITS } from '../src/transport/index.js'
import { FakeHub, MemoryRelayPool, type Answer } from './fakeHub.js'
import { fill } from './helpers.js'

const R1 = 'wss://r1.test'
const R2 = 'wss://r2.test'
const holder = localSigner(fill(2, 32))
const now = () => Math.floor(Date.now() / 1000)

let pool: MemoryRelayPool
let hub: FakeHub
const deps = () => ({ relays: pool })

beforeEach(async () => {
  pool = new MemoryRelayPool()
  hub = new FakeHub(pool, [R1, R2])
  await hub.start()
})

function bill(i: number, amount = 21000n) {
  return hub.mintBill({ walletKey: fill(0x40 + i, 32), connSecret: fill(0x60 + i, 32), amount })
}

/** A signer that takes `stepMs` per signature on a fake clock the Hub shares; `fail` makes call n throw. */
function slowSetup(stepMs: number, fail?: number) {
  const clock = { t: Date.now() }
  hub.clock = () => clock.t
  let calls = 0
  const signer = {
    pubkey: holder.pubkey,
    signEvent: async (t: Parameters<typeof holder.signEvent>[0]) => {
      calls++
      if (calls === fail) throw new Error('the signer refused')
      clock.t += stepMs
      return holder.signEvent(t)
    },
    nip44Decrypt: holder.nip44Decrypt,
  }
  const d = { relays: pool, clock: () => clock.t }
  return { signer, d, requests: () => pool.published.filter((x) => x.event.kind === 23190).length }
}
const items = (n: number, signer: ReturnType<typeof slowSetup>['signer']) =>
  Array.from({ length: n }, (_, i) => ({ id: `i${i + 1}`, bill: billFor(decodeToken(bill(i + 1))), credential: bySigning(signer) }))

describe('slow signers (design §3: sign as you pack, shrink to fit)', () => {
  test('a slow signer gets smaller envelopes, each with its own fresh not_after', async () => {
    const { signer, d, requests } = slowSetup(20_000)
    const r = await new CashClient(d, bill(1)).statusMany(items(5, signer))
    expect(r.error).toBeUndefined()
    expect(r.outcomes.map((o) => o.state)).toEqual(['result', 'result', 'result', 'result', 'result'])
    // 20 s per signature against a 30 s budget (half of 60 s): two items, two items, one.
    expect(requests()).toBe(3)
    expect(new Set(r.outcomes.map((o) => o.envelope))).toEqual(new Set([0, 1, 2]))
  })
  test('one signature slower than the whole window is refused before anything is sent', async () => {
    const { signer, d, requests } = slowSetup(70_000)
    await expect(new CashClient(d, bill(1)).statusMany(items(2, signer))).rejects.toMatchObject({ code: 'signer_too_slow' })
    expect(requests()).toBe(0)
  })
  test('items left unsent when a later envelope cannot be built are refused NOT_SENT, safe to resend', async () => {
    const { signer, d } = slowSetup(40_000, 2)
    const r = await new CashClient(d, bill(1)).statusMany(items(2, signer))
    expect(r.outcomes[0]).toMatchObject({ id: 'i1', state: 'result' })
    expect(r.outcomes[1]).toMatchObject({ id: 'i2', state: 'error', error: { code: NOT_SENT } })
    expect(safeToResend(r.outcomes[1]!)).toBe(true)
  })
})

describe('BatchSession (batch_session.go)', () => {
  test('opens with a compressed node key, adopting the announced inbox and limits', async () => {
    const s = await BatchSession.open(deps(), '02' + hub.node, [R1])
    expect(s.hub).toBe(hub.node)
    expect(s.inbox).toBe(hub.inbox)
    expect(s.limits).toEqual(DEFAULT_LIMITS)
    expect(s.relays).toEqual([R1, R2])
  })
  test('no announcement is a distinct error', async () => {
    await expect(BatchSession.open(deps(), getPublicKey(fill(0x77, 32)), [R1])).rejects.toMatchObject({ code: 'no_announcement' })
  })
  test('an announcement signed by someone else is ignored', async () => {
    const other = new FakeHub(pool, [R1], 0x30)
    const forged = other.announcementEvent({ relays: [R1], createdAt: now() + 10, inbox: other.inbox })
    pool.store(R1, { ...forged, pubkey: hub.node })
    const s = await BatchSession.open(deps(), hub.node, [R1])
    expect(s.inbox).toBe(hub.inbox)
  })
  test('the newest announcement wins and a replayed older one never rolls it back', async () => {
    const s = await BatchSession.open(deps(), hub.node, [R1])
    const newer = hub.announcementEvent({ relays: [R2], createdAt: now() + 100, limits: { ...DEFAULT_LIMITS, padBucketBytes: 4096 } })
    await pool.publish(R2, newer)
    await s.refresh()
    expect(s.limits.padBucketBytes).toBe(4096)
    pool.store(R1, hub.announcementEvent({ relays: [R1], createdAt: now() - 1000 }))
    pool.relay(R2).stored = []
    await s.refresh()
    expect(s.limits.padBucketBytes).toBe(4096)
  })
  test('needs relays to look on', async () => {
    await expect(BatchSession.open(deps(), hub.node, [])).rejects.toMatchObject({ code: 'no_relay' })
  })
})

describe('sending (batch_send.go)', () => {
  test('a cash_status round trip: subscribe, publish, collect', async () => {
    const c = new CashClient(deps(), bill(1))
    hub.handler = () => ({ result: { recipients: [{ identity_type: 'pubkey', identity_value: holder.pubkey, amount_millis: 21000, claimed: false }] } })
    const r = await c.cashStatus(bySigning(holder))
    expect(r.recipients[0]!.amount_millis).toBe(21000n)
    const req = hub.requests[0]!
    expect(req.signer).toBe(holder.pubkey)
    expect(req.billSigner).toBe(getPublicKey(fill(0x61, 32)))
    expect(req.params).toEqual({ scope: 'mine' })
  })
  test('a cash credential sends its secret and no slice proof', async () => {
    const c = new CashClient(deps(), bill(1))
    await c.cashStatus(bySecret('5e'.repeat(32)))
    expect(hub.requests[0]!.signer).toBeUndefined()
    expect(hub.requests[0]!.params).toEqual({ scope: 'mine', cash_secret: '5e'.repeat(32) })
  })
  test('fails over to the next relay when the first is down', async () => {
    pool.relay(R1).down = true
    const c = new CashClient(deps(), bill(1))
    await expect(c.cashStatus(bySigning(holder))).resolves.toBeDefined()
    expect(pool.published.some((p) => p.relay === R2 && p.event.kind === 23190)).toBe(true)
  })
  test('a refusing relay is skipped too', async () => {
    const c = new CashClient(deps(), bill(1))
    await c.session()
    pool.relay(R1).refuse = true
    await expect(c.cashStatus(bySigning(holder))).resolves.toBeDefined()
  })
  test('an imposter reply addressed to us is ignored', async () => {
    hub.faults = { imposter: true }
    await expect(new CashClient(deps(), bill(1)).cashStatus(bySigning(holder))).resolves.toBeDefined()
  })
  test('the same reply from two relays is one chunk', async () => {
    hub.faults = { replyOnAllRelays: true }
    const c = new CashClient(deps(), bill(1))
    const s = await c.session()
    const r = await statusMany(s, [1, 2, 3].map((i) => ({ id: `s${i}`, bill: billFor(decodeToken(bill(i))), credential: bySigning(holder) })), now)
    expect(r.error).toBeUndefined()
    expect(r.outcomes.map((o) => o.state)).toEqual(['result', 'result', 'result'])
  })
  test('a chunked reply is merged', async () => {
    hub.faults = { chunks: 3 }
    const s = await new CashClient(deps(), bill(1)).session()
    const r = await statusMany(s, [1, 2, 3].map((i) => ({ id: `s${i}`, bill: billFor(decodeToken(bill(i))), credential: bySigning(holder) })), now)
    expect(r.error).toBeUndefined()
    expect(r.outcomes.every((o) => o.state === 'result')).toBe(true)
  })
  test('an inflated total is bounded by the items asked', async () => {
    hub.faults = { declaredTotal: 5 }
    const r = await new CashClient(deps(), bill(1)).statusMany([{ id: 'a', bill: billFor(decodeToken(bill(1))), credential: bySigning(holder) }])
    expect(r.error).toBeUndefined()
    expect(r.outcomes[0]!.state).toBe('result')
  })
  test('a partial reply keeps what arrived and says it is incomplete, at not_after', async () => {
    hub.faults = { chunks: 2, sendChunks: 1 }
    const s = await new CashClient({ relays: pool, notAfterSeconds: 2 }, bill(1)).session()
    const r = await statusMany(s, [1, 2].map((i) => ({ id: `s${i}`, bill: billFor(decodeToken(bill(i))), credential: bySigning(holder) })), now)
    expect(r.error).toMatchObject({ code: 'incomplete_reply' })
    expect(r.outcomes).toHaveLength(2)
    expect(r.outcomes.map((o) => o.state)).toEqual(expect.arrayContaining(['not_served', 'result']))
  }, 10_000)
  test('no reply at all: every item not_served, with a timeout error', async () => {
    hub.faults = { drop: true }
    const s = await new CashClient({ relays: pool, notAfterSeconds: 1 }, bill(1)).session()
    const r = await statusMany(s, [{ id: 'a', bill: billFor(decodeToken(bill(1))), credential: bySigning(holder) }], now)
    expect(r.outcomes).toMatchObject([{ id: 'a', state: 'not_served' }])
    expect(r.error).toMatchObject({ code: 'timeout' })
  }, 10_000)
  test('an omitted item is not_served and not safe to resend', async () => {
    hub.faults = { omit: new Set(['b']) }
    const r = await new CashClient(deps(), bill(1)).statusMany(['a', 'b'].map((id, i) => ({ id, bill: billFor(decodeToken(bill(i))), credential: bySigning(holder) })))
    const b = r.outcomes.find((o) => o.id === 'b')!
    expect(b.state).toBe('not_served')
    expect(safeToResend(b)).toBe(false)
  })
  test('an envelope-level error is a decided refusal for every item, safe to resend', async () => {
    hub.faults = { envelopeError: { code: 'RATE_LIMITED' } }
    const r = await new CashClient(deps(), bill(1)).statusMany([{ id: 'a', bill: billFor(decodeToken(bill(1))), credential: bySigning(holder) }])
    expect(r.outcomes[0]).toMatchObject({ state: 'error', error: { code: 'RATE_LIMITED' } })
    expect(safeToResend(r.outcomes[0]!)).toBe(true)
  })
  test('an undecodable success is an error that ran: not safe to resend', async () => {
    hub.handler = () => ({ result: { recipients: 'nope' } })
    const r = await new CashClient(deps(), bill(1)).statusMany([{ id: 'a', bill: billFor(decodeToken(bill(1))), credential: bySigning(holder) }])
    expect(r.outcomes[0]).toMatchObject({ state: 'error', undecodable: true })
    expect(safeToResend(r.outcomes[0]!)).toBe(false)
  })
  test('a single call with an undecodable success throws undecodable_result, never a WalletError', async () => {
    hub.handler = () => ({ result: { recipients: 'nope' } })
    const err = await new CashClient(deps(), bill(1)).cashStatus(bySigning(holder)).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect(err).not.toBeInstanceOf(WalletError)
    expect((err as ClientError).code).toBe('undecodable_result')
  })
  test('a bill minted by another node is refused locally', async () => {
    const other = new FakeHub(pool, [R1], 0x30)
    const foreign = other.mintBill({ walletKey: fill(0x50, 32), connSecret: fill(0x51, 32), amount: 1n })
    const s = await new CashClient(deps(), bill(1)).session()
    await expect(statusMany(s, [{ bill: billFor(decodeToken(foreign)), credential: bySigning(holder) }], now)).rejects.toThrow(ClientError)
  })
})

describe('packing (batch_pack.go)', () => {
  test('a batch too big for one envelope splits, each envelope with its own nonce', async () => {
    hub.limits = { ...DEFAULT_LIMITS, maxItems: 3 }
    await hub.announce({ relays: [R1, R2], createdAt: now() + 1, limits: hub.limits })
    const s = await new CashClient(deps(), bill(1)).session()
    const r = await statusMany(s, [0, 1, 2, 3, 4].map((i) => ({ id: `s${i}`, bill: billFor(decodeToken(bill(i))), credential: bySigning(holder) })), now)
    expect(r.error).toBeUndefined()
    expect(r.outcomes.map((o) => o.envelope)).toEqual([0, 0, 0, 1, 1])
    expect(r.outcomes.every((o) => o.state === 'result')).toBe(true)
  })
})

describe('single-bill calls (client.go oneItemOutcome)', () => {
  test('a refusal is a WalletError with the Hub code', async () => {
    hub.handler = () => ({ error: { code: 'NOT_FOUND', message: 'no such bill' } })
    await expect(new CashClient(deps(), bill(1)).cashStatus(bySigning(holder))).rejects.toMatchObject({ walletCode: 'NOT_FOUND' })
  })
  test('an omission is NotServedError', async () => {
    hub.handler = (): Answer => 'omit'
    await expect(new CashClient(deps(), bill(1)).cashStatus(bySigning(holder))).rejects.toBeInstanceOf(NotServedError)
  })
  test('a bill without a mint signature cannot reach its hub', async () => {
    const tok = decodeToken(bill(1))
    const { mintSignature: _s, attestedAmountMillis: _a, ...bare } = tok
    await expect(new CashClient(deps(), bare).session()).rejects.toThrow(ClientError)
  })
})

describe('bill state and claims (bill_state.go, check_claim.go)', () => {
  test('a roster is available, an explicit spent is spent', async () => {
    const c = new CashClient(deps(), bill(1))
    expect((await c.state(bySigning(holder))).state).toBe('available')
    hub.handler = () => ({ result: { status: 'spent', reason: 'redeemed', retained_until: 5 } })
    expect((await c.state(bySigning(holder))).state).toBe('spent')
  })
  test('a tombstone answering a transfer is spent, never a decode failure', async () => {
    const c = new CashClient(deps(), bill(1))
    hub.handler = () => ({ result: { status: 'spent', reason: 'consolidated' } })
    const err = await c.cashTransfer({ credential: bySigning(holder), to: pubkeyTarget(holder.pubkey), currentAmount: 21000n }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).code).toBe('spent')
  })
  test('silence is indeterminate, never spent', async () => {
    hub.faults = { drop: true }
    const st = await new CashClient({ relays: pool, notAfterSeconds: 1 }, bill(1)).state(bySigning(holder))
    expect(st.state).toBe('indeterminate')
    expect(st.error).toBeDefined()
  }, 10_000)
  test('checkClaim reports the matching row and the minter', async () => {
    hub.handler = () => ({ result: { recipients: [{ identity_type: 'cash', amount_millis: 5000, claimed: false, redeem_fee_millis: 10, net_redeemable_millis: 4990 }] } })
    const r = await new CashClient(deps(), bill(1)).checkClaim(bySecret('ab'), '')
    expect(r).toMatchObject({ isCash: true, amountMillis: 5000n, redeemFeeMillis: 10n, netRedeemableMillis: 4990n })
    expect(r.minterPubkey!.slice(2)).toBe(hub.node)
  })
  test('checkClaim: NOT_FOUND and no matching row are claim_not_found; spent is spent', async () => {
    const c = new CashClient(deps(), bill(1))
    hub.handler = () => ({ error: { code: 'NOT_FOUND' } })
    await expect(c.checkClaim(bySigning(holder), holder.pubkey)).rejects.toMatchObject({ code: 'claim_not_found' })
    hub.handler = () => ({ result: { recipients: [{ identity_type: 'pubkey', identity_value: 'ab'.repeat(32), amount_millis: 1, claimed: false }] } })
    await expect(c.checkClaim(bySigning(holder), holder.pubkey)).rejects.toMatchObject({ code: 'claim_not_found' })
    hub.handler = () => ({ result: { status: 'spent' } })
    await expect(c.checkClaim(bySigning(holder), holder.pubkey)).rejects.toMatchObject({ code: 'spent' })
  })
})

describe('composite flows (transfer_from_sources.go, rekey_cash_slice.go)', () => {
  const merged = fill(0x70, 32)
  test('one source: a single split transfer', async () => {
    hub.handler = (m) => (m === 'cash_transfer' ? { result: { amount_millis: 500, identity_type: 'pubkey', identity_value: 'cd'.repeat(32) } } : 'omit')
    const c = new CashClient(deps(), bill(1))
    const r = await c.transferFromSources({
      sources: [{ walletPubkey: c.walletPubkey, amount: 21000n, credential: bySigning(holder) }],
      amount: 500n,
      to: pubkeyTarget('cd'.repeat(32)),
      interimIdentity: pubkeyTarget(holder.pubkey),
      interimCredential: bySigning(holder),
    })
    expect(r.consolidatedFirst).toBeUndefined()
    expect(hub.requests[0]!.params['amount_millis']).toBe(500)
  })
  test('several sources: consolidate, reconnect, split; a failed split is PartialProgressError holding the new bill', async () => {
    const newToken = hub.mintBill({ walletKey: merged, connSecret: fill(0x71, 32), amount: 3000n })
    const c = new CashClient(deps(), bill(1))
    const sources = [1, 2].map((i) => ({ walletPubkey: decodeToken(bill(i)).walletPubkey, amount: 1500n, credential: bySigning(holder) }))
    // A cash interim target receives the new token as delivered (not encrypted).
    hub.handler = (m) =>
      m === 'cash_consolidate'
        ? { result: { amount_millis: 3000, new_wallet_pubkey: getPublicKey(merged), new_wallet_token: newToken } }
        : { error: { code: 'INTERNAL' } }
    const err = await c
      .transferFromSources({ sources, amount: 1000n, to: pubkeyTarget('cd'.repeat(32)), interimIdentity: cashTargetFromSecret('11'.repeat(32)), interimCredential: bySecret('11'.repeat(32)) })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(PartialProgressError)
    expect((err as PartialProgressError).consolidated).toMatchObject({ amountMillis: 3000n, newWalletToken: newToken })
  })
  test('rekeying a lone cash slice is one in-place transfer to the new secret', async () => {
    hub.handler = () => ({ result: { amount_millis: 21000, identity_type: 'cash' } })
    const c = new CashClient(deps(), bill(1))
    const target = cashTargetFromSecret('22'.repeat(32))
    const r = await c.rekeyCashSlice({ cashSlice: { walletPubkey: c.walletPubkey, amount: 21000n, credential: bySecret('ab') }, newTarget: target })
    expect(r).toEqual({ newSecret: target.secret, newWalletPubkey: c.walletPubkey, newToken: '', amountMillis: 21000n })
    expect(hub.requests[0]!.params['new_identity']).toEqual({ identity_type: 'cash', identity_value: target.identityValue })
  })
  test('rekey with other bills needs a pubkey interim', async () => {
    const c = new CashClient(deps(), bill(1))
    await expect(
      c.rekeyCashSlice({
        cashSlice: { walletPubkey: c.walletPubkey, amount: 1n, credential: bySecret('ab') },
        consolidateWith: [{ walletPubkey: 'cd'.repeat(32), amount: 1n, credential: bySigning(holder) }],
        newTarget: cashTargetFromSecret('22'.repeat(32)),
      }),
    ).rejects.toThrow(ClientError)
  })
})

