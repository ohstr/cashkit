// wallet.circles: joining over the private transport only, the join written
// ahead and settled by a join lookup, the Circle Wallet stored as fields,
// Lightning through it, member requests, notifications and deletion.
import { describe, expect, test } from 'vitest'
import { getPublicKey, localSigner, toHex, verifyEvent } from '../src/core/index.js'
import { CashkitError, toJSON } from '../src/wallet/index.js'
import { FakeCircle } from './fakeCircle.js'
import { fill } from './helpers.js'
import { harness, type Harness } from './walletHarness.js'

const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )

const terms = { maxAmount: 50_000n, maxReceive: 80_000n, budgetRenewal: 'monthly' as const }
const yes = () => Promise.resolve(true)

async function setup(o: ConstructorParameters<typeof FakeCircle>[1] = { rotationDelaySecs: 432000 }): Promise<{ h: Harness; circle: FakeCircle }> {
  const h = await harness({ deps: { nwcTimeoutMs: 2000 } })
  return { h, circle: new FakeCircle(h.bank, o) }
}
const privateJoins = (h: Harness) => h.pool.published.filter((x) => x.event.kind === 23190).length

describe('circles.join', () => {
  test('joins privately: the key is generated here, only its pubkey leaves; the wallet is stored as fields', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    expect(r).toMatchObject({ name: 'ada-s-circle', isDefault: true, maxAmount: 50_000n, maxReceive: 80_000n, feesPpm: 1000, rotatable: true, testNetwork: false, missingTerms: [] })
    const [join] = circle.joins
    expect(join!.params['connection_pubkey']).toBe(r.connectionPubkey)
    expect(join!.params['max_receive']).toBe(80_000)
    const secret = await h.wallet.circles.exportConnectionSecret(r.name)
    expect(JSON.stringify(join!.params)).not.toContain(secret)
    expect(toJSON(r)).not.toContain(secret)
    const row = (await h.storage.tx('r', (t) => t.get('connections', r.name)))!
    expect(row).toMatchObject({ kind: 'circle_wallet', walletPubkey: r.walletPubkey })
    expect(row.uri).toBeUndefined()
    expect(h.wallet.state.pendingJoins).toEqual([])
    expect((await h.wallet.circles.list())[0]).toMatchObject({ name: r.name, hubPubkey: circle.hubPubkey, rotatable: true, frozen: false })
  })
  test('Lightning through the circle wallet: balance and invoices; an amountless invoice is refused locally', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const w = [...circle.wallets.values()][0]!
    w.balance = 4200n
    const ln = await h.wallet.lightning(r.name)
    expect((await ln.getBalance()).balance).toBe(4200)
    expect((await ln.makeInvoice({ amount: 10n }))['invoice']).toMatch(/^lnbc/)
    await expect(ln.makeInvoice({ amount: 0n })).rejects.toMatchObject({ code: 'invalid_input' })
    await expect(ln.signMessage('x')).rejects.toMatchObject({ code: 'usage' })
    const budget = await (await h.wallet.circles.client(r.name)).getBudget()
    expect(budget).toMatchObject({ totalBudget: 50_000n, totalReceiveBudget: 80_000n, renewalPeriod: 'monthly' })
  })
  test('a cashhub1 or a URI is refused; terms over the Hub’s limits are refused before anything is signed', async () => {
    const { h, circle } = await setup({ rotationDelaySecs: 1, perWalletMax: 10n })
    expect(await failure(h.wallet.circles.join(h.bank.openCashHub(), terms))).toMatchObject({ code: 'invalid_input', reason: 'connection_invalid' })
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ code: 'invalid_input', reason: 'limit_exceeded', input: 'max_amount' })
    expect(privateJoins(h)).toBe(0)
  })
  test('a Hub that cannot rotate needs confirmNoRecovery before anything is signed', async () => {
    const { h, circle } = await setup({})
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ code: 'usage', reason: 'no_recovery_unconfirmed' })
    expect(circle.joins).toHaveLength(0)
    const r = await h.wallet.circles.join(circle.string, terms, { confirmNoRecovery: yes })
    expect(r.rotatable).toBe(false)
    expect(await failure(h.wallet.circles.memberRequest(r.name, 'freeze'))).toMatchObject({ code: 'usage', reason: 'rotation_not_served' })
  })
  test('a closed circle is not_accepting; a refusal is final and drops the pending join', async () => {
    const { h, circle } = await setup()
    circle.accepting = false
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ code: 'auth', reason: 'not_accepting' })
    circle.accepting = true
    circle.refuseWith = 'RATE_LIMITED'
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ code: 'conflict', nwcCode: 'RATE_LIMITED' })
    expect(circle.joins).toHaveLength(1)
    expect(h.wallet.state.pendingJoins).toEqual([])
  })
  test('one wallet per circle: a second join is refused locally', async () => {
    const { h, circle } = await setup()
    await h.wallet.circles.join(circle.string, terms)
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ code: 'exists' })
  })
  test('a lost reply leaves the join pending; settle() finds it by lookup and adds the wallet', async () => {
    const { h, circle } = await setup()
    circle.loseJoinReply = true
    const x = await harness({ pool: h.pool, bank: h.bank, deps: { replyWaitMs: 300, nwcTimeoutMs: 2000 } })
    const e = await failure(x.wallet.circles.join(circle.string, terms))
    expect(e).toMatchObject({ code: 'indeterminate', reason: 'join_pending' })
    const pj = (await x.storage.tx('r', (t) => t.list('pendingJoins')))[0]!
    expect(pj).toMatchObject({ sent: true, deadline: pj.proofCreatedAt + 300 })
    circle.loseJoinReply = false
    const rep = await x.wallet.settle()
    expect(rep.joins.joined).toEqual([pj.id])
    expect((await x.wallet.circles.list()).map((c) => c.connectionPubkey)).toEqual([pj.id])
    expect(await x.storage.tx('r', (t) => t.list('pendingJoins'))).toEqual([])
  }, 20_000)
})

describe('member requests, notifications, deletion', () => {
  test('a rotate stores the new key first and returns the signed request; rotation_completed switches to it', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const ev = await h.wallet.circles.memberRequest(r.name, 'rotate')
    expect(verifyEvent(ev)).toBe(true)
    const newKey = ev.tags.find((t) => t[0] === 'connection')![1]!
    expect(ev.tags.slice(0, 3)).toEqual([['d', circle.hubPubkey], ['action', 'rotate'], ['wallet', r.walletPubkey]])
    expect(await h.wallet.circles.notify(r.name, { notification_type: 'rotation_pending', notification: { connection_pubkey: newKey, completes_at: 99 } })).toBe('rotation_alert')
    expect((await h.wallet.circles.list())[0]!.rotation).toEqual({ newConnectionPubkey: newKey, completesAt: 99 })
    expect(await h.wallet.circles.notify(r.name, { notification_type: 'rotation_completed', notification: { connection_pubkey: newKey } })).toBe('rotation_completed')
    expect((await h.wallet.circles.list())[0]).toMatchObject({ connectionPubkey: newKey })
    expect((await h.wallet.circles.list())[0]!.rotation).toBeUndefined()
  })
  test('wallet_frozen: no payment is attempted until it is lifted', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    expect(await h.wallet.circles.notify(r.name, { notification_type: 'wallet_frozen', notification: {} })).toBe('frozen_alert')
    expect(await failure(h.wallet.lightning(r.name))).toMatchObject({ code: 'auth', nwcCode: 'FROZEN' })
  })
  test('delete: refused above dust; after confirmDelete the Hub deletes it and the connection goes', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const w = [...circle.wallets.values()][0]!
    w.balance = 5000n
    expect(await failure(h.wallet.circles.delete(r.name, yes))).toMatchObject({ code: 'usage', reason: 'not_dust' })
    w.balance = 10n
    let dust = -1n
    await h.wallet.circles.delete(r.name, ({ dust: d }) => {
      dust = d
      return Promise.resolve(true)
    })
    expect(dust).toBe(10n)
    expect(w.deleted).toBe(true)
    expect(await h.wallet.circles.list()).toEqual([])
  })
})

describe('connections.add and inspect of a circlehub1', () => {
  test('inspect shows what a string is and stores nothing; online reads get_info', async () => {
    const { h, circle } = await setup()
    expect(await h.wallet.connections.inspect(circle.string)).toMatchObject({ kind: 'circlehub', connectionPubkey: circle.hubPubkey, hubIdentity: h.bank.hub.node, verified: true, online: 'unchecked', label: 'Ada’s Circle' })
    expect(await h.wallet.connections.inspect(circle.string, { online: true })).toMatchObject({ online: 'pass', network: 'mainnet', testNetwork: false })
    expect(await h.wallet.connections.inspect(h.bank.openCashHub())).toMatchObject({ kind: 'cashhub', online: 'unchecked' })
    circle.infoIdentity = '22'.repeat(32)
    expect(await h.wallet.connections.inspect(circle.string, { online: true })).toMatchObject({ online: 'fail' })
    expect(await failure(h.wallet.connections.inspect('nostr+walletconnect://abc?relay=wss://r&secret=00'))).toMatchObject({ code: 'invalid_input', reason: 'connection_invalid' })
    expect(await h.wallet.connections.list()).toEqual([])
  })
  test('add checks the string online and stores it as given; it joins nothing and is no Lightning wallet', async () => {
    const { h, circle } = await setup()
    const v = await h.wallet.connections.add('ada', circle.string)
    expect(v).toMatchObject({ name: 'ada', kind: 'circlehub', isDefault: false, walletPubkey: circle.hubPubkey, hubIdentity: h.bank.hub.node, chain: 'bitcoin', verified: true, network: 'mainnet' })
    const row = (await h.storage.tx('r', (t) => t.get('connections', 'ada')))!
    expect(row).toMatchObject({ kind: 'circlehub', walletPubkey: circle.hubPubkey })
    expect(row.uri).toBeUndefined()
    expect(await h.wallet.connections.list()).toEqual([v])
    expect(circle.joins).toHaveLength(0)
    expect(await failure(h.wallet.connections.setDefault('ada'))).toMatchObject({ code: 'usage' })
    expect(await failure(h.wallet.lightning('ada'))).toMatchObject({ code: 'usage' })
    expect(await failure(h.wallet.lightning())).toMatchObject({ code: 'not_found' })
  })
  test('a string whose get_info names another node is refused, and nothing is stored', async () => {
    const { h, circle } = await setup()
    circle.infoIdentity = '22'.repeat(32)
    expect(await failure(h.wallet.connections.add('ada', circle.string))).toMatchObject({ code: 'invalid_input', reason: 'connection_mismatch' })
    expect(await h.wallet.connections.list()).toEqual([])
  })
})

/** A wallet and a Hub sharing a clock that a test moves forward. */
async function skewed(): Promise<{ h: Harness; circle: FakeCircle; advance: (s: number) => void }> {
  const skew = { ms: 0 }
  const clock = () => Date.now() + skew.ms
  const h = await harness({ deps: { nwcTimeoutMs: 1500, replyWaitMs: 400, clock } })
  h.bank.hub.clock = clock
  return { h, circle: new FakeCircle(h.bank, { rotationDelaySecs: 432000 }), advance: (s) => (skew.ms += s * 1000) }
}

describe('a join lookup through another string of the same circle', () => {
  test('past the deadline plus 360 s, a revoked join string gives way to another held one, once', async () => {
    const { h, circle, advance } = await skewed()
    circle.loseJoinReply = true
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ reason: 'join_pending' })
    const other = circle.addConnection()
    await h.wallet.connections.add('ada-2', other)
    circle.revoke(circle.string)
    const early = await h.wallet.settle()
    expect(early.joins).toMatchObject({ joined: [], needsUser: [] })
    expect(circle.lookups).toHaveLength(0)
    advance(700)
    const late = await h.wallet.settle()
    expect(late.joins.joined).toHaveLength(1)
    // The revoked string's get_info goes unanswered, so the one lookup sent carries the other string's bill proof.
    expect(circle.lookups).toHaveLength(1)
    expect(circle.lookups[0]!.billSigner).not.toBe(circle.client)
    expect(circle.live.has(circle.lookups[0]!.billSigner)).toBe(true)
    const [c] = await h.wallet.circles.list()
    expect(c).toMatchObject({ hubPubkey: circle.hubPubkey })
  }, 30_000)
  test('a join still unanswered through both strings is shown as unanswered', async () => {
    const { h, circle, advance } = await skewed()
    circle.loseJoinReply = true
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ reason: 'join_pending' })
    const other = circle.addConnection()
    await h.wallet.connections.add('ada-2', other)
    circle.omitLookups = true
    expect((await h.wallet.settle()).joins.needsUser).toEqual([])
    advance(700)
    const rep = await h.wallet.settle()
    expect(rep.joins.needsUser).toHaveLength(1)
    // The join's own string, then the other one: each bill proof signed with its own secret.
    const signers = circle.lookups.map((l) => l.billSigner)
    expect(signers.slice(-2)).toEqual([circle.client, [...circle.live].find((k) => k !== circle.client)])
    const pj = (await h.storage.tx('r', (t) => t.list('pendingJoins')))[0]!
    expect(pj).toMatchObject({ needsUser: 'lookup_unanswered', lookup: { viaOther: true } })
  }, 30_000)
})

describe('circles.recover', () => {
  test('on a new device holding the rotated key: pending until completes_at, then the wallet with the new key', async () => {
    const id = localSigner(fill(7, 32))
    const h = await harness({ identity: false, deps: { nwcTimeoutMs: 2000 } })
    const circle = new FakeCircle(h.bank, { rotationDelaySecs: 432000 })
    await h.wallet.identity.useSigner(id)
    const r = await h.wallet.circles.join(circle.string, terms)
    const w = circle.wallets.get(r.walletPubkey)!
    w.balance = 777n
    const fresh = toHex(fill(9, 32))
    const freshPub = getPublicKey(fill(9, 32))
    const b = await harness({ pool: h.pool, bank: h.bank, identity: false, deps: { nwcTimeoutMs: 2000 } })
    await b.wallet.identity.useSigner(id)
    expect(await b.wallet.circles.recover(circle.string, fresh)).toEqual({ state: 'not_found' })
    circle.rotate(w, freshPub, { completesAt: 1_900_000_000 })
    expect(await b.wallet.circles.recover(circle.string, fresh)).toEqual({ state: 'pending', retryAt: 1_900_000_000 })
    circle.rotations.clear()
    circle.rotate(w, freshPub)
    const done = await b.wallet.circles.recover(circle.string, fresh, { name: 'ada' })
    expect(done).toMatchObject({ state: 'done', wallet: { name: 'ada', walletPubkey: r.walletPubkey, connectionPubkey: freshPub, isDefault: true } })
    expect((await b.wallet.circles.list())[0]).toMatchObject({ name: 'ada', connectionPubkey: freshPub, hubPubkey: circle.hubPubkey })
    expect((await (await b.wallet.lightning('ada')).getBalance()).balance).toBe(777)
    expect(await b.wallet.circles.exportConnectionSecret('ada')).toBe(fresh)
  }, 30_000)
  test('on a device holding the moved connection, the same wallet is updated in place', async () => {
    const id = localSigner(fill(8, 32))
    const h = await harness({ identity: false, deps: { nwcTimeoutMs: 2000 } })
    const circle = new FakeCircle(h.bank, { rotationDelaySecs: 432000 })
    await h.wallet.identity.useSigner(id)
    const r = await h.wallet.circles.join(circle.string, terms)
    await h.wallet.circles.memberRequest(r.name, 'rotate')
    const w = circle.wallets.get(r.walletPubkey)!
    const fresh = toHex(fill(10, 32))
    circle.rotate(w, getPublicKey(fill(10, 32)))
    const done = await h.wallet.circles.recover(circle.string, fresh)
    expect(done).toMatchObject({ state: 'done', wallet: { name: r.name } })
    const [c] = await h.wallet.circles.list()
    expect(c).toMatchObject({ name: r.name, connectionPubkey: getPublicKey(fill(10, 32)), moved: false })
    expect(c!.rotation).toBeUndefined()
    expect(await h.wallet.circles.list()).toHaveLength(1)
  }, 30_000)
  test('a string that is no circlehub1, or a bad key, is refused before anything is sent', async () => {
    const { h, circle } = await setup()
    expect(await failure(h.wallet.circles.recover(h.bank.openCashHub(), toHex(fill(9, 32))))).toMatchObject({ code: 'invalid_input', reason: 'connection_invalid' })
    expect(await failure(h.wallet.circles.recover(circle.string, 'zz'))).toMatchObject({ code: 'invalid_input' })
    expect(circle.lookups).toHaveLength(0)
  })
})
