// wallet.circles: joining over the private transport only, the join written
// ahead and settled by a join lookup, the Circle Wallet stored as fields,
// Lightning through it, member requests, notifications and deletion.
import { describe, expect, test } from 'vitest'
import { verifyEvent } from '../src/core/index.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { CashkitError, toJSON, type Storage, type StorageTx } from '../src/wallet/index.js'
import { FakeCircle } from './fakeCircle.js'
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
  test('a pending join that does not read back is never sent', async () => {
    // Storage that loses every pending-join write: the join's secret would not survive, so nothing may go out.
    class LosesJoins implements Storage {
      constructor(readonly inner: MemoryStorage) {}
      tx<T>(mode: 'r' | 'rw', fn: (t: StorageTx) => Promise<T>): Promise<T> {
        return this.inner.tx(mode, (t) => fn(new Proxy(t, { get: (o, k) => (k === 'put' ? (c: string, ...rest: unknown[]) => (c === 'pendingJoins' ? Promise.resolve() : (o.put as (...a: unknown[]) => Promise<void>)(c, ...rest)) : Reflect.get(o, k)) })))
      }
    }
    const h = await harness({ storage: new LosesJoins(new MemoryStorage()), deps: { nwcTimeoutMs: 2000 } })
    const circle = new FakeCircle(h.bank, { rotationDelaySecs: 432000 })
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ code: 'internal' })
    expect(circle.joins).toHaveLength(0)
    expect(privateJoins(h)).toBe(0)
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

describe('settling joins', () => {
  test('a join written on another device (a restored backup) is still looked up and added', async () => {
    const { h, circle } = await setup()
    circle.loseJoinReply = true
    const x = await harness({ pool: h.pool, bank: h.bank, deps: { replyWaitMs: 300, nwcTimeoutMs: 2000 } })
    await failure(x.wallet.circles.join(circle.string, terms))
    circle.loseJoinReply = false
    const pj = (await x.storage.tx('r', (t) => t.list('pendingJoins')))[0]!
    await x.storage.tx('rw', (t) => t.put('pendingJoins', { ...pj, device: 'ff'.repeat(16), version: pj.version + 1 }, pj.version))
    expect((await x.wallet.settle()).joins.joined).toEqual([pj.id])
    expect((await x.wallet.circles.list()).map((c) => c.connectionPubkey)).toEqual([pj.id])
  }, 20_000)
  test('one join whose answer does not parse never stops the others', async () => {
    const { h, circle: a } = await setup()
    const b = new FakeCircle(h.bank, { rotationDelaySecs: 432000, label: 'Bea’s Circle' })
    const x = await harness({ pool: h.pool, bank: h.bank, deps: { replyWaitMs: 300, nwcTimeoutMs: 2000 } })
    a.loseJoinReply = true
    b.loseJoinReply = true
    await failure(x.wallet.circles.join(a.string, terms))
    await failure(x.wallet.circles.join(b.string, terms))
    for (const [k, r] of a.records) a.records.set(k, { ...r, result: { encrypted_details: 'not sealed' } })
    const [pa, pb] = await x.storage.tx('r', (t) => t.list('pendingJoins'))
    const rep = await x.wallet.settle()
    expect(rep.joins.joined).toEqual([pb!.id])
    expect(rep.joins.pending).toEqual([pa!.id])
    expect((await x.storage.tx('r', (t) => t.get('pendingJoins', pa!.id)))?.lookup?.omissions).toBe(1)
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
