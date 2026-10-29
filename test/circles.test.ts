// wallet.circles: joining over the private transport only, the join written
// ahead and settled by a join lookup, the Circle Wallet stored as fields,
// Lightning through it, member requests, notifications and deletion.
import { describe, expect, test } from 'vitest'
import { decodeCircleHubConnection, encodeCircleHubConnection, fromHex, getPublicKey, localSigner, toHex, verifyEvent } from '../src/core/index.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { CashkitError, toJSON, type Storage, type StorageTx } from '../src/wallet/index.js'
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
  test('REQUEST_REUSED is not a failure: the pending join and its connection secret are kept and looked up (NIP-CW §Errors)', async () => {
    const { h, circle } = await setup()
    circle.refuseWith = 'REQUEST_REUSED'
    expect(await failure(h.wallet.circles.join(circle.string, terms))).toMatchObject({ code: 'indeterminate', reason: 'join_pending' })
    const pending = await h.storage.tx('r', (t) => t.list('pendingJoins'))
    expect(pending).toHaveLength(1)
    expect(pending[0]).toMatchObject({ sent: true })
    expect(await h.wallet.circles.exportConnectionSecret(pending[0]!.id)).toMatch(/^[0-9a-f]{64}$/)
  }, 20_000)
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
  test('another device\'s join never seen sent waits until nothing can arrive, then is looked up, never kept forever (R2-K11)', async () => {
    const { h, circle } = await setup()
    circle.loseJoinReply = true
    const x = await harness({ pool: h.pool, bank: h.bank, deps: { replyWaitMs: 300, nwcTimeoutMs: 2000 } })
    await failure(x.wallet.circles.join(circle.string, terms))
    circle.loseJoinReply = false
    const pj = (await x.storage.tx('r', (t) => t.list('pendingJoins')))[0]!
    // A backup taken between the write-ahead and the send: the join did go out from the other device.
    await x.storage.tx('rw', (t) => t.put('pendingJoins', { ...pj, sent: false, device: 'ff'.repeat(16), version: pj.version + 1 }, pj.version))
    expect((await x.wallet.settle()).joins.pending).toEqual([pj.id])
    const cur = (await x.storage.tx('r', (t) => t.get('pendingJoins', pj.id)))!
    await x.storage.tx('rw', (t) => t.put('pendingJoins', { ...cur, deadline: Math.floor(Date.now() / 1000) - 400, version: cur.version + 1 }, cur.version))
    expect((await x.wallet.settle()).joins.joined).toEqual([pj.id])
    expect(await x.storage.tx('r', (t) => t.list('pendingJoins'))).toEqual([])
  }, 20_000)
  test.each([
    ['unknown, past the deadline', 10, 'join_not_made'],
    ['expired, past the deadline and the horizon', 400, 'lookup_expired'],
  ] as const)('a join the Hub has no record of, read %s, asks the user (%s) and is never joined again by itself', async (_, ago, want) => {
    const { h, circle } = await setup()
    circle.refuseWith = 'REQUEST_REUSED'
    await failure(h.wallet.circles.join(circle.string, terms))
    circle.refuseWith = undefined
    const pj = (await h.storage.tx('r', (t) => t.list('pendingJoins')))[0]!
    await h.storage.tx('rw', (t) => t.put('pendingJoins', { ...pj, deadline: Math.floor(Date.now() / 1000) - ago, version: pj.version + 1 }, pj.version))
    const rep = await h.wallet.settle()
    expect(rep.joins.needsUser).toEqual([pj.id])
    expect(h.wallet.state.pendingJoins.map((j) => j.needsUser)).toEqual([want])
    expect(circle.joins).toHaveLength(1)
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
  test('an unverified string is added only on a yes: the caller\'s confirmUnverified, else the wallet\'s question', async () => {
    const { h, circle } = await setup()
    const c = decodeCircleHubConnection(circle.string)
    const tampered = encodeCircleHubConnection({ ...c, label: 'Not Ada', labelBytes: new TextEncoder().encode('Not Ada') })
    expect(await failure(h.wallet.connections.add('ada', tampered))).toMatchObject({ code: 'auth' })
    const asked: string[] = []
    h.wallet.on('confirm', (q) => (asked.push(q.type), q.type === 'confirmUnverified'))
    const v = await h.wallet.connections.add('ada', tampered)
    expect(v).toMatchObject({ kind: 'circlehub', verified: false })
    expect(asked).toEqual(['confirmUnverified'])
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

async function eventually(cond: () => Promise<boolean> | boolean, what: string): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (await cond()) return
    await new Promise((r) => setTimeout(r, 10))
  }
  throw new Error(`not reached: ${what}`)
}

describe('member requests end to end: watch and refresh', () => {
  test('a rotate the host submits: watch applies rotation_pending, then rotation_completed on the new key, and the wallet answers on it', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const w = circle.wallets.get(r.walletPubkey)!
    w.balance = 4321n
    const alerts: string[] = []
    const stop = await h.wallet.circles.watch(r.name, { onAlert: (a) => alerts.push(a) })
    try {
      const ev = await h.wallet.circles.memberRequest(r.name, 'rotate')
      const newKey = ev.tags.find((t) => t[0] === 'connection')![1]!
      expect(circle.submit(ev)).toBeUndefined()
      await eventually(() => alerts.includes('rotation_alert'), 'rotation_pending applied')
      expect((await h.wallet.circles.list())[0]!.rotation).toEqual({ newConnectionPubkey: newKey, completesAt: circle.pendingRotations.get(r.walletPubkey)!.completesAt })
      // Watching sent the Hub nothing: the pending rotation stands.
      expect(w.seen).toEqual([])
      circle.completeRotation(w)
      await eventually(() => alerts.includes('rotation_completed'), 'rotation_completed applied')
      const [c] = await h.wallet.circles.list()
      expect(c).toMatchObject({ connectionPubkey: newKey, frozen: false })
      expect(c!.rotation).toBeUndefined()
      expect((await (await h.wallet.lightning(r.name)).getBalance()).balance).toBe(4321)
      // The same request again is spent.
      expect(circle.submit(ev)).toBe('REQUEST_REUSED')
    } finally {
      stop()
    }
  }, 30_000)

  test('freeze: wallet_frozen stops payments; refresh reads FROZEN, then lifts the mark once the unfreeze is applied', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const alerts: string[] = []
    const stop = await h.wallet.circles.watch(r.name, { onAlert: (a) => alerts.push(a) })
    try {
      expect(circle.submit(await h.wallet.circles.memberRequest(r.name, 'freeze'))).toBeUndefined()
      await eventually(() => alerts.includes('frozen_alert'), 'wallet_frozen applied')
      expect(await failure(h.wallet.lightning(r.name))).toMatchObject({ code: 'auth', nwcCode: 'FROZEN' })
      expect(await h.wallet.circles.refresh(r.name)).toMatchObject({ frozen: true })
      expect(circle.submit(await h.wallet.circles.memberRequest(r.name, 'unfreeze'))).toBeUndefined()
      // An unfreeze has no notification: refresh asks.
      expect((await h.wallet.circles.list())[0]!.frozen).toBe(true)
      expect(await h.wallet.circles.refresh(r.name)).toMatchObject({ frozen: false })
      expect((await (await h.wallet.lightning(r.name)).getBalance()).balance).toBe(0)
    } finally {
      stop()
    }
  }, 30_000)

  test('refresh is refused while this device\'s rotation is pending; with cancelRotation it cancels it, and watch drops it', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const w = circle.wallets.get(r.walletPubkey)!
    const alerts: string[] = []
    const stop = await h.wallet.circles.watch(r.name, { onAlert: (a) => alerts.push(a) })
    try {
      expect(circle.submit(await h.wallet.circles.memberRequest(r.name, 'rotate'))).toBeUndefined()
      expect(await failure(h.wallet.circles.refresh(r.name))).toMatchObject({ code: 'usage', reason: 'rotation_pending' })
      expect(w.seen).toEqual([])
      expect(await h.wallet.circles.refresh(r.name, { cancelRotation: true })).toMatchObject({ frozen: false })
      await eventually(() => alerts.includes('rotation_cancelled'), 'rotation_cancelled applied')
      expect((await h.wallet.circles.list())[0]!.rotation).toBeUndefined()
      expect(circle.pendingRotations.size).toBe(0)
    } finally {
      stop()
    }
  }, 30_000)

  test('a rotation this device did not ask for: alert, then the connection is marked moved once completes_at passes', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const w = circle.wallets.get(r.walletPubkey)!
    const alerts: string[] = []
    const stop = await h.wallet.circles.watch(r.name, { onAlert: (a) => alerts.push(a) })
    try {
      circle.notify(w, 'rotation_pending', { connection_pubkey: 'cd'.repeat(32), completes_at: Math.floor(Date.now() / 1000) - 1 })
      await eventually(() => alerts.includes('rotation_alert'), 'foreign rotation_pending applied')
      await eventually(async () => (await h.wallet.circles.list())[0]!.moved, 'marked moved')
      // Anything else on the key is not NIP-CW's and is left alone.
      circle.notify(w, 'payment_received', { amount: 1 })
      circle.notify(w, 'rotation_completed', { connection_pubkey: 'nothex' })
      await new Promise((res) => setTimeout(res, 50))
      expect(alerts).toEqual(['rotation_alert'])
    } finally {
      stop()
    }
  }, 30_000)

  test('a lost device: memberRequestFor on a new device signs a rotate for the wallet by its pubkey; the old device is alerted; recover takes it once completed', async () => {
    const id = localSigner(fill(21, 32))
    const h = await harness({ identity: false, deps: { nwcTimeoutMs: 2000 } })
    const circle = new FakeCircle(h.bank, { rotationDelaySecs: 432000 })
    await h.wallet.identity.useSigner(id)
    const r = await h.wallet.circles.join(circle.string, terms)
    const w = circle.wallets.get(r.walletPubkey)!
    w.balance = 900n
    const alerts: string[] = []
    const stop = await h.wallet.circles.watch(r.name, { onAlert: (a) => alerts.push(a) })
    try {
      const b = await harness({ pool: h.pool, bank: h.bank, identity: false, deps: { nwcTimeoutMs: 2000 } })
      await b.wallet.identity.useSigner(id)
      expect(await failure(b.wallet.circles.memberRequestFor(circle.string, 'XY', 'rotate'))).toMatchObject({ code: 'invalid_input' })
      const { event, newConnectionSecret } = await b.wallet.circles.memberRequestFor(circle.string, r.walletPubkey, 'rotate')
      expect(verifyEvent(event)).toBe(true)
      expect(event.tags.find((t) => t[0] === 'connection')![1]).toBe(getPublicKey(fromHex(newConnectionSecret!)))
      expect(circle.submit(event)).toBeUndefined()
      await eventually(() => alerts.includes('rotation_alert'), 'the old device sees the rotation')
      expect(await b.wallet.circles.recover(circle.string, newConnectionSecret!)).toMatchObject({ state: 'pending' })
      circle.completeRotation(w)
      // The rotate key was stored before the request was returned: recover finds it without being passed it (R2-K8).
      expect(await b.storage.tx('r', (t) => t.get('pendingRecoveries', r.walletPubkey))).toMatchObject({ newConnectionPubkey: getPublicKey(fromHex(newConnectionSecret!)) })
      expect(await b.wallet.circles.recover(circle.string)).toMatchObject({ state: 'done', wallet: { walletPubkey: r.walletPubkey } })
      expect(await b.storage.tx('r', (t) => t.get('pendingRecoveries', r.walletPubkey))).toBeUndefined()
      expect((await (await b.wallet.lightning((await b.wallet.circles.list())[0]!.name)).getBalance()).balance).toBe(900)
      // A freeze for a wallet held here goes through memberRequest: no secret comes back.
      const held = await b.wallet.circles.memberRequestFor(circle.string, r.walletPubkey, 'freeze')
      expect(held.newConnectionSecret).toBeUndefined()
      expect(held.event.tags.find((t) => t[0] === 'action')![1]).toBe('freeze')
    } finally {
      stop()
    }
  }, 30_000)

  test('memberRequestFor asks the wallet\'s confirmUnverified handler for an unverified string (R2-K6)', async () => {
    const { h, circle } = await setup()
    const c = decodeCircleHubConnection(circle.string)
    const tampered = encodeCircleHubConnection({ ...c, label: 'Not Ada', labelBytes: new TextEncoder().encode('Not Ada') })
    const asked: string[] = []
    h.wallet.on('confirm', (q) => (asked.push(q.type), q.type === 'confirmUnverified'))
    const out = await h.wallet.circles.memberRequestFor(tampered, 'ab'.repeat(32), 'freeze')
    expect(asked).toEqual(['confirmUnverified'])
    expect(out.event.tags.find((t) => t[0] === 'action')![1]).toBe('freeze')
  })
  test('a late rotation_cancelled for an earlier rotation keeps the pending one and its key (R2-K7)', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    await h.wallet.circles.memberRequest(r.name, 'rotate')
    const pending = (await h.wallet.circles.list())[0]!.rotation!
    expect(await h.wallet.circles.notify(r.name, { notification_type: 'rotation_cancelled', notification: { connection_pubkey: 'cd'.repeat(32) } })).toBe('ignored')
    expect((await h.wallet.circles.list())[0]!.rotation).toEqual(pending)
    expect(await h.wallet.circles.notify(r.name, { notification_type: 'rotation_cancelled', notification: { connection_pubkey: pending.newConnectionPubkey } })).toBe('rotation_cancelled')
    expect((await h.wallet.circles.list())[0]!.rotation).toBeUndefined()
  })
  test('a request by the wrong member or for a wallet the Hub does not hold is refused by the Hub', async () => {
    const { h, circle } = await setup()
    const r = await h.wallet.circles.join(circle.string, terms)
    const ev = await h.wallet.circles.memberRequest(r.name, 'freeze')
    circle.wallets.get(r.walletPubkey)!.member = 'ef'.repeat(32)
    expect(circle.submit(ev)).toBe('UNAUTHORIZED')
    const { h: h2, circle: noRotation } = await setup({})
    const r2 = await h2.wallet.circles.join(noRotation.string, terms, { confirmNoRecovery: yes })
    expect(await failure(h2.wallet.circles.memberRequest(r2.name, 'freeze'))).toMatchObject({ code: 'usage', reason: 'rotation_not_served' })
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
  test('a device holding another wallet of the same circle keeps it and adds the recovered one', async () => {
    const id = localSigner(fill(11, 32))
    const h = await harness({ identity: false, deps: { nwcTimeoutMs: 2000 } })
    const circle = new FakeCircle(h.bank, { rotationDelaySecs: 432000 })
    await h.wallet.identity.useSigner(id)
    const r = await h.wallet.circles.join(circle.string, terms)
    // As if this device held an older wallet of the circle, not the one being recovered.
    await h.storage.tx('rw', async (t) => {
      const c = (await t.get('connections', r.name))!
      await t.put('connections', { ...c, walletPubkey: 'ab'.repeat(32), version: c.version + 1 }, c.version)
    })
    const w = circle.wallets.get(r.walletPubkey)!
    const fresh = toHex(fill(12, 32))
    circle.rotate(w, getPublicKey(fill(12, 32)))
    const done = await h.wallet.circles.recover(circle.string, fresh, { name: 'ada-recovered' })
    expect(done).toMatchObject({ state: 'done', wallet: { name: 'ada-recovered', walletPubkey: r.walletPubkey } })
    const names = (await h.wallet.circles.list()).map((c) => c.name)
    expect(names).toHaveLength(2)
    expect(names).toEqual(expect.arrayContaining(['ada-recovered', r.name]))
  }, 30_000)
  test('a string that is no circlehub1, or a bad key, is refused before anything is sent', async () => {
    const { h, circle } = await setup()
    expect(await failure(h.wallet.circles.recover(h.bank.openCashHub(), toHex(fill(9, 32))))).toMatchObject({ code: 'invalid_input', reason: 'connection_invalid' })
    expect(await failure(h.wallet.circles.recover(circle.string, 'zz'))).toMatchObject({ code: 'invalid_input' })
    expect(circle.lookups).toHaveLength(0)
  })
})
