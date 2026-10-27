// The engine scenario suite (design §11.2), over FakeBank. Ports cashctl's
// audit tests: auditD_cli_killwindow, auditD_cli_writeahead,
// park_forget_test, auditD_cli_recovery_handoff, auditD_cli_history_secrets,
// pending_secret_batch_test, auditD_cli_occ_crossprocess and the auditC
// amount checks (names in comments).
//
// The kill-window invariant: whatever step the engine dies at, every live
// bill on the Hub stays controlled by something someone still has — a key
// or secret in this wallet's storage, this wallet's identity, or the
// recipient's identity. Losing time is allowed; losing a secret is not.
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import { fromHex, getPublicKey, newCashTarget, redact, splitCashString, toHex } from '../src/core/index.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { CashkitError, toJSON, type Sealed, type Storage, type StorageTx, type Wallet } from '../src/wallet/index.js'
import type { PendingCall } from '../src/wallet/model.js'
import { commitment, FakeBank, type BankWallet } from './fakeBank.js'
import { FakeNwcWallet, harness, type Harness } from './walletHarness.js'
import { MemoryRelayPool } from './fakeHub.js'

/** Storage that "crashes" after a number of read-write transactions: every later one throws. */
class CrashableStorage implements Storage {
  writes = 0
  crashAfter: number | undefined
  crashed = false
  constructor(readonly inner: MemoryStorage) {}
  tx<T>(mode: 'r' | 'rw', fn: (t: StorageTx) => Promise<T>): Promise<T> {
    if (mode === 'rw') {
      if (this.crashAfter !== undefined && this.writes >= this.crashAfter) {
        this.crashed = true
        return Promise.reject(new Error('storage: the process died here'))
      }
      this.writes++
    }
    return this.inner.tx(mode, fn)
  }
}

/** The CashkitError a promise rejects with; fails the test if it resolves. */
const failure = (p: Promise<unknown>): Promise<CashkitError> =>
  p.then(
    () => {
      throw new Error('expected a failure')
    },
    (e: unknown) => e as CashkitError,
  )

const unseal = (s: Sealed | undefined) => (s === undefined ? undefined : new TextDecoder().decode(fromHex(s.data)))

/** Every key and secret the storage holds, as pubkeys and cash commitments. */
async function controls(storage: Storage): Promise<{ pubkeys: Set<string>; commitments: Set<string> }> {
  const pubkeys = new Set<string>()
  const commitments = new Set<string>()
  const addSecret = (s: string | undefined) => s !== undefined && /^[0-9a-f]{64}$/.test(s) && commitments.add(toHex(sha256(fromHex(s))))
  const addKey = (k: string | undefined) => k !== undefined && pubkeys.add(getPublicKey(fromHex(k)))
  await storage.tx('r', async (t) => {
    const id = await t.get('identity', 'self')
    if (id !== undefined) pubkeys.add(id.pubkey)
    for (const h of await t.list('holdings')) {
      addSecret(unseal(h.cashSecret))
      addKey(unseal(h.throwawayKey))
    }
    for (const c of await t.list('pendingCalls')) {
      if (c.authorizer.kind === 'throwaway') addKey(unseal(c.authorizer.authorizerKey))
      for (const o of c.outputs) {
        if (o.destination.kind === 'cash') addSecret(unseal(o.destination.secret))
        if (o.destination.kind === 'throwaway') addKey(unseal(o.destination.key))
      }
    }
    for (const ho of await t.list('handoffs')) addSecret(splitCashString(unseal(ho.handoff) ?? '').cashSecret || undefined)
  })
  return { pubkeys, commitments }
}

/** Secrets held outside the wallet under test: a sender who still has the note they were handing over. */
const outside = new Set<string>()

async function uncontrolled(bank: FakeBank, storage: Storage, others: readonly string[]): Promise<BankWallet[]> {
  const c = await controls(storage)
  return [...bank.wallets.values()].filter((w) => {
    if (w.spent) return false
    if (w.identity.type === 'cash') return !c.commitments.has(w.identity.value) && !outside.has(w.identity.value)
    return !c.pubkeys.has(w.identity.value) && !others.includes(w.identity.value)
  })
}

interface Op {
  readonly name: string
  setup(h: Harness, bob: Harness): Promise<void>
  run(w: Wallet, bob: Harness, bank: FakeBank): Promise<unknown>
}

const BOB_KEY = new Uint8Array(32).fill(0x5b)

const ops: Op[] = [
  {
    name: 'receive + protect a cash note',
    setup: async () => {},
    run: async (w, _bob, bank) => {
      const t = newCashTarget()
      outside.add(commitment(t.secret))
      return w.receive(`${bank.mintToCash(700n, t.secret).token}#${t.secret}`)
    },
  },
  {
    name: 'send a split cash note',
    setup: async (h) => void (await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)),
    run: (w) => w.send({ amount: 2000n }),
  },
  {
    name: 'send a whole bill to a pubkey',
    setup: async (h) => void (await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)),
    run: (w, bob) => w.send({ to: bob.me }),
  },
  {
    name: 'send from a cash note (remainder keeps the secret)',
    setup: async (h) => {
      const t = newCashTarget()
      await h.wallet.receive(`${h.bank.mintToCash(5000n, t.secret).token}#${t.secret}`)
    },
    run: (w) => w.send({ amount: 1000n }),
  },
  {
    name: 'auto-consolidate a cash note and a pubkey bill, then split to cash',
    setup: async (h) => {
      const t = newCashTarget()
      await h.wallet.receive(`${h.bank.mintToCash(3000n, t.secret).token}#${t.secret}`)
      await h.wallet.receive(h.bank.mintToPubkey(3000n, h.me).token)
    },
    run: (w) => w.send({ amount: 5000n }),
  },
  {
    name: 'consolidate cash notes into a fresh note',
    setup: async (h) => {
      for (const a of [1000n, 2000n]) {
        const t = newCashTarget()
        await h.wallet.receive(`${h.bank.mintToCash(a, t.secret).token}#${t.secret}`)
      }
    },
    run: (w) => w.consolidate(),
  },
  {
    name: 'consolidate in rounds (cap 2) to self',
    setup: async (h) => {
      h.bank.hub.limits = { ...h.bank.hub.limits, maxConsolidateSources: 2 }
      await h.bank.hub.announce({ relays: h.bank.hub.relayUrls, createdAt: Math.floor(Date.now() / 1000) + 1 })
      for (const a of [1000n, 2000n, 3000n]) await h.wallet.receive(h.bank.mintToPubkey(a, h.me).token)
    },
    run: (w) => w.consolidate(),
  },
]

async function scenario(op: Op, crashAfter: number | undefined, o: { loseReply?: string } = {}) {
  const pool = new MemoryRelayPool()
  const bank = new FakeBank(pool, ['wss://bank.test'])
  await bank.start()
  const storage = new CrashableStorage(new MemoryStorage())
  const h = await harness({ pool, bank, storage })
  const bob = await harness({ pool, bank })
  await op.setup(h, bob)
  storage.writes = 0
  storage.crashAfter = crashAfter
  if (o.loseReply !== undefined) bank.loseReplyFor.add(o.loseReply)
  const outcome = await op.run(h.wallet, bob, bank).then(
    () => 'ok',
    (e: unknown) => e,
  )
  // The process comes back: same disk, healthy again, replies flowing.
  storage.crashAfter = undefined
  bank.loseReplyFor.clear()
  const again = await h.reopen()
  await again.settle().catch(() => undefined)
  return { bank, storage, h, bob, outcome, crashed: storage.crashed }
}

describe('kill window (auditD_cli_killwindow): every step boundary, then settle()', () => {
  for (const op of ops) {
    test(op.name, async () => {
      let steps = 0
      for (let k = 0; k < 40; k++) {
        const s = await scenario(op, k)
        const lost = await uncontrolled(s.bank, s.storage.inner, [s.bob.me, getPublicKey(BOB_KEY)])
        expect(lost.map((w) => `${w.walletPubkey}:${w.amount}`), `${op.name}, killed after ${k} commits`).toEqual([])
        steps = k
        if (!s.crashed) break
      }
      expect(steps).toBeGreaterThan(0)
    }, 120_000)
  }
})

describe('lost replies: indeterminate, then settle() (auditD_cli_killwindow)', () => {
  const cases: [Op, string][] = [
    [ops[0]!, 'cash_transfer'],
    [ops[1]!, 'cash_transfer'],
    [ops[4]!, 'cash_transfer'],
    [ops[4]!, 'cash_consolidate'],
    [ops[5]!, 'cash_consolidate'],
  ]
  for (const [op, method] of cases) {
    test(`${op.name}, ${method} reply lost`, async () => {
      const s = await scenario(op, undefined, { loseReply: method })
      const lost = await uncontrolled(s.bank, s.storage.inner, [s.bob.me])
      expect(lost).toEqual([])
      if (s.outcome !== 'ok' && s.outcome instanceof CashkitError && op !== ops[0]) expect(['indeterminate', 'network']).toContain(s.outcome.code)
    }, 60_000)
  }
})

/** The open calls storage held at the instant the Hub saw a method's call. */
function watch(h: Harness, method: string) {
  const seen: { params: Record<string, unknown>; calls: Promise<PendingCall[]> }[] = []
  h.bank.override = (m, info) => {
    if (m === method) seen.push({ params: info.params, calls: h.storage.tx('r', async (t) => (await t.list('pendingCalls')).filter((c) => c.state !== 'done')) })
    return undefined
  }
  return seen
}
const newIdentityValue = (p: Record<string, unknown>) => (p['new_identity'] as { identity_value: string }).identity_value
/** The written-ahead output of one role, as the identity value the Hub sees. */
const outputIdentity = (c: PendingCall, role: string): string | undefined => {
  const d = c.outputs.find((o) => o.role === role)?.destination
  if (d?.kind === 'cash') return commitment(unseal(d.secret)!)
  if (d?.kind === 'throwaway') return getPublicKey(fromHex(unseal(d.key)!))
  return d?.kind === 'pubkey' ? d.pubkey : undefined
}
const openCalls = (h: Harness) => h.storage.tx('r', async (t) => (await t.list('pendingCalls')).filter((c) => c.state !== 'done'))

describe('write-ahead ordering (auditD_cli_writeahead)', () => {
  test('a send to cash writes the destination secret ahead of its wire call, and the call is marked sent', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const seen = watch(h, 'cash_transfer')
    await h.wallet.send({ amount: 2000n })
    const [call] = await seen[0]!.calls
    expect(call!.state).toBe('sent')
    expect(call!.requestId).toBe(seen[0]!.params['request_id'])
    expect(outputIdentity(call!, 'new')).toBe(newIdentityValue(seen[0]!.params))
    expect(await openCalls(h)).toEqual([])
  })
  test('a consolidate to cash writes its secret ahead of its wire call', async () => {
    const h = await harness()
    for (const a of [1000n, 2000n]) {
      const t = newCashTarget()
      await h.wallet.receive(`${h.bank.mintToCash(a, t.secret).token}#${t.secret}`)
    }
    const seen = watch(h, 'cash_consolidate')
    await h.wallet.consolidate()
    const calls = await seen[0]!.calls
    expect(calls.map((c) => outputIdentity(c, 'new'))).toEqual([newIdentityValue(seen[0]!.params)])
  })
  test('protect writes the new secret ahead of its wire call', async () => {
    const h = await harness()
    const t = newCashTarget()
    const tok = h.bank.mintToCash(700n, t.secret).token
    const seen = watch(h, 'cash_transfer')
    await h.wallet.receive(`${tok}#${t.secret}`)
    const calls = await seen[0]!.calls
    expect(calls.map((c) => outputIdentity(c, 'new'))).toEqual([newIdentityValue(seen[0]!.params)])
  })
  test('a cash-note move writes the merge key ahead of its wire call', async () => {
    const h = await harness()
    const t = newCashTarget()
    await h.wallet.receive(`${h.bank.mintToCash(1000n, t.secret).token}#${t.secret}`)
    await h.wallet.receive(h.bank.mintToPubkey(2000n, h.me).token)
    const seen = watch(h, 'cash_transfer')
    await h.wallet.consolidate()
    const calls = await seen[0]!.calls
    expect(calls.map((c) => c.outputs[0]!.destination.kind)).toEqual(['throwaway'])
    expect(calls.map((c) => outputIdentity(c, 'new'))).toEqual([newIdentityValue(seen[0]!.params)])
  })
  test('a split of a cash note writes its remainder secret ahead and sends its commitment', async () => {
    const h = await harness()
    const t = newCashTarget()
    await h.wallet.receive(`${h.bank.mintToCash(5000n, t.secret).token}#${t.secret}`, { protect: false })
    const seen = watch(h, 'cash_transfer')
    const r = await h.wallet.send({ amount: 1000n, to: getPublicKey(BOB_KEY) })
    const [call] = await seen[0]!.calls
    const rc = outputIdentity(call!, 'remainder')
    expect(rc).toBe(seen[0]!.params['remainder_commitment'])
    expect(rc).not.toBe(commitment(t.secret))
    const rem = (await h.storage.tx('r', (x) => x.get('holdings', r.remainder!.id)))!
    expect(commitment(unseal(rem.cashSecret)!)).toBe(rc)
  })
  test('a non-cash target writes no secret ahead', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const seen = watch(h, 'cash_transfer')
    await h.wallet.send({ amount: 1000n, to: getPublicKey(BOB_KEY) })
    const [call] = await seen[0]!.calls
    expect(call!.outputs.map((o) => o.destination.kind)).toEqual(['pubkey', 'pubkey'])
  })
  test('a call that cannot be written ahead is not placed', async () => {
    const storage = new CrashableStorage(new MemoryStorage())
    const h = await harness({ storage })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const plan = await h.wallet.planSend({ amount: 2000n })
    const before = h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer').length
    storage.writes = 0
    storage.crashAfter = 0
    await failure(h.wallet.executeSend(plan))
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer').length).toBe(before)
  })
  test('a lost reply leaves the call open with its secret, and its source locked; settle() applies it', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    h.bank.loseReplyFor.add('cash_transfer')
    const e = await failure(h.wallet.send({ amount: 2000n }))
    expect(e.code).toBe('indeterminate')
    expect(e.pendingCallId).toBeDefined()
    const [call] = await openCalls(h)
    expect(call!.id).toBe(e.pendingCallId)
    expect(outputIdentity(call!, 'new')).toMatch(/^[0-9a-f]{64}$/)
    expect((await h.wallet.holdings()).map((x) => x.unsettled)).toEqual([true])
    const stale = await h.storage.tx('r', (t) => t.get('holdings', call!.sources[0]!))
    expect(stale?.status).toBe('held')
    h.bank.loseReplyFor.clear()
    const rep = await h.wallet.settle()
    expect(rep.applied).toEqual([call!.id])
    expect(await openCalls(h)).toEqual([])
    expect((await h.wallet.handoffs()).length).toBe(1)
  })
  test('redeem never picks or spends a bill an open call names (I-4)', async () => {
    const h = await harness()
    const nwc = new FakeNwcWallet(h.pool)
    await h.wallet.connections.add('main', nwc.uri)
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const id = (await h.wallet.holdings())[0]!.id
    const early = await h.wallet.planRedeem({ holdings: [id] }) // planned before the call opens
    h.bank.loseReplyFor.add('cash_transfer')
    h.bank.loseReplyFor.add('cash_lookup') // lookups go unanswered, so the call stays open
    await failure(h.wallet.send({ amount: 2000n }))
    expect((await openCalls(h)).map((c) => c.sources)).toEqual([[id]])
    expect(await failure(h.wallet.planRedeem({ holdings: [id] }))).toMatchObject({ code: 'conflict' })
    expect(await failure(h.wallet.redeem())).toMatchObject({ code: 'conflict' })
    expect(await failure(h.wallet.redeem({ amount: 1000n }))).toMatchObject({ code: 'conflict' })
    expect(await failure(h.wallet.executeRedeem(early))).toMatchObject({ code: 'conflict' })
    expect(h.bank.hub.requests.filter((x) => x.item.method === 'cash_redeem')).toHaveLength(0)
  })
  test('BAD_REQUEST is final: the call closes not applied and the bill is free at once', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    h.bank.override = (m) => (m === 'cash_transfer' ? { error: { code: 'BAD_REQUEST', message: 'malformed' } } : undefined)
    const e = await failure(h.wallet.send({ amount: 2000n }))
    expect(e.code).toBe('invalid_input')
    expect(e.pendingCallId).toBeUndefined()
    expect(await openCalls(h)).toEqual([])
    const calls = await h.storage.tx('r', (t) => t.list('pendingCalls'))
    expect(calls.map((c) => [c.state, c.outcome, c.lastCode])).toEqual([['done', 'not_applied', 'BAD_REQUEST']])
    expect((await h.wallet.holdings()).map((x) => x.unsettled)).toEqual([false])
    h.bank.override = undefined
    expect((await h.wallet.send({ amount: 2000n })).sent).toBe(2000n)
  })
  test('a tombstone answer closes the call and marks the bill spent', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    h.bank.override = (m) => (m === 'cash_transfer' ? { result: { status: 'spent', reason: 'redeemed' } } : undefined)
    expect((await failure(h.wallet.send({ amount: 2000n }))).code).toBe('spent')
    expect(await openCalls(h)).toEqual([])
    expect(await h.wallet.holdings()).toEqual([])
  })
  test('a tombstone answer to a consolidate marks only its first source spent; the others stay held', async () => {
    const h = await harness()
    for (const a of [1000n, 2000n, 3000n]) await h.wallet.receive(h.bank.mintToPubkey(a, h.me).token)
    h.bank.override = (m) => (m === 'cash_consolidate' ? { result: { status: 'spent', reason: 'transferred' } } : undefined)
    const r = await h.wallet.consolidate()
    expect(r.outcomes.map((o) => o.ok)).toEqual([false])
    expect(await openCalls(h)).toEqual([])
    const [call] = await h.storage.tx('r', (t) => t.list('pendingCalls'))
    expect(call!.method).toBe('cash_consolidate')
    expect(call!.sources).toHaveLength(3)
    const rows = await h.storage.tx('r', (t) => Promise.all(call!.sources.map((id) => t.get('holdings', id))))
    expect(rows.map((x) => x?.status)).toEqual(['spent', 'held', 'held'])
    const held = await h.wallet.holdings()
    expect(new Set(held.map((x) => x.id))).toEqual(new Set(call!.sources.slice(1)))
    expect(held.every((x) => !x.unsettled)).toBe(true)
  })
  test('any other code keeps the call open and the bill locked until a lookup', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    h.bank.override = (m) => (m === 'cash_transfer' ? { error: { code: 'RATE_LIMITED', message: 'slow down' } } : undefined)
    const e = await failure(h.wallet.send({ amount: 2000n }))
    expect(e.pendingCallId).toBeDefined()
    expect((await openCalls(h)).map((c) => c.lastCode)).toEqual(['RATE_LIMITED'])
    expect((await h.wallet.holdings()).map((x) => x.unsettled)).toEqual([true])
  })
  test('the call survives a failed final commit and a reopen; settle() applies it', async () => {
    const storage = new CrashableStorage(new MemoryStorage())
    const h = await harness({ storage })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const plan = await h.wallet.planSend({ amount: 2000n })
    storage.writes = 0
    storage.crashAfter = 2 // the call is written ahead and marked sent; the result commit does not land
    const e = await failure(h.wallet.executeSend(plan))
    expect(e.recovery).toBeDefined()
    storage.crashAfter = undefined
    const again = await h.reopen({}) // opening settles: the lookup finds the call done
    expect(await openCalls(h)).toEqual([])
    const notes = await again.handoffs()
    expect(notes).toHaveLength(1)
  })
})

describe('recovery text (auditD_cli_recovery_handoff)', () => {
  test('keeps every secret, intact and paired, in the error and its JSON (TestAuditD_CLI_RecoveryHandoffKeepsItsSecret_Human, _JSON)', async () => {
    const storage = new CrashableStorage(new MemoryStorage())
    const h = await harness({ storage })
    const t = newCashTarget()
    await h.wallet.receive(`${h.bank.mintToCash(5000n, t.secret).token}#${t.secret}`)
    const plan = await h.wallet.planSend({ amount: 2000n })
    storage.writes = 0
    storage.crashAfter = 2 // written ahead and marked sent; the result commit fails
    const e = await failure(h.wallet.executeSend(plan))
    expect(e.recoveryHandoffs).toHaveLength(2)
    for (const ho of e.recoveryHandoffs!) {
      expect(ho).toMatch(/^lokicash1[0-9a-z]+#[0-9a-f]{64}$/)
      expect(e.recovery).toContain(ho)
      expect(JSON.parse(toJSON(e)).recovery).toContain(ho)
    }
    const [note, own] = e.recoveryHandoffs!
    expect(h.bank.wallet(splitCashString(note!).token)?.identity.value).toBe(commitment(splitCashString(note!).cashSecret))
    expect(h.bank.wallet(splitCashString(own!).token)?.identity.value).toBe(commitment(splitCashString(own!).cashSecret))
  })
  test('is never truncated (TestAuditD_CLI_RecoveryHandoffIsNeverTruncated)', () => {
    const long = `lokicash1${'q'.repeat(4000)}#${'ab'.repeat(32)}`
    const e = new CashkitError('internal', 'x', { recovery: `Save this: ${long}`, recoveryHandoffs: [long] })
    expect(e.recovery).toBe(`Save this: ${long}`)
    expect(JSON.parse(toJSON(e)).recovery).toBe(`Save this: ${long}`)
  })
})

describe('no secrets in activity (auditD_cli_history_secrets)', () => {
  test('an nconnection target never lands in activity; public targets stay intact; cash interpolates nothing', async () => {
    const h = await harness()
    for (const a of [1000n, 1000n, 1000n]) await h.wallet.receive(h.bank.mintToPubkey(a, h.me).token)
    const { encodeNConnection } = await import('../src/core/index.js')
    const nc = encodeNConnection({ connectionKey: 'ef'.repeat(32), relays: ['wss://r'], platform: 'discord' })
    const ia = getPublicKey(BOB_KEY)
    await h.wallet.send({ amount: 1000n, to: nc, ia })
    await h.wallet.send({ amount: 1000n, to: getPublicKey(BOB_KEY) })
    const r = await h.wallet.send({ amount: 1000n })
    const acts = (await h.wallet.activity()).filter((a) => a.type === 'activity')
    const json = toJSON(acts)
    expect(json).not.toContain('nconnection1')
    expect(json).not.toContain(r.cashNote!.split('#')[1])
    const tos = acts.flatMap((a) => (a.type === 'activity' && a.action === 'send' ? [a.to] : []))
    expect(tos).toEqual(['cash', expect.stringMatching(/^npub1/), 'discord connection'])
  })
  test('every activity string survives redact unchanged (TestAuditD_CLI_HistoryDetailsCarryNothingSecretShaped)', async () => {
    const h = await harness()
    const t = newCashTarget()
    await h.wallet.receive(`${h.bank.mintToCash(5000n, t.secret).token}#${t.secret}`)
    await h.wallet.send({ amount: 1000n })
    await h.wallet.send({ amount: 1000n, to: getPublicKey(BOB_KEY) })
    await h.wallet.consolidate()
    const strings: string[] = []
    const walk = (v: unknown) => {
      if (typeof v === 'string') strings.push(v)
      else if (v !== null && typeof v === 'object') Object.values(v).forEach(walk)
    }
    walk(await h.storage.tx('r', (t2) => t2.list('activity')))
    expect(strings.length).toBeGreaterThan(5)
    for (const s of strings) expect(redact(s)).toBe(s)
  })
})

describe('a rekey whose reply was lost', () => {
  test('settle() applies the new secret from the lookup', async () => {
    const h = await harness()
    const t = newCashTarget()
    h.bank.loseReplyFor.add('cash_transfer')
    const r = await h.wallet.receive(`${h.bank.mintToCash(5000n, t.secret).token}#${t.secret}`)
    const id = r.received ? r.holding.id : ''
    const [call] = await openCalls(h)
    const fresh = unseal((call!.outputs[0]!.destination as { secret: Sealed }).secret)!
    h.bank.loseReplyFor.clear()
    const rep = await h.wallet.settle()
    expect(rep.applied).toEqual([call!.id])
    expect(await h.wallet.exportHolding(id)).toContain(fresh)
  })
  test('an omission is never resent: one status read decides it (TestRetryWithPendingSecrets_NeverRetriesAnOmission)', async () => {
    const h = await harness()
    const nwc = new FakeNwcWallet(h.pool)
    await h.wallet.connections.add('main', nwc.uri)
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    h.bank.loseReplyFor.add('cash_redeem')
    const r = await h.wallet.redeem()
    // The one status read finds the bill gone (the lost reply had paid it); nothing is resent.
    expect(r.firstError?.code).toBe('spent')
    expect(h.bank.hub.requests.filter((x) => x.item.method === 'cash_redeem')).toHaveLength(1)
  })
})

describe('a second protect never overwrites an open call\'s secret (pending_secret_batch_test)', () => {
  test('while the first protect is unresolved, a second one sends nothing and the open secret keeps control', async () => {
    const h = await harness()
    const t = newCashTarget()
    const w = h.bank.mintToCash(5000n, t.secret)
    const r = await h.wallet.receive(`${w.token}#${t.secret}`, { protect: false })
    if (!r.received) throw new Error('not received')
    const id = r.holding.id
    h.bank.loseReplyFor.add('cash_transfer') // the Hub applies the rekey; the reply is lost
    h.bank.loseReplyFor.add('cash_lookup') // and lookups go unanswered, so the call stays open
    expect((await h.wallet.protect({ holdings: [id] })).outcomes[0]).toMatchObject({ ok: false, error: { code: 'indeterminate' } })
    const [call] = await openCalls(h)
    const fresh = unseal((call!.outputs[0]!.destination as { secret: Sealed }).secret)!
    expect(w.identity).toEqual({ type: 'cash', value: commitment(fresh) })
    const before = h.bank.hub.requests.filter((x) => x.item.method === 'cash_transfer').length
    const rowBefore = await h.storage.tx('r', (t2) => t2.get('holdings', id))
    for (const again of [() => h.wallet.protect({ holdings: [id] }), () => h.wallet.protect()]) {
      const p = await again()
      expect(p.outcomes.map((o) => o.ok)).toEqual([false])
    }
    expect(h.bank.hub.requests.filter((x) => x.item.method === 'cash_transfer').length).toBe(before)
    const calls = await h.storage.tx('r', (t2) => t2.list('pendingCalls'))
    expect(calls).toHaveLength(1)
    expect(unseal((calls[0]!.outputs[0]!.destination as { secret: Sealed }).secret)).toBe(fresh)
    expect((await h.storage.tx('r', (t2) => t2.get('holdings', id)))?.cashSecret).toEqual(rowBefore?.cashSecret)
    h.bank.loseReplyFor.clear()
    expect((await h.wallet.settle()).applied).toEqual([call!.id])
    expect(await h.wallet.exportHolding(id)).toContain(fresh)
  })
})

describe('OCC (auditD_cli_occ_crossprocess)', () => {
  test('two wallets on one store: a stale plan conflicts; different rows both succeed', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    await h.wallet.receive(h.bank.mintToPubkey(3000n, h.me).token)
    const other = await h.reopen()
    const [a, b] = await h.wallet.holdings()
    const stale = await h.wallet.planSend({ holdings: [a!.id], amount: 1000n })
    await other.send({ holdings: [a!.id], amount: 1000n })
    expect((await failure(h.wallet.executeSend(stale))).code).toBe('conflict')
    const [x, y] = await Promise.all([h.wallet.send({ holdings: [b!.id], amount: 1000n }), other.send({ holdings: [(await other.holdings()).find((z) => z.amount === 4000n)!.id], amount: 1000n })])
    expect([x.sent, y.sent]).toEqual([1000n, 1000n])
  })
})

describe('amount bounds (auditC_ledger_amount_invariant, auditC_sdk_quote_unvalidated)', () => {
  test('a Hub figure that disagrees with the verified attestation is refused at receive', async () => {
    const h = await harness()
    const w = h.bank.mintToPubkey(5000n, h.me)
    w.amount = 6000n
    expect((await failure(h.wallet.receive(w.token))).code).toBe('invalid_input')
    expect(await h.wallet.holdings()).toHaveLength(0)
  })
  test('a quote that does not add up is refused, and nothing is redeemed', async () => {
    const h = await harness()
    const nwc = new FakeNwcWallet(h.pool)
    await h.wallet.connections.add('main', nwc.uri)
    const w = h.bank.mintToPubkey(5000n, h.me)
    await h.wallet.receive(w.token)
    h.bank.override = (m) =>
      m === 'cash_status'
        ? { result: { recipients: [{ identity_type: 'pubkey', identity_value: h.me, amount_millis: 5000, claimed: false, redeem_fee_millis: 10, net_redeemable_millis: 5000, min_transfer_millis: 0 }] } }
        : undefined
    const plan = await h.wallet.planRedeem()
    expect(plan.items).toHaveLength(0)
    expect(plan.refused[0]!.error.code).toBe('invalid_input')
  })
})
