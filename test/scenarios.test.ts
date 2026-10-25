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
import { fromHex, getPublicKey, newCashTarget, redact, splitCashString, toHex, utf8 } from '../src/core/index.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { CashkitError, toJSON, type Sealed, type Storage, type StorageTx, type Wallet } from '../src/wallet/index.js'
import { releasePark } from '../src/wallet/bills.js'
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
      for (const s of [h.cashSecret, h.pendingCashSecret, h.pendingDestinationCashSecret]) addSecret(unseal(s))
      for (const k of [h.throwawayKey, h.pendingThrowawayKey]) addKey(unseal(k))
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
  {
    // B4: the first rekey landed but its reply was lost, so only the pending secret works.
    name: 'protect again a cash note whose earlier rekey is unresolved',
    setup: async (h) => {
      const t = newCashTarget()
      outside.add(commitment(t.secret))
      await h.wallet.receive(`${h.bank.mintToCash(900n, t.secret).token}#${t.secret}`, { protect: false })
      h.bank.loseReplyFor.add('cash_transfer')
      await h.wallet.protect()
      h.bank.loseReplyFor.clear()
    },
    run: (w) => w.protect({ holdings: [] }).then(async () => w.protect({ holdings: (await w.holdings()).map((x) => x.id) })),
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
    [ops[7]!, 'cash_transfer'],
  ]
  for (const [op, method] of cases) {
    test(`${op.name}, ${method} reply lost`, async () => {
      const s = await scenario(op, undefined, { loseReply: method })
      const lost = await uncontrolled(s.bank, s.storage.inner, [s.bob.me])
      expect(lost).toEqual([])
      if (s.outcome !== 'ok' && s.outcome instanceof CashkitError && op !== ops[0] && op !== ops[7]) expect(['indeterminate', 'network']).toContain(s.outcome.code)
    }, 60_000)
  }
})

/** What storage held at the instant the Hub saw a method's call. */
function watch(h: Harness, method: string) {
  const seen: { params: Record<string, unknown>; holdings: Promise<unknown[]> }[] = []
  h.bank.override = (m, info) => {
    if (m === method) seen.push({ params: info.params, holdings: h.storage.tx('r', (t) => t.list('holdings')) })
    return undefined
  }
  return seen
}
const newIdentityValue = (p: Record<string, unknown>) => (p['new_identity'] as { identity_value: string }).identity_value

describe('write-ahead ordering (auditD_cli_writeahead)', () => {
  test('a send to cash parks the destination secret before its wire call (TestAuditD_CLI_TransferSitesParkBeforeTheirWireCall)', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const seen = watch(h, 'cash_transfer')
    await h.wallet.send({ amount: 2000n })
    const rows = (await seen[0]!.holdings) as { pendingDestinationCashSecret?: Sealed }[]
    const parked = rows.map((r) => unseal(r.pendingDestinationCashSecret)).filter((x) => x !== undefined)
    expect(parked.map((x) => commitment(x!))).toEqual([newIdentityValue(seen[0]!.params)])
    expect(await h.wallet.unfinishedCashSends()).toEqual([])
  })
  test('a consolidate to cash parks before its wire call (TestAuditD_CLI_ConsolidateToCash_SecretIsWrittenAheadOfWireCall)', async () => {
    const h = await harness()
    for (const a of [1000n, 2000n]) {
      const t = newCashTarget()
      await h.wallet.receive(`${h.bank.mintToCash(a, t.secret).token}#${t.secret}`)
    }
    const seen = watch(h, 'cash_consolidate')
    await h.wallet.consolidate()
    const rows = (await seen[0]!.holdings) as { pendingDestinationCashSecret?: Sealed }[]
    const parked = rows.flatMap((r) => (r.pendingDestinationCashSecret !== undefined ? [commitment(unseal(r.pendingDestinationCashSecret)!)] : []))
    expect(parked).toEqual([newIdentityValue(seen[0]!.params)])
  })
  test('protect persists the new secret before its wire call (TestReKeySites_PersistTheNewSecretBeforeTheirWireCall)', async () => {
    const h = await harness()
    const t = newCashTarget()
    const tok = h.bank.mintToCash(700n, t.secret).token
    const seen = watch(h, 'cash_transfer')
    await h.wallet.receive(`${tok}#${t.secret}`)
    const rows = (await seen[0]!.holdings) as { pendingCashSecret?: Sealed }[]
    expect(rows.map((r) => commitment(unseal(r.pendingCashSecret)!))).toEqual([newIdentityValue(seen[0]!.params)])
  })
  test('a cash-note move persists the merge key before its wire call (cash_merge.go moveCashNotesToKey)', async () => {
    const h = await harness()
    const t = newCashTarget()
    await h.wallet.receive(`${h.bank.mintToCash(1000n, t.secret).token}#${t.secret}`)
    await h.wallet.receive(h.bank.mintToPubkey(2000n, h.me).token)
    const seen = watch(h, 'cash_transfer')
    await h.wallet.consolidate()
    const rows = (await seen[0]!.holdings) as { pendingThrowawayKey?: Sealed }[]
    const keys = rows.flatMap((r) => (r.pendingThrowawayKey !== undefined ? [getPublicKey(fromHex(unseal(r.pendingThrowawayKey)!))] : []))
    expect(keys).toEqual([newIdentityValue(seen[0]!.params)])
  })
  test('a non-cash target parks nothing (TestAuditD_CLI_ParkIsANoOpForANonCashTarget)', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const seen = watch(h, 'cash_transfer')
    await h.wallet.send({ amount: 1000n, to: getPublicKey(BOB_KEY) })
    const rows = (await seen[0]!.holdings) as { pendingDestinationCashSecret?: Sealed }[]
    expect(rows.every((r) => r.pendingDestinationCashSecret === undefined)).toBe(true)
  })
  test('a park that cannot be recorded refuses the call (TestAuditD_CLI_ParkRefusesWhenItCannotRecord)', async () => {
    const storage = new CrashableStorage(new MemoryStorage())
    const h = await harness({ storage })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const plan = await h.wallet.planSend({ amount: 2000n })
    const before = h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer').length
    storage.writes = 0
    storage.crashAfter = 0
    const e = await failure(h.wallet.executeSend(plan))
    expect(e).toBeInstanceOf(CashkitError)
    expect(e.message).toMatch(/call was not placed/)
    expect(h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer').length).toBe(before)
  })
  test('a definite refusal forgets the park; silence keeps it (TestForgetIfNothingCreated)', async () => {
    const h = await harness()
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    h.bank.override = (m) => (m === 'cash_transfer' ? { error: { code: 'RATE_LIMITED', message: 'slow down' } } : undefined)
    expect((await failure(h.wallet.send({ amount: 2000n }))).code).toBe('conflict')
    expect(await h.wallet.unfinishedCashSends()).toEqual([])
    h.bank.override = undefined
    h.bank.loseReplyFor.add('cash_transfer')
    expect((await failure(h.wallet.send({ amount: 2000n }))).code).toBe('indeterminate')
    const open = await h.wallet.unfinishedCashSends({ includeSecrets: true })
    expect(open).toHaveLength(1)
    expect(open[0]!.cashSecret).toMatch(/^[0-9a-f]{64}$/)
    expect(h.wallet.state.unfinishedCashSends).toEqual([{ holdingId: open[0]!.holdingId }])
  })
  test('release clears only the park it wrote (TestAuditD_CLI_ReleaseLeavesAConcurrentParkAlone)', () => {
    const mine: Sealed = { alg: 'none', data: '01' }
    const theirs: Sealed = { alg: 'none', data: '02' }
    const row = { id: 'h-1', pendingDestinationCashSecret: theirs } as never
    expect(releasePark(row, { holdingId: 'h-1', sealed: mine })).toBe(row)
    const ours = { id: 'h-1', pendingDestinationCashSecret: mine } as never
    expect((releasePark(ours, { holdingId: 'h-1', sealed: mine }) as { pendingDestinationCashSecret?: Sealed }).pendingDestinationCashSecret).toBeUndefined()
  })
  test('the park survives a failed final commit and a reopen (TestAuditD_CLI_ParkIsNotSavedByReleaseAlone, …SurvivesALedgerReloadRoundTrip)', async () => {
    const storage = new CrashableStorage(new MemoryStorage())
    const h = await harness({ storage })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const plan = await h.wallet.planSend({ amount: 2000n })
    storage.writes = 0
    storage.crashAfter = 1 // the park commits; the result commit does not
    const e = await failure(h.wallet.executeSend(plan))
    expect(e.recovery).toBeDefined()
    storage.crashAfter = undefined
    const again = await h.reopen({})
    const open = await again.unfinishedCashSends({ includeSecrets: true })
    expect(open).toHaveLength(1)
    expect(e.recovery).toContain(open[0]!.cashSecret)
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
    storage.crashAfter = 1
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

/** A cash holding whose rekey landed unseen: the Hub knows the pending secret, the row still the old one. */
async function landedUnseen(h: Harness, amount = 5000n) {
  const t = newCashTarget()
  const w = h.bank.mintToCash(amount, t.secret)
  const r = await h.wallet.receive(`${w.token}#${t.secret}`, { protect: false })
  const id = r.received ? r.holding.id : ''
  const fresh = newCashTarget()
  await h.storage.tx('rw', async (tx) => {
    const row = (await tx.get('holdings', id))!
    await tx.put('holdings', { ...row, pendingCashSecret: { alg: 'none', data: toHex(utf8(fresh.secret)) }, version: row.version + 1 }, row.version)
  })
  w.identity = { type: 'cash', value: commitment(fresh.secret) }
  return { id, w, fresh }
}
describe('pending secrets (pending_secret_batch_test.go)', () => {
  test('a wrong-secret decline retries with the pending secret and promotes it (TestRetryWithPendingSecrets_RecoversAndPromotes)', async () => {
    const h = await harness()
    const nwc = new FakeNwcWallet(h.pool)
    await h.wallet.connections.add('main', nwc.uri)
    const { id, fresh } = await landedUnseen(h)
    // Quoting with the old secret fails (BAD_REQUEST on status), so execute a hand-built plan.
    const r = await h.wallet.executeRedeem({
      op: 'redeem',
      items: [{ holdingId: id, version: (await h.storage.tx('r', (t) => t.get('holdings', id)))!.version, amount: 5000n, fee: 0n, net: 5000n }],
      refused: [],
      destination: { kind: 'connection', name: 'main' },
      total: 5000n,
      totalFee: 0n,
      totalNet: 5000n,
    })
    expect(r.outcomes[0]).toMatchObject({ ok: true, holdingId: id })
    const row = (await h.storage.tx('r', (t) => t.get('holdings', id)))!
    expect(unseal(row.cashSecret)).toBe(fresh.secret)
    expect(row.pendingCashSecret).toBeUndefined()
  })
  test('settle() promotes a landed pending secret without waiting for a spend', async () => {
    const h = await harness()
    const { id, fresh } = await landedUnseen(h)
    const rep = await h.wallet.settle()
    expect(rep.cashSecretsPromoted).toEqual([id])
    expect(await h.wallet.exportHolding(id)).toContain(fresh.secret)
  })
  test('an omission is never retried (TestRetryWithPendingSecrets_NeverRetriesAnOmission)', async () => {
    const h = await harness()
    const nwc = new FakeNwcWallet(h.pool)
    await h.wallet.connections.add('main', nwc.uri)
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    h.bank.loseReplyFor.add('cash_redeem')
    const r = await h.wallet.redeem()
    expect(r.firstError?.code).toBe('indeterminate')
    expect(h.bank.hub.requests.filter((x) => x.item.method === 'cash_redeem')).toHaveLength(1)
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
