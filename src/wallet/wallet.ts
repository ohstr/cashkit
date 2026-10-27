// The wallet engine's public face (design §6). Every money-moving operation
// is plan, then execute; the one-call forms are execute(await plan(...)).
import { decodeCashHubConnection, encodeNpub, fromHex, localSigner, nip49Encrypt, parsePairingURI, sniff, toHex, type MemberAction, type NostrEvent, type Payment, type ReportReason, type Signer } from '../core/index.js'
import type { CircleWalletClient, HubView } from '../client/index.js'
import { mint, verifyCashHubString, type MintInput, type MintResult } from './mint.js'
import {
  cancelOutbox,
  editCurators,
  listCurators,
  listDiscover,
  listedConnection,
  listOutbox,
  loadDiscover,
  nextOutboxDue,
  publishCurators,
  publishDue,
  recommend,
  recommendPreview,
  refreshDiscover,
  report as reportOffer,
  setDefaultCurators,
  syncCurators,
  tapDiscover,
  withdrawRecommendation,
  type CuratorsView,
  type DiscoverOptions,
  type DiscoverView,
  type OutboxItem,
  type RecommendPreview,
  type ReportPreview,
  type TapView,
} from './discover.js'
import { pocketBalanceOf, pocketEntries, syncPocket, type PocketSyncReport } from './pocket.js'
import { approveMinter, claimZap, listZaps, sendZap, type ZapInput, type ZapSent, type ZapView } from './zap.js'
import { cancelWithdrawal, listWithdrawals, quoteWithdrawal, refreshWithdrawal, sendWithdrawal, signedTx, watchWithdrawal, withdrawalReceipt, withdrawalView, withdrawTerms, type WithdrawalView, type WithdrawQuoteView, type WithdrawTermsView } from './withdraw.js'
import { listOrders, orderView, placeOrder, quoteOrder, refreshOrder, watchOrder, type OrderQuote, type OrderView, type PlaceOrderInput } from './orders.js'
import { type GetInfoResult, type MakeInvoiceParams } from '../client/index.js'
import { exportBackup, importBackup, valueFingerprint, type ImportSummary } from './backup.js'
import {
  applyCircleNotification,
  circleRow,
  circleView,
  circleWalletClient,
  deleteCircleWallet,
  isLightning,
  joinCircle,
  memberRequest,
  nwcFor,
  settleJoins,
  type CircleAlert,
  type CircleNotification,
  type CircleView,
  type JoinOptions,
  type JoinResult,
  type JoinTermsInput,
  type SettleJoinsReport,
} from './circle.js'
import { consolidate, type ConsolidateReport } from './consolidate.js'
import { Ctx, type OperationEvent } from './context.js'
import { CashkitError } from './errors.js'
import { activity, balance, listHandoffs, type ActivityItem, type Balance, type HandoffView } from './feed.js'
import { newId, updateHolding } from './ledger.js'
import { DEFAULT_SETTINGS, SCHEMA_VERSION, type Connection, type ConnectionKind, type HandoffStatus, type Holding, type PendingJoin, type Meta, type Settings } from './model.js'
import type { WalletDeps } from './ports.js'
import { executeRedeem, planRedeem, settleRedeeming, type RedeemingReport, type RedeemInput, type RedeemOutcome, type RedeemPlan } from './redeem.js'
import { protectMany, receive, type ReceiveResult, type Secured } from './receive.js'
import { report, type Report } from './report.js'
import { executeSend, planSend, type SendInput, type SendPlan, type SendResult } from './send.js'
import { lockedHoldings } from './bills.js'
import { closeByUser, confirmReplace, settleCalls, type SettleCallsReport } from './runner.js'
import { status, type StatusOutcome } from './status.js'
import { holdingView, pendingCallView, type HoldingView, type PendingCallView } from './views.js'

/** What `settle()` did: the pending calls, then the `redeeming` holdings. */
export type SettleReport = SettleCallsReport & { readonly redeems: RedeemingReport; readonly joins: SettleJoinsReport }

export interface ConnectionView {
  readonly name: string
  readonly kind: ConnectionKind
  readonly isDefault: boolean
  readonly walletPubkey: string
  readonly relays: readonly string[]
  /** `cashhub`: the Hub identity, chain, whether the signature verified, and the network last seen. */
  readonly hubIdentity?: string
  readonly chain?: string
  readonly verified?: boolean
  readonly network?: string
  readonly lastKnownBalance?: { readonly millis: bigint; readonly at: number }
}

export interface IdentityView {
  readonly pubkey: string
  readonly npub: string
  readonly source: 'local' | 'signer'
  readonly label?: string
}

export interface PendingJoinView {
  readonly connectionPubkey: string
  readonly hubPubkey: string
  readonly hubLabel: string
  readonly name: string
  readonly at: number
  readonly deadline: number
  /** Set when the member must decide: the join was not made (they may join again), its outcome can no longer be known, or its lookups go unanswered. */
  readonly needsUser?: PendingJoin['needsUser']
}

export interface WalletState {
  readonly holdings: readonly HoldingView[]
  readonly balance: { readonly held: bigint; readonly count: number; readonly expired: bigint }
  readonly pendingJoins: readonly PendingJoinView[]
  /** Holdings moved for a merge that has not finished. */
  readonly pendingMerge: number
  /** Known only where the platform reports it (browsers). */
  readonly storagePersisted?: boolean
  /** Value-bearing changes since the last exportBackup (or none ever, with something to lose). */
  readonly backupStale: boolean
  readonly lastBackupAt?: number
  readonly locked: boolean
  /** Open calls, and closed ones that wait for the user. */
  readonly pendingCalls: readonly PendingCallView[]
  /** Unix seconds: the earliest time a pending lookup asked to be retried. */
  readonly nextSettleAt?: number
  /** Calls whose outcome can no longer be learned; their written-ahead secrets are in `unreconciledSecrets`. */
  readonly unreconciled: number
}

export interface ProtectOutcome {
  readonly holdingId: string
  readonly secured: Secured
  readonly holding: HoldingView
}

export interface Lightning {
  getInfo(): Promise<GetInfoResult>
  getBalance(): Promise<{ balance: number }>
  makeInvoice(p: MakeInvoiceParams): Promise<Record<string, unknown>>
  payInvoice(invoice: string, amount?: bigint): Promise<{ preimage: string; fees_paid?: number }>
  listTransactions(p?: { from?: number; until?: number; limit?: number; offset?: number; unpaid?: boolean; type?: string }): Promise<{ transactions: unknown[] }>
  signMessage(message: string): Promise<{ message: string; signature: string }>
}

const EMPTY_STATE: WalletState = { holdings: [], balance: { held: 0n, count: 0, expired: 0n }, pendingJoins: [], pendingMerge: 0, backupStale: false, locked: false, pendingCalls: [], unreconciled: 0 }

/**
 * This store's device id, created on first open. A store whose meta names
 * another fingerprint than its device row (a copied or restored store) gets
 * a new device id, so the calls it holds become foreign and are never
 * re-placed from here.
 */
async function ensureDevice(ctx: Ctx, meta: Meta): Promise<string> {
  return ctx.commit(async (t) => {
    let m = meta
    if (m.storeFingerprint === undefined) {
      m = { ...m, storeFingerprint: toHex(ctx.random(16)), version: m.version + 1 }
      await t.put('meta', m, meta.version)
    }
    const cur = await t.get('device', 'self')
    if (cur !== undefined && cur.storeFingerprint === m.storeFingerprint) return cur.deviceId
    const row = { id: 'self', deviceId: toHex(ctx.random(16)), createdAt: ctx.now(), storeFingerprint: m.storeFingerprint!, version: (cur?.version ?? 0) + 1 }
    await t.put('device', row, cur?.version ?? 0)
    return row.deviceId
  })
}

export class Wallet {
  private snapshot: WalletState = EMPTY_STATE
  private readonly subscribers = new Set<(s: WalletState) => void>()
  private refreshQueued: Promise<void> | undefined
  private refreshRunning: Promise<void> = Promise.resolve()
  private storagePersisted: boolean | undefined
  private readonly stops: (() => void)[] = []

  private constructor(private readonly ctx: Ctx) {
    ctx.onChange(() => this.refreshState())
  }

  /**
   * Opens (and on first use, initialises) a wallet over `deps.storage`, then
   * runs `settle()` so no pending call is left unexamined. A settle that cannot
   * reach a Hub leaves its calls open for the next one; open still succeeds.
   */
  static async open(deps: WalletDeps, o: { settle?: boolean } = {}): Promise<Wallet> {
    if (deps.storage === undefined || deps.vault === undefined) throw new CashkitError('usage', 'Wallet.open needs storage and a vault (vault-none must be chosen explicitly)')
    const ctx = new Ctx(deps)
    const random = ctx.random
    // Refuse another schema before writing anything: there is no migration from schema 1.
    const existing = await ctx.read((t) => t.get('meta', 'meta'))
    if (existing !== undefined && existing.schemaVersion > SCHEMA_VERSION) throw new CashkitError('usage', `this wallet was written by a newer cashkit (schema ${existing.schemaVersion}); upgrade to open it`)
    if (existing !== undefined && existing.schemaVersion < SCHEMA_VERSION) {
      throw new CashkitError('internal', `this store was written by an older cashkit (schema ${existing.schemaVersion}) and cannot be opened by this one: start a new store, then restore what it held from the old app`)
    }
    const meta = await ctx.commit(async (t) => {
      const m = await t.get('meta', 'meta')
      if (m !== undefined) return m
      const row = { id: 'meta', schemaVersion: SCHEMA_VERSION, walletId: newId('w', random).slice(2) + toHex(random(4)), storeFingerprint: toHex(random(16)), version: 1 }
      await t.put('meta', row, 0)
      await t.put('settings', { id: 'settings', ...DEFAULT_SETTINGS, version: 1 }, 0)
      return row
    })
    ctx.walletId = meta.walletId
    ctx.deviceId = await ensureDevice(ctx, meta)
    if (deps.signer !== undefined) {
      const signer = deps.signer
      await ctx.commit(async (t) => {
        const cur = await t.get('identity', 'self')
        if (cur?.source === 'signer' && cur.pubkey === signer.pubkey) return
        if (cur?.source === 'local' && cur.pubkey !== signer.pubkey) {
          throw new CashkitError('conflict', 'this wallet already has a different local identity; pass no signer, or start a new wallet')
        }
        if (cur === undefined) await t.put('identity', { id: 'self', source: 'signer', pubkey: signer.pubkey, version: 1 }, 0)
      })
    }
    const w = new Wallet(ctx)
    if (deps.sync !== undefined) {
      w.stops.push(deps.sync.subscribe((m) => {
        if (m.walletId === ctx.walletId) void ctx.changedElsewhere()
      }))
    }
    if (deps.persist !== undefined) w.storagePersisted = await deps.persist().catch(() => false)
    if (o.settle !== false && !deps.vault.locked()) await w.settle().catch(() => undefined)
    await loadDiscover(ctx).catch(() => undefined)
    if (!deps.vault.locked()) await publishDue(ctx).catch(() => undefined)
    await w.refreshState()
    return w
  }

  get walletId(): string {
    return this.ctx.walletId
  }

  /** Stops listening to other tabs. The storage and vault stay the app's to close. */
  close(): void {
    for (const s of this.stops.splice(0)) s()
    this.subscribers.clear()
  }

  // ---- state and events (§6.11)

  get state(): WalletState {
    return this.snapshot
  }

  subscribe(fn: (s: WalletState) => void): () => void {
    this.subscribers.add(fn)
    return () => this.subscribers.delete(fn)
  }

  on(event: 'operation', fn: (e: OperationEvent) => void): () => void {
    if (event !== 'operation') throw new CashkitError('usage', `unknown event ${String(event)}`)
    return this.ctx.onOperation(fn)
  }

  /**
   * Re-reads the snapshot. Calls while a read is running share one queued
   * read, which starts after it, so no caller gets a snapshot older than its
   * own commit.
   */
  private refreshState(): Promise<void> {
    if (this.refreshQueued !== undefined) return this.refreshQueued
    const q = this.refreshRunning.then(() => {
      this.refreshQueued = undefined
      return this.readState()
    })
    this.refreshQueued = q
    this.refreshRunning = q.catch(() => undefined)
    return q
  }

  private async readState(): Promise<void> {
    const now = this.ctx.nowSeconds()
    const [rows, joins, meta, calls] = await this.ctx.read(async (t) => [await t.list('holdings'), await t.list('pendingJoins'), await t.get('meta', 'meta'), await t.list('pendingCalls')] as const)
    const shown = calls.filter((c) => c.state !== 'done' || c.needsUser !== undefined)
    const lockedIds = new Set(calls.flatMap((c) => (c.state === 'done' ? [] : [...c.sources, ...(c.authorizer.kind === 'cash' ? [c.authorizer.holdingId] : [])])))
    const retries = calls.flatMap((c) => (c.state !== 'done' && c.lookup?.retryAfter !== undefined ? [c.lookup.retryAfter] : []))
    const fp = await valueFingerprint(this.ctx)
    const held = rows.filter((h) => h.status === 'held')
    let sum = 0n
    let expired = 0n
    let count = 0
    for (const h of held) {
      if (h.amount === undefined) continue
      count++
      if (h.expiresAt !== undefined && h.expiresAt <= now) expired += h.amount
      else sum += h.amount
    }
    this.snapshot = {
      holdings: held.map((h) => holdingView(h, now, lockedIds.has(h.id))),
      balance: { held: sum, count, expired },
      pendingJoins: joins.map((j) => ({ connectionPubkey: j.id, hubPubkey: j.hubPubkey, hubLabel: j.hubLabel, name: j.name, at: j.at, deadline: j.deadline, ...(j.needsUser !== undefined && { needsUser: j.needsUser }) })),
      pendingMerge: held.filter((h) => h.throwawayKey !== undefined).length,
      ...(this.storagePersisted !== undefined && { storagePersisted: this.storagePersisted }),
      backupStale: fp !== '' && fp !== meta?.backupFingerprint,
      ...(meta?.lastBackupAt !== undefined && { lastBackupAt: meta.lastBackupAt }),
      locked: this.ctx.deps.vault.locked(),
      pendingCalls: shown.map((c) => pendingCallView(c, this.ctx.deviceId)),
      ...(retries.length > 0 && { nextSettleAt: Math.min(...retries) }),
      unreconciled: calls.filter((c) => c.outcome === 'lookup_expired').length,
    }
    for (const s of this.subscribers) {
      try {
        s(this.snapshot)
      } catch {
        // an app subscriber that throws must not fail the commit that refreshed it
      }
    }
  }

  /** Re-reads the state now (another process changed the store, say). */
  reload(): Promise<WalletState> {
    return this.refreshState().then(() => this.snapshot)
  }

  // ---- holdings

  /**
   * The held bills (`includeSpent` for every row). `holdings.setExcludeFromMerge(id, on)`
   * keeps a bill out of every merge the wallet plans: merging tells the Hub
   * that the bills share an owner.
   */
  readonly holdings: ((o?: { includeSpent?: boolean }) => Promise<HoldingView[]>) & { setExcludeFromMerge(id: string, on: boolean): Promise<HoldingView> } = Object.assign(
    async (o: { includeSpent?: boolean } = {}): Promise<HoldingView[]> => {
      const now = this.ctx.nowSeconds()
      const rows = await this.ctx.read((t) => t.list('holdings'))
      const locked = await lockedHoldings(this.ctx)
      return rows.filter((h) => o.includeSpent === true || h.status === 'held').map((h) => holdingView(h, now, locked.has(h.id)))
    },
    {
      setExcludeFromMerge: async (id: string, on: boolean): Promise<HoldingView> => {
        const row = await this.ctx.commit(async (t) => {
          if ((await t.get('holdings', id)) === undefined) throw new CashkitError('not_found', `no holding ${id}`, { input: id })
          return updateHolding(t, id, (x) => {
            const { excludeFromMerge: _x, ...rest } = x
            return (on ? { ...rest, excludeFromMerge: true } : rest) as Holding
          })
        })
        return holdingView(row, this.ctx.nowSeconds())
      },
    },
  )

  /**
   * A holding's recovery string, `<token>` or `<token>#<secret>`
   * (`entryRecoveryString`). Secret-bearing: shown only when asked for.
   */
  async exportHolding(id: string): Promise<string> {
    const h = await this.ctx.read((t) => t.get('holdings', id))
    if (h === undefined) throw new CashkitError('not_found', `no holding ${id}`, { input: id })
    const secret = await this.ctx.openOpt(h.cashSecret)
    return secret !== undefined ? `${h.token}#${secret}` : h.token
  }

  // ---- money (§6.1–§6.4)

  /**
   * Settles every open call by `cash_lookup`: applies a lost reply, places
   * an unknown call again under its derived id, surfaces the rest. Then
   * re-reads every `redeeming` holding.
   */
  settle(): Promise<SettleReport> {
    return this.ctx.spend(async () => {
      const calls = await settleCalls(this.ctx)
      const redeems = await settleRedeeming(this.ctx).catch(() => ({ released: [], redeemed: [], spent: [], stillRedeeming: [] }))
      const joins = await settleJoins(this.ctx).catch(() => ({ joined: [], pending: [], needsUser: [] }))
      return { ...calls, redeems, joins }
    })
  }

  /** Pending calls: list them, close one, or confirm placing one again. */
  get pendingCalls(): {
    list(): Promise<PendingCallView[]>
    close(id: string): Promise<void>
    confirmReplace(id: string): Promise<void>
  } {
    const ctx = this.ctx
    return {
      list: async () => (await ctx.read((t) => t.list('pendingCalls'))).filter((c) => c.state !== 'done' || c.needsUser !== undefined).map((c) => pendingCallView(c, ctx.deviceId)),
      close: (id) => ctx.spend(() => closeByUser(ctx, id)),
      confirmReplace: (id) => ctx.spend(() => confirmReplace(ctx, id)),
    }
  }

  /**
   * The written-ahead secrets of calls whose outcome can no longer be
   * learned (`lookup_expired`): a bill one of them created may exist. Never
   * described as recoverable: there is no request id left to ask with.
   */
  async unreconciledSecrets(o: { includeSecrets?: boolean } = {}): Promise<{ pendingCallId: string; role: string; cashSecret?: string }[]> {
    const calls = (await this.ctx.read((t) => t.list('pendingCalls'))).filter((c) => c.outcome === 'lookup_expired')
    const out: { pendingCallId: string; role: string; cashSecret?: string }[] = []
    for (const c of calls) {
      for (const x of c.outputs) {
        if (x.destination.kind !== 'cash') continue
        out.push({ pendingCallId: c.id, role: x.role, ...(o.includeSecrets === true && { cashSecret: await this.ctx.open(x.destination.secret) }) })
      }
    }
    return out
  }

  /**
   * Runs `settle()` when a pending lookup asks to be retried
   * (`state.nextSettleAt`), and again while calls stay open. Returns the stop.
   */
  autoSettle(o: { setTimeout?: (fn: () => void, ms: number) => unknown; clearTimeout?: (h: unknown) => void; idleMs?: number } = {}): () => void {
    const set = o.setTimeout ?? ((fn: () => void, ms: number) => setTimeout(fn, ms))
    const clear = o.clearTimeout ?? ((h: unknown) => clearTimeout(h as ReturnType<typeof setTimeout>))
    let handle: unknown
    let stopped = false
    const schedule = () => {
      if (stopped) return
      const open = this.snapshot.pendingCalls.some((c) => c.state === 'sent' || c.state === 'prepared')
      if (!open) return
      const at = this.snapshot.nextSettleAt
      const delay = at !== undefined ? Math.max(at * 1000 - this.ctx.now(), 0) : (o.idleMs ?? 30_000)
      handle = set(() => {
        void this.settle()
          .catch(() => undefined)
          .then(() => this.refreshState())
          .then(schedule)
      }, delay)
    }
    // The discover outbox: publish each queued item once its time comes.
    let outbox: unknown
    let outboxAt: number | undefined
    const scheduleOutbox = () => {
      void nextOutboxDue(this.ctx).then((due) => {
        if (stopped || due === undefined || (outbox !== undefined && outboxAt === due)) return
        if (outbox !== undefined) clear(outbox)
        outboxAt = due
        outbox = set(() => {
          outbox = undefined
          outboxAt = undefined
          void publishDue(this.ctx)
            .catch(() => undefined)
            .then(scheduleOutbox)
        }, Math.max(due * 1000 - this.ctx.now(), 0))
      })
    }
    const unsub = this.subscribe(() => {
      if (handle === undefined) schedule()
      scheduleOutbox()
    })
    schedule()
    scheduleOutbox()
    return () => {
      stopped = true
      unsub()
      if (handle !== undefined) clear(handle)
      if (outbox !== undefined) clear(outbox)
    }
  }

  receive(input: string, o: { protect?: boolean } = {}): Promise<ReceiveResult> {
    return this.ctx.spend(() => receive(this.ctx, input, o))
  }

  async protect(o: { holdings?: readonly string[] } = {}): Promise<Report<ProtectOutcome>> {
    return this.ctx.spend(async () => {
      // Resolve any earlier rekey first, inside this lock (it is not re-entrant).
      await settleCalls(this.ctx).catch(() => undefined)
      const now = this.ctx.nowSeconds()
      const rs = await protectMany(this.ctx, o.holdings)
      return report<ProtectOutcome>(
        rs.map((r) =>
          r.secured.status === 'failed'
            ? {
                ok: false as const,
                error: new CashkitError(r.secured.unresolved === true ? 'indeterminate' : 'internal', r.secured.likelyWrongSecret === true ? 'the Hub did not recognise this cash secret' : 'protect failed', { input: r.holdingId }),
                holdingIds: [r.holdingId],
              }
            : { ok: true as const, holdingId: r.holdingId, secured: r.secured, holding: holdingView(r.holding, now) },
        ),
      )
    })
  }

  async planSend(o: SendInput): Promise<SendPlan> {
    await this.settle().catch(() => undefined)
    const plan = await planSend(this.ctx, o)
    this.ctx.emit({ op: 'send', phase: 'planned', id: this.ctx.newOpId('send') })
    return plan
  }
  executeSend(plan: SendPlan): Promise<SendResult> {
    return executeSend(this.ctx, plan)
  }
  async send(o: SendInput): Promise<SendResult> {
    return this.executeSend(await this.planSend(o))
  }

  /**
   * Mints over a stored Cash Hub connection (`connections.add` of its
   * `cashhub1`), as one pending call: a lost reply is settled by lookup, and
   * an `unknown` one waits for `pendingCalls.confirmReplace`.
   */
  mint(o: MintInput): Promise<MintResult> {
    return this.ctx.spend(() => mint(this.ctx, o))
  }

  async planRedeem(o: RedeemInput = {}): Promise<RedeemPlan> {
    await this.settle().catch(() => undefined)
    return planRedeem(this.ctx, o)
  }
  executeRedeem(plan: RedeemPlan): Promise<Report<RedeemOutcome>> {
    return executeRedeem(this.ctx, plan)
  }
  async redeem(o: RedeemInput = {}): Promise<Report<RedeemOutcome>> {
    return this.executeRedeem(await this.planRedeem(o))
  }

  async consolidate(o: { holdings?: readonly string[]; to?: string; ia?: string } = {}): Promise<ConsolidateReport> {
    await this.settle().catch(() => undefined)
    return consolidate(this.ctx, o)
  }

  status(o: { holdings?: readonly string[] } = {}): Promise<Report<StatusOutcome>> {
    return status(this.ctx, o)
  }

  // ---- reads (§6.5, §6.6)

  balance(o: { refresh?: boolean } = {}): Promise<Balance> {
    return balance(this.ctx, o)
  }
  activity(o: { refresh?: boolean; includeSecrets?: boolean; limit?: number; before?: number } = {}): Promise<ActivityItem[]> {
    return activity(this.ctx, o)
  }
  handoffs(o: { status?: readonly HandoffStatus[]; includeSecrets?: boolean; refresh?: boolean } = {}): Promise<HandoffView[]> {
    return listHandoffs(this.ctx, o)
  }

  // ---- backup (§10)

  /**
   * Every collection as a JSON text, each secret re-sealed under
   * `passphrase` (scrypt, NIP-49 parameters; XChaCha20-Poly1305). Store it
   * somewhere the browser cannot evict: it is how an unclaimed cash note
   * survives a cleared site.
   */
  exportBackup(passphrase: string, o: { logN?: number } = {}): Promise<string> {
    return exportBackup(this.ctx, passphrase, o)
  }

  /** Restores a backup into this (empty) wallet, then settles. */
  async importBackup(text: string, passphrase: string): Promise<ImportSummary> {
    const r = await this.ctx.spend(() => importBackup(this.ctx, text, passphrase))
    this.ctx.signerOverride = this.ctx.deps.signer
    await this.settle().catch(() => undefined)
    await this.refreshState()
    return r
  }

  // ---- circles, lightning, connections, identity, settings (§6.7–§6.9)

  /**
   * Discover (NIP-CASH §Listing Offers): offer listings ranked by the
   * user's follows and curators only; browsing contacts no Hub. A tap reads
   * the terms from the listed connection; an order or a join then runs over
   * the listed string.
   */
  readonly discover = {
    refresh: (o: DiscoverOptions): Promise<void> => refreshDiscover(this.ctx, o),
    list: (): DiscoverView => listDiscover(this.ctx),
    tap: (address: string, o: { timeoutMs?: number } = {}): Promise<TapView> => tapDiscover(this.ctx, address, o),
    /** After a tap showed the terms: an order over the listed `cashorder1`. */
    order: async (address: string, o: Omit<PlaceOrderInput, 'connection'>): Promise<OrderView> => {
      const c = listedConnection(this.ctx, address)
      if (c.type !== 'cash_order') throw new CashkitError('usage', 'this offer is a circle: join it', { input: address })
      return this.orders.place({ ...o, connection: c.connection })
    },
    /** After a tap showed the terms: a join over the listed `circlehub1`, private only. */
    join: async (address: string, terms: JoinTermsInput, o: JoinOptions = {}): Promise<JoinResult> => {
      const c = listedConnection(this.ctx, address)
      if (c.type !== 'circle_wallet') throw new CashkitError('usage', 'this offer sells cash: order from it', { input: address })
      return this.circles.join(c.connection, terms, o)
    },
    recommendPreview: (address: string) => recommendPreview(this.ctx, address),
    /** Queues a public recommendation of a used offer, published 1 to 6 hours later. */
    recommend: (address: string, o: { content: string; confirm?: (p: RecommendPreview) => Promise<boolean> }) => recommend(this.ctx, address, o),
    /** Queues a public report of a node or an offer (by address), naming the user as the reporter. */
    report: (target: string, o: { reason: ReportReason; content: string; confirm?: (p: ReportPreview) => Promise<boolean> }) => reportOffer(this.ctx, target, o),
    /** Publishes the deletion of the user's recommendation of `node` at once. */
    withdrawRecommendation: (node: string, o: { relays?: readonly string[]; confirm?: (p: { audience: { public: true }; node: string }) => Promise<boolean> } = {}) => withdrawRecommendation(this.ctx, node, o),
    outbox: {
      list: (): Promise<OutboxItem[]> => listOutbox(this.ctx),
      cancel: (id: string): Promise<void> => cancelOutbox(this.ctx, id),
      /** Publishes what is due; also run on open and by `autoSettle`. */
      publishDue: (): Promise<{ published: string[] }> => publishDue(this.ctx),
    },
    curators: {
      list: (): Promise<CuratorsView> => listCurators(this.ctx),
      add: (pubkey: string): Promise<CuratorsView> => editCurators(this.ctx, { add: pubkey }),
      remove: (pubkey: string): Promise<CuratorsView> => editCurators(this.ctx, { remove: pubkey }),
      /** An app's defaults, shown as curated by `sourceName`; ignored once the user has edited the list. */
      setDefaults: (o: { pubkeys: readonly string[]; sourceName?: string }): Promise<CuratorsView> => setDefaultCurators(this.ctx, o),
      publish: (o: { relays?: readonly string[] } = {}) => publishCurators(this.ctx, o),
      sync: (o: { relays?: readonly string[] } = {}): Promise<CuratorsView> => syncCurators(this.ctx, o),
    },
  }

  /**
   * The Cash Pocket (NIP-CP, with `WalletDeps.pocket`): the wallet's tokens
   * and calls in flight, gift-wrapped to the user. Every bill-creating call
   * and withdrawal is written ahead to it; `sync` imports and republishes.
   */
  readonly pocket = {
    sync: (): Promise<PocketSyncReport> => this.ctx.spend(() => syncPocket(this.ctx)),
    balance: (): Promise<Map<string, bigint>> => pocketBalanceOf(this.ctx),
    entries: () => pocketEntries(this.ctx),
  }

  /**
   * Cash Zaps (NIP-CZ): send a zap as a zap transfer whose 9522 is published
   * once its bill exists; list incoming zaps through rules 1–8 (shown as
   * issued, never received); claim one after rule 9; approve a minter.
   */
  readonly zaps = {
    send: (o: ZapInput): Promise<ZapSent> => this.ctx.spend(() => sendZap(this.ctx, o)),
    list: (o: { relays: readonly string[]; connectionKeys?: readonly string[] }): Promise<ZapView[]> => listZaps(this.ctx, o),
    claim: (event: NostrEvent): Promise<HoldingView> => this.ctx.spend(async () => holdingView(await claimZap(this.ctx, event), this.ctx.nowSeconds())),
    approveMinter: (minter: string, chain: string): Promise<{ readonly networkUnverifiable: true }> => approveMinter(this.ctx, minter, chain),
  }

  /**
   * On-chain withdrawals (NIP-CASH §Redeeming On-chain): quote a bill's
   * payout to an address, confirm, send, then follow the payout. Views never
   * carry the request id, `notify`, the quote, the receipt or secrets.
   */
  readonly withdraw = {
    terms: (holdingId: string): Promise<WithdrawTermsView> => withdrawTerms(this.ctx, holdingId),
    quote: (holdingId: string, address: string, o: { sendBefore?: number } = {}): Promise<WithdrawQuoteView> => quoteWithdrawal(this.ctx, holdingId, address, o),
    /** `confirm(view)` must resolve true: no confirmation, no withdrawal. */
    send: (quote: WithdrawQuoteView, o: { confirm?: (v: WithdrawQuoteView) => Promise<boolean> } = {}): Promise<WithdrawalView> => this.ctx.spend(() => sendWithdrawal(this.ctx, quote, o)),
    refresh: (id: string): Promise<WithdrawalView> => this.ctx.spend(() => refreshWithdrawal(this.ctx, id)),
    cancel: (id: string): Promise<WithdrawalView> => this.ctx.spend(() => cancelWithdrawal(this.ctx, id)),
    list: (): Promise<WithdrawalView[]> => listWithdrawals(this.ctx),
    get: async (id: string): Promise<WithdrawalView> => {
      const c = await this.ctx.read((t) => t.get('pendingCalls', id))
      if (c === undefined || c.kind !== 'withdraw') throw new CashkitError('not_found', `no withdrawal ${id}`, { input: id })
      return withdrawalView(c)
    },
    receipt: (id: string): Promise<string> => withdrawalReceipt(this.ctx, id),
    signedTx: (id: string): Promise<{ tx: string; txid: string; vout: number }> => signedTx(this.ctx, id),
    watch: (id: string, o: { signal?: AbortSignal; onUpdate?: (v: WithdrawalView) => void } = {}): Promise<() => void> => watchWithdrawal(this.ctx, id, o),
  }

  /**
   * Orders (NIP-CO): buy a bill from a Cash Hub through its `cashorder1`
   * Order connection, paid over Lightning or on-chain. Views never carry the
   * buyer key, a secret, `notify` or the request id.
   */
  readonly orders = {
    /** The terms, the fee, what to pay and the bill's redeem fee; nothing is written. */
    quote: (connection: string, o: { amountMillis: bigint; payment: Payment; confirmUnverified?: (v: HubView) => Promise<boolean> }): Promise<OrderQuote> => quoteOrder(this.ctx, connection, o),
    /** Places an order as one pending call; the view shows the invoice or address to pay. */
    place: (o: PlaceOrderInput): Promise<OrderView> => this.ctx.spend(() => placeOrder(this.ctx, o)),
    /** Reads an order with `cash_lookup`; new bills become holdings. */
    refresh: (id: string): Promise<OrderView> => this.ctx.spend(() => refreshOrder(this.ctx, id)),
    list: (): Promise<OrderView[]> => listOrders(this.ctx),
    get: async (id: string): Promise<OrderView> => {
      const c = await this.ctx.read((t) => t.get('pendingCalls', id))
      if (c === undefined || c.kind !== 'order') throw new CashkitError('not_found', `no order ${id}`, { input: id })
      return orderView(c)
    },
    /** Reads the order on each notice and, for Lightning, every 5 s until `pay_by`, while the app watches. Returns the stop. */
    watch: (id: string, o: { signal?: AbortSignal; pollMs?: number; onUpdate?: (v: OrderView) => void } = {}): Promise<() => void> => watchOrder(this.ctx, id, o),
  }

  /** Circles (NIP-CW): join over the private transport, list, member requests, notifications, delete. */
  readonly circles = {
    /**
     * Joins a circle through its `circlehub1` string, over the private
     * transport only; the join is written ahead and a lost reply is settled
     * by `settle()`'s join lookup.
     */
    join: (hub: string, terms: JoinTermsInput, o: JoinOptions = {}): Promise<JoinResult> => joinCircle(this.ctx, hub, terms, o),
    list: async (): Promise<CircleView[]> => {
      const rows = await this.ctx.read((t) => t.list('connections'))
      return rows.flatMap((c) => (c.kind === 'circle_wallet' && c.circle !== undefined && c.walletPubkey !== undefined ? [circleView(c as Parameters<typeof circleView>[0])] : []))
    },
    /** The member's own client for a Circle Wallet: budget, keysend, delete and the payment preview. */
    client: (name: string): Promise<CircleWalletClient> => circleWalletClient(this.ctx, name),
    /** A signed member request (`rotate`, `freeze`, `unfreeze`) for the host to submit; cashkit never sends it. */
    memberRequest: (name: string, action: MemberAction): Promise<NostrEvent> => memberRequest(this.ctx, name, action),
    /** Applies a NIP-47 notification the wallet's key received; returns what it means for the member. */
    notify: (name: string, n: CircleNotification): Promise<CircleAlert> => applyCircleNotification(this.ctx, name, n),
    /** Deletes a wallet holding at most dust, after `confirmDelete({dust})`; the dust goes to the host. */
    delete: (name: string, confirmDelete: (x: { dust: bigint }) => Promise<boolean>): Promise<void> => this.ctx.spend(() => deleteCircleWallet(this.ctx, name, confirmDelete)),
    /** The member's connection secret (of a stored wallet by name, or a pending join by its connection key), for a backup. */
    exportConnectionSecret: async (nameOrPendingJoin: string): Promise<string> => {
      this.ctx.requireUnlocked()
      const pj = await this.ctx.read((t) => t.get('pendingJoins', nameOrPendingJoin))
      if (pj !== undefined) return this.ctx.open(pj.connectionSecret)
      return this.ctx.open((await circleRow(this.ctx, nameOrPendingJoin)).secret)
    },
    /** Drops a pending join the member decided about (`needsUser`). */
    forgetJoin: (connectionPubkey: string): Promise<void> => this.ctx.commit((t) => t.delete('pendingJoins', connectionPubkey)),
  }

  /**
   * NIP-47 calls against a Lightning connection (default: the default one):
   * a NIP-47 URI or a Circle Wallet, never a Cash Hub connection.
   */
  async lightning(name?: string): Promise<Lightning> {
    const rows = await this.ctx.read((t) => t.list('connections'))
    const wallets = rows.filter(isLightning)
    const c = name !== undefined ? rows.find((r) => r.id === name) : (wallets.find((r) => r.isDefault) ?? wallets[0])
    if (c === undefined) throw new CashkitError('not_found', name !== undefined ? `no connection named "${name}"` : 'no wallet connection: add one first', name !== undefined ? { input: name } : {})
    const nwc = await nwcFor(this.ctx, c)
    if (c.kind === 'circle_wallet') {
      return {
        getInfo: () => nwc.getInfo(),
        getBalance: () => nwc.getBalance(),
        makeInvoice: (p) => {
          if (BigInt(p.amount) <= 0n) return Promise.reject(new CashkitError('invalid_input', 'a circle wallet invoice needs an amount above zero'))
          return nwc.makeInvoice(p)
        },
        payInvoice: (inv, amount) => nwc.payInvoice(inv, amount),
        listTransactions: (p) => nwc.listTransactions(p),
        signMessage: () => Promise.reject(new CashkitError('usage', 'a circle wallet connection does not sign messages')),
      }
    }
    return {
      getInfo: () => nwc.getInfo(),
      getBalance: () => nwc.getBalance(),
      makeInvoice: (p) => nwc.makeInvoice(p),
      payInvoice: (inv, amount) => nwc.payInvoice(inv, amount),
      listTransactions: (p) => nwc.listTransactions(p),
      signMessage: (m) => nwc.signMessage(m),
    }
  }

  readonly connections = {
    /**
     * Adds a NIP-47 wallet (a pairing URI) or a Cash Hub (`cashhub1…`). A
     * `cashhub1` string is decoded, verified and checked online first, and
     * stored as given; an unverified one only after `confirmUnverified`
     * resolved true. A Cash Hub is never the default Lightning wallet.
     */
    add: async (name: string, uri: string, o: { kind?: ConnectionKind; makeDefault?: boolean; confirmUnverified?: (view: HubView) => Promise<boolean> } = {}): Promise<ConnectionView> => {
      if (name.trim() === '') throw new CashkitError('usage', 'a connection needs a name')
      if (o.kind === 'cashhub' || sniff(uri.trim()) === 'cashhub') {
        const v = await verifyCashHubString(this.ctx, uri, o.confirmUnverified)
        const sealedConn = await this.ctx.seal(uri.trim())
        const now = this.ctx.nowSeconds()
        const row = await this.ctx.commit(async (t) => {
          if ((await t.get('connections', name)) !== undefined) throw new CashkitError('exists', `a connection named "${name}" already exists`, { input: name })
          const r: Connection = {
            id: name,
            kind: 'cashhub',
            connection: sealedConn,
            isDefault: false,
            hubIdentity: v.hubIdentity!,
            ...(v.chain !== undefined && { chain: v.chain }),
            verified: v.verified!,
            ...(v.confirmed && { confirmedUnverifiedAt: now }),
            ...(v.network !== undefined && { network: v.network }),
            version: 1,
          }
          await t.put('connections', r, 0)
          return r
        })
        return { name: row.id, kind: row.kind, isDefault: false, walletPubkey: v.walletPubkey, relays: v.relays, hubIdentity: row.hubIdentity!, ...(row.chain !== undefined && { chain: row.chain }), verified: row.verified!, ...(row.network !== undefined && { network: row.network }) }
      }
      if (sniff(uri.trim()) === 'circlehub') throw new CashkitError('usage', 'a circlehub1 string is joined, not added: use wallet.circles.join()', { input: name })
      if (o.kind !== undefined && o.kind !== 'nwc') throw new CashkitError('usage', `a pairing URI is added as kind nwc, not ${o.kind}`, { input: name })
      let pairing
      try {
        pairing = parsePairingURI(uri)
      } catch (err) {
        throw new CashkitError('invalid_input', (err as Error).message, { input: uri, cause: err })
      }
      const sealed = await this.ctx.seal(uri)
      const row = await this.ctx.commit(async (t) => {
        const conns = await t.list('connections')
        if (conns.some((c) => c.id === name)) throw new CashkitError('exists', `a connection named "${name}" already exists`, { input: name })
        const makeDefault = o.makeDefault === true || !conns.some(isLightning)
        if (makeDefault) for (const c of conns.filter((x) => x.isDefault)) await t.put('connections', { ...c, isDefault: false, version: c.version + 1 }, c.version)
        const r = { id: name, uri: sealed, kind: 'nwc' as const, isDefault: makeDefault, version: 1 }
        await t.put('connections', r, 0)
        return r
      })
      return { name: row.id, kind: row.kind, isDefault: row.isDefault, walletPubkey: pairing.walletPubkey, relays: pairing.relays }
    },
    list: async (): Promise<ConnectionView[]> => {
      const rows = await this.ctx.read((t) => t.list('connections'))
      return Promise.all(
        rows.map(async (c) => {
          if (c.kind === 'circle_wallet') {
            return { name: c.id, kind: c.kind, isDefault: c.isDefault, walletPubkey: c.walletPubkey ?? '', relays: c.relays ?? [], ...(c.lastKnownBalance !== undefined && { lastKnownBalance: c.lastKnownBalance }) }
          }
          if (c.uri === undefined) {
            const hc = decodeCashHubConnection(await this.ctx.open(c.connection!))
            return { name: c.id, kind: c.kind, isDefault: c.isDefault, walletPubkey: hc.walletPubkey, relays: hc.relays, hubIdentity: hc.hubIdentity, ...(c.chain !== undefined && { chain: c.chain }), verified: c.verified ?? false, ...(c.network !== undefined && { network: c.network }) }
          }
          const p = parsePairingURI(await this.ctx.open(c.uri))
          return { name: c.id, kind: c.kind, isDefault: c.isDefault, walletPubkey: p.walletPubkey, relays: p.relays, ...(c.lastKnownBalance !== undefined && { lastKnownBalance: c.lastKnownBalance }) }
        }),
      )
    },
    remove: async (name: string): Promise<void> => {
      await this.ctx.commit(async (t) => {
        const c = await t.get('connections', name)
        if (c === undefined) throw new CashkitError('not_found', `no connection named "${name}"`, { input: name })
        await t.delete('connections', name)
        if (c.isDefault) {
          const next = (await t.list('connections')).find(isLightning)
          if (next !== undefined) await t.put('connections', { ...next, isDefault: true, version: next.version + 1 }, next.version)
        }
      })
    },
    setDefault: async (name: string): Promise<void> => {
      await this.ctx.commit(async (t) => {
        const conns = await t.list('connections')
        if (!conns.some((c) => c.id === name)) throw new CashkitError('not_found', `no connection named "${name}"`, { input: name })
        if (!isLightning(conns.find((c) => c.id === name)!)) throw new CashkitError('usage', `"${name}" is a Cash Hub connection, not a Lightning wallet`, { input: name })
        for (const c of conns) {
          const isDefault = c.id === name
          if (c.isDefault !== isDefault) await t.put('connections', { ...c, isDefault, version: c.version + 1 }, c.version)
        }
      })
    },
  }

  readonly identity = {
    get: async (): Promise<IdentityView | undefined> => {
      const row = await this.ctx.read((t) => t.get('identity', 'self'))
      if (row === undefined) return undefined
      return { pubkey: row.pubkey, npub: encodeNpub(row.pubkey), source: row.source, ...(row.label !== undefined && { label: row.label }) }
    },
    /** A fresh local key, sealed by the vault. Refused when an identity exists. */
    generate: async (o: { label?: string } = {}): Promise<IdentityView> => {
      this.ctx.requireUnlocked()
      let priv: Uint8Array
      let signer: Signer
      for (;;) {
        priv = this.ctx.random(32)
        try {
          signer = localSigner(priv)
          break
        } catch {
          // out of range: draw again
        }
      }
      const sealed = await this.ctx.seal(toHex(priv))
      await this.ctx.commit(async (t) => {
        if ((await t.get('identity', 'self')) !== undefined) throw new CashkitError('exists', 'this wallet already has an identity')
        await t.put('identity', { id: 'self', source: 'local', pubkey: signer.pubkey, priv: sealed, ...(o.label !== undefined && { label: o.label }), version: 1 }, 0)
      })
      this.ctx.signerOverride = signer
      return { pubkey: signer.pubkey, npub: encodeNpub(signer.pubkey), source: 'local', ...(o.label !== undefined && { label: o.label }) }
    },
    /** Use an external signer (NIP-07, NIP-46) as the identity. */
    useSigner: async (signer: Signer): Promise<IdentityView> => {
      await this.ctx.commit(async (t) => {
        const cur = await t.get('identity', 'self')
        if (cur !== undefined && cur.pubkey !== signer.pubkey) throw new CashkitError('conflict', 'this wallet already has a different identity; bills bound to it would become unspendable')
        if (cur === undefined) await t.put('identity', { id: 'self', source: 'signer', pubkey: signer.pubkey, version: 1 }, 0)
      })
      this.ctx.signerOverride = signer
      return { pubkey: signer.pubkey, npub: encodeNpub(signer.pubkey), source: 'signer' }
    },
    /** The local key as an ncryptsec (NIP-49). Secret-bearing under the password. */
    export: async (password: string, o: { logN?: number } = {}): Promise<string> => {
      const row = await this.ctx.read((t) => t.get('identity', 'self'))
      if (row?.source !== 'local' || row.priv === undefined) throw new CashkitError('usage', 'only a local identity key can be exported; a signer keeps its own key')
      return nip49Encrypt(fromHex(await this.ctx.open(row.priv), 'identity key'), password, { ...(o.logN !== undefined && { logN: o.logN }), random: this.ctx.random })
    },
  }

  readonly settings = {
    get: (): Promise<Settings> => this.ctx.settings(),
    update: async (patch: Partial<Settings>): Promise<Settings> => {
      return this.ctx.commit(async (t) => {
        const cur = await t.get('settings', 'settings')
        const next = { id: 'settings', ...DEFAULT_SETTINGS, ...cur, ...patch, version: (cur?.version ?? 0) + 1 }
        await t.put('settings', next, cur?.version ?? 0)
        const { id: _i, version: _v, ...s } = next
        return s
      })
    },
  }
}
