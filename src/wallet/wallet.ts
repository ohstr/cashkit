// The wallet engine's public face (design §6). Every money-moving operation
// is plan, then execute; the one-call forms are execute(await plan(...)).
import { encodeNpub, fromHex, localSigner, nip49Encrypt, parsePairingURI, toHex, type Signer } from '../core/index.js'
import { NwcClient, type GetInfoResult, type MakeInvoiceParams } from '../client/index.js'
import { exportBackup, importBackup, valueFingerprint, type ImportSummary } from './backup.js'
import { joinCircle, type JoinInput, type JoinResult } from './circle.js'
import { consolidate, type ConsolidateReport } from './consolidate.js'
import { Ctx, type OperationEvent } from './context.js'
import { CashkitError } from './errors.js'
import { activity, balance, listHandoffs, type ActivityItem, type Balance, type HandoffView } from './feed.js'
import { newId } from './ledger.js'
import { DEFAULT_SETTINGS, SCHEMA_VERSION, type ConnectionKind, type HandoffStatus, type Settings } from './model.js'
import type { WalletDeps } from './ports.js'
import { executeRedeem, planRedeem, type RedeemInput, type RedeemOutcome, type RedeemPlan } from './redeem.js'
import { protectMany, receive, type ReceiveResult, type Secured } from './receive.js'
import { report, type Report } from './report.js'
import { executeSend, planSend, type SendInput, type SendPlan, type SendResult } from './send.js'
import { settle, type SettleReport } from './settle.js'
import { status, type StatusOutcome } from './status.js'
import { holdingView, type HoldingView } from './views.js'

export interface ConnectionView {
  readonly name: string
  readonly kind: ConnectionKind
  readonly isDefault: boolean
  readonly walletPubkey: string
  readonly relays: readonly string[]
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
}

export interface WalletState {
  readonly holdings: readonly HoldingView[]
  readonly balance: { readonly held: bigint; readonly count: number; readonly expired: bigint }
  readonly pendingJoins: readonly PendingJoinView[]
  /** Interrupted sends that may have created a cash note; its secret is in `unfinishedCashSends({ includeSecrets })`. */
  readonly unfinishedCashSends: readonly { readonly holdingId: string }[]
  /** Holdings moved for a merge that has not finished. */
  readonly pendingMerge: number
  /** Known only where the platform reports it (browsers). */
  readonly storagePersisted?: boolean
  /** Value-bearing changes since the last exportBackup (or none ever, with something to lose). */
  readonly backupStale: boolean
  readonly lastBackupAt?: number
  readonly locked: boolean
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

const EMPTY_STATE: WalletState = { holdings: [], balance: { held: 0n, count: 0, expired: 0n }, pendingJoins: [], unfinishedCashSends: [], pendingMerge: 0, backupStale: false, locked: false }

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
   * runs `settle()` so no write-ahead slot is left open. A settle that cannot
   * reach a Hub leaves its slots for the next call; open still succeeds.
   */
  static async open(deps: WalletDeps, o: { settle?: boolean } = {}): Promise<Wallet> {
    if (deps.storage === undefined || deps.vault === undefined) throw new CashkitError('usage', 'Wallet.open needs storage and a vault (vault-none must be chosen explicitly)')
    const ctx = new Ctx(deps)
    const random = ctx.random
    const meta = await ctx.commit(async (t) => {
      const m = await t.get('meta', 'meta')
      if (m !== undefined) return m
      const row = { id: 'meta', schemaVersion: SCHEMA_VERSION, walletId: newId('w', random).slice(2) + toHex(random(4)), version: 1 }
      await t.put('meta', row, 0)
      await t.put('settings', { id: 'settings', ...DEFAULT_SETTINGS, ...(deps.fallbackRelays !== undefined && { fallbackRelays: deps.fallbackRelays }), version: 1 }, 0)
      return row
    })
    if (meta.schemaVersion > SCHEMA_VERSION) throw new CashkitError('usage', `this wallet was written by a newer cashkit (schema ${meta.schemaVersion}); upgrade to open it`)
    ctx.walletId = meta.walletId
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
    const [rows, joins, meta] = await this.ctx.read(async (t) => [await t.list('holdings'), await t.list('pendingJoins'), await t.get('meta', 'meta')] as const)
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
      holdings: held.map((h) => holdingView(h, now)),
      balance: { held: sum, count, expired },
      pendingJoins: joins.map((j) => ({ connectionPubkey: j.id, hubPubkey: j.hubPubkey, hubLabel: j.hubLabel, name: j.name, at: j.at })),
      unfinishedCashSends: rows.filter((h) => h.pendingDestinationCashSecret !== undefined).map((h) => ({ holdingId: h.id })),
      pendingMerge: held.filter((h) => h.throwawayKey !== undefined || h.pendingThrowawayKey !== undefined).length,
      ...(this.storagePersisted !== undefined && { storagePersisted: this.storagePersisted }),
      backupStale: fp !== '' && fp !== meta?.backupFingerprint,
      ...(meta?.lastBackupAt !== undefined && { lastBackupAt: meta.lastBackupAt }),
      locked: this.ctx.deps.vault.locked(),
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

  async holdings(o: { includeSpent?: boolean } = {}): Promise<HoldingView[]> {
    const now = this.ctx.nowSeconds()
    const rows = await this.ctx.read((t) => t.list('holdings'))
    return rows.filter((h) => o.includeSpent === true || h.status === 'held').map((h) => holdingView(h, now))
  }

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

  /** Interrupted cash sends; with includeSecrets, the destination secret, the only copy. */
  async unfinishedCashSends(o: { includeSecrets?: boolean } = {}): Promise<{ holdingId: string; cashSecret?: string }[]> {
    const rows = (await this.ctx.read((t) => t.list('holdings'))).filter((h) => h.pendingDestinationCashSecret !== undefined)
    return Promise.all(rows.map(async (h) => ({ holdingId: h.id, ...(o.includeSecrets === true && { cashSecret: await this.ctx.open(h.pendingDestinationCashSecret!) }) })))
  }

  // ---- money (§6.1–§6.4)

  settle(): Promise<SettleReport> {
    return this.ctx.spend(() => settle(this.ctx))
  }

  receive(input: string, o: { protect?: boolean } = {}): Promise<ReceiveResult> {
    return this.ctx.spend(() => receive(this.ctx, input, o))
  }

  async protect(o: { holdings?: readonly string[] } = {}): Promise<Report<ProtectOutcome>> {
    return this.ctx.spend(async () => {
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

  joinCircle(o: JoinInput): Promise<JoinResult> {
    return joinCircle(this.ctx, o)
  }

  /** NIP-47 calls against a registered connection (default: the default one). */
  async lightning(name?: string): Promise<Lightning> {
    const rows = await this.ctx.read((t) => t.list('connections'))
    const c = name !== undefined ? rows.find((r) => r.id === name) : (rows.find((r) => r.isDefault) ?? rows[0])
    if (c === undefined) throw new CashkitError('not_found', name !== undefined ? `no connection named "${name}"` : 'no wallet connection: add one first', name !== undefined ? { input: name } : {})
    const nwc = new NwcClient(this.ctx.clientDeps, await this.ctx.open(c.uri))
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
    add: async (name: string, uri: string, o: { kind?: ConnectionKind; makeDefault?: boolean } = {}): Promise<ConnectionView> => {
      if (name.trim() === '') throw new CashkitError('usage', 'a connection needs a name')
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
        const makeDefault = o.makeDefault === true || conns.length === 0
        if (makeDefault) for (const c of conns.filter((x) => x.isDefault)) await t.put('connections', { ...c, isDefault: false, version: c.version + 1 }, c.version)
        const r = { id: name, uri: sealed, kind: o.kind ?? ('nwc' as const), isDefault: makeDefault, version: 1 }
        await t.put('connections', r, 0)
        return r
      })
      return { name: row.id, kind: row.kind, isDefault: row.isDefault, walletPubkey: pairing.walletPubkey, relays: pairing.relays }
    },
    list: async (): Promise<ConnectionView[]> => {
      const rows = await this.ctx.read((t) => t.list('connections'))
      return Promise.all(
        rows.map(async (c) => {
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
          const next = (await t.list('connections'))[0]
          if (next !== undefined) await t.put('connections', { ...next, isDefault: true, version: next.version + 1 }, next.version)
        }
      })
    },
    setDefault: async (name: string): Promise<void> => {
      await this.ctx.commit(async (t) => {
        const conns = await t.list('connections')
        if (!conns.some((c) => c.id === name)) throw new CashkitError('not_found', `no connection named "${name}"`, { input: name })
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
