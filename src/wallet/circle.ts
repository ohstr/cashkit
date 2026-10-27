// Circles (design §6.7, NIP-CW): joining over the private transport only,
// with the join written ahead and settled by a join lookup when its reply is
// lost; the member's Circle Wallet as fields and its own secret (never a
// URI); member requests and the notifications that move a wallet's key.
import {
  buildMemberRequest,
  connectionKeyFromSecret,
  decodeLookupDone,
  isRenewal,
  parseCreateCircleWalletResult,
  sniff,
  toHex,
  validateJoinTerms,
  type CashLookupResult,
  type CircleWalletDetails,
  type JoinTerms,
  type MemberAction,
  type NostrEvent,
  type Renewal,
  type Signer,
} from '../core/index.js'
import { CircleWalletClient, ClientError, connectCircle, inspectConnection, NwcClient, WalletError, type CircleHub, type ConnectCircleOptions, type HubView, type TypedOutcome } from '../client/index.js'
import { validateRequestedAmount } from './amounts.js'
import type { Ctx } from './context.js'
import { unverifiedAnswer } from './confirm.js'
import { CashkitError, fromWalletError } from './errors.js'
import { appendActivity } from './ledger.js'
import type { CircleDetailsRow, Connection, PendingJoin, Sealed } from './model.js'

export interface JoinTermsInput {
  /** Send cap per budget period, in milli-units. */
  readonly maxAmount: bigint
  /** Receive cap per budget period, in milli-units. */
  readonly maxReceive: bigint
  /** Lifetime in seconds; 0 or omitted lets the Hub choose its default. */
  readonly expirySeconds?: number
  readonly budgetRenewal?: Renewal
}

export interface JoinOptions {
  readonly name?: string
  readonly makeDefault?: boolean
  /** Asked once for a `circlehub1` whose signature does not verify. */
  readonly confirmUnverified?: (view: HubView) => Promise<boolean>
  /**
   * Asked before anything is signed when the Hub cannot rotate a wallet to a
   * new key: losing the connection secret then makes the balance
   * unreachable. Resolve true to join anyway; back the secret up with
   * `circles.exportConnectionSecret` after.
   */
  readonly confirmNoRecovery?: () => Promise<boolean>
}

/** Carries no secret and no connection string. */
export interface JoinResult {
  readonly name: string
  readonly isDefault: boolean
  readonly walletPubkey: string
  readonly relays: readonly string[]
  readonly connectionPubkey: string
  readonly expiresAt: number
  readonly maxAmount: bigint
  readonly maxReceive: bigint
  readonly feesPpm: number
  readonly dustThresholdMillis: bigint
  readonly budgetRenewal: string
  /** Whether the wallet can be moved to a new key if its secret is lost. */
  readonly rotatable: boolean
  readonly network?: string
  readonly testNetwork: boolean
  /** Required terms the details did not carry; shown as unknown. */
  readonly missingTerms: readonly string[]
}

export interface CircleView {
  readonly name: string
  readonly hubPubkey: string
  readonly hubLabel: string
  readonly walletPubkey: string
  readonly connectionPubkey: string
  readonly maxAmount: bigint
  readonly maxReceive: bigint
  readonly expiresAt: number
  readonly feesPpm: number
  readonly dustThresholdMillis: bigint
  readonly budgetRenewal: string
  /** From the join's details, never from the Hub's current `get_info`. */
  readonly rotatable: boolean
  readonly frozen: boolean
  /** The key moved to one this device does not hold: recover on the device that does. */
  readonly moved: boolean
  readonly rotation?: { readonly newConnectionPubkey: string; readonly completesAt?: number }
}

/** A connection-layer failure, as the wallet reports it; nothing was signed or sent. */
function connectError(err: unknown): CashkitError {
  if (err instanceof CashkitError) return err
  if (err instanceof WalletError) return fromWalletError(err)
  if (err instanceof ClientError) {
    switch (err.code) {
      case 'connection_invalid':
      case 'connection_mismatch':
        return new CashkitError('invalid_input', err.message, { reason: err.code, cause: err })
      case 'connection_unverified':
      case 'not_accepting':
        return new CashkitError('auth', err.message, { reason: err.code, cause: err })
      case 'join_unavailable':
        return new CashkitError('network', err.message, { reason: err.code, cause: err })
      default:
        return new CashkitError('network', `the Circle Wallet Hub could not be reached, so nothing was sent: ${err.message}`, { cause: err })
    }
  }
  return new CashkitError('internal', (err as Error).message, { cause: err })
}

async function connect(ctx: Ctx, hub: string, o: ConnectCircleOptions): Promise<CircleHub> {
  try {
    return await connectCircle(ctx.clientDeps, hub, o)
  } catch (err) {
    throw connectError(err)
  }
}

/** `SuggestName`: the label slugged, else "circle", made unique. */
export function suggestName(taken: readonly string[], base: string, label: string): string {
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
  const root = slug !== '' ? slug : base
  if (!taken.includes(root)) return root
  for (let i = 2; ; i++) if (!taken.includes(`${root}-${i}`)) return `${root}-${i}`
}

function newConnectionKey(ctx: Ctx) {
  for (;;) {
    try {
      return connectionKeyFromSecret(toHex(ctx.random(32)))
    } catch {
      // an out-of-range draw
    }
  }
}

function termsOf(t: JoinTermsInput): JoinTerms {
  validateRequestedAmount(t.maxAmount, 'maxAmount')
  if (t.maxReceive < 0n) throw new CashkitError('invalid_input', 'maxReceive cannot be negative')
  if (t.budgetRenewal !== undefined && !isRenewal(t.budgetRenewal)) throw new CashkitError('invalid_input', `budgetRenewal must be one of daily, weekly, monthly, yearly, never`)
  return { maxAmount: t.maxAmount, maxReceive: t.maxReceive, ...(t.expirySeconds !== undefined && { expiry: t.expirySeconds }), ...(t.budgetRenewal !== undefined && { budgetRenewal: t.budgetRenewal }) }
}

/**
 * Adds the member's Circle Wallet and drops its pending join, in one
 * transaction. `hubConnection` is the string the answer came through when
 * it was not the join's own.
 */
async function addCircleWallet(ctx: Ctx, pj: PendingJoin, d: CircleWalletDetails, hubIdentity: string, hubConnection: Sealed = pj.hubConnection): Promise<{ row: Connection; isDefault: boolean }> {
  return ctx.commit(async (t) => {
    const conns = await t.list('connections')
    const lightning = conns.filter(isLightning)
    let name = pj.name
    if (conns.some((c) => c.id === name)) name = suggestName(conns.map((c) => c.id), 'circle', pj.hubLabel)
    const makeDefault = pj.makeDefault || lightning.length === 0
    if (makeDefault) for (const c of conns.filter((x) => x.isDefault)) await t.put('connections', { ...c, isDefault: false, version: c.version + 1 }, c.version)
    const circle: CircleDetailsRow = {
      hubPubkey: pj.hubPubkey,
      hubIdentity,
      hubLabel: pj.hubLabel,
      hubConnection,
      memberPubkey: pj.signerPubkey,
      connectionPubkey: pj.id,
      maxAmount: d.maxAmount,
      maxReceive: d.maxReceive,
      expiresAt: d.expiresAt,
      feesPpm: d.feesPpm,
      dustThresholdMillis: d.dustThresholdMillis,
      ...(d.rotationDelaySecs !== undefined && { rotationDelaySecs: d.rotationDelaySecs }),
      budgetRenewal: d.budgetRenewal,
      createdAt: pj.proofCreatedAt,
    }
    const row: Connection = { id: name, kind: 'circle_wallet', isDefault: makeDefault, walletPubkey: d.walletPubkey, relays: d.relays, secret: pj.connectionSecret, circle, version: 1 }
    await t.put('connections', row, 0)
    await t.delete('pendingJoins', pj.id)
    await appendActivity(t, ctx.now(), { action: 'join', circle: pj.hubLabel !== '' ? pj.hubLabel : pj.hubPubkey, connection: name })
    return { row, isDefault: makeDefault }
  })
}

function joinResult(row: Connection, d: CircleWalletDetails, hub: CircleHub | undefined): JoinResult {
  const network = hub?.view().network
  return {
    name: row.id,
    isDefault: row.isDefault,
    walletPubkey: d.walletPubkey,
    relays: d.relays,
    connectionPubkey: d.connectionPubkey,
    expiresAt: d.expiresAt,
    maxAmount: d.maxAmount,
    maxReceive: d.maxReceive,
    feesPpm: d.feesPpm,
    dustThresholdMillis: d.dustThresholdMillis,
    budgetRenewal: d.budgetRenewal,
    rotatable: d.rotationDelaySecs !== undefined,
    ...(network !== undefined && { network }),
    testNetwork: hub?.view().testNetwork ?? false,
    missingTerms: d.missingTerms,
  }
}

const pendingJoinError = (id: string, cause?: unknown) =>
  new CashkitError('indeterminate', `the join got no decided answer, so whether the wallet was made is unknown; settle() looks it up (pending join ${id})`, { reason: 'join_pending', ...(cause !== undefined && { cause }) })

/**
 * Joins a circle through its `circlehub1` string, over the private
 * transport only. The connection key is generated here and only its pubkey
 * leaves the device; the join is written ahead (deadline = proof
 * `created_at` + 300) before it is sent. A refusal is final for that proof
 * (a retry signs a new one with a new key); `REQUEST_REUSED` or a lost reply
 * leaves the join pending for `settle()`'s lookup.
 */
export async function joinCircle(ctx: Ctx, hubString: string, t: JoinTermsInput, o: JoinOptions = {}): Promise<JoinResult> {
  const kind = sniff(hubString.trim())
  if (kind === 'cashhub' || kind === 'cashorder') throw new CashkitError('invalid_input', 'that is a Cash Hub or Order connection, not a Circle Wallet Hub: a circle is joined through its circlehub1 string', { reason: 'connection_invalid' })
  if (kind !== 'circlehub') throw new CashkitError('invalid_input', 'not a circlehub1 connection string', { reason: 'connection_invalid' })
  const terms = termsOf(t)
  const signer = await ctx.requireSigner()
  const hub = await connect(ctx, hubString, { confirmUnverified: unverifiedAnswer(ctx.confirmations, o.confirmUnverified), purpose: 'join' })
  const over = validateJoinTerms(hub.circle, terms)
  if (over !== undefined) throw new CashkitError('invalid_input', `${over} is over this circle's limits`, { reason: 'limit_exceeded', input: over })
  const noRecovery = o.confirmNoRecovery ?? (() => ctx.confirmations.ask({ type: 'confirmNoRecovery', view: hub.view() }))
  if (hub.circle.rotation_delay_secs === undefined && !(await noRecovery())) {
    throw new CashkitError('usage', 'this circle cannot move a wallet to a new key: losing its connection secret would make the balance unreachable, and that was not confirmed', { reason: 'no_recovery_unconfirmed' })
  }
  const hubPubkey = hub.connection.walletPubkey
  return ctx.spend(async () => {
    const opId = ctx.newOpId('join')
    const [conns, joins] = await ctx.read(async (x) => [await x.list('connections'), await x.list('pendingJoins')] as const)
    if (conns.some((c) => c.circle?.hubPubkey === hubPubkey)) throw new CashkitError('exists', 'you already hold a wallet in this circle', { reason: 'wallet_exists' })
    if (joins.some((j) => j.hubPubkey === hubPubkey && j.needsUser === undefined)) throw new CashkitError('conflict', 'a join to this circle is still pending; settle() resolves it', { reason: 'join_pending' })
    const name = o.name ?? suggestName(conns.map((c) => c.id), 'circle', hub.connection.label)
    if (conns.some((c) => c.id === name)) throw new CashkitError('exists', `a connection named "${name}" already exists`, { input: name })
    const key = newConnectionKey(ctx)
    const prepared = await hub.prepareJoin(signer, key.pubkey, terms)
    const pj: PendingJoin = {
      id: key.pubkey,
      connectionSecret: await ctx.seal(key.secret),
      hubPubkey,
      hubLabel: hub.connection.label,
      hubConnection: await ctx.seal(hubString.trim()),
      signerPubkey: signer.pubkey,
      name,
      makeDefault: o.makeDefault === true,
      proofCreatedAt: prepared.createdAt,
      deadline: prepared.deadline,
      terms: { maxAmount: terms.maxAmount, maxReceive: terms.maxReceive, expiry: terms.expiry ?? 0, budgetRenewal: terms.budgetRenewal ?? 'never' },
      device: ctx.deviceId,
      sent: false,
      at: ctx.now(),
      version: 1,
    }
    await ctx.commit((x) => x.put('pendingJoins', pj, 0))
    const markSent = () => ctx.commit(async (x) => {
      const cur = await x.get('pendingJoins', pj.id)
      if (cur !== undefined) await x.put('pendingJoins', { ...cur, sent: true, version: cur.version + 1 }, cur.version)
    })
    const drop = () => ctx.commit((x) => x.delete('pendingJoins', pj.id)).catch(() => undefined)
    ctx.emit({ op: 'join', phase: 'sent', id: opId })
    let r
    try {
      r = await hub.join(signer, prepared, terms, { beforePublish: markSent })
    } catch (err) {
      ctx.emit({ op: 'join', phase: 'failed', id: opId })
      const cur = await ctx.read((x) => x.get('pendingJoins', pj.id))
      if (cur?.sent !== true) {
        await drop()
        throw connectError(err)
      }
      throw pendingJoinError(pj.id, err)
    }
    const out = r.outcomes[0]
    if (out?.state === 'result' && out.value !== undefined) {
      let saved
      try {
        saved = await addCircleWallet(ctx, pj, out.value, hub.connection.hubIdentity)
      } catch (err) {
        throw new CashkitError('internal', 'your new circle wallet was made but could not be saved; settle() saves it from the join lookup', {
          cause: err,
          recovery: `Wallet ${out.value.walletPubkey} on relays ${out.value.relays.join(', ')}; its secret is the pending join's connection secret (circles.exportConnectionSecret("${pj.id}")).`,
          recoveryHandoffs: [out.value.walletPubkey, ...out.value.relays],
        })
      }
      ctx.emit({ op: 'join', phase: 'committed', id: opId })
      return joinResult(saved.row, out.value, hub)
    }
    ctx.emit({ op: 'join', phase: 'failed', id: opId })
    if (out?.state === 'error' && out.error !== undefined && out.error.code !== 'REQUEST_REUSED') {
      // Every join code but REQUEST_REUSED is final for this proof: nothing was made.
      await drop()
      if (out.error.code === 'NOT_SENT') throw new CashkitError('network', 'the join was not sent, so nothing was made', { nwcCode: out.error.code })
      throw fromWalletError(new WalletError('create_circle_wallet', out.error.code, out.error.message ?? ''))
    }
    throw pendingJoinError(pj.id)
  })
}

export interface SettleJoinsReport {
  readonly joined: readonly string[]
  readonly pending: readonly string[]
  readonly needsUser: readonly string[]
}

/** A join lookup sent through one `circlehub1`: the connected Hub, its answer (undefined when none came) and the string, sealed. */
interface Looked {
  readonly hub: CircleHub
  readonly o: TypedOutcome<CashLookupResult> | undefined
  readonly via: Sealed
}

/** Connects through `via` for a lookup and looks the join up; undefined when no verified announcement was found (nothing sent). */
async function lookupThrough(ctx: Ctx, via: Sealed, signer: Signer, pj: PendingJoin): Promise<Looked | undefined> {
  let hub: CircleHub
  try {
    hub = await connectCircle(ctx.clientDeps, await ctx.open(via), { purpose: 'lookup', confirmUnverified: () => Promise.resolve(true) })
  } catch {
    return undefined
  }
  try {
    return { hub, o: await hub.lookupJoin(signer, pj.id, pj.deadline), via }
  } catch {
    return { hub, o: undefined, via }
  }
}

/** Whether a lookup was answered: a status, or `UNAUTHORIZED` (final for that lookup). Anything else counts as an omission. */
const answered = (r: Looked | undefined): boolean => (r?.o?.state === 'result' && r.o.value !== undefined) || (r?.o?.state === 'error' && r.o.error?.code === 'UNAUTHORIZED')

/** Another held `circlehub1` (added with `connections.add`) naming the join's Hub pubkey, sealed; undefined when there is none. */
async function otherHubString(ctx: Ctx, pj: PendingJoin): Promise<Sealed | undefined> {
  const own = (await ctx.open(pj.hubConnection)).trim()
  const rows = await ctx.read((t) => t.list('connections'))
  for (const c of rows) {
    if (c.kind !== 'circlehub' || c.walletPubkey !== pj.hubPubkey || c.connection === undefined) continue
    if ((await ctx.open(c.connection)).trim() !== own) return c.connection
  }
  return undefined
}

/**
 * Looks every pending join of this device up, by its connection key and
 * exact deadline, signed by the join's `pubkey`, through the string the join
 * used: `done` adds the wallet; `pending` waits; `unknown` asks the member
 * (they may join again, with a new proof and key); `expired` is shown and
 * never rejoined with that key; an `UNAUTHORIZED` answer is final for that
 * lookup. Omissions are counted. Past the deadline plus 360 s (the join's
 * string may have been revoked), one lookup goes through another held
 * `circlehub1` of the same Hub pubkey, if there is one; a join still
 * unanswered then is shown as unanswered.
 */
export async function settleJoins(ctx: Ctx): Promise<SettleJoinsReport> {
  const joins = (await ctx.read((t) => t.list('pendingJoins'))).filter((j) => j.needsUser === undefined && j.device === ctx.deviceId)
  const joined: string[] = []
  const pending: string[] = []
  const needsUser: string[] = []
  if (joins.length === 0) return { joined, pending, needsUser }
  const signer = await ctx.signer()
  for (const pj of joins) {
    const now = ctx.nowSeconds()
    if (!pj.sent) {
      await ctx.commit((t) => t.delete('pendingJoins', pj.id)).catch(() => undefined)
      continue
    }
    if (signer === undefined || signer.pubkey !== pj.signerPubkey || (pj.lookup?.retryAfter !== undefined && now < pj.lookup.retryAfter)) {
      pending.push(pj.id)
      continue
    }
    const set = (f: (x: PendingJoin) => PendingJoin) =>
      ctx.commit(async (t) => {
        const cur = await t.get('pendingJoins', pj.id)
        if (cur !== undefined) await t.put('pendingJoins', { ...f(cur), version: cur.version + 1 }, cur.version)
      })
    const late = now > pj.deadline + 360
    let r = await lookupThrough(ctx, pj.hubConnection, signer, pj)
    let viaOther = pj.lookup?.viaOther === true
    if (!answered(r) && late && !viaOther) {
      const other = await otherHubString(ctx, pj)
      if (other !== undefined) {
        viaOther = true
        await set((x) => ({ ...x, lookup: { omissions: x.lookup?.omissions ?? 0, viaOther: true } }))
        const r2 = await lookupThrough(ctx, other, signer, pj)
        if (r2 !== undefined) r = r2
      }
    }
    if (r === undefined) {
      // No verified announcement: the lookup is not sent and the join stays open.
      pending.push(pj.id)
      continue
    }
    const { o } = r
    const v = o?.state === 'result' ? o.value : undefined
    if (v?.status === 'done') {
      const d = await parseCreateCircleWalletResult(decodeLookupDone(v.result).result, { signer, hubPubkey: pj.hubPubkey, connectionPubkey: pj.id })
      await addCircleWallet(ctx, pj, d, r.hub.connection.hubIdentity, r.via)
      joined.push(pj.id)
    } else if (v?.status === 'pending') {
      await set((x) => ({ ...x, lookup: { omissions: x.lookup?.omissions ?? 0, retryAfter: v.retryAfter, ...(viaOther && { viaOther }) } }))
      pending.push(pj.id)
    } else if (v?.status === 'unknown' || v?.status === 'expired') {
      await set((x) => ({ ...x, needsUser: v.status === 'unknown' ? 'join_not_made' : 'lookup_expired' }))
      needsUser.push(pj.id)
    } else if (o?.state === 'error' && o.error?.code === 'UNAUTHORIZED') {
      await set((x) => ({ ...x, needsUser: 'auth' }))
      needsUser.push(pj.id)
    } else {
      const omissions = (pj.lookup?.omissions ?? 0) + 1
      await set((x) => ({ ...x, lookup: { omissions, ...(viaOther && { viaOther }) }, ...(late && { needsUser: 'lookup_unanswered' as const }) }))
      ;(late ? needsUser : pending).push(pj.id)
    }
  }
  return { joined, pending, needsUser }
}

export interface RecoverOptions {
  /** The name for a wallet this device does not hold yet (default: from the circle's label). */
  readonly name?: string
  readonly makeDefault?: boolean
  /** Asked once for a `circlehub1` whose signature does not verify. */
  readonly confirmUnverified?: (view: HubView) => Promise<boolean>
}

/**
 * What `circles.recover` found: the wallet, now held under the new key; a
 * rotation still pending (ask again at `retryAt`, its `completes_at`); or no
 * rotation to that key (`not_found`).
 */
export type RecoverResult =
  | { readonly state: 'done'; readonly wallet: JoinResult }
  | { readonly state: 'pending'; readonly retryAt: number }
  | { readonly state: 'not_found' }

/**
 * Recovers a Circle Wallet on the device that holds the key a rotation moved
 * it to (NIP-CW §Recovering a Lost Connection): a join lookup through the
 * circle's `circlehub1`, signed by the member's identity (the join's
 * `pubkey`), naming the new key. Its deadline is a second in the past, so a
 * Hub with no rotation to that key answers `unknown` at once. `done` is
 * checked as a join reply (its `connection_pubkey` must be the new key) and
 * the wallet is stored with the new key's secret: in place of the moved
 * connection when this device holds one, else as a new connection.
 */
export async function recoverCircle(ctx: Ctx, hubString: string, newConnectionSecret: string, o: RecoverOptions = {}): Promise<RecoverResult> {
  if (sniff(hubString.trim()) !== 'circlehub') throw new CashkitError('invalid_input', 'not a circlehub1 connection string', { reason: 'connection_invalid' })
  let key
  try {
    key = connectionKeyFromSecret(newConnectionSecret.trim())
  } catch (err) {
    throw new CashkitError('invalid_input', `the new connection secret is not a valid key: ${(err as Error).message}`, { cause: err })
  }
  const signer = await ctx.requireSigner()
  const hub = await connect(ctx, hubString, { confirmUnverified: unverifiedAnswer(ctx.confirmations, o.confirmUnverified), purpose: 'lookup' })
  const hubPubkey = hub.connection.walletPubkey
  let out
  try {
    out = await hub.lookupJoin(signer, key.pubkey, ctx.nowSeconds() - 1)
  } catch (err) {
    throw connectError(err)
  }
  if (out.state === 'error' && out.error !== undefined) throw fromWalletError(new WalletError('cash_lookup', out.error.code, out.error.message ?? ''))
  const v = out.state === 'result' ? out.value : undefined
  if (v === undefined) throw new CashkitError('network', 'the Hub did not answer the recovery lookup; nothing changed, so asking again is safe', { reason: 'lookup_unanswered' })
  if (v.status === 'pending') return { state: 'pending', retryAt: v.retryAfter ?? ctx.nowSeconds() }
  if (v.status !== 'done') return { state: 'not_found' }
  let d: CircleWalletDetails
  try {
    d = await parseCreateCircleWalletResult(decodeLookupDone(v.result).result, { signer, hubPubkey, connectionPubkey: key.pubkey })
  } catch (err) {
    throw new CashkitError('invalid_input', `the recovered wallet details do not check out: ${(err as Error).message}`, { reason: 'lookup_undecodable', cause: err })
  }
  const secret = await ctx.seal(key.secret)
  const hubConnection = await ctx.seal(hubString.trim())
  const row = await ctx.commit(async (t) => {
    const conns = await t.list('connections')
    // The same wallet held here takes the new key; another wallet of this circle (another identity's, or an older one) stays as it is.
    const held = conns.find((c) => c.kind === 'circle_wallet' && c.circle?.hubPubkey === hubPubkey && c.walletPubkey === d.walletPubkey)
    if (held !== undefined) {
      const { rotation: _r, frozen: _f, moved: _m, ...rest } = held
      const next: Connection = { ...rest, secret, relays: d.relays, circle: { ...held.circle!, connectionPubkey: key.pubkey }, version: held.version + 1 }
      await t.put('connections', next, held.version)
      return next
    }
    const name = o.name ?? suggestName(conns.map((c) => c.id), 'circle', hub.connection.label)
    if (conns.some((c) => c.id === name)) throw new CashkitError('exists', `a connection named "${name}" already exists`, { input: name })
    const makeDefault = o.makeDefault === true || !conns.some(isLightning)
    if (makeDefault) for (const c of conns.filter((x) => x.isDefault)) await t.put('connections', { ...c, isDefault: false, version: c.version + 1 }, c.version)
    const circle: CircleDetailsRow = {
      hubPubkey,
      hubIdentity: hub.connection.hubIdentity,
      hubLabel: hub.connection.label,
      hubConnection,
      memberPubkey: signer.pubkey,
      connectionPubkey: key.pubkey,
      maxAmount: d.maxAmount,
      maxReceive: d.maxReceive,
      expiresAt: d.expiresAt,
      feesPpm: d.feesPpm,
      dustThresholdMillis: d.dustThresholdMillis,
      ...(d.rotationDelaySecs !== undefined && { rotationDelaySecs: d.rotationDelaySecs }),
      budgetRenewal: d.budgetRenewal,
      // The join's own proof time is not in the details: this is when this device took the wallet.
      createdAt: ctx.nowSeconds(),
    }
    const r: Connection = { id: name, kind: 'circle_wallet', isDefault: makeDefault, walletPubkey: d.walletPubkey, relays: d.relays, secret, circle, version: 1 }
    await t.put('connections', r, 0)
    return r
  })
  return { state: 'done', wallet: joinResult(row, d, hub) }
}

/**
 * Checks a `circlehub1` string for `connections.add`: decoded (a URI or any
 * other form is `connection_invalid`), its signature checked, its Hub's
 * `get_info` read and matched with TLV 4 and TLV 6 (`connection_mismatch`),
 * and an unverified one confirmed (`connection_unverified`). Nothing is
 * signed, sent or joined: a held string serves the lookups of a join made
 * through another string of the same circle.
 */
export async function verifyCircleHubString(ctx: Ctx, value: string, confirmUnverified?: (v: HubView) => Promise<boolean>): Promise<{ view: HubView; hubPubkey: string; confirmed: boolean }> {
  const s = value.trim()
  if (sniff(s) !== 'circlehub') throw new CashkitError('invalid_input', 'not a circlehub1 connection string (a URI form is never accepted)', { reason: 'connection_invalid' })
  let view: HubView
  try {
    view = await inspectConnection(ctx.clientDeps, s, { online: true })
  } catch (err) {
    throw connectError(err)
  }
  if (view.online !== 'pass') throw new CashkitError('invalid_input', "this Circle Wallet Hub's get_info does not match its connection string", { reason: 'connection_mismatch' })
  if (!view.verified && (confirmUnverified === undefined || !(await confirmUnverified(view)))) {
    throw new CashkitError('auth', "this connection string's signature does not verify, and it was not confirmed", { reason: 'connection_unverified' })
  }
  return { view, hubPubkey: view.connectionPubkey, confirmed: !view.verified }
}

/** A stored Circle Wallet connection by name. */
export async function circleRow(ctx: Ctx, name: string): Promise<Connection & { circle: CircleDetailsRow; secret: Sealed; walletPubkey: string; relays: readonly string[] }> {
  const c = await ctx.read((t) => t.get('connections', name))
  if (c === undefined) throw new CashkitError('not_found', `no connection named "${name}"`, { input: name })
  if (c.kind !== 'circle_wallet' || c.circle === undefined || c.secret === undefined || c.walletPubkey === undefined || c.relays === undefined) throw new CashkitError('usage', `"${name}" is not a circle wallet`, { input: name })
  return c as Connection & { circle: CircleDetailsRow; secret: Sealed; walletPubkey: string; relays: readonly string[] }
}

/** The member's own client for a stored Circle Wallet. A frozen wallet attempts no payment. */
export async function circleWalletClient(ctx: Ctx, name: string): Promise<CircleWalletClient> {
  const c = await circleRow(ctx, name)
  return new CircleWalletClient(ctx.clientDeps, { walletPubkey: c.walletPubkey, relays: c.relays, secret: await ctx.open(c.secret) })
}

export function circleView(c: Connection & { circle: CircleDetailsRow; walletPubkey: string }): CircleView {
  const d = c.circle
  return {
    name: c.id,
    hubPubkey: d.hubPubkey,
    hubLabel: d.hubLabel,
    walletPubkey: c.walletPubkey,
    connectionPubkey: d.connectionPubkey,
    maxAmount: d.maxAmount,
    maxReceive: d.maxReceive,
    expiresAt: d.expiresAt,
    feesPpm: d.feesPpm,
    dustThresholdMillis: d.dustThresholdMillis,
    budgetRenewal: d.budgetRenewal,
    rotatable: d.rotationDelaySecs !== undefined,
    frozen: c.frozen === true,
    moved: c.moved === true,
    ...(c.rotation !== undefined && { rotation: { newConnectionPubkey: c.rotation.newConnectionPubkey, ...(c.rotation.completesAt !== undefined && { completesAt: c.rotation.completesAt }) } }),
  }
}

/**
 * A member request for the host to submit (cashkit never sends it): signed
 * by the join's key; a `rotate` generates the new connection key and stores
 * its secret sealed first. A wallet that cannot be rotated takes none.
 */
export async function memberRequest(ctx: Ctx, name: string, action: MemberAction): Promise<NostrEvent> {
  const c = await circleRow(ctx, name)
  if (c.circle.rotationDelaySecs === undefined) throw new CashkitError('usage', 'this circle does not serve member requests for this wallet: it cannot be rotated, frozen or unfrozen', { reason: 'rotation_not_served' })
  const signer = await ctx.requireSigner()
  if (signer.pubkey !== c.circle.memberPubkey) throw new CashkitError('auth', 'a member request must be signed by the key that joined', { reason: 'not_the_member' })
  let newKey: { pubkey: string; secret: string } | undefined
  if (action === 'rotate') {
    newKey = newConnectionKey(ctx)
    const sealed = await ctx.seal(newKey.secret)
    const requestedAt = ctx.nowSeconds()
    await ctx.commit(async (t) => {
      const cur = (await t.get('connections', name))!
      await t.put('connections', { ...cur, rotation: { newConnectionPubkey: newKey!.pubkey, newSecret: sealed, requestedAt }, version: cur.version + 1 }, cur.version)
    })
  }
  return buildMemberRequest(signer, { hubPubkey: c.circle.hubPubkey, action, walletPubkey: c.walletPubkey, ...(newKey !== undefined && { newConnectionPubkey: newKey.pubkey }), now: ctx.nowSeconds() })
}

export type CircleNotification =
  | { readonly notification_type: 'rotation_pending'; readonly notification: { readonly connection_pubkey: string; readonly completes_at: number } }
  | { readonly notification_type: 'rotation_cancelled' | 'rotation_completed'; readonly notification: { readonly connection_pubkey: string } }
  | { readonly notification_type: 'wallet_frozen'; readonly notification: Record<string, never> }

/** What a notification means for the member, as an event for the app. */
export type CircleAlert = 'rotation_alert' | 'rotation_cancelled' | 'rotation_completed' | 'frozen_alert' | 'ignored'

/**
 * Applies a NIP-47 notification a Circle Wallet's key received.
 * `rotation_pending` records the pending rotation and asks the app whether
 * the member asked for it (any request by the old key cancels it);
 * `rotation_completed` switches to the stored new key; `wallet_frozen` marks
 * the wallet frozen until an unfreeze succeeds or a rotation completes.
 */
export async function applyCircleNotification(ctx: Ctx, name: string, n: CircleNotification): Promise<CircleAlert> {
  const c = await circleRow(ctx, name)
  const put = (f: (x: Connection) => Connection) =>
    ctx.commit(async (t) => {
      const cur = (await t.get('connections', name))!
      await t.put('connections', { ...f(cur), version: cur.version + 1 }, cur.version)
    })
  switch (n.notification_type) {
    case 'rotation_pending': {
      const mine = c.rotation?.newConnectionPubkey === n.notification.connection_pubkey
      await put((x) => ({ ...x, ...(mine && x.rotation !== undefined ? { rotation: { ...x.rotation, completesAt: n.notification.completes_at } } : {}) }))
      ctx.emit({ op: 'circle', phase: 'rotation_alert', id: name })
      if (!mine) ctx.confirmations.notify({ type: 'rotationAlert', name })
      return 'rotation_alert'
    }
    case 'rotation_cancelled':
      await put((x) => {
        const { rotation: _r, ...rest } = x
        return rest as Connection
      })
      return 'rotation_cancelled'
    case 'rotation_completed': {
      if (c.rotation?.newConnectionPubkey !== n.notification.connection_pubkey) return 'ignored'
      const r = c.rotation
      await put((x) => {
        const { rotation: _r, frozen: _f, ...rest } = x
        return { ...rest, secret: r.newSecret, circle: { ...x.circle!, connectionPubkey: r.newConnectionPubkey } } as Connection
      })
      return 'rotation_completed'
    }
    case 'wallet_frozen':
      await put((x) => ({ ...x, frozen: true }))
      ctx.emit({ op: 'circle', phase: 'frozen_alert', id: name })
      ctx.confirmations.notify({ type: 'walletFrozen', name })
      return 'frozen_alert'
    default:
      return 'ignored'
  }
}

/**
 * A device holding only the old key learns of a completed rotation by its
 * absence: once now ≥ `completes_at` with no cancellation seen, the
 * connection is marked moved (recover on the device that holds the new key).
 */
export async function markMovedIfDue(ctx: Ctx, name: string, completesAt: number): Promise<boolean> {
  if (ctx.nowSeconds() < completesAt) return false
  const c = await circleRow(ctx, name)
  if (c.rotation !== undefined) return false
  await ctx.commit(async (t) => {
    const cur = (await t.get('connections', name))!
    await t.put('connections', { ...cur, moved: true, version: cur.version + 1 }, cur.version)
  })
  return true
}

/**
 * Deletes the member's Circle Wallet: refused locally while it holds more
 * than its dust threshold; `confirmDelete({dust})` must resolve true (the
 * dust goes to the host). The connection is removed once the Hub agrees.
 */
export async function deleteCircleWallet(ctx: Ctx, name: string, confirmDelete?: (x: { dust: bigint }) => Promise<boolean>): Promise<void> {
  const c = await circleRow(ctx, name)
  const client = await circleWalletClient(ctx, name)
  const balance = await client.getBalance()
  if (balance > c.circle.dustThresholdMillis) throw new CashkitError('usage', `this wallet still holds ${balance} millis, more than its dust threshold of ${c.circle.dustThresholdMillis}: pay it out first`, { reason: 'not_dust' })
  const ok = confirmDelete !== undefined ? await confirmDelete({ dust: balance }) : await ctx.confirmations.ask({ type: 'confirmDelete', name, dust: balance })
  if (!ok) throw new CashkitError('usage', 'deleting was not confirmed', { reason: 'not_confirmed' })
  try {
    await client.deleteWallet()
  } catch (err) {
    if (err instanceof WalletError) throw fromWalletError(err)
    throw connectError(err)
  }
  await ctx.commit((t) => t.delete('connections', name))
}

/** Whether a stored connection is a Lightning wallet: a NIP-47 URI, or a Circle Wallet (a Hub connection string is not). */
export const isLightning = (c: Connection): boolean => (c.kind === 'nwc' || c.kind === 'circle_wallet') && (c.uri !== undefined || c.secret !== undefined)

/** The NIP-47 client for a Lightning connection: from its URI, or a Circle Wallet's fields and the member's secret. */
export async function nwcFor(ctx: Ctx, c: Connection): Promise<NwcClient> {
  if (c.uri !== undefined) return new NwcClient(ctx.clientDeps, await ctx.open(c.uri))
  if (c.kind === 'circle_wallet' && c.secret !== undefined && c.walletPubkey !== undefined && c.relays !== undefined) {
    if (c.frozen === true) throw new CashkitError('auth', 'this circle wallet is frozen: no payment is attempted until it is unfrozen or rotated', { nwcCode: 'FROZEN', input: c.id })
    return new NwcClient(ctx.clientDeps, { walletPubkey: c.walletPubkey, relays: c.relays, secret: await ctx.open(c.secret), extra: {} })
  }
  throw new CashkitError('usage', `"${c.id}" is a Cash Hub connection, not a Lightning wallet`, { input: c.id })
}
