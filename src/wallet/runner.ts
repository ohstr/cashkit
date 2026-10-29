// Running and settling pending calls (NIP-CASH §Lost Replies, §Looking Up a
// Call). Every call that carries a request_id is written ahead
// (`prepareCall`), marked sent from the session's `beforePublish`, and then
// either closed by its answer or left open and settled by `cash_lookup`:
// `done` applies the original result, `pending` waits, `unknown` lets the
// device that placed it place it again under the derived id (or asks the
// user), `expired` surfaces it. A call is never resent under its own id.
import { derivedRequestId, newRequestId, type Tombstone } from '../core/index.js'
import {
  BatchSession,
  classifyCall,
  deadlineFor,
  lookupOne,
  type Bill,
  type ItemOutcome,
  type LookupAuthorizer,
} from '../client/index.js'
import { finishCall, isOwnCall, markSent, noteHub, recordDerivedId } from './calls.js'
import type { Ctx } from './context.js'
import { CashkitError, codeForNwc } from './errors.js'
import { credentialKindOf, endHolding, goneError, notFoundByEntryKey, tombstoneStatus, type GoneStatus } from './billState.js'
import type { CallCreated, CallNeedsUser, PendingCall } from './model.js'
import type { StorageTx } from './ports.js'
import { pendingCallView } from './views.js'

/** An item outcome with its decoded value or tombstone, as the client returns it. */
export type PlacedOutcome = ItemOutcome & { readonly value?: unknown; readonly tombstone?: Tombstone }

export interface PlaceResult {
  readonly outcome: PlacedOutcome | undefined
  readonly error?: Error
}

/** How one kind of operation places, finishes and looks up its calls. */
export interface CallKind {
  /**
   * Sends the call: `call.requestId`, `call.deadline` as the envelope's
   * `not_after`, and `beforePublish` as the session's hook. Throws only when
   * nothing was sent.
   */
  place(ctx: Ctx, call: PendingCall, beforePublish: () => Promise<void>): Promise<PlaceResult>
  /**
   * Prepares the writes that apply a result: a reply's decoded value, or a
   * lookup's `done` result. Runs outside any transaction (it may decrypt);
   * the returned function runs inside the transaction that closes the call.
   */
  finish(ctx: Ctx, call: PendingCall, result: unknown, from: 'reply' | 'lookup'): Promise<(t: StorageTx) => Promise<CallCreated | void>>
  /** The bill a lookup targets and who signs it, as the call was authorized. */
  lookupTarget(ctx: Ctx, call: PendingCall): Promise<{ readonly bill: Bill; readonly authorizer: LookupAuthorizer }>
  /**
   * The cash notes `<token>#<secret>` a reply created, for the error text
   * when the transaction applying it fails (the call stays written ahead).
   */
  recovery?(ctx: Ctx, call: PendingCall, result: unknown): Promise<readonly string[]>
  /** Runs once the result is saved (e.g. publishing a zap's 9522); failures are left for the next settle. */
  afterApply?(ctx: Ctx, callId: string): Promise<void>
  /**
   * Whether `unknown` re-places it automatically (`cash_transfer`,
   * `cash_consolidate`; a `cash_withdraw` unless it saw `REQUEST_REUSED`) or
   * asks the user first.
   */
  readonly autoReplace: boolean | ((call: PendingCall) => boolean)
  /**
   * Before an automatic re-placement: a reason it may not be placed again
   * (a withdrawal whose quote is no longer valid), which closes it refused.
   */
  replaceBlocked?(ctx: Ctx, call: PendingCall): Promise<{ readonly code: string; readonly detail?: string } | undefined>
  /** The confirmation request that asks the user to place it again (kinds that are not `autoReplace`). */
  readonly replaceRequest?: 'confirmMintReplace' | 'confirmOrderReplace' | 'confirmWithdrawReplace'
  /** Changes a re-placed call before it is written (a `cash_order` gets a fresh `notify`). */
  forReplace?(ctx: Ctx, call: PendingCall): PendingCall
}

const KINDS = new Map<string, CallKind>()

/** Registers the kind that runs the calls of one operation. */
export function registerCallKind(name: string, kind: CallKind): void {
  KINDS.set(name, kind)
}

function kindOf(call: PendingCall): CallKind {
  const k = KINDS.get(call.kind)
  if (k === undefined) throw new CashkitError('internal', `no handler for calls of kind ${call.kind}`)
  return k
}

/** At most this many attempts (the original and two re-placements) before the user decides. */
export const MAX_ATTEMPTS = 3

async function update(ctx: Ctx, id: string, change: (c: PendingCall) => PendingCall): Promise<PendingCall | undefined> {
  return ctx.commit(async (t) => {
    const cur = await t.get('pendingCalls', id)
    if (cur === undefined || cur.state === 'done') return cur
    const next = { ...change(cur), version: cur.version + 1 }
    await t.put('pendingCalls', next, cur.version)
    return next
  })
}

/**
 * Cash Pocket hooks (set by the pocket module when a Pocket is configured):
 * the write-ahead pending entry, read back before the call is sent, and the
 * entries a call's outcome makes once it is saved.
 */
export const pocketHooks: {
  writeAhead?: (ctx: Ctx, call: PendingCall) => Promise<void>
  after?: (ctx: Ctx, callId: string) => Promise<void>
  /** Before placing a call again: the pocket's derived-id check (`derived` or `closed` stop it). */
  beforeReplace?: (ctx: Ctx, call: PendingCall) => Promise<'place' | 'derived' | 'closed'>
  /** After a call is closed because its entry is final elsewhere: its sources are read before they count as held. */
  closedElsewhere?: (ctx: Ctx, call: PendingCall) => Promise<void>
} = {}

/** Closes an open call; a call already closed stays as it is. */
async function close(ctx: Ctx, id: string, outcome: Parameters<typeof finishCall>[2], o: { code?: string; detail?: string; needsUser?: CallNeedsUser } = {}): Promise<void> {
  await closeRow(ctx, id, outcome, o)
  if (ctx.deps.pocket !== undefined) await pocketHooks.after?.(ctx, id).catch(() => undefined)
}

async function closeRow(ctx: Ctx, id: string, outcome: Parameters<typeof finishCall>[2], o: { code?: string; detail?: string; needsUser?: CallNeedsUser }): Promise<void> {
  await ctx.commit(async (t) => {
    const cur = await t.get('pendingCalls', id)
    if (cur === undefined || cur.state === 'done') return
    const done = await finishCall(t, id, outcome, { ...(o.code !== undefined && { code: o.code }), ...(o.detail !== undefined && { detail: o.detail }) })
    if (o.needsUser !== undefined) await t.put('pendingCalls', { ...done, needsUser: o.needsUser, version: done.version + 1 }, done.version)
  })
}

/** Applies a result and closes the call `applied` in one transaction; nothing when it is already closed. */
async function applyResult(ctx: Ctx, call: PendingCall, result: unknown, from: 'reply' | 'lookup'): Promise<CallCreated> {
  const kind = kindOf(call)
  const writes = await kind.finish(ctx, call, result, from)
  let created: CallCreated
  try {
    created = await ctx.commit(async (t) => {
      const cur = await t.get('pendingCalls', call.id)
      if (cur === undefined || cur.state === 'done') return cur?.created ?? {}
      const made = (await writes(t)) ?? {}
      // A kind may keep its call open past the reply (an order until it is finished): its writes set that state.
      const after = await t.get('pendingCalls', call.id)
      // A kind may also close its call itself (a payout that ended): its outcome and any notice for the user are kept.
      if (after?.state === 'open_order' || after?.state === 'open_withdraw' || after?.state === 'done') {
        await t.put('pendingCalls', { ...after, created: made, version: after.version + 1 }, after.version)
        return made
      }
      const done = await finishCall(t, call.id, 'applied')
      await t.put('pendingCalls', { ...done, created: made, version: done.version + 1 }, done.version)
      return made
    })
  } catch (err) {
    if (from !== 'reply' || err instanceof CashkitError) throw err
    const notes = (await kind.recovery?.(ctx, call, result).catch(() => [])) ?? []
    throw new CashkitError('internal', `the Hub applied this ${call.method}, but saving its result failed; the call stays written ahead and settle() applies it`, {
      pendingCallId: call.id,
      cause: err,
      ...(notes.length > 0 && { recovery: `Save these cash notes until settle() has run:\n${notes.join('\n')}`, recoveryHandoffs: notes }),
    })
  }
  await kind.afterApply?.(ctx, call.id).catch(() => undefined)
  if (ctx.deps.pocket !== undefined) await pocketHooks.after?.(ctx, call.id).catch(() => undefined)
  return created
}

/**
 * A tombstone for the bill the call's item named: that bill is gone, so the
 * call never ran. A `cash_consolidate` item names only its first source
 * (NIP-CASH §What Can Be Consolidated Together), so the tombstone says
 * nothing about the others: they stay held and are released by the close.
 */
async function applyTombstone(ctx: Ctx, call: PendingCall, ends: GoneStatus, code = 'TOMBSTONE'): Promise<void> {
  await ctx.commit(async (t) => {
    for (const id of namedSources(call)) await endHolding(t, ctx.now(), id, ends)
    const cur = await t.get('pendingCalls', call.id)
    if (cur !== undefined && cur.state !== 'done') await finishCall(t, call.id, 'not_applied', { code })
  })
}

const namedSources = (call: PendingCall): readonly string[] => (call.method === 'cash_consolidate' ? call.sources.slice(0, 1) : call.sources)

/**
 * `NOT_FOUND` for an item proof signed by the named bill's identity key or
 * made with its cash secret: the sender removed the slice, so the bill is
 * `reclaimed` and the call never ran (NIP-CP §Balance). A connection-key
 * holder's `NOT_FOUND` says nothing and leaves the call open.
 */
async function reclaimedByRefusal(ctx: Ctx, call: PendingCall, code: string | undefined): Promise<boolean> {
  if (code !== 'NOT_FOUND') return false
  const h = await ctx.read((t) => t.get('holdings', namedSources(call)[0] ?? ''))
  if (h === undefined || h.status !== 'held') return false
  return notFoundByEntryKey({ kind: credentialKindOf(h) }, { code })
}

/**
 * Places a prepared call and acts on its answer: applied ⇒ result applied
 * and call closed in one transaction; `BAD_REQUEST` ⇒ closed not applied
 * (`invalid_input`); a tombstone ⇒ source spent, closed; nothing sent ⇒
 * closed `not_sent`; anything else ⇒ left open (sources stay locked) and
 * thrown with its `pendingCallId`, for `settle()` to look up.
 */
export async function executeCall(ctx: Ctx, call: PendingCall): Promise<CallCreated> {
  const kind = kindOf(call)
  let placed: PlaceResult
  try {
    placed = await kind.place(ctx, call, async () => {
      await markSent(ctx, call)
      // With a Cash Pocket the pending entry is stored and read back before the call goes out; failing that, nothing is sent.
      if (ctx.deps.pocket !== undefined) await pocketHooks.writeAhead?.(ctx, call)
    })
  } catch (err) {
    await close(ctx, call.id, 'not_sent').catch(() => undefined)
    throw err
  }
  const o = placed.outcome
  const c = o === undefined ? ({ kind: 'open', reason: 'not_served' } as const) : classifyCall(o)
  switch (c.kind) {
    case 'applied':
      return applyResult(ctx, call, o!.value, 'reply')
    case 'final_not_applied':
      await close(ctx, call.id, 'not_applied', { code: c.code, ...(c.detail !== undefined && { detail: c.detail }) })
      throw new CashkitError('invalid_input', `the Hub refused this ${call.method} as malformed, so it was not applied`, { nwcCode: c.code, ...(o?.error?.message !== undefined && { rawMessage: o.error.message }) })
    case 'tombstone': {
      const ends = tombstoneStatus(o!.tombstone)
      await applyTombstone(ctx, call, ends)
      throw goneError(ends)
    }
    case 'not_sent':
      await close(ctx, call.id, 'not_sent')
      throw new CashkitError('network', `this ${call.method} was not sent; nothing moved`, ...(placed.error !== undefined ? [{ cause: placed.error }] : []))
    case 'open': {
      if (c.reason === 'refused' && (await reclaimedByRefusal(ctx, call, c.code))) {
        await applyTombstone(ctx, call, 'reclaimed', 'NOT_FOUND')
        throw goneError('reclaimed')
      }
      if (c.reason === 'refused' && c.code !== 'REQUEST_REUSED') await update(ctx, call.id, (x) => ({ ...x, lastCode: c.code!, ...(c.detail !== undefined && { lastDetail: c.detail }) }))
      if (c.reason === 'refused' && c.code === 'REQUEST_REUSED') await update(ctx, call.id, (x) => ({ ...x, sawReused: true }))
      ctx.emit({ op: call.kind, phase: 'pending', id: call.id, pendingCallId: call.id })
      const code = c.reason === 'refused' && c.code !== undefined && c.code !== 'REQUEST_REUSED' ? codeForNwc(c.code) : 'indeterminate'
      throw new CashkitError(
        code === 'internal' ? 'indeterminate' : code,
        c.reason === 'refused'
          ? `the Hub refused this ${call.method} (${c.code}); it stays pending until a lookup confirms nothing was applied`
          : `this ${call.method} got no decided answer, so whether it was applied is unknown; settle() looks it up`,
        { pendingCallId: call.id, ...(c.code !== undefined && { nwcCode: c.code }), ...(placed.error !== undefined && { cause: placed.error }) },
      )
    }
  }
}

export interface SettleCallsReport {
  readonly applied: readonly string[]
  readonly closed: readonly string[]
  readonly replaced: readonly string[]
  readonly open: readonly string[]
  readonly needsUser: readonly string[]
}

/**
 * Settles every open call once: a call never marked sent is closed
 * `not_sent`; a sent one is looked up (by its exact deadline, signed by its
 * authorizer) and moved per NIP-CASH §Looking Up a Call.
 */
export async function settleCalls(ctx: Ctx): Promise<SettleCallsReport> {
  const applied: string[] = []
  const closed: string[] = []
  const replaced: string[] = []
  const open: string[] = []
  const needsUser: string[] = []
  const sessions = new Map<string, Promise<BatchSession>>()
  const sessionFor = (call: PendingCall) => {
    let s = sessions.get(call.node)
    if (s === undefined) {
      s = BatchSession.open(ctx.clientDeps, call.node, call.relays)
      sessions.set(call.node, s)
    }
    return s
  }
  const calls = (await ctx.read((t) => t.list('pendingCalls'))).filter((c) => c.state === 'prepared' || c.state === 'sent')
  for (const call of calls) {
    if (call.state === 'prepared') {
      await close(ctx, call.id, 'not_sent')
      closed.push(call.id)
      continue
    }
    const now = ctx.nowSeconds()
    if (call.lookup?.retryAfter !== undefined && now < call.lookup.retryAfter && call.lookup.status === 'pending') {
      open.push(call.id)
      continue
    }
    let answer: PlacedOutcome | undefined
    try {
      const kind = kindOf(call)
      const { bill, authorizer } = await kind.lookupTarget(ctx, call)
      answer = await lookupOne(await sessionFor(call), { bill, by: { requestId: call.requestId }, deadline: call.deadline, authorizer }, () => ctx.nowSeconds())
    } catch {
      answer = undefined
    }
    const status = answer?.state === 'result' ? (answer.value as { status?: string } | undefined) : undefined
    if (status === undefined) {
      // No answer, an omission, a refused lookup or REQUEST_REUSED on the lookup itself: asked again later, never read as unknown.
      const omissions = (call.lookup?.omissions ?? 0) + 1
      const unanswered = now > call.deadline + call.hAtSend
      await update(ctx, call.id, (x) => ({ ...x, lookup: { ...x.lookup, omissions, checkedAt: now }, ...(unanswered && { needsUser: 'lookup_unanswered' as const }) }))
      if (unanswered) needsUser.push(call.id)
      else open.push(call.id)
      continue
    }
    switch (status.status) {
      case 'done': {
        try {
          await applyResult(ctx, call, (status as { result: unknown }).result, 'lookup')
          applied.push(call.id)
          ctx.emit({ op: call.kind, phase: 'recovered', id: call.id, pendingCallId: call.id })
        } catch {
          open.push(call.id)
        }
        break
      }
      case 'pending': {
        const retryAfter = (status as { retryAfter: number }).retryAfter
        await update(ctx, call.id, (x) => ({ ...x, lookup: { ...(x.lookup ?? { omissions: 0 }), status: 'pending', retryAfter, checkedAt: now } }))
        open.push(call.id)
        break
      }
      case 'unknown': {
        const r = await onUnknown(ctx, call)
        ;({ closed, replaced, needsUser, open })[r].push(call.id)
        break
      }
      case 'expired': {
        // Final whatever the device: no re-placement is decided here, so a foreign call closes too.
        await close(ctx, call.id, 'lookup_expired', { needsUser: 'lookup_expired' })
        needsUser.push(call.id)
        ctx.emit({ op: call.kind, phase: 'needs_user', id: call.id, pendingCallId: call.id })
        const row = await ctx.read((t) => t.get('pendingCalls', call.id))
        if (row !== undefined) ctx.confirmations.notify({ type: 'lookupExpired', call: pendingCallView(row, ctx.deviceId) })
        break
      }
      default:
        open.push(call.id)
    }
  }
  return { applied, closed, replaced, open, needsUser }
}

/** A call rebuilt from the Hub's records (a recovered withdrawal): it is only looked up, never placed again. */
const isRecovered = (call: PendingCall) => call.params?.['recovered'] === '1'

/** `unknown`: the call was not applied and never will be. */
async function onUnknown(ctx: Ctx, call: PendingCall): Promise<'closed' | 'replaced' | 'needsUser' | 'open'> {
  if (isRecovered(call)) {
    await close(ctx, call.id, 'lookup_expired', { needsUser: 'lookup_expired' })
    const closed = await ctx.read((t) => t.get('pendingCalls', call.id))
    if (closed !== undefined) ctx.confirmations.notify({ type: 'lookupExpired', call: pendingCallView(closed, ctx.deviceId) })
    return 'closed'
  }
  if (!isOwnCall(ctx, call)) {
    await update(ctx, call.id, (x) => ({ ...x, needsUser: 'foreign_device', lookup: { ...(x.lookup ?? { omissions: 0 }), status: 'unknown' } }))
    return 'needsUser'
  }
  if (call.lastCode !== undefined && call.lastCode !== 'BAD_REQUEST' && call.lastCode !== 'REQUEST_REUSED') {
    // A coded refusal: never placed again.
    await close(ctx, call.id, 'not_applied', { code: call.lastCode, ...(call.lastDetail !== undefined && { detail: call.lastDetail }), needsUser: 'refused' })
    return 'closed'
  }
  if (call.attempts >= MAX_ATTEMPTS) {
    await close(ctx, call.id, 'not_applied', { needsUser: 'replace_cap' })
    ctx.emit({ op: call.kind, phase: 'needs_user', id: call.id, pendingCallId: call.id })
    return 'needsUser'
  }
  const kind = kindOf(call)
  const auto = typeof kind.autoReplace === 'function' ? kind.autoReplace(call) : kind.autoReplace
  const blocked = auto ? await kind.replaceBlocked?.(ctx, call) : undefined
  if (blocked !== undefined) {
    await close(ctx, call.id, 'not_applied', { code: blocked.code, ...(blocked.detail !== undefined && { detail: blocked.detail }), needsUser: 'refused' })
    return 'closed'
  }
  if (!auto) {
    await update(ctx, call.id, (x) => ({ ...x, needsUser: 'confirm_replace', lookup: { ...(x.lookup ?? { omissions: 0 }), status: 'unknown' } }))
    ctx.emit({ op: call.kind, phase: 'needs_user', id: call.id, pendingCallId: call.id })
    askReplace(ctx, call.id)
    return 'needsUser'
  }
  await replace(ctx, call).catch(() => undefined)
  return 'replaced'
}

/**
 * Places a call again under its derived id (NIP-CASH §Looking Up a Call,
 * Finality): same target, amounts and written-ahead secrets, a new deadline
 * and fresh proofs. A derived id already recorded or placed only closes the
 * old call. The derived id is recorded before anything is sent. A recovered
 * call is refused before anything is written.
 */
export async function replace(ctx: Ctx, call: PendingCall): Promise<PendingCall | undefined> {
  if (isRecovered(call)) throw new CashkitError('usage', 'a recovered call is only looked up: it is never placed again', { input: call.id, reason: 'recovered_call' })
  const { created: _c, ...base } = call
  const derived = derivedRequestId(call.requestId)
  const seen = await ctx.read(async (t) => (await t.get('derivedIds', derived)) !== undefined || (await t.list('pendingCalls')).some((c) => c.requestId === derived))
  if (seen) {
    await close(ctx, call.id, 'replaced')
    return undefined
  }
  // With a Cash Pocket: the old entry must still be open and no entry may carry the derived id (NIP-CP §Writing).
  if (ctx.deps.pocket !== undefined && pocketHooks.beforeReplace !== undefined) {
    const check = await pocketHooks.beforeReplace(ctx, call)
    if (check === 'derived') {
      await close(ctx, call.id, 'replaced')
      return undefined
    }
    if (check === 'closed') {
      // Final elsewhere: another device may have applied it, so its sources are read before they count as held.
      await close(ctx, call.id, 'closed_elsewhere', { detail: 'closed in the Cash Pocket' })
      await pocketHooks.closedElsewhere?.(ctx, call).catch(() => undefined)
      return undefined
    }
  }
  const session = await BatchSession.open(ctx.clientDeps, call.node, call.relays)
  const h = session.maxRequestAge ?? call.hAtSend
  const deadline = deadlineFor(h, ctx.nowSeconds())
  const hub = await ctx.read((t) => t.get('hubs', call.node))
  const placed: PendingCall = {
    ...stripOpen(base as PendingCall),
    id: `pc-${newRequestId(ctx.random).slice(0, 16)}`,
    requestId: derived,
    deadline,
    hAtSend: h,
    device: ctx.deviceId,
    attempts: call.attempts + 1,
    derivedFrom: call.id,
    state: 'prepared',
    createdAt: ctx.now(),
    version: 1,
  }
  const next = kindOf(call).forReplace?.(ctx, placed) ?? placed
  await ctx.commit(async (t) => {
    await recordDerivedId(t, { derivedId: derived, parentCallId: call.id, deadline, hMax: Math.max(hub?.hMax ?? 0, h) })
    if (h > 0) await noteHub(t, call.node, h)
    await t.put('pendingCalls', next, 0)
  })
  try {
    await executeCall(ctx, next)
  } finally {
    await close(ctx, call.id, 'replaced')
  }
  return next
}

function stripOpen(c: PendingCall): PendingCall {
  const { outcome: _o, lastCode: _c, lastDetail: _d, lookup: _l, needsUser: _n, derivedFrom: _f, sawReused: _r, ...rest } = c
  return rest as PendingCall
}

/** The user closes an open call (`user_closed`); its sources are released. */
export async function closeByUser(ctx: Ctx, id: string): Promise<void> {
  await close(ctx, id, 'user_closed')
}

/**
 * Raises the kind's replace request for a call now waiting on
 * `confirm_replace`; a yes places it again (under the spend lock, once the
 * current operation is done). No handler: the call keeps waiting for
 * `pendingCalls.confirmReplace`.
 */
function askReplace(ctx: Ctx, id: string): void {
  if (!ctx.confirmations.handled) return
  void (async () => {
    const call = await ctx.read((t) => t.get('pendingCalls', id))
    const type = call === undefined ? undefined : KINDS.get(call.kind)?.replaceRequest
    if (call === undefined || type === undefined) return
    if (await ctx.confirmations.ask({ type, call: pendingCallView(call, ctx.deviceId) })) await ctx.spend(() => confirmReplace(ctx, id))
  })().catch(() => undefined)
}

/** The user confirms re-placing a call that waits for it (`confirm_replace`). */
export async function confirmReplace(ctx: Ctx, id: string): Promise<void> {
  const call = await ctx.read((t) => t.get('pendingCalls', id))
  if (call === undefined || call.state === 'done' || call.needsUser !== 'confirm_replace') throw new CashkitError('usage', 'this call is not waiting for a confirmation to be placed again')
  if (!isOwnCall(ctx, call)) throw new CashkitError('usage', 'only the device that placed this call may place it again')
  await replace(ctx, call)
}
