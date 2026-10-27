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
import { finishCall, isOwnCall, markSent, recordDerivedId } from './calls.js'
import type { Ctx } from './context.js'
import { CashkitError, codeForNwc } from './errors.js'
import { appendActivity, updateHolding } from './ledger.js'
import type { CallNeedsUser, PendingCall } from './model.js'
import type { StorageTx } from './ports.js'

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
  finish(ctx: Ctx, call: PendingCall, result: unknown, from: 'reply' | 'lookup'): Promise<(t: StorageTx) => Promise<void>>
  /** The bill a lookup targets and who signs it, as the call was authorized. */
  lookupTarget(ctx: Ctx, call: PendingCall): Promise<{ readonly bill: Bill; readonly authorizer: LookupAuthorizer }>
  /** Whether `unknown` re-places it automatically (`cash_transfer`, `cash_consolidate`) or asks the user first. */
  readonly autoReplace: boolean
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

/** Closes an open call; a call already closed stays as it is. */
async function close(ctx: Ctx, id: string, outcome: Parameters<typeof finishCall>[2], o: { code?: string; detail?: string; needsUser?: CallNeedsUser } = {}): Promise<void> {
  await ctx.commit(async (t) => {
    const cur = await t.get('pendingCalls', id)
    if (cur === undefined || cur.state === 'done') return
    const done = await finishCall(t, id, outcome, { ...(o.code !== undefined && { code: o.code }), ...(o.detail !== undefined && { detail: o.detail }) })
    if (o.needsUser !== undefined) await t.put('pendingCalls', { ...done, needsUser: o.needsUser, version: done.version + 1 }, done.version)
  })
}

/** Applies a result and closes the call `applied` in one transaction; nothing when it is already closed. */
async function applyResult(ctx: Ctx, call: PendingCall, result: unknown, from: 'reply' | 'lookup'): Promise<void> {
  const writes = await kindOf(call).finish(ctx, call, result, from)
  await ctx.commit(async (t) => {
    const cur = await t.get('pendingCalls', call.id)
    if (cur === undefined || cur.state === 'done') return
    await writes(t)
    await finishCall(t, call.id, 'applied')
  })
}

/** A tombstone for the call's source: the bill is gone, so the call never ran. */
async function applyTombstone(ctx: Ctx, call: PendingCall): Promise<void> {
  await ctx.commit(async (t) => {
    for (const id of call.sources) {
      const h = await t.get('holdings', id)
      if (h?.status !== 'held') continue
      await updateHolding(t, id, (x) => ({ ...x, status: 'spent' }))
      await appendActivity(t, ctx.now(), { action: 'spent', holdingId: id })
    }
    const cur = await t.get('pendingCalls', call.id)
    if (cur !== undefined && cur.state !== 'done') await finishCall(t, call.id, 'not_applied', { code: 'TOMBSTONE' })
  })
}

/**
 * Places a prepared call and acts on its answer: applied ⇒ result applied
 * and call closed in one transaction; `BAD_REQUEST` ⇒ closed not applied
 * (`invalid_input`); a tombstone ⇒ source spent, closed; nothing sent ⇒
 * closed `not_sent`; anything else ⇒ left open (sources stay locked) and
 * thrown with its `pendingCallId`, for `settle()` to look up.
 */
export async function executeCall(ctx: Ctx, call: PendingCall): Promise<void> {
  const kind = kindOf(call)
  let placed: PlaceResult
  try {
    placed = await kind.place(ctx, call, async () => void (await markSent(ctx, call)))
  } catch (err) {
    await close(ctx, call.id, 'not_sent').catch(() => undefined)
    throw err
  }
  const o = placed.outcome
  const c = o === undefined ? ({ kind: 'open', reason: 'not_served' } as const) : classifyCall(o)
  switch (c.kind) {
    case 'applied':
      await applyResult(ctx, call, o!.value, 'reply')
      return
    case 'final_not_applied':
      await close(ctx, call.id, 'not_applied', { code: c.code, ...(c.detail !== undefined && { detail: c.detail }) })
      throw new CashkitError('invalid_input', `the Hub refused this ${call.method} as malformed, so it was not applied`, { nwcCode: c.code, ...(o?.error?.message !== undefined && { rawMessage: o.error.message }) })
    case 'tombstone':
      await applyTombstone(ctx, call)
      throw new CashkitError('spent', 'the Hub says this bill is spent: its value has already moved and the bill is gone')
    case 'not_sent':
      await close(ctx, call.id, 'not_sent')
      throw new CashkitError('network', `this ${call.method} was not sent; nothing moved`, ...(placed.error !== undefined ? [{ cause: placed.error }] : []))
    case 'open': {
      if (c.reason === 'refused' && c.code !== 'REQUEST_REUSED') await update(ctx, call.id, (x) => ({ ...x, lastCode: c.code!, ...(c.detail !== undefined && { lastDetail: c.detail }) }))
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
        if (isOwnCall(ctx, call)) {
          await close(ctx, call.id, 'lookup_expired', { needsUser: 'lookup_expired' })
          needsUser.push(call.id)
          ctx.emit({ op: call.kind, phase: 'needs_user', id: call.id, pendingCallId: call.id })
        } else open.push(call.id)
        break
      }
      default:
        open.push(call.id)
    }
  }
  return { applied, closed, replaced, open, needsUser }
}

/** `unknown`: the call was not applied and never will be. */
async function onUnknown(ctx: Ctx, call: PendingCall): Promise<'closed' | 'replaced' | 'needsUser' | 'open'> {
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
  if (!kindOf(call).autoReplace) {
    await update(ctx, call.id, (x) => ({ ...x, needsUser: 'confirm_replace', lookup: { ...(x.lookup ?? { omissions: 0 }), status: 'unknown' } }))
    ctx.emit({ op: call.kind, phase: 'needs_user', id: call.id, pendingCallId: call.id })
    return 'needsUser'
  }
  await replace(ctx, call).catch(() => undefined)
  return 'replaced'
}

/**
 * Places a call again under its derived id (NIP-CASH §Looking Up a Call,
 * Finality): same target, amounts and written-ahead secrets, a new deadline
 * and fresh proofs. A derived id already recorded or placed only closes the
 * old call. The derived id is recorded before anything is sent.
 */
export async function replace(ctx: Ctx, call: PendingCall): Promise<PendingCall | undefined> {
  const derived = derivedRequestId(call.requestId)
  const seen = await ctx.read(async (t) => (await t.get('derivedIds', derived)) !== undefined || (await t.list('pendingCalls')).some((c) => c.requestId === derived))
  if (seen) {
    await close(ctx, call.id, 'replaced')
    return undefined
  }
  const session = await BatchSession.open(ctx.clientDeps, call.node, call.relays)
  const h = session.maxRequestAge ?? call.hAtSend
  const deadline = deadlineFor(h, ctx.nowSeconds())
  const hub = await ctx.read((t) => t.get('hubs', call.node))
  const next: PendingCall = {
    ...stripOpen(call),
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
  await ctx.commit(async (t) => {
    await recordDerivedId(t, { derivedId: derived, parentCallId: call.id, deadline, hMax: Math.max(hub?.hMax ?? 0, h) })
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
  const { outcome: _o, lastCode: _c, lastDetail: _d, lookup: _l, needsUser: _n, derivedFrom: _f, ...rest } = c
  return rest as PendingCall
}

/** The user closes an open call (`user_closed`); its sources are released. */
export async function closeByUser(ctx: Ctx, id: string): Promise<void> {
  await close(ctx, id, 'user_closed')
}

/** The user confirms re-placing a call that waits for it (`confirm_replace`). */
export async function confirmReplace(ctx: Ctx, id: string): Promise<void> {
  const call = await ctx.read((t) => t.get('pendingCalls', id))
  if (call === undefined || call.state === 'done' || call.needsUser !== 'confirm_replace') throw new CashkitError('usage', 'this call is not waiting for a confirmation to be placed again')
  if (!isOwnCall(ctx, call)) throw new CashkitError('usage', 'only the device that placed this call may place it again')
  await replace(ctx, call)
}
