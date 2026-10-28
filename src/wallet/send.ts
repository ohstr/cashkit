// Send (design §6.2). Port of cashctl cmd/cash_transfer.go runCashTransfer,
// transferWithAutoConsolidate and printAndSaveTransferResult, and
// cmd/cash_merge.go mergeThenSend.
//
// One deliberate difference: cashctl's identity path consolidates and
// splits in one TransferFromSources call, whose interim bill exists only in
// memory until the split lands. cashkit always commits the interim holding
// first (consolidateInRounds), then splits from it: the same wire calls and
// the same result for the recipient, with no window where the only copy of
// a landed bill is unsaved.
import { newCashTarget, pubkeyTarget, type CashTarget, type Target } from '../core/index.js'
import { validateRequestedAmount } from './amounts.js'
import { getHeld, liveAmount, lockedHoldings, moveCashNotesToKey, newThrowawayKey, requireUnlocked, toCashNotes } from './bills.js'
import type { PlainDestination } from './calls.js'
import { runTransfer } from './kinds.js'
import type { Ctx } from './context.js'
import { CashkitError, classifySpendError } from './errors.js'
import { heldHoldings } from './ledger.js'
import { consolidateCap, consolidateInRounds } from './merge.js'
import type { CallCreated, Holding, TargetDisplay } from './model.js'
import { FundsFragmentedError, InsufficientFundsError, selectForAmount, sumAmounts, type Selectable } from './select.js'
import { parseTarget, type TargetKind } from './target.js'
import { holdingView, type HoldingView } from './views.js'

export interface SendInput {
  readonly amount?: bigint
  /** Default "cash": a note anyone holding it can claim. */
  readonly to?: string
  readonly holdings?: readonly string[]
  /** Identity Authority for an nconnection target that doesn't name one. */
  readonly ia?: string
}

export interface PlannedSource {
  readonly holdingId: string
  readonly version: number
  readonly amount: bigint
}

/** Everything cashctl would ask the user to confirm. Carries no secret. */
export interface SendPlan {
  readonly op: 'send'
  readonly amount: bigint
  readonly to: TargetDisplay
  readonly targetKind: TargetKind
  readonly targetResolved: string
  readonly sources: readonly PlannedSource[]
  /** Several bills merge first; their Hub learns they share an owner. */
  readonly consolidateFirst: boolean
  /** Set with `consolidateFirst`: the Hub learns that `sources` share an owner (NIP-CASH §Privacy Considerations). */
  readonly disclosesCommonOwnership?: true
  /** The (merged) bill is split, and change comes back. */
  readonly split: boolean
  readonly earliestExpiry?: number
  /** The resolved target; undefined for cash, whose secret is minted at execute. */
  readonly target?: Target
}

export interface SendResult {
  readonly sent: bigint
  readonly to: TargetDisplay
  readonly targetResolved: string
  /** to = cash: the `<token>#<secret>` to hand over. The only copy besides the handoff row. */
  readonly cashNote?: string
  /** What a pubkey or connection recipient now holds. */
  readonly recipientToken?: string
  readonly handoffId?: string
  readonly remainder?: HoldingView
  readonly consolidatedFirst: boolean
}

export const selectable = (h: Holding): Selectable & Holding => ({ ...h, hasCashSecret: h.cashSecret !== undefined })

/** Whether the amount could be covered if the bills kept out of merges were merged too. */
function coverableWithExcluded(held: readonly Holding[], amount: bigint): boolean {
  try {
    selectForAmount(held.map((h) => ({ ...selectable(h), excludeFromMerge: false })), amount)
    return true
  } catch {
    return false
  }
}

/** Build a plan; reads only, and never moves value. */
export async function planSend(ctx: Ctx, o: SendInput): Promise<SendPlan> {
  if (o.amount !== undefined) validateRequestedAmount(o.amount)
  if (o.to === undefined && o.amount === undefined && o.holdings === undefined) {
    throw new CashkitError('usage', 'say what to send: an amount alone makes a cash note anyone can take, or add a destination (or name holdings to send whole)')
  }
  const rt = await parseTarget(o.to ?? 'cash', { ...(o.ia !== undefined && { ia: o.ia }), ...(ctx.deps.fetch !== undefined && { fetch: ctx.deps.fetch }), random: ctx.random })
  const base = { op: 'send' as const, to: rt.display, targetKind: rt.kind, targetResolved: rt.resolved, ...(rt.kind !== 'cash' && { target: rt.target }) }

  let group: Holding[]
  if (o.holdings !== undefined) {
    if (new Set(o.holdings).size !== o.holdings.length) throw new CashkitError('usage', 'a holding was named more than once')
    if (o.holdings.length === 0) throw new CashkitError('usage', 'holdings was given no ids')
    await requireUnlocked(ctx, o.holdings)
    group = []
    for (const id of o.holdings) group.push((await liveAmount(ctx, await getHeld(ctx, id))).holding)
  } else {
    const locked = await lockedHoldings(ctx)
    const held = (await ctx.read(heldHoldings)).filter((h) => !locked.has(h.id))
    if (o.amount === undefined) {
      if (held.length === 0) throw new CashkitError('not_found', 'you have no held cash tokens: receive one first')
      if (held.length > 1) throw new CashkitError('usage', `you hold ${held.length} cash tokens: name which with holdings, or give an amount`)
      group = [(await liveAmount(ctx, held[0]!)).holding]
    } else {
      if (held.length === 0) throw new CashkitError('not_found', 'you have no held cash tokens: receive one first')
      let plan
      try {
        plan = selectForAmount(held.map(selectable), o.amount)
      } catch (err) {
        if ((err instanceof InsufficientFundsError || err instanceof FundsFragmentedError) && held.some((h) => h.excludeFromMerge === true) && coverableWithExcluded(held, o.amount)) {
          throw new CashkitError('invalid_input', 'covering this amount would merge a bill you keep out of merges; nothing was changed', { reason: 'excluded_from_merge' })
        }
        if (err instanceof InsufficientFundsError) throw new CashkitError('invalid_input', `not enough funds: you hold ${err.totalHeld} millis, need ${err.target} millis`)
        if (err instanceof FundsFragmentedError) throw new CashkitError('usage', err.message)
        throw err
      }
      if (plan.kind === 'consolidate' && !(await ctx.settings()).allowAutoConsolidate) {
        throw new CashkitError('usage', 'no single holding covers this amount, and auto-consolidation is turned off in settings')
      }
      group = plan.kind === 'single' ? [(await liveAmount(ctx, plan.holding)).holding] : [...plan.consolidateFirst]
    }
  }

  const sum = sumAmounts(group)
  const amount = o.amount ?? sum
  if (group.length === 1) {
    const h = group[0]!
    if (amount > h.amount!) throw new CashkitError('usage', `can't send ${amount} millis: the held token only has ${h.amount} millis`)
    return { ...base, amount, sources: [{ holdingId: h.id, version: h.version, amount: h.amount! }], consolidateFirst: false, split: amount < h.amount!, ...(h.expiresAt !== undefined && { earliestExpiry: h.expiresAt }) }
  }
  const hub = group[0]!.hubGroup
  if (hub === '' || group.some((h) => h.hubGroup !== hub || h.mode === 'connection_key' || (h.mode === 'cash' && h.cashSecret === undefined))) {
    throw new CashkitError('usage', 'only bills from one Cash Hub, in pubkey mode or with a known cash secret, can be merged into one send')
  }
  // Ordered bills never merge with others (as consolidate refuses): refused before any call moves a cash note.
  if (new Set(group.map((h) => h.ordered === true)).size > 1) {
    throw new CashkitError('invalid_input', 'bills minted for your orders never merge with other bills; nothing was changed', { reason: 'mixed_ordered', input: group.map((h) => h.id).join(',') })
  }
  if (amount > sum) throw new CashkitError('usage', `can't send ${amount} millis: the named holdings only have ${sum} millis`)
  const now = ctx.nowSeconds()
  const expired = group.filter((h) => h.expiresAt !== undefined && h.expiresAt <= now)
  if (expired.length > 0 && expired.length < group.length) {
    throw new CashkitError(
      'invalid_input',
      `${expired.map((h) => h.id).join(',')} already expired — auto-consolidating it to cover this amount would make the whole result unusable too. Nothing was changed`,
      { input: expired.map((h) => h.id).join(',') },
    )
  }
  const expiries = group.flatMap((h) => (h.expiresAt !== undefined ? [h.expiresAt] : []))
  return {
    ...base,
    amount,
    sources: group.map((h) => ({ holdingId: h.id, version: h.version, amount: h.amount! })),
    consolidateFirst: true,
    disclosesCommonOwnership: true,
    split: amount < sum,
    ...(expiries.length > 0 && { earliestExpiry: Math.min(...expiries) }),
  }
}

/** Re-reads the plan's holdings; any that moved since, or that an open call now holds, is a `conflict`. */
async function livePlanSources(ctx: Ctx, sources: readonly PlannedSource[]): Promise<Holding[]> {
  await requireUnlocked(ctx, sources.map((x) => x.holdingId))
  const out: Holding[] = []
  for (const s of sources) {
    const h = await ctx.read((t) => t.get('holdings', s.holdingId))
    if (h === undefined || h.status !== 'held' || h.version !== s.version) {
      throw new CashkitError('conflict', 'your wallet changed since this send was planned; plan it again', { input: s.holdingId })
    }
    out.push(h)
  }
  return out
}

export async function executeSend(ctx: Ctx, plan: SendPlan): Promise<SendResult> {
  return ctx.spend(async () => {
    const id = ctx.newOpId('send')
    const group = await livePlanSources(ctx, plan.sources)
    const target: Target = plan.target ?? newCashTarget(ctx.random)
    ctx.emit({ op: 'send', phase: 'sent', id })
    try {
      const r = plan.consolidateFirst ? await sendMerged(ctx, plan, group, target) : await sendSingle(ctx, plan, group[0]!, target, false)
      ctx.emit({ op: 'send', phase: 'committed', id })
      return r
    } catch (err) {
      ctx.emit({ op: 'send', phase: 'failed', id })
      throw err
    }
  })
}

/** The wallet-side destination of a send target: a cash target's secret is written ahead with the call. */
export function destinationOf(target: Target): PlainDestination {
  if (target.identityType === 'cash') {
    const secret = (target as CashTarget).secret
    if (secret === undefined || secret === '') throw new CashkitError('internal', 'a cash-mode target carries no secret, so its destination bill would be unspendable')
    return { kind: 'cash', secret }
  }
  if (target.identityType === 'connection_key') return { kind: 'connection_key', key: target.identityValue, platform: '', ia: target.iaPubkey }
  return { kind: 'pubkey', pubkey: target.identityValue }
}

/** The send's result, read back from what its call created. */
async function sendResult(ctx: Ctx, plan: SendPlan, created: CallCreated, consolidatedFirst: boolean): Promise<SendResult> {
  const isCash = plan.targetKind === 'cash'
  const ho = created.handoffId !== undefined ? await ctx.read((t) => t.get('handoffs', created.handoffId!)) : undefined
  const value = ho !== undefined ? await ctx.open(ho.handoff) : ''
  const remId = created.holdingIds?.[0]
  // Change left on a merge key goes back to a cash note (best effort: a failure leaves it on the key).
  if (remId !== undefined && (await ctx.read((t) => t.get('holdings', remId)))?.throwawayKey !== undefined) await toCashNotes(ctx, [remId])
  const remainder = remId !== undefined ? await ctx.read((t) => t.get('holdings', remId)) : undefined
  return {
    sent: plan.amount,
    to: plan.to,
    targetResolved: isCash ? '' : plan.targetResolved,
    ...(isCash && value !== '' && { cashNote: value }),
    ...(!isCash && value !== '' && { recipientToken: value }),
    ...(created.handoffId !== undefined && { handoffId: created.handoffId }),
    ...(remainder !== undefined && { remainder: holdingView(remainder, ctx.nowSeconds()) }),
    consolidatedFirst,
  }
}

/** One bill: a full or split transfer (`runCashTransfer`'s tail), one call. */
async function sendSingle(ctx: Ctx, plan: SendPlan, h: Holding, target: Target, consolidatedFirst: boolean): Promise<SendResult> {
  const split = plan.amount < h.amount!
  const created = await runTransfer(ctx, {
    op: 'send',
    source: h,
    to: target,
    destination: destinationOf(target),
    keep: 'handoff',
    amount: plan.amount,
    ...(split && { split: plan.amount }),
    display: plan.to,
  })
  return sendResult(ctx, plan, created, consolidatedFirst)
}

/**
 * Several bills (`transferWithAutoConsolidate` / `mergeThenSend`): cash
 * notes move onto a merge key; everything merges (into the target when the
 * sum is exact, else into the interim identity, kept); then the merged bill
 * is sent. Every step is its own call.
 */
async function sendMerged(ctx: Ctx, plan: SendPlan, group: Holding[], target: Target): Promise<SendResult> {
  const hasCashNote = group.some((h) => h.mode === 'cash')
  const throwaway = hasCashNote ? newThrowawayKey(ctx.random) : undefined
  const interimPub = throwaway?.pub ?? (await ctx.requireSigner()).pubkey
  let moved: string[] = []
  try {
    if (hasCashNote) moved = await moveCashNotesToKey(ctx, group.map((h) => h.id), throwaway!.priv, throwaway!.pub)
    const live: Holding[] = []
    for (const h of group) live.push(await getHeld(ctx, h.id))
    const maxSources = await consolidateCap(ctx, live[0]!.token)
    const sum = sumAmounts(live)
    const interim = throwaway !== undefined ? { interimKey: throwaway.priv } : {}
    if (sum === plan.amount) {
      const r = await consolidateInRounds(ctx, live, { ...target, ...(target.identityType === 'cash' && { secret: (target as CashTarget).secret }) }, { keep: 'handoff', maxSources, display: plan.to, ...interim })
      return sendResult(ctx, plan, { ...(r.handoffId !== undefined && { handoffId: r.handoffId }) }, true)
    }
    const r = await consolidateInRounds(ctx, live, pubkeyTarget(interimPub), { keep: 'holding', maxSources, ...interim })
    const merged = r.holding!
    try {
      return await sendSingle(ctx, plan, merged, target, true)
    } catch (err) {
      if (err instanceof CashkitError && err.pendingCallId === undefined && merged.throwawayKey !== undefined) await toCashNotes(ctx, [merged.id])
      throw err
    }
  } catch (err) {
    const c = err instanceof CashkitError ? err : classifySpendError(err, 'transfer', group.map((h) => h.id))
    if (moved.length > 0 && c.pendingCallId === undefined) await toCashNotes(ctx, moved)
    throw c
  }
}
