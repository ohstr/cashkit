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
import { decodeToken, MAX_AMOUNT_MILLIS, newCashTarget, newRequestId, pubkeyTarget, type CashTarget, type CashTransferResult, type Target } from '../core/index.js'
import { validateRequestedAmount } from './amounts.js'
import { followMove, forgetPark, forgetRemainder, getHeld, newRemainder, releaseRemainder, liveAmount, moveCashNotesToKey, newThrowawayKey, parkDestination, promotePending, releasePark, toCashNotes, withPendingSecret } from './bills.js'
import { tokenFacts, type Ctx } from './context.js'
import { CashkitError, classifySpendError } from './errors.js'
import { addHandoff, addHolding, appendActivity, heldHoldings, updateHolding } from './ledger.js'
import { consolidateCap, consolidateInRounds, type MergeSource } from './merge.js'
import type { Holding, TargetDisplay } from './model.js'
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
    group = []
    for (const id of o.holdings) group.push((await liveAmount(ctx, await getHeld(ctx, id))).holding)
  } else {
    const held = await ctx.read(heldHoldings)
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
    split: amount < sum,
    ...(expiries.length > 0 && { earliestExpiry: Math.min(...expiries) }),
  }
}

/** Re-reads the plan's holdings; any that moved since is a `conflict`. */
async function livePlanSources(ctx: Ctx, sources: readonly PlannedSource[]): Promise<Holding[]> {
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

/** One bill: a full or split transfer (`runCashTransfer`'s tail). */
async function sendSingle(ctx: Ctx, plan: SendPlan, h: Holding, target: Target, consolidatedFirst: boolean): Promise<SendResult> {
  const cred = await ctx.credentialFor(h)
  const split = plan.amount < h.amount!
  // A split of a cash note gives its remainder a fresh secret, written ahead with the destination's.
  const remainder = split && h.mode === 'cash' && cred.kind === 'secret' ? await newRemainder(ctx) : undefined
  const park = await parkDestination(ctx, h.id, target, remainder?.sealed)
  let out: { result: CashTransferResult; promoted?: import('./model.js').Sealed }
  try {
    out = await withPendingSecret(ctx, h, cred, (c) =>
      ctx.client(h.token).cashTransfer({ credential: c, to: target, currentAmount: h.amount!, requestId: newRequestId(ctx.random), ...(split && { splitAmount: plan.amount }), ...(remainder !== undefined && { remainderCommitment: remainder.commitment }) }),
    )
  } catch (err) {
    const c = classifySpendError(err, 'transfer', [h.id])
    await forgetPark(ctx, park, c)
    if (remainder !== undefined) await forgetRemainder(ctx, h.id, remainder.sealed, c)
    throw c
  }
  const cashSecret = remainder?.sealed ?? out.promoted ?? h.cashSecret
  return finishSend(ctx, {
    plan,
    target,
    result: out.result,
    originalToken: h.token,
    sourceIds: [h.id],
    updateSource: (x) => promotePending({ ...releaseRemainder(releasePark(x, park), remainder?.sealed), status: 'transferred' }, out.promoted),
    remainderMode: {
      mode: h.mode,
      protection: h.protection,
      ...(cashSecret !== undefined && h.mode === 'cash' && { cashSecret }),
      ...(h.connectionKey !== undefined && { connectionKey: h.connectionKey }),
      ...(h.throwawayKey !== undefined && { throwawayKey: h.throwawayKey }),
      ...(h.minterPubkey !== undefined && { minterPubkey: h.minterPubkey }),
    },
    consolidatedFirst,
  })
}

type RemainderMode = Pick<Holding, 'mode' | 'protection' | 'cashSecret' | 'connectionKey' | 'throwawayKey' | 'minterPubkey'>

/**
 * `printAndSaveTransferResult`: in one commit, the sources' new status, the
 * remainder holding, the handoff and the activity. A failed commit is a
 * recovery error carrying every handoff verbatim.
 */
async function finishSend(
  ctx: Ctx,
  p: {
    plan: SendPlan
    target: Target
    result: Pick<CashTransferResult, 'newWalletToken' | 'remainderWalletToken' | 'remainderWalletPubkey' | 'remainingAmountMillis'>
    originalToken: string
    sourceIds: readonly string[]
    updateSource: (h: Holding) => Holding
    remainderMode?: RemainderMode
    consolidatedFirst: boolean
  },
): Promise<SendResult> {
  const isCash = p.target.identityType === 'cash'
  const recipientToken = p.result.newWalletToken !== '' ? p.result.newWalletToken : p.originalToken
  const cashNote = isCash ? `${recipientToken}#${(p.target as CashTarget).secret}` : undefined
  const handoffValue = cashNote ?? recipientToken
  const sealedHandoff = await ctx.seal(handoffValue)
  const remainderToken = p.result.remainderWalletToken
  const remainderAmount = p.result.remainingAmountMillis !== undefined && p.result.remainingAmountMillis <= MAX_AMOUNT_MILLIS ? p.result.remainingAmountMillis : undefined
  const remainderSecret = p.remainderMode?.mode === 'cash' && p.remainderMode.cashSecret !== undefined ? await ctx.open(p.remainderMode.cashSecret) : undefined
  let recipientWallet = ''
  try {
    recipientWallet = decodeToken(recipientToken).walletPubkey
  } catch {
    // an undecodable token still goes in the handoff verbatim
  }
  let remainder: Holding | undefined
  let handoffId: string
  try {
    ;({ remainder, handoffId } = await ctx.commit(async (t) => {
      for (const id of p.sourceIds) await updateHolding(t, id, p.updateSource)
      let rem: Holding | undefined
      if (remainderToken !== '' && p.remainderMode !== undefined) {
        const f = tokenFacts(remainderToken)
        rem = await addHolding(
          t,
          {
            ...p.remainderMode,
            token: remainderToken,
            walletPubkey: p.result.remainderWalletPubkey,
            hubGroup: f.hubGroup,
            relayUrls: f.tok.relays,
            verified: false,
            ...(remainderAmount !== undefined && { amount: remainderAmount }),
          },
          { now: ctx.now(), random: ctx.random },
        )
      }
      const ho = await addHandoff(
        t,
        { kind: isCash ? 'cash_note' : 'gift', handoff: sealedHandoff, amount: p.plan.amount, target: p.plan.to, walletPubkey: recipientWallet },
        { now: ctx.now(), random: ctx.random },
      )
      await appendActivity(t, ctx.now(), {
        action: 'send',
        amount: p.plan.amount,
        to: p.plan.to,
        handoffId: ho.id,
        holdingIds: [...p.sourceIds],
        ...(rem !== undefined && { remainderId: rem.id }),
      })
      return { remainder: rem, handoffId: ho.id }
    }))
  } catch (err) {
    const parts = [`the recipient's own — save this now, it will not be shown again: ${handoffValue}`]
    const handoffs = [handoffValue]
    if (remainderToken !== '') {
      const own = remainderSecret !== undefined ? `${remainderToken}#${remainderSecret}` : remainderToken
      parts.push(`your own remainder: ${own}`)
      handoffs.push(own)
    }
    throw new CashkitError('internal', "Transfer succeeded on the Hub, but saving that locally failed — your wallet's local record does not match reality.", {
      cause: err,
      recovery: `Save these: ${parts.join('; ')}`,
      recoveryHandoffs: handoffs,
    })
  }
  if (remainder?.throwawayKey !== undefined) {
    await toCashNotes(ctx, [remainder.id])
    remainder = (await ctx.read((t) => t.get('holdings', remainder!.id))) ?? remainder
  }
  return {
    sent: p.plan.amount,
    to: p.plan.to,
    targetResolved: isCash ? '' : p.plan.targetResolved,
    ...(cashNote !== undefined && { cashNote }),
    ...(!isCash && { recipientToken }),
    handoffId,
    ...(remainder !== undefined && { remainder: holdingView(remainder, ctx.nowSeconds()) }),
    consolidatedFirst: p.consolidatedFirst,
  }
}

/**
 * Several bills (`transferWithAutoConsolidate` / `mergeThenSend`): cash
 * notes move onto a throwaway key; everything merges (into the target when
 * the sum is exact, else into the interim identity, committed); then the
 * merged bill is split-sent.
 */
async function sendMerged(ctx: Ctx, plan: SendPlan, group: Holding[], target: Target): Promise<SendResult> {
  const hasCashNote = group.some((h) => h.mode === 'cash')
  // A merge key is used only when cash notes move onto it first, which
  // persists it (pendingThrowawayKey) before any merge can depend on it.
  const throwaway = hasCashNote ? newThrowawayKey(ctx.random) : undefined
  const interimPub = throwaway?.pub ?? (await ctx.requireSigner()).pubkey
  let moved: string[] = []
  try {
    if (hasCashNote) moved = await moveCashNotesToKey(ctx, group.map((h) => h.id), throwaway!.priv, throwaway!.pub)
    const live: Holding[] = []
    for (const h of group) live.push(await getHeld(ctx, h.id))
    const items: MergeSource[] = []
    for (const h of live) {
      items.push({ holdingId: h.id, token: h.token, source: { walletPubkey: h.walletPubkey, amount: h.amount!, credential: await ctx.credentialFor(h) }, ...(h.minterPubkey !== undefined && { minterPubkey: h.minterPubkey }) })
    }
    const maxSources = await consolidateCap(ctx, live[0]!.token)
    const sum = sumAmounts(live)
    const interim = throwaway !== undefined ? { interimKey: throwaway.priv } : {}
    if (sum === plan.amount) {
      const r = await consolidateInRounds(ctx, items, target, { isSelf: false, maxSources, ...interim })
      return finishSend(ctx, {
        plan,
        target,
        result: { newWalletToken: r.result.newWalletToken, remainderWalletToken: '', remainderWalletPubkey: '' },
        originalToken: r.result.newWalletToken,
        sourceIds: r.holding !== undefined ? [r.holding.id] : [],
        updateSource: (x) => ({ ...x, status: 'transferred' }),
        consolidatedFirst: true,
      })
    }
    const r = await consolidateInRounds(ctx, items, pubkeyTarget(interimPub), { isSelf: true, maxSources, ...interim })
    const merged = r.holding!
    try {
      return await sendSingle(ctx, plan, merged, target, true)
    } catch (err) {
      if (err instanceof CashkitError && err.code !== 'indeterminate' && merged.throwawayKey !== undefined) await toCashNotes(ctx, [merged.id])
      throw err
    }
  } catch (err) {
    const c = err instanceof CashkitError ? err : classifySpendError(err, 'transfer', group.map((h) => h.id))
    if (moved.length > 0 && c.code !== 'indeterminate') await toCashNotes(ctx, moved)
    throw c
  }
}

export { followMove }
