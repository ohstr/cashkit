// Consolidate (design §6.4). Port of cashctl cmd/cash_consolidate.go
// runCashConsolidate, consolidateItems, mergeableHubGroups and
// aloneOnTheirHub.
import { newCashTarget, pubkeyTarget, type Target } from '../core/index.js'
import { getHeld, liveAmount, lockedHoldings, moveCashNotesToKey, newThrowawayKey, requireUnlocked, toCashNotes } from './bills.js'
import type { Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { heldHoldings, updateHolding } from './ledger.js'
import { consolidateCap, consolidateInRounds } from './merge.js'
import type { Holding } from './model.js'
import type { Report } from './report.js'
import { groupableForConsolidation, groupByHub } from './select.js'
import { selectable } from './send.js'
import { parseTarget } from './target.js'
import { holdingView, type HoldingView } from './views.js'

export interface ConsolidateOutcome {
  readonly hubGroup: string
  readonly from: readonly string[]
  readonly amount: bigint
  /** The merged holding, when it stays in this wallet. */
  readonly holding?: HoldingView
  /** Always: the Hub learned that `from` share an owner (NIP-CASH §Privacy Considerations). */
  readonly disclosesCommonOwnership: true
  readonly expiresAt?: number
  readonly targetResolved: string
}

export interface ConsolidateReport extends Report<ConsolidateOutcome> {
  /** Held bills that are the only one from their Cash Hub. */
  readonly aloneOnTheirHub: readonly string[]
}

const crossHub = (ids: readonly string[]) =>
  new CashkitError(
    'invalid_input',
    `these bills (${ids.join(',')}) were minted by the same Lightning node but not by the same Cash Hub, and a consolidation can only merge bills of one Hub. Nothing was changed`,
    { input: ids.join(',') },
  )

/** One merge of named holdings (`consolidateItems`). */
async function consolidateGroup(ctx: Ctx, ids: readonly string[], to: string | undefined, ia: string | undefined): Promise<ConsolidateOutcome> {
  await requireUnlocked(ctx, ids)
  const group: Holding[] = []
  for (const id of ids) group.push((await liveAmount(ctx, await getHeld(ctx, id))).holding)
  if (group.length < 2) throw new CashkitError('usage', `consolidate needs at least 2 sources, got ${group.length}`)
  // Bills of different Cash Hubs never merge; known only from their hub groups, so checked locally.
  if (new Set(group.map((h) => h.hubGroup).filter((g) => g !== '')).size > 1) throw crossHub(ids)
  // Ordered bills never merge with others: the Hub refuses the mix, so it is refused here first.
  if (new Set(group.map((h) => h.ordered === true)).size > 1) {
    throw new CashkitError('invalid_input', 'bills minted for your orders never merge with other bills; nothing was changed', { reason: 'mixed_ordered', input: ids.join(',') })
  }
  const now = ctx.nowSeconds()
  const expired = group.filter((h) => h.expiresAt !== undefined && h.expiresAt <= now)
  if (expired.length > 0 && expired.length < group.length) {
    throw new CashkitError(
      'invalid_input',
      `${expired.map((h) => h.id).join(',')} already expired — merging with a healthy source would make the whole result unusable too. Nothing was changed`,
      { input: expired.map((h) => h.id).join(',') },
    )
  }
  const hasCashNote = group.some((h) => h.mode === 'cash')
  let target: Target
  let targetResolved = ''
  let display = ''
  if (to !== undefined) {
    const rt = await parseTarget(to, { ...(ia !== undefined && { ia }), ...(ctx.deps.fetch !== undefined && { fetch: ctx.deps.fetch }), random: ctx.random })
    target = rt.target
    targetResolved = rt.kind === 'cash' ? '' : rt.resolved
    display = rt.display
  } else {
    const signer = await ctx.signer()
    target = hasCashNote || signer === undefined ? newCashTarget(ctx.random) : pubkeyTarget(signer.pubkey)
  }
  const isSelf = to === undefined
  const throwaway = hasCashNote ? newThrowawayKey(ctx.random) : undefined
  let moved: string[] = []
  try {
    if (throwaway !== undefined) moved = await moveCashNotesToKey(ctx, ids, throwaway.priv, throwaway.pub)
    const live: Holding[] = []
    for (const id of ids) live.push(await getHeld(ctx, id))
    // To self the merged bill stays a holding; to a cash target too (its secret is ours); to anyone else it is a gift.
    const keep = isSelf || target.identityType === 'cash' ? 'holding' : 'handoff'
    const r = await consolidateInRounds(ctx, live, target, { keep, maxSources: await consolidateCap(ctx, live[0]!.token), ...(throwaway !== undefined && { interimKey: throwaway.priv }), ...(display !== '' && { display }) })
    return {
      hubGroup: group[0]!.hubGroup,
      from: [...ids],
      amount: r.amount,
      disclosesCommonOwnership: true,
      ...(r.holding !== undefined && { holding: holdingView(r.holding, ctx.nowSeconds()) }),
      ...(r.expiresAt !== undefined && { expiresAt: r.expiresAt }),
      targetResolved,
    }
  } catch (err) {
    if (moved.length > 0 && !(err instanceof CashkitError && err.pendingCallId !== undefined)) await toCashNotes(ctx, moved)
    throw err
  }
}

/** The key a set of holdings is remembered by. */
// oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
const setKey = (ids: readonly string[]): string => [...ids].sort().join(',')

/** Remembers a set the Hub refused `RESTRICTED`, on each of its holdings. */
async function rememberRefused(ctx: Ctx, ids: readonly string[]): Promise<void> {
  const key = setKey(ids)
  await ctx.commit(async (t) => {
    for (const id of ids) {
      const h = await t.get('holdings', id)
      if (h === undefined || (h.refusedMerges ?? []).includes(key)) continue
      await updateHolding(t, id, (x) => ({ ...x, refusedMerges: [...(x.refusedMerges ?? []), key] }))
    }
  })
}

const refusedBefore = (group: readonly Holding[]): boolean => {
  const key = setKey(group.map((h) => h.id))
  return group.every((h) => (h.refusedMerges ?? []).includes(key))
}

const isRestricted = (err: unknown): boolean => err instanceof CashkitError && err.nwcCode === 'RESTRICTED'

/**
 * Named holdings merge into one; with none named, every hub group of two or
 * more merges on its own, and failures are reported per group. A set the
 * Hub refused `RESTRICTED` is remembered and not planned again (naming it
 * still tries).
 */
export async function consolidate(ctx: Ctx, o: { holdings?: readonly string[]; to?: string; ia?: string } = {}): Promise<ConsolidateReport> {
  return ctx.spend(async () => {
    const locked = await lockedHoldings(ctx)
    const held = (await ctx.read(heldHoldings)).filter((h) => !locked.has(h.id))
    const groups = groupByHub(groupableForConsolidation(held.map(selectable), ctx.nowSeconds()))
    // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
    const alone = [...groups.values()].filter((g) => g.length === 1).map((g) => g[0]!.id).sort()
    if (o.holdings !== undefined) {
      if (new Set(o.holdings).size !== o.holdings.length) throw new CashkitError('usage', 'a holding was named more than once')
      try {
        const outcome = await consolidateGroup(ctx, o.holdings, o.to, o.ia)
        return { outcomes: [{ ok: true, ...outcome }], aloneOnTheirHub: [] }
      } catch (err) {
        if (isRestricted(err)) await rememberRefused(ctx, o.holdings)
        throw err
      }
    }
    const report: ConsolidateReport = { outcomes: [], aloneOnTheirHub: alone }
    const outcomes = report.outcomes as ConsolidateReport['outcomes'][number][]
    let firstError: CashkitError | undefined
    // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
    for (const key of [...groups.keys()].sort()) {
      const ids = groups.get(key)!.map((h) => h.id)
      if (ids.length < 2) continue
      if (refusedBefore(held.filter((h) => ids.includes(h.id)))) continue
      try {
        outcomes.push({ ok: true, ...(await consolidateGroup(ctx, ids, o.to, o.ia)) })
      } catch (err) {
        if (isRestricted(err)) await rememberRefused(ctx, ids)
        const e = err instanceof CashkitError ? err : new CashkitError('internal', (err as Error).message, { cause: err })
        outcomes.push({ ok: false, error: e, holdingIds: ids })
        firstError ??= e
      }
    }
    return { ...report, ...(firstError !== undefined && { firstError }) }
  })
}
