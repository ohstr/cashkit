// Consolidate (design §6.4). Port of cashctl cmd/cash_consolidate.go
// runCashConsolidate, consolidateItems, mergeableHubGroups and
// aloneOnTheirHub.
import { decodeToken, newCashTarget, pubkeyTarget, type Target } from '../core/index.js'
import { getHeld, liveAmount, moveCashNotesToKey, newThrowawayKey, toCashNotes } from './bills.js'
import type { Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { addHandoff, heldHoldings } from './ledger.js'
import { consolidateCap, consolidateInRounds, type MergeSource } from './merge.js'
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
  const group: Holding[] = []
  for (const id of ids) group.push((await liveAmount(ctx, await getHeld(ctx, id))).holding)
  if (group.length < 2) throw new CashkitError('usage', `consolidate needs at least 2 sources, got ${group.length}`)
  // Bills of different Cash Hubs never merge; known only from their hub groups, so checked locally.
  if (new Set(group.map((h) => h.hubGroup).filter((g) => g !== '')).size > 1) throw crossHub(ids)
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
    const items: MergeSource[] = []
    for (const id of ids) {
      const h = await getHeld(ctx, id)
      items.push({ holdingId: h.id, token: h.token, source: { walletPubkey: h.walletPubkey, amount: h.amount!, credential: await ctx.credentialFor(h) }, ...(h.minterPubkey !== undefined && { minterPubkey: h.minterPubkey }) })
    }
    const r = await consolidateInRounds(ctx, items, target, { isSelf, maxSources: await consolidateCap(ctx, items[0]!.token), ...(throwaway !== undefined && { interimKey: throwaway.priv }) })
    if (!isSelf && target.identityType !== 'cash') {
      // Consolidate to someone else leaves a gift and no holding (design §6.4).
      const sealed = await ctx.seal(r.result.newWalletToken)
      let wallet = ''
      try {
        wallet = decodeToken(r.result.newWalletToken).walletPubkey
      } catch {
        // kept verbatim
      }
      await ctx.commit((t) => addHandoff(t, { kind: 'gift', handoff: sealed, amount: r.result.amountMillis, target: display, walletPubkey: wallet }, { now: ctx.now(), random: ctx.random }))
    }
    return {
      hubGroup: group[0]!.hubGroup,
      from: [...ids],
      amount: r.result.amountMillis,
      ...(r.holding !== undefined && { holding: holdingView(r.holding, ctx.nowSeconds()) }),
      ...(r.result.expiresAt !== undefined && { expiresAt: r.result.expiresAt }),
      targetResolved,
    }
  } catch (err) {
    if (moved.length > 0 && !(err instanceof CashkitError && err.code === 'indeterminate')) await toCashNotes(ctx, moved)
    throw err
  }
}

/**
 * Named holdings merge into one; with none named, every hub group of two or
 * more merges on its own, and failures are reported per group.
 */
export async function consolidate(ctx: Ctx, o: { holdings?: readonly string[]; to?: string; ia?: string } = {}): Promise<ConsolidateReport> {
  return ctx.spend(async () => {
    const held = await ctx.read(heldHoldings)
    const groups = groupByHub(groupableForConsolidation(held.map(selectable)))
    // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
    const alone = [...groups.values()].filter((g) => g.length === 1).map((g) => g[0]!.id).sort()
    if (o.holdings !== undefined) {
      if (new Set(o.holdings).size !== o.holdings.length) throw new CashkitError('usage', 'a holding was named more than once')
      const outcome = await consolidateGroup(ctx, o.holdings, o.to, o.ia)
      return { outcomes: [{ ok: true, ...outcome }], aloneOnTheirHub: [] }
    }
    const report: ConsolidateReport = { outcomes: [], aloneOnTheirHub: alone }
    const outcomes = report.outcomes as ConsolidateReport['outcomes'][number][]
    let firstError: CashkitError | undefined
    // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
    for (const key of [...groups.keys()].sort()) {
      const ids = groups.get(key)!.map((h) => h.id)
      if (ids.length < 2) continue
      try {
        outcomes.push({ ok: true, ...(await consolidateGroup(ctx, ids, o.to, o.ia)) })
      } catch (err) {
        const e = err instanceof CashkitError ? err : new CashkitError('internal', (err as Error).message, { cause: err })
        outcomes.push({ ok: false, error: e, holdingIds: ids })
        firstError ??= e
      }
    }
    return { ...report, ...(firstError !== undefined && { firstError }) }
  })
}
