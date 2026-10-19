// Cash selection (design §7.1, §7.2). Port of cashctl
// internal/ledger/cashselect.go and cmd/cash_redeem.go exactSameHubSum /
// exactSubsetSumNet. Ported from the code, not its comments.

/** What selection reads from a holding. */
export interface Selectable {
  readonly id: string
  readonly amount?: bigint
  /** Hex hub-group fingerprint, "" when the token carries none. */
  readonly hubGroup: string
  readonly mode: 'pubkey' | 'cash' | 'connection_key'
  /** Cash mode: whether the secret is known. */
  readonly hasCashSecret: boolean
}

export type SelectionPlan<H extends Selectable> =
  | { readonly kind: 'single'; readonly holding: H; readonly split: boolean }
  | { readonly kind: 'consolidate'; readonly consolidateFirst: readonly H[]; readonly split: boolean }

export class InsufficientFundsError extends Error {
  override readonly name = 'InsufficientFundsError'
  constructor(
    readonly totalHeld: bigint,
    readonly target: bigint,
  ) {
    super(`not enough funds: you hold ${totalHeld} millis, need ${target} millis`)
  }
}

export class FundsFragmentedError extends Error {
  override readonly name = 'FundsFragmentedError'
  constructor(
    readonly totalHeld: bigint,
    readonly target: bigint,
  ) {
    super(`funds are fragmented across separate Hubs: you hold ${totalHeld} millis total, but no single Hub's bills sum to the ${target} millis wanted`)
  }
}

export function sumAmounts(hs: readonly Pick<Selectable, 'amount'>[]): bigint {
  let s = 0n
  for (const h of hs) s += h.amount ?? 0n
  return s
}

/**
 * Bills a consolidation may merge: amount and hub group known, not bound to
 * a connection key, and either pubkey mode or a cash note whose secret is
 * known (a merge first moves it onto a throwaway key).
 */
export function groupableForConsolidation<H extends Selectable>(held: readonly H[]): H[] {
  return held.filter((h) => {
    if (h.amount === undefined || h.hubGroup === '') return false
    if (h.mode === 'connection_key') return false
    if (h.mode === 'cash' && !h.hasCashSecret) return false
    return true
  })
}

/** Bills by hub-group key, skipping those without one. */
export function groupByHub<H extends Selectable>(hs: readonly H[]): Map<string, H[]> {
  const groups = new Map<string, H[]>()
  for (const h of hs) {
    if (h.hubGroup === '') continue
    groups.set(h.hubGroup, [...(groups.get(h.hubGroup) ?? []), h])
  }
  return groups
}

const byAmountDesc = (a: Selectable, b: Selectable) => (a.amount! > b.amount! ? -1 : a.amount! < b.amount! ? 1 : 0)

function smallestCoveringSubset<H extends Selectable>(group: readonly H[], target: bigint): { subset: H[]; sum: bigint } | undefined {
  // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
  const sorted = [...group].sort(byAmountDesc)
  const subset: H[] = []
  let sum = 0n
  for (const h of sorted) {
    subset.push(h)
    sum += h.amount!
    if (sum >= target) return { subset, sum }
  }
  return undefined
}

// oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
const sortedKeys = (m: Map<string, unknown>) => [...m.keys()].sort()

/**
 * `SelectForAmount`: an exact single bill; else the smallest bill above the
 * target (split); else, per hub group in key order, the largest-first prefix
 * that covers it (consolidate first). Throws InsufficientFundsError or
 * FundsFragmentedError.
 */
export function selectForAmount<H extends Selectable>(held: readonly H[], target: bigint): SelectionPlan<H> {
  let bestFit: H | undefined
  for (const h of held) {
    if (h.amount === undefined) continue
    if (h.amount === target) return { kind: 'single', holding: h, split: false }
    if (h.amount > target && (bestFit === undefined || bestFit.amount! > h.amount)) bestFit = h
  }
  if (bestFit !== undefined) return { kind: 'single', holding: bestFit, split: true }
  const groups = groupByHub(groupableForConsolidation(held))
  for (const key of sortedKeys(groups)) {
    const covered = smallestCoveringSubset(groups.get(key)!, target)
    if (covered !== undefined) return { kind: 'consolidate', consolidateFirst: covered.subset, split: covered.sum > target }
  }
  const total = sumAmounts(held)
  if (total < target) throw new InsufficientFundsError(total, target)
  throw new FundsFragmentedError(total, target)
}

export const EXACT_SUBSET_SUM_LIMIT = 20

/** Indices of the first subset (by bitmask order) summing exactly to `target`. */
export function exactSubsetSum(values: readonly bigint[], target: bigint): number[] | undefined {
  const n = values.length
  if (n > EXACT_SUBSET_SUM_LIMIT) return undefined
  for (let mask = 1; mask < 1 << n; mask++) {
    let sum = 0n
    for (let i = 0; i < n; i++) if (mask & (1 << i)) sum += values[i]!
    if (sum === target) {
      const idxs: number[] = []
      for (let i = 0; i < n; i++) if (mask & (1 << i)) idxs.push(i)
      return idxs
    }
  }
  return undefined
}

/**
 * An exact same-hub subset on net amount (`exactSameHubSum`). cashctl walks
 * its hub map in Go's random order; this walks hub keys sorted, so the
 * answer is deterministic.
 */
export function exactSameHubSum<Q extends { readonly hubGroup: string; readonly net: bigint }>(quotes: readonly Q[], target: bigint): Q[] | undefined {
  const byHub = new Map<string, Q[]>()
  for (const q of quotes) {
    if (q.hubGroup === '') continue
    byHub.set(q.hubGroup, [...(byHub.get(q.hubGroup) ?? []), q])
  }
  for (const key of sortedKeys(byHub)) {
    const group = byHub.get(key)!
    const idxs = exactSubsetSum(
      group.map((g) => g.net),
      target,
    )
    if (idxs !== undefined) return idxs.map((i) => group[i]!)
  }
  return undefined
}
