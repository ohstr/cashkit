// Consolidation (design §7.3). Port of cashctl cmd/cash_consolidate.go
// doCashConsolidate, consolidateInRounds, reconcileAmbiguousSources and
// hubConsolidateCap: rounds of at most the Hub's announced source cap, each
// interim committed (with the merge key) before the next round goes out.
import { localSigner, pubkeyTarget, type Target } from '../core/index.js'
import { ClientError } from '../client/index.js'
import { DEFAULT_LIMITS, maxSourcesForEnvelope } from '../transport/index.js'
import { hexBytes } from './bills.js'
import type { PlainDestination } from './calls.js'
import type { Ctx } from './context.js'
import { runConsolidate, type Keep } from './kinds.js'
import type { Holding } from './model.js'

/** The Hub's announced source cap, at least 2 (`hubConsolidateCap`). */
export async function consolidateCap(ctx: Ctx, token: string): Promise<number> {
  let limits = DEFAULT_LIMITS
  try {
    limits = (await ctx.client(token).session()).limits
  } catch {
    // the defaults
  }
  // §7.3: the announced cap, and never more than fits in one envelope.
  const n = Math.min(limits.maxConsolidateSources, maxSourcesForEnvelope(limits.maxEnvelopeBytes))
  return n >= 2 ? n : DEFAULT_LIMITS.maxConsolidateSources
}

/** The client refused an item that fits no envelope, before sending: nothing moved. */
const isTooLarge = (err: unknown) => err instanceof ClientError && err.code === 'item_too_large'

/** `sharedMinter`: the minter every source shares, else undefined. */
export function sharedMinter(minters: readonly (string | undefined)[]): string | undefined {
  let m: string | undefined
  for (const x of minters) {
    if (x === undefined) return undefined
    if (m === undefined) m = x
    else if (m !== x) return undefined
  }
  return m
}

export interface MergeResult {
  /** The new holding, when it stays in this wallet (self or cash target). */
  readonly holding?: Holding
  /** The handoff, when the merged bill went to someone else. */
  readonly handoffId?: string
  readonly amount: bigint
  readonly expiresAt?: number
}

/**
 * One cash_consolidate, as a pending call (target `sources[0]`). In one
 * commit: sources consolidated, the merged bill kept or handed off, the
 * activity recorded; or the call left open for `settle()`.
 */
export async function consolidateOnce(ctx: Ctx, holdings: readonly Holding[], target: Target & { readonly secret?: string }, o: { keep: Keep; interimKey?: string; display?: string }): Promise<MergeResult> {
  const destination: PlainDestination =
    target.identityType === 'cash'
      ? { kind: 'cash', secret: target.secret! }
      : o.interimKey !== undefined && target.identityType === 'pubkey'
        ? { kind: 'throwaway', pubkey: target.identityValue, key: o.interimKey }
        : target.identityType === 'connection_key'
          ? { kind: 'connection_key', key: target.identityValue, platform: '', ia: target.iaPubkey }
          : { kind: 'pubkey', pubkey: target.identityValue }
  const created = await runConsolidate(ctx, { sources: holdings, to: target, destination, keep: o.keep, ...(o.display !== undefined && { display: o.display }) })
  const id = created.holdingIds?.[0]
  const holding = id !== undefined ? await ctx.read((t) => t.get('holdings', id)) : undefined
  let amount = 0n
  for (const h of holdings) amount += h.amount ?? 0n
  return {
    ...(holding !== undefined && { holding }),
    ...(created.handoffId !== undefined && { handoffId: created.handoffId }),
    amount: holding?.amount ?? amount,
    ...(holding?.expiresAt !== undefined && { expiresAt: holding.expiresAt }),
  }
}

/**
 * `consolidateInRounds`: while there are more sources than the cap, merge
 * chunks into the interim identity (the merge key when given, else the
 * wallet's identity), each round its own call; then merge what is left
 * into `target`.
 */
export async function consolidateInRounds(
  ctx: Ctx,
  items: readonly Holding[],
  target: Target & { readonly secret?: string },
  o: { keep: Keep; maxSources: number; interimKey?: string; display?: string },
): Promise<MergeResult> {
  let max = Math.max(o.maxSources, 2)
  let cur = [...items]
  for (;;) {
    try {
      while (cur.length > max) {
        const interimPub = o.interimKey !== undefined ? localSigner(hexBytes(o.interimKey)).pubkey : (await ctx.requireSigner()).pubkey
        const next: Holding[] = []
        let start = 0
        try {
          for (; start < cur.length; start += max) {
            const chunk = cur.slice(start, start + max)
            if (chunk.length === 1) {
              next.push(chunk[0]!)
              continue
            }
            const r = await consolidateOnce(ctx, chunk, pubkeyTarget(interimPub), { keep: 'holding', ...(o.interimKey !== undefined && { interimKey: o.interimKey }) })
            next.push(r.holding!)
          }
        } catch (err) {
          // Keep what this round already merged; the rest goes again.
          cur = [...next, ...cur.slice(start)]
          throw err
        }
        cur = next
      }
      return await consolidateOnce(ctx, cur, target, { keep: o.keep, ...(o.interimKey !== undefined && { interimKey: o.interimKey }), ...(o.display !== undefined && { display: o.display }) })
    } catch (err) {
      if (!isTooLarge(err) || max <= 2) throw err
      max = Math.max(2, Math.floor(max / 2))
    }
  }
}
