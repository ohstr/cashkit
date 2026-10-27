// Consolidation (design §7.3). Port of cashctl cmd/cash_consolidate.go
// doCashConsolidate, consolidateInRounds, reconcileAmbiguousSources and
// hubConsolidateCap: rounds of at most the Hub's announced source cap, each
// interim committed (with the merge key) before the next round goes out.
import { bySigning, localSigner, newRequestId, pubkeyTarget, type CashConsolidateResult, type CashTarget, type ConsolidateSource, type Target } from '../core/index.js'
import { ClientError, NotServedError } from '../client/index.js'
import { DEFAULT_LIMITS, maxSourcesForEnvelope } from '../transport/index.js'
import { forgetPark, hexBytes, parkDestination, releasePark, type Park } from './bills.js'
import { tokenFacts, type Ctx } from './context.js'
import { CashkitError, classifySpendError, isExpiredDecline } from './errors.js'
import { addHolding, appendActivity, updateHolding } from './ledger.js'
import type { Holding, Sealed } from './model.js'

/** One consolidation source: a held row, or (rounds only) nothing local. */
export interface MergeSource {
  readonly holdingId?: string
  readonly token: string
  readonly source: ConsolidateSource
  readonly minterPubkey?: string
}

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
const isTooLarge = (err: unknown) => err instanceof CashkitError && err.cause instanceof ClientError && err.cause.code === 'item_too_large'

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
  readonly result: CashConsolidateResult
}

const isUndecodable = (err: unknown) => err instanceof ClientError && err.code === 'undecodable_result'

/**
 * `reconcileAmbiguousSources`: after a reply that could not be read, asks
 * each source's Hub; a confirmed spent source is marked consolidated.
 */
async function reconcileAmbiguousSources(ctx: Ctx, ids: readonly string[]): Promise<string[]> {
  const gone: string[] = []
  for (const id of ids) {
    const h = await ctx.read((t) => t.get('holdings', id))
    if (h === undefined) continue
    try {
      const s = await ctx.client(h.token).state(await ctx.credentialFor(h))
      if (s.state === 'spent') gone.push(id)
    } catch {
      // inconclusive
    }
  }
  if (gone.length > 0) {
    await ctx
      .commit(async (t) => {
        for (const id of gone) await updateHolding(t, id, (x) => ({ ...x, status: 'consolidated' }))
      })
      .catch(() => undefined)
  }
  return gone
}

/**
 * One cash_consolidate (`doCashConsolidate`). Dials each source's token in
 * turn, moving on only after an EXPIRED decline. On success, in one
 * commit: sources consolidated, the new holding added when it stays here,
 * the park released, and the activity recorded.
 */
export async function consolidateOnce(
  ctx: Ctx,
  items: readonly MergeSource[],
  target: Target,
  o: { isSelf: boolean; interimKey?: Sealed },
): Promise<MergeResult> {
  const localIds = items.flatMap((i) => (i.holdingId !== undefined ? [i.holdingId] : []))
  let park: Park | undefined
  if (localIds.length > 0) park = await parkDestination(ctx, localIds[0]!, target)
  const isCash = target.identityType === 'cash'
  const cashSecret = isCash ? await ctx.seal((target as CashTarget).secret) : undefined
  const sources = items.map((i) => i.source)
  let last: CashkitError | undefined
  for (const [n, dial] of items.entries()) {
    let result: CashConsolidateResult
    try {
      result = await ctx.client(dial.token).cashConsolidate(sources[0]!.credential, { sources, to: target, requestId: newRequestId(ctx.random) })
    } catch (err) {
      let cause: unknown = err
      if (isUndecodable(err) || err instanceof NotServedError) {
        const gone = await reconcileAmbiguousSources(ctx, localIds)
        if (gone.length > 0) {
          cause = new CashkitError('indeterminate', `the Hub's reply could not be read, but it confirms ${gone.join(', ')} consumed; the merged result itself could not be recovered`, { cause: err })
        }
      }
      last = classifySpendError(cause, 'consolidate', localIds)
      if (!isExpiredDecline(err) || n === items.length - 1) {
        await forgetPark(ctx, park, last)
        throw last
      }
      continue
    }
    const facts = tokenFacts(result.newWalletToken)
    const minter = sharedMinter(items.map((i) => i.minterPubkey))
    const keep = o.isSelf || isCash
    try {
      const holding = await ctx.commit(async (t) => {
        for (const id of localIds) await updateHolding(t, id, (h) => ({ ...releasePark(h, park), status: 'consolidated' }))
        let added: Holding | undefined
        if (keep) {
          added = await addHolding(
            t,
            {
              token: result.newWalletToken,
              walletPubkey: result.newWalletPubkey,
              hubGroup: facts.hubGroup,
              relayUrls: facts.tok.relays,
              amount: result.amountMillis,
              verified: true,
              ...(minter !== undefined && { minterPubkey: minter }),
              ...(result.expiresAt !== undefined && { expiresAt: result.expiresAt }),
              ...(isCash
                ? { mode: 'cash' as const, protection: 'protected' as const, cashSecret: cashSecret! }
                : { mode: 'pubkey' as const, protection: 'none' as const, ...(o.interimKey !== undefined && { throwawayKey: o.interimKey }) }),
            },
            { now: ctx.now(), random: ctx.random },
          )
        }
        await appendActivity(t, ctx.now(), { action: 'consolidate', amount: result.amountMillis, from: localIds, ...(added !== undefined && { into: added.id }) })
        return added
      })
      return { ...(holding !== undefined && { holding }), result }
    } catch (err) {
      const recovery = isCash ? `${result.newWalletToken}#${(target as CashTarget).secret}` : result.newWalletToken
      const key = keep && !isCash && o.interimKey !== undefined ? await ctx.open(o.interimKey).catch(() => undefined) : undefined
      throw new CashkitError('internal', "Consolidate succeeded on the Hub, but saving that locally failed — your wallet's local record does not match reality.", {
        cause: err,
        recovery: `The resulting token — save this now, it will not be shown again: ${recovery}${key !== undefined ? ` — spent by the private key ${key}` : ''}`,
        recoveryHandoffs: key !== undefined ? [recovery, key] : [recovery],
      })
    }
  }
  throw last ?? new CashkitError('internal', 'consolidate: no sources given')
}

/**
 * `consolidateInRounds`: while there are more sources than the cap, merge
 * chunks into the interim identity (the merge key when given, else the
 * wallet's identity), committing each interim with that key; then merge
 * what is left into `target`.
 */
export async function consolidateInRounds(
  ctx: Ctx,
  items: readonly MergeSource[],
  target: Target,
  o: { isSelf: boolean; maxSources: number; interimKey?: string },
): Promise<MergeResult> {
  let max = Math.max(o.maxSources, 2)
  const interimSealed = o.interimKey !== undefined ? await ctx.seal(o.interimKey) : undefined
  let cur = [...items]
  // A round that fits no envelope is refused before it is sent, so it is
  // safe to halve the round size and go on from what has merged so far.
  for (;;) {
    try {
      while (cur.length > max) {
        const signer = o.interimKey !== undefined ? localSigner(hexBytes(o.interimKey)) : await ctx.requireSigner()
        const next: MergeSource[] = []
        let start = 0
        try {
          for (; start < cur.length; start += max) {
            const chunk = cur.slice(start, start + max)
            if (chunk.length === 1) {
              next.push(chunk[0]!)
              continue
            }
            const r = await consolidateOnce(ctx, chunk, pubkeyTarget(signer.pubkey), { isSelf: true, ...(interimSealed !== undefined && { interimKey: interimSealed }) })
            const h = r.holding!
            next.push({
              holdingId: h.id,
              token: h.token,
              source: { walletPubkey: h.walletPubkey, amount: h.amount!, credential: bySigning(signer) },
              ...(h.minterPubkey !== undefined && { minterPubkey: h.minterPubkey }),
            })
          }
        } catch (err) {
          // Keep what this round already merged; the rest goes again.
          cur = [...next, ...cur.slice(start)]
          throw err
        }
        cur = next
      }
      return await consolidateOnce(ctx, cur, target, { isSelf: o.isSelf, ...(interimSealed !== undefined && target.identityType === 'pubkey' && { interimKey: interimSealed }) })
    } catch (err) {
      if (!isTooLarge(err) || max <= 2) throw err
      max = Math.max(2, Math.floor(max / 2))
    }
  }
}
