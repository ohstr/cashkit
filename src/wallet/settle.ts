// settle() (design §5.3): reconciles leftover write-ahead slots. Port of
// cashctl cmd/cash_merge.go settlePendingMoves, extended to the other two
// slots the same way:
//
// - pendingThrowawayKey: probe the key; a match promotes it. Else probe the
//   cash secret; a match clears it. Then leftover merge-key holdings go back
//   to cash notes (toCashNotes).
// - pendingCashSecret: probe the pending secret; a match promotes it (the
//   rekey landed). Else probe the current secret; a match clears it. cashctl
//   only resolves this slot lazily on the next spend (retry on NOT_FOUND),
//   which cashkit also does; probing here closes the kill window sooner.
// - pendingDestinationCashSecret and pendingRemainderCashSecret: cleared only when the source is still held
//   and the Hub still answers for it at the recorded amount, so the send
//   cannot have happened. Otherwise it stays in state.unfinishedCashSends.
//
// A probe that errors is inconclusive and leaves the slot alone.
import { bySecret, bySigning, localSigner, NO_LOCAL_IDENTITY, type Credential } from '../core/index.js'
import { hexBytes, promoteThrowaway, toCashNotes } from './bills.js'
import type { Ctx } from './context.js'
import { appendActivity, updateHolding } from './ledger.js'
import type { Holding } from './model.js'

export interface SettleReport {
  /** Merge keys promoted, or cleared because the move did not land. */
  readonly mergeKeysPromoted: readonly string[]
  readonly mergeKeysCleared: readonly string[]
  /** Holdings returned from a merge key to a cash note. */
  readonly returnedToCash: number
  readonly cashSecretsPromoted: readonly string[]
  readonly cashSecretsCleared: readonly string[]
  readonly destinationsCleared: readonly string[]
  /** Slots still open after this pass. */
  readonly unresolved: readonly string[]
}

/** `probeCredential`: true on a claim match, false on a definite no, undefined when inconclusive. */
async function probe(ctx: Ctx, h: Holding, cred: Credential, asPubkey: string): Promise<{ ok: boolean; amount?: bigint } | undefined> {
  try {
    const r = await ctx.client(h.token).checkClaim(cred, asPubkey)
    return { ok: true, amount: r.amountMillis }
  } catch (err) {
    const code = (err as { code?: string }).code
    if (code === 'claim_not_found' || code === 'spent' || code === 'wallet_error') return { ok: false }
    return undefined
  }
}

export async function settle(ctx: Ctx): Promise<SettleReport> {
  const promotedKeys: string[] = []
  const clearedKeys: string[] = []
  const promotedSecrets: string[] = []
  const clearedSecrets: string[] = []
  const clearedDest: string[] = []
  const rows = await ctx.read((t) => t.list('holdings'))
  for (const h of rows) {
    if (h.status !== 'held') continue
    if (h.pendingThrowawayKey !== undefined) {
      const signer = localSigner(hexBytes(await ctx.open(h.pendingThrowawayKey)))
      const viaKey = await probe(ctx, h, bySigning(signer), signer.pubkey)
      if (viaKey?.ok === true) {
        await ctx.commit((t) => updateHolding(t, h.id, (x) => promoteThrowaway(x), h.version)).then(() => promotedKeys.push(h.id), () => undefined)
        continue
      }
      if (h.cashSecret !== undefined) {
        const viaSecret = await probe(ctx, h, bySecret(await ctx.open(h.cashSecret)), NO_LOCAL_IDENTITY)
        if (viaSecret?.ok === true) {
          await ctx.commit((t) => updateHolding(t, h.id, ({ pendingThrowawayKey: _k, ...x }) => x, h.version)).then(() => clearedKeys.push(h.id), () => undefined)
        }
      }
      continue
    }
    if (h.pendingCashSecret !== undefined) {
      const viaPending = await probe(ctx, h, bySecret(await ctx.open(h.pendingCashSecret)), NO_LOCAL_IDENTITY)
      if (viaPending?.ok === true) {
        const sealed = h.pendingCashSecret
        await ctx
          .commit(async (t) => {
            await updateHolding(
              t,
              h.id,
              ({ pendingCashSecret: _p, throwawayKey: _k, ...x }) => ({ ...x, cashSecret: sealed, mode: 'cash', protection: 'protected' }),
              h.version,
            )
            await appendActivity(t, ctx.now(), { action: 'protect', holdingId: h.id })
          })
          .then(() => promotedSecrets.push(h.id), () => undefined)
        continue
      }
      const current = h.cashSecret !== undefined ? bySecret(await ctx.open(h.cashSecret)) : h.throwawayKey !== undefined ? await ctx.credentialFor(h) : undefined
      if (viaPending?.ok === false && current !== undefined) {
        const viaCurrent = await probe(ctx, h, current, await ctx.claimPubkeyFor(h))
        if (viaCurrent?.ok === true) {
          await ctx.commit((t) => updateHolding(t, h.id, ({ pendingCashSecret: _p, ...x }) => x, h.version)).then(() => clearedSecrets.push(h.id), () => undefined)
        }
      }
      continue
    }
    if ((h.pendingDestinationCashSecret !== undefined || h.pendingRemainderCashSecret !== undefined) && h.amount !== undefined) {
      let cred: Credential
      try {
        cred = await ctx.credentialFor(h)
      } catch {
        continue
      }
      const still = await probe(ctx, h, cred, await ctx.claimPubkeyFor(h))
      if (still?.ok === true && still.amount === h.amount) {
        await ctx.commit((t) => updateHolding(t, h.id, ({ pendingDestinationCashSecret: _d, pendingRemainderCashSecret: _r, ...x }) => x, h.version)).then(() => clearedDest.push(h.id), () => undefined)
      }
    }
  }
  const leftovers = (await ctx.read((t) => t.list('holdings'))).filter((h) => h.status === 'held' && h.throwawayKey !== undefined && h.pendingThrowawayKey === undefined)
  const returnedToCash = await toCashNotes(ctx, leftovers.map((h) => h.id))
  const after = await ctx.read((t) => t.list('holdings'))
  const unresolved = after
    .filter((h) => h.status === 'held' && (h.pendingThrowawayKey !== undefined || h.pendingCashSecret !== undefined || h.pendingDestinationCashSecret !== undefined || h.pendingRemainderCashSecret !== undefined))
    .map((h) => h.id)
  return {
    mergeKeysPromoted: promotedKeys,
    mergeKeysCleared: clearedKeys,
    returnedToCash,
    cashSecretsPromoted: promotedSecrets,
    cashSecretsCleared: clearedSecrets,
    destinationsCleared: clearedDest,
    unresolved,
  }
}
