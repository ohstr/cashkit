// Per-holding Hub calls and the write-ahead slots (design §5.1). Ports cashctl
// cmd/{cash_redeem.go resolveAmount, spent.go markSpent,
// pending_secret_fallback.go spendCashEntry, cash_writeahead.go,
// cash_merge.go moveCashNotesToKey/toCashNotes/promoteThrowaway}.
//
// Every secret is sealed before the transaction that writes it opens: a
// transaction never awaits anything but storage (§3).
import { bySecret, bySigning, decodeToken, localSigner, newCashTarget, pubkeyTarget, toHex, type CashTarget, type CashTransferResult, type Credential, type Target } from '../core/index.js'
import { ClientError, WalletError } from '../client/index.js'
import { validateQuote, type Quote } from './amounts.js'
import type { Ctx } from './context.js'
import { CashkitError, classifyReadError, classifySpendError, isDefiniteRefusal, isNotSent } from './errors.js'
import { appendActivity, notHeldError, updateHolding } from './ledger.js'
import type { Holding, Sealed } from './model.js'

export const sameSealed = (a: Sealed | undefined, b: Sealed | undefined) => a !== undefined && b !== undefined && a.alg === b.alg && a.data === b.data

export async function getHolding(ctx: Ctx, id: string): Promise<Holding> {
  const h = await ctx.read((t) => t.get('holdings', id))
  if (h === undefined) throw new CashkitError('not_found', `no holding ${id}`, { input: id })
  return h
}

export async function getHeld(ctx: Ctx, id: string): Promise<Holding> {
  const h = await getHolding(ctx, id)
  if (h.status !== 'held') throw notHeldError(h)
  return h
}

/** Records the Hub's tombstone (`markSpent`). */
export async function markSpent(ctx: Ctx, id: string): Promise<void> {
  await ctx.commit(async (t) => {
    const h = await t.get('holdings', id)
    if (h?.status !== 'held') return
    await updateHolding(t, id, (x) => ({ ...x, status: 'spent' }))
    await appendActivity(t, ctx.now(), { action: 'spent', holdingId: id })
  })
}

const spentError = (id: string) => new CashkitError('spent', 'the Hub says this bill is spent: its value has already moved and the bill is gone', { input: id })

/**
 * A live quote for a holding (`resolveRedeemQuote`): checks the claim,
 * validates the figures, and records amount, expiry and verified. A spent
 * bill is tombstoned and reported `spent`.
 */
export async function quoteHolding(ctx: Ctx, h: Holding): Promise<{ holding: Holding; quote: Quote }> {
  const cred = await ctx.credentialFor(h)
  const asPubkey = await ctx.claimPubkeyFor(h)
  let r
  try {
    r = await ctx.client(h.token).checkClaim(cred, asPubkey)
  } catch (err) {
    if (err instanceof ClientError && err.code === 'spent') {
      await markSpent(ctx, h.id)
      throw spentError(h.id)
    }
    if (err instanceof ClientError && err.code === 'claim_not_found') {
      throw new CashkitError('not_found', "couldn't determine this token's amount: check that it is still valid", { input: h.id })
    }
    throw classifyReadError(err, h.id)
  }
  const quote: Quote = { amount: r.amountMillis, fee: r.redeemFeeMillis, net: r.netRedeemableMillis, ...(r.expiresAt !== undefined && { expiresAt: r.expiresAt }) }
  validateQuote(decodeToken(h.token), r.minterPubkey, quote)
  const holding = await ctx.commit((t) =>
    updateHolding(t, h.id, (x) => {
      const { expiresAt: _e, ...rest } = x
      return { ...rest, amount: quote.amount, verified: true, ...(quote.expiresAt !== undefined && { expiresAt: quote.expiresAt }) }
    }),
  )
  return { holding, quote }
}

/** The holding's amount: cached, else quoted live (`resolveAmount`). */
export async function liveAmount(ctx: Ctx, h: Holding): Promise<{ holding: Holding; amount: bigint }> {
  if (h.amount !== undefined) return { holding: h, amount: h.amount }
  const { holding, quote } = await quoteHolding(ctx, h)
  return { holding, amount: quote.amount }
}

const isWrongSecretDecline = (err: unknown) => err instanceof WalletError && err.walletCode === 'NOT_FOUND'

/**
 * `spendCashEntry`: places the call; on an explicit NOT_FOUND, and only
 * then, retries once with the holding's pending cash secret (an earlier
 * rekey that landed unseen). Silence is never retried: it may have paid.
 * Returns the promoted secret when the retry worked.
 */
export async function withPendingSecret<T>(ctx: Ctx, h: Holding, cred: Credential, place: (c: Credential) => Promise<T>): Promise<{ result: T; promoted?: Sealed }> {
  try {
    return { result: await place(cred) }
  } catch (err) {
    if (h.pendingCashSecret === undefined || sameSealed(h.pendingCashSecret, h.cashSecret) || !isWrongSecretDecline(err)) throw err
    const pending = await ctx.open(h.pendingCashSecret)
    let result: T
    try {
      result = await place(bySecret(pending))
    } catch {
      throw err
    }
    return { result, promoted: h.pendingCashSecret }
  }
}

/** Applies a promoted pending secret to a row. */
export function promotePending(h: Holding, promoted: Sealed | undefined): Holding {
  if (promoted === undefined) return h
  const { pendingCashSecret: _p, ...rest } = h
  return { ...rest, cashSecret: promoted, protection: 'protected' }
}

/** A destination cash secret parked on a source row before the call (`parkDestinationCashSecret`). */
export interface Park {
  readonly holdingId: string
  readonly sealed: Sealed
}

export async function parkDestination(ctx: Ctx, holdingId: string, target: Target): Promise<Park | undefined> {
  if (target.identityType !== 'cash') return undefined
  const secret = (target as CashTarget).secret
  if (secret === undefined || secret === '') throw new CashkitError('internal', 'a cash-mode target carries no secret, so its destination bill would be unspendable')
  const sealed = await ctx.seal(secret)
  try {
    await ctx.commit((t) => updateHolding(t, holdingId, (h) => ({ ...h, pendingDestinationCashSecret: sealed })))
  } catch (err) {
    throw new CashkitError('internal', 'could not record the destination cash secret before placing the call, so the call was not placed (your funds have not moved)', { cause: err })
  }
  return { holdingId, sealed }
}

/** Clears a park inside a transaction, if it is still ours. */
export function releasePark(h: Holding, park: Park | undefined): Holding {
  if (park === undefined || h.id !== park.holdingId || !sameSealed(h.pendingDestinationCashSecret, park.sealed)) return h
  const { pendingDestinationCashSecret: _d, ...rest } = h
  return rest
}

/** `forgetIfNothingCreated`: a definite failure created nothing, so the park goes; best-effort. */
export async function forgetPark(ctx: Ctx, park: Park | undefined, failure: CashkitError): Promise<void> {
  if (park === undefined || failure.code === 'indeterminate') return
  await ctx.commit((t) => updateHolding(t, park.holdingId, (h) => releasePark(h, park))).catch(() => undefined)
}

/** A fresh throwaway merge key: hex secret and its pubkey. */
export function newThrowawayKey(random: (n: number) => Uint8Array): { priv: string; pub: string } {
  for (;;) {
    const priv = toHex(random(32))
    try {
      return { priv, pub: localSigner(Uint8Array.from(priv.match(/../g)!.map((b) => parseInt(b, 16)))).pubkey }
    } catch {
      // out of range: draw again
    }
  }
}

/** A holding's token moved to a new bill (`followMove`). */
export function followMove(h: Holding, res: Pick<CashTransferResult, 'newWalletToken' | 'newWalletPubkey'>): Holding {
  if (res.newWalletToken === '') return h
  return { ...h, token: res.newWalletToken.toLowerCase(), walletPubkey: res.newWalletPubkey !== '' ? res.newWalletPubkey : h.walletPubkey }
}

/** `promoteThrowaway`: the merge key now controls the bill; it is no longer a cash note. */
export function promoteThrowaway(h: Holding): Holding {
  const { pendingThrowawayKey, cashSecret: _c, ...rest } = h
  return { ...rest, ...(pendingThrowawayKey !== undefined && { throwawayKey: pendingThrowawayKey }), mode: 'pubkey', protection: 'none' }
}

const isCashNote = (h: Holding) => h.throwawayKey === undefined && h.mode === 'cash' && h.cashSecret !== undefined

/**
 * `moveCashNotesToKey`: moves each cash note among `ids` onto the merge
 * key, parking the key first. A definite refusal undoes the earlier moves;
 * an ambiguous one leaves the park for `settle()`. Returns the moved ids.
 */
export async function moveCashNotesToKey(ctx: Ctx, ids: readonly string[], priv: string, pub: string): Promise<string[]> {
  const sealedKey = await ctx.seal(priv)
  const moved: string[] = []
  for (const id of ids) {
    const h = await getHolding(ctx, id)
    if (!isCashNote(h)) continue
    const parked = await ctx.commit((t) => updateHolding(t, id, (x) => ({ ...x, pendingThrowawayKey: sealedKey })))
    let res: CashTransferResult
    try {
      if (parked.amount === undefined) throw new ClientError('no_relay', `${id} has no known amount`)
      res = await ctx.client(parked.token).cashTransfer({ credential: await ctx.credentialFor(parked), to: pubkeyTarget(pub), currentAmount: parked.amount })
    } catch (err) {
      const classified = classifySpendError(err, 'merge', [id])
      if (isNotSent(err) || isDefiniteRefusal(err)) {
        await ctx.commit((t) => updateHolding(t, id, ({ pendingThrowawayKey: _k, ...x }) => x)).catch(() => undefined)
        await toCashNotes(ctx, moved)
        throw classified
      }
      throw classified
    }
    try {
      await ctx.commit((t) => updateHolding(t, id, (x) => promoteThrowaway(followMove(x, res))))
    } catch (err) {
      throw new CashkitError('internal', `Merge (moving a note) succeeded on the Hub, but saving that locally failed — your wallet's local record does not match reality.`, {
        cause: err,
        recovery: `${id} is now spent by the private key ${priv}`,
        recoveryHandoffs: [priv],
      })
    }
    moved.push(id)
  }
  return moved
}

/**
 * `toCashNotes`: returns throwaway-key holdings to cash notes under fresh
 * secrets, parking each secret first. Best-effort: returns how many moved.
 */
export async function toCashNotes(ctx: Ctx, ids: readonly string[]): Promise<number> {
  let converted = 0
  for (const id of ids) {
    let h: Holding
    try {
      h = await getHolding(ctx, id)
    } catch {
      continue
    }
    if (h.throwawayKey === undefined || h.status !== 'held' || h.amount === undefined) continue
    const target = newCashTarget(ctx.random)
    const sealed = await ctx.seal(target.secret)
    try {
      h = await ctx.commit((t) => updateHolding(t, id, (x) => ({ ...x, pendingCashSecret: sealed })))
    } catch {
      continue
    }
    let res: CashTransferResult
    try {
      const signer = localSigner(hexBytes(await ctx.open(h.throwawayKey!)))
      res = await ctx.client(h.token).cashTransfer({ credential: bySigning(signer), to: target, currentAmount: h.amount! })
    } catch (err) {
      if (isDefiniteRefusal(err)) await ctx.commit((t) => updateHolding(t, id, ({ pendingCashSecret: _p, ...x }) => x)).catch(() => undefined)
      continue
    }
    await ctx
      .commit((t) =>
        updateHolding(t, id, (x) => {
          const { pendingCashSecret: _p, throwawayKey: _k, ...rest } = followMove(x, res)
          return { ...rest, cashSecret: sealed, mode: 'cash', protection: 'protected' }
        }),
      )
      .catch(() => undefined)
    converted++
  }
  return converted
}

export const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))
