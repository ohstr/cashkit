// Per-holding Hub calls and the holding locks (design §5.1). Ports cashctl
// cmd/{cash_redeem.go resolveAmount, spent.go markSpent,
// cash_merge.go moveCashNotesToKey/toCashNotes}. A holding an open pending
// call names is locked: no plan picks it until the call closes.
//
// Every secret is sealed before the transaction that writes it opens: a
// transaction never awaits anything but storage (§3).
import { decodeToken, localSigner, newCashTarget, pubkeyTarget, toHex } from '../core/index.js'
import { ClientError } from '../client/index.js'
import { validateQuote, type Quote } from './amounts.js'
import type { Ctx } from './context.js'
import { CashkitError, classifyReadError, notClaimableError } from './errors.js'
import { appendActivity, notHeldError, updateHolding } from './ledger.js'
import { runTransfer } from './kinds.js'
import type { Holding } from './model.js'

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
  let r
  try {
    r = await ctx.clientFor(h).checkClaim(cred)
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
  if (!r.claimable) throw notClaimableError(r.reason, h.id)
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

const isCashNote = (h: Holding) => h.throwawayKey === undefined && h.mode === 'cash' && h.cashSecret !== undefined

/** Holdings an open call names as source or authorizer: excluded from every plan until it closes (I-4). */
export async function lockedHoldings(ctx: Ctx): Promise<Set<string>> {
  const calls = await ctx.read((t) => t.list('pendingCalls'))
  const out = new Set<string>()
  for (const c of calls) {
    if (c.state === 'done') continue
    for (const id of c.sources) out.add(id)
    if (c.authorizer.kind === 'cash') out.add(c.authorizer.holdingId)
  }
  return out
}

/** Refuses a holding an open call holds (I-4). */
export async function requireUnlocked(ctx: Ctx, ids: readonly string[]): Promise<void> {
  const locked = await lockedHoldings(ctx)
  const busy = ids.filter((id) => locked.has(id))
  if (busy.length > 0) throw new CashkitError('conflict', `${busy.join(',')} is in a call that has not finished; settle() resolves it. Nothing was changed`, { input: busy.join(',') })
}

/**
 * `moveCashNotesToKey`: moves each cash note among `ids` onto the merge
 * key, each move its own call. A definite refusal moves the earlier ones
 * back to cash notes; a call left open stays for `settle()`. Returns the
 * moved ids.
 */
export async function moveCashNotesToKey(ctx: Ctx, ids: readonly string[], priv: string, pub: string): Promise<string[]> {
  const moved: string[] = []
  for (const id of ids) {
    const h = await getHolding(ctx, id)
    if (!isCashNote(h)) continue
    try {
      await runTransfer(ctx, { op: 'move', source: h, to: pubkeyTarget(pub), destination: { kind: 'throwaway', pubkey: pub, key: priv }, keep: 'holding', amount: h.amount ?? 0n })
    } catch (err) {
      if (!(err instanceof CashkitError && err.pendingCallId !== undefined)) await toCashNotes(ctx, moved)
      throw err
    }
    moved.push(id)
  }
  return moved
}

/**
 * `toCashNotes`: returns merge-key holdings to cash notes under fresh
 * secrets, each its own call. Best-effort: returns how many moved.
 */
export async function toCashNotes(ctx: Ctx, ids: readonly string[]): Promise<number> {
  let converted = 0
  const locked = await lockedHoldings(ctx)
  for (const id of ids) {
    let h: Holding
    try {
      h = await getHolding(ctx, id)
    } catch {
      continue
    }
    if (h.throwawayKey === undefined || h.status !== 'held' || h.amount === undefined || locked.has(id)) continue
    const target = newCashTarget(ctx.random)
    try {
      await runTransfer(ctx, { op: 'to_cash', source: h, to: target, destination: { kind: 'cash', secret: target.secret }, keep: 'holding', amount: h.amount })
      converted++
    } catch {
      // an open call is settled later; a refusal leaves the merge key holding as it is
    }
  }
  return converted
}

export const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))
