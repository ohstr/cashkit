// Batched cash_status per node, quotes and `status` (design §6.3, §6.4).
// Port of cashctl cmd/redeem_private.go groupEntriesByHub/quoteHubGroup and
// recordQuote. Bills batch by `nodeKey` (the verified minter, whose
// announcement names the inbox), never by hubGroup (design §6.3).
import { cashCommitment, decodeToken, isCashSecret, isSpent, ownClaim, type CashStatusResult, type NotClaimableReason, type OwnClaim, type RecipientStatus } from '../core/index.js'
import { NotServedError, WalletError, type BatchStatus } from '../client/index.js'
import { validateQuote, type Quote } from './amounts.js'
import { getHeld } from './bills.js'
import { billOf, type Ctx } from './context.js'
import { CashkitError, classifyReadError, notClaimableError } from './errors.js'
import { appendActivity, heldHoldings, updateHolding } from './ledger.js'
import type { Holding } from './model.js'
import { report, type Outcome, type Report } from './report.js'

export type NodeStatus = { readonly state: 'available'; readonly result: CashStatusResult } | { readonly state: 'spent' } | { readonly error: CashkitError }

const noMinter = (id: string) =>
  new CashkitError('invalid_input', 'this token has no verifiable mint signature, so its hub cannot be identified and it cannot be spent', { input: id })

/** Holdings by node key, in first-seen order; those without one are ungrouped. */
export function byNode(hs: readonly Holding[]): { groups: Holding[][]; ungrouped: Holding[] } {
  const m = new Map<string, Holding[]>()
  const ungrouped: Holding[] = []
  for (const h of hs) {
    if (h.minterPubkey === undefined) ungrouped.push(h)
    else m.set(h.minterPubkey, [...(m.get(h.minterPubkey) ?? []), h])
  }
  return { groups: [...m.values()], ungrouped }
}

/**
 * A cash-mode status carries no secret, so the secret is checked against the
 * cash row's commitment when the Hub shows it.
 */
function secretMatches(r: CashStatusResult, secret: string): boolean {
  const row = r.recipients.find((x) => x.identity_type === 'cash' && !x.claimed)
  if (row?.identity_value === undefined) return true
  return isCashSecret(secret) && row.identity_value === cashCommitment(secret)
}

/** One cash_status per holding, one request per node. */
export async function statusByNode(ctx: Ctx, hs: readonly Holding[]): Promise<Map<string, NodeStatus>> {
  const out = new Map<string, NodeStatus>()
  const { groups, ungrouped } = byNode(hs)
  for (const h of ungrouped) out.set(h.id, { error: noMinter(h.id) })
  for (const g of groups) {
    const items: BatchStatus[] = []
    for (const h of g) {
      try {
        items.push({ id: h.id, bill: billOf(h), credential: await ctx.credentialFor(h), scope: 'mine' })
      } catch (err) {
        out.set(h.id, { error: err instanceof CashkitError ? err : classifyReadError(err, h.id) })
      }
    }
    if (items.length === 0) continue
    let r
    try {
      r = await ctx.clientFor(g[0]!).statusMany(items)
    } catch (err) {
      for (const it of items) out.set(it.id!, { error: classifyReadError(err, it.id) })
      continue
    }
    const secrets = new Map(items.flatMap((it) => (it.credential.kind === 'secret' ? [[it.id!, it.credential.secret] as const] : [])))
    for (const o of r.outcomes) {
      const secret = secrets.get(o.id)
      if (o.state === 'result' && o.value !== undefined && secret !== undefined && !secretMatches(o.value, secret)) {
        out.set(o.id, { error: new CashkitError('invalid_input', 'the cash secret does not match this bill: it was received incomplete, or someone else has re-keyed the note', { input: o.id }) })
      } else if (o.state === 'result' && o.value !== undefined) out.set(o.id, isSpent(o.value) ? { state: 'spent' } : { state: 'available', result: o.value })
      else if (o.state === 'error' && o.undecodable) out.set(o.id, { error: new CashkitError('network', "the Hub's answer for this bill could not be read; asking again is safe", { input: o.id }) })
      else if (o.state === 'error' && o.error) out.set(o.id, { error: classifyReadError(new WalletError('cash_status', o.error.code, o.error.message ?? ''), o.id) })
      else out.set(o.id, { error: classifyReadError(r.error ?? new NotServedError('cash_status'), o.id) })
    }
  }
  return out
}

/**
 * The holder's own row of a scope-mine answer (`ownClaim`), found from the
 * holding's credential; undefined when the answer is not exactly that row.
 */
async function ownClaimOf(ctx: Ctx, h: Holding, r: CashStatusResult): Promise<OwnClaim<RecipientStatus> | undefined> {
  try {
    return ownClaim(r.recipients, await ctx.credentialFor(h), ctx.nowSeconds())
  } catch {
    return undefined
  }
}

export interface QuotedHolding {
  readonly holding: Holding
  readonly quote: Quote
}

/**
 * Live quotes for `hs` (`quoteHubGroup` + `recordQuote`): spent bills are
 * tombstoned, figures validated, and amounts recorded in one commit.
 */
export async function quoteMany(ctx: Ctx, hs: readonly Holding[]): Promise<Map<string, QuotedHolding | { error: CashkitError }>> {
  const st = await statusByNode(ctx, hs)
  const out = new Map<string, QuotedHolding | { error: CashkitError }>()
  const spent: string[] = []
  const updates: { id: string; quote: Quote; minTransfer: bigint }[] = []
  for (const h of hs) {
    const s = st.get(h.id)!
    if ('error' in s) {
      out.set(h.id, s)
      continue
    }
    if (s.state === 'spent') {
      spent.push(h.id)
      out.set(h.id, { error: new CashkitError('spent', 'the Hub says this bill is spent: its value has already moved and the bill is gone', { input: h.id }) })
      continue
    }
    const own = await ownClaimOf(ctx, h, s.result)
    if (own === undefined) {
      out.set(h.id, { error: new CashkitError('not_found', "couldn't determine this token's amount: check that it is still valid", { input: h.id }) })
      continue
    }
    if (!own.claimable) {
      out.set(h.id, { error: notClaimableError(own.reason, h.id) })
      continue
    }
    const full = own.row
    const quote: Quote = { amount: full.amount_millis, fee: full.redeem_fee_millis, net: full.net_redeemable_millis, ...(full.expires_at !== undefined && { expiresAt: full.expires_at }) }
    try {
      validateQuote(decodeToken(h.token), h.minterPubkey, quote)
    } catch (err) {
      out.set(h.id, { error: err as CashkitError })
      continue
    }
    updates.push({ id: h.id, quote, minTransfer: full.min_transfer_millis })
  }
  const saved = await ctx.commit(async (t) => {
    const rows = new Map<string, Holding>()
    for (const id of spent) {
      await updateHolding(t, id, (x) => ({ ...x, status: 'spent' }))
      await appendActivity(t, ctx.now(), { action: 'spent', holdingId: id })
    }
    for (const u of updates) {
      rows.set(
        u.id,
        await updateHolding(t, u.id, (x) => {
          const { expiresAt: _e, ...rest } = x
          return { ...rest, amount: u.quote.amount, verified: true, minTransfer: u.minTransfer, ...(u.quote.expiresAt !== undefined && { expiresAt: u.quote.expiresAt }) }
        }),
      )
    }
    return rows
  })
  for (const u of updates) out.set(u.id, { holding: saved.get(u.id)!, quote: u.quote })
  return out
}

export interface StatusOutcome {
  readonly holdingId: string
  readonly state: 'available' | 'spent'
  readonly amount?: bigint
  readonly fee?: bigint
  readonly net?: bigint
  readonly expiresAt?: number
  /** Unclaimed recipients on the bill's wallet, as the Hub lists them. */
  readonly recipients: number
  /** Set when this holder's row is shown but cannot be spent: claimed, withdrawn or expired. */
  readonly notClaimable?: NotClaimableReason
}

/** `status`: asks the Hub about each holding; a spent one is tombstoned. */
export async function status(ctx: Ctx, o: { holdings?: readonly string[] } = {}): Promise<Report<StatusOutcome>> {
  const hs = o.holdings !== undefined ? await Promise.all(o.holdings.map(async (id) => (await ctx.read((t) => t.get('holdings', id))) ?? getHeld(ctx, id))) : await ctx.read(heldHoldings)
  const st = await statusByNode(ctx, hs)
  const outcomes: Outcome<StatusOutcome>[] = []
  const spent: string[] = []
  const amounts: { id: string; amount: bigint; expiresAt?: number }[] = []
  for (const h of hs) {
    const s = st.get(h.id)!
    if ('error' in s) {
      outcomes.push({ ok: false, error: s.error, holdingIds: [h.id] })
      continue
    }
    if (s.state === 'spent') {
      if (h.status === 'held') spent.push(h.id)
      outcomes.push({ ok: true, holdingId: h.id, state: 'spent', recipients: 0 })
      continue
    }
    const own = await ownClaimOf(ctx, h, s.result)
    const full = own?.row
    if (full !== undefined && h.status === 'held') amounts.push({ id: h.id, amount: full.amount_millis, ...(full.expires_at !== undefined && { expiresAt: full.expires_at }) })
    outcomes.push({
      ok: true,
      holdingId: h.id,
      state: 'available',
      recipients: s.result.recipients.filter((x) => !x.claimed).length,
      ...(full !== undefined && { amount: full.amount_millis, fee: full.redeem_fee_millis, net: full.net_redeemable_millis }),
      ...(full?.expires_at !== undefined && { expiresAt: full.expires_at }),
      ...(own !== undefined && !own.claimable && { notClaimable: own.reason }),
    })
  }
  if (spent.length > 0 || amounts.length > 0) {
    await ctx.commit(async (t) => {
      for (const id of spent) {
        await updateHolding(t, id, (x) => ({ ...x, status: 'spent' }))
        await appendActivity(t, ctx.now(), { action: 'spent', holdingId: id })
      }
      for (const a of amounts) {
        await updateHolding(t, a.id, (x) => {
          const { expiresAt: _e, ...rest } = x
          return { ...rest, amount: a.amount, verified: true, ...(a.expiresAt !== undefined && { expiresAt: a.expiresAt }) }
        })
      }
    })
  }
  return report(outcomes)
}
