// Redeem (design §6.3, §7.2). Port of cashctl cmd/cash_redeem.go
// runCashRedeem, resolveHeldTokensForRedeem, selectHeldTokensForRedeemAmount,
// invoiceAmountOverride and makeRedeemInvoices, and cmd/redeem_private.go
// redeemHubGroup, retryWithPendingSecrets and applyRedeemResults.
import { decodeBolt11, decodeToken, type CashRedeemResult } from '../core/index.js'
import { billFor, NotServedError, NwcClient, WalletError, type BatchRedeem } from '../client/index.js'
import { validateRequestedAmount } from './amounts.js'
import { getHeld, getHolding } from './bills.js'
import { isLightning, nwcFor } from './circle.js'
import type { Ctx } from './context.js'
import { CashkitError, classifyReadError, classifySpendError, fromWalletError } from './errors.js'
import { appendActivity, heldHoldings, updateHolding } from './ledger.js'
import type { Connection, Holding } from './model.js'
import { report, type Outcome, type Report } from './report.js'
import { exactSameHubSum } from './select.js'
import { byNode, quoteMany, statusByNode } from './status.js'

export interface RedeemInput {
  /** Exactly this much, net: one holding or a same-hub subset that sums to it. */
  readonly amount?: bigint
  readonly holdings?: readonly string[]
  readonly all?: boolean
  /** A connection name; default the default connection. */
  readonly into?: string
  /** Redeem one holding straight into this invoice instead. */
  readonly invoice?: string
}

export interface RedeemPlanItem {
  readonly holdingId: string
  readonly version: number
  readonly amount: bigint
  readonly fee: bigint
  /** What the destination receives: the invoice amount. */
  readonly net: bigint
  readonly expiresAt?: number
}

export interface RedeemPlan {
  readonly op: 'redeem'
  readonly items: readonly RedeemPlanItem[]
  /** Holdings selected but not redeemable now (spent, unreachable, …). */
  readonly refused: readonly { readonly holdingId: string; readonly error: CashkitError }[]
  readonly destination: { readonly kind: 'connection'; readonly name: string } | { readonly kind: 'invoice'; readonly invoice: string; readonly amount?: bigint }
  readonly total: bigint
  readonly totalFee: bigint
  readonly totalNet: bigint
}

export interface RedeemOutcome {
  readonly holdingId: string
  readonly amount: bigint
  readonly feesPaid: bigint
  readonly preimage: string
  readonly invoice: string
}

const noneHeld = () => new CashkitError('not_found', 'you have no held cash tokens: receive one first')

async function selectByAmount(ctx: Ctx, target: bigint): Promise<Holding[]> {
  const held = (await ctx.read(heldHoldings)).filter((h) => h.amount !== undefined)
  if (held.length === 0) throw noneHeld()
  const quotes = await quoteMany(ctx, held)
  const quoted: { holding: Holding; hubGroup: string; net: bigint }[] = []
  let totalNet = 0n
  for (const h of held) {
    const q = quotes.get(h.id)
    if (q === undefined || 'error' in q) continue
    totalNet += q.quote.net
    if (q.quote.net === target) return [q.holding]
    quoted.push({ holding: q.holding, hubGroup: q.holding.hubGroup, net: q.quote.net })
  }
  const subset = exactSameHubSum(quoted, target)
  if (subset !== undefined) return subset.map((q) => q.holding)
  if (totalNet < target) throw new CashkitError('invalid_input', `not enough funds: you hold ${totalNet} millis net redeemable, need ${target} millis`)
  throw new CashkitError('usage', `funds are fragmented across separate Hubs: you hold ${totalNet} millis total, but no single Hub's tokens sum to exactly the ${target} millis you're redeeming`)
}

async function destinationConnection(ctx: Ctx, into: string | undefined): Promise<Connection> {
  const rows = (await ctx.read((t) => t.list('connections'))).filter((r) => isLightning(r) || r.id === into)
  const c = into !== undefined ? rows.find((r) => r.id === into) : (rows.find((r) => r.isDefault) ?? rows[0])
  if (c === undefined) {
    throw new CashkitError(
      'not_found',
      into !== undefined ? `no connection named "${into}"` : 'no wallet connection to redeem into: add one with wallet.connections.add(), or redeem straight into an invoice',
      into !== undefined ? { input: into } : {},
    )
  }
  if (!isLightning(c)) throw new CashkitError('usage', `"${c.id}" is a Cash Hub connection, not a Lightning wallet to redeem into`, { input: c.id })
  return c
}

export async function planRedeem(ctx: Ctx, o: RedeemInput): Promise<RedeemPlan> {
  let invoiceAmount: bigint | undefined
  if (o.invoice !== undefined) {
    let fixed: bigint
    try {
      fixed = decodeBolt11(o.invoice).amountMillis
    } catch (err) {
      throw new CashkitError('invalid_input', (err as Error).message, { input: o.invoice, cause: err })
    }
    if (fixed > 0n && o.amount !== undefined) throw new CashkitError('usage', `this invoice already asks for ${fixed} millis; amount is only for an invoice that doesn't fix one`)
    if (fixed === 0n && o.amount === undefined) throw new CashkitError('usage', "this invoice doesn't encode an amount: pass amount to say how much to redeem into it")
    if (fixed === 0n) {
      validateRequestedAmount(o.amount!)
      invoiceAmount = o.amount
    }
  } else if (o.amount !== undefined) validateRequestedAmount(o.amount)
  if (o.holdings !== undefined && o.all === true) throw new CashkitError('usage', 'got both holdings and all: pass one or the other')

  let selected: Holding[]
  if (o.amount !== undefined && o.invoice === undefined) {
    if (o.holdings !== undefined || o.all === true) throw new CashkitError('usage', 'got amount with holdings/all: pass one or the other')
    selected = await selectByAmount(ctx, o.amount)
  } else if (o.holdings !== undefined) {
    if (o.holdings.length === 0) throw new CashkitError('usage', 'holdings was given no ids')
    if (new Set(o.holdings).size !== o.holdings.length) throw new CashkitError('usage', 'a holding was named more than once')
    selected = []
    for (const id of o.holdings) selected.push(await getHeld(ctx, id))
  } else {
    const held = await ctx.read(heldHoldings)
    if (held.length === 0) throw noneHeld()
    if (o.all === true || held.length === 1) selected = held
    else throw new CashkitError('usage', `you hold ${held.length} cash tokens: name which with holdings, or pass all to redeem every one`)
  }
  if (o.invoice !== undefined && selected.length > 1) {
    throw new CashkitError('usage', `an invoice is payable once, but ${selected.length} tokens were selected: drop invoice to have them paid into a wallet, or redeem them one at a time`)
  }
  const destination: RedeemPlan['destination'] =
    o.invoice !== undefined ? { kind: 'invoice', invoice: o.invoice, ...(invoiceAmount !== undefined && { amount: invoiceAmount }) } : { kind: 'connection', name: (await destinationConnection(ctx, o.into)).id }

  const quotes = await quoteMany(ctx, selected)
  const items: RedeemPlanItem[] = []
  const refused: RedeemPlan['refused'][number][] = []
  for (const h of selected) {
    const q = quotes.get(h.id)!
    if ('error' in q) {
      refused.push({ holdingId: h.id, error: q.error })
      continue
    }
    if (invoiceAmount !== undefined && invoiceAmount > q.quote.net) {
      refused.push({ holdingId: h.id, error: new CashkitError('invalid_input', `amount ${invoiceAmount} millis exceeds this bill's own net redeemable value of ${q.quote.net} millis`, { input: h.id }) })
      continue
    }
    items.push({ holdingId: h.id, version: q.holding.version, amount: q.quote.amount, fee: q.quote.fee, net: q.quote.net, ...(q.quote.expiresAt !== undefined && { expiresAt: q.quote.expiresAt }) })
  }
  const sum = (f: (i: RedeemPlanItem) => bigint) => items.reduce((a, i) => a + f(i), 0n)
  return { op: 'redeem', items, refused, destination, total: sum((i) => i.amount), totalFee: sum((i) => i.fee), totalNet: sum((i) => i.net) }
}

interface Ready {
  readonly item: RedeemPlanItem
  readonly holding: Holding
  readonly invoice: string
}

export async function executeRedeem(ctx: Ctx, plan: RedeemPlan): Promise<Report<RedeemOutcome>> {
  return ctx.spend(async () => {
    const opId = ctx.newOpId('redeem')
    const outcomes: Outcome<RedeemOutcome>[] = plan.refused.map((r) => ({ ok: false, error: r.error, holdingIds: [r.holdingId] }))
    const live: { item: RedeemPlanItem; holding: Holding }[] = []
    for (const item of plan.items) {
      const h = await getHolding(ctx, item.holdingId)
      if (h.status !== 'held' || h.version !== item.version) {
        throw new CashkitError('conflict', 'your wallet changed since this redeem was planned; plan it again', { input: item.holdingId })
      }
      live.push({ item, holding: h })
    }
    // Invoices first: one per holding, for its net amount (`makeRedeemInvoices`), valid for an hour.
    const ready: Ready[] = []
    const into = plan.destination.kind === 'invoice' ? 'invoice' : plan.destination.name
    let freshInvoice: ((r: Ready) => Promise<string>) | undefined
    if (plan.destination.kind === 'invoice') {
      for (const l of live) ready.push({ ...l, invoice: plan.destination.invoice })
    } else {
      const conn = await destinationConnection(ctx, plan.destination.name)
      const nwc = await nwcFor(ctx, conn)
      freshInvoice = (r) => makeInvoice(nwc, r.item.net)
      for (const l of live) {
        try {
          ready.push({ ...l, invoice: await makeInvoice(nwc, l.item.net) })
        } catch (err) {
          const e = err instanceof WalletError ? fromWalletError(err) : err instanceof CashkitError ? err : classifyReadError(err)
          outcomes.push({ ok: false, error: e, holdingIds: [l.item.holdingId] })
        }
      }
    }
    ctx.emit({ op: 'redeem', phase: 'sent', id: opId })
    const invoiceAmount = plan.destination.kind === 'invoice' ? plan.destination.amount : undefined
    const { groups, ungrouped } = byNode(ready.map((r) => r.holding))
    for (const h of ungrouped) {
      outcomes.push({ ok: false, error: new CashkitError('invalid_input', 'this token has no verifiable mint signature, so its hub cannot be identified and it cannot be spent', { input: h.id }), holdingIds: [h.id] })
    }
    for (const g of groups) {
      const group = g.map((h) => ready.find((r) => r.holding.id === h.id)!)
      outcomes.push(...(await redeemGroup(ctx, group, into, invoiceAmount, freshInvoice)))
    }
    const r = report(outcomes)
    ctx.emit({ op: 'redeem', phase: r.firstError === undefined ? 'committed' : 'failed', id: opId })
    return r
  })
}

/** A redeem invoice the app's NWC wallet makes: `expiry` 3600. */
async function makeInvoice(nwc: NwcClient, amount: bigint): Promise<string> {
  const r = await nwc.makeInvoice({ amount, expiry: INVOICE_EXPIRY })
  const invoice = r['invoice']
  if (typeof invoice !== 'string' || invoice === '') throw new CashkitError('internal', 'the wallet answered make_invoice without an invoice')
  return invoice
}

const INVOICE_EXPIRY = 3600
/** How long past its invoice's expiry a row still claimed is read as paid. */
const CLAIMED_GRACE = 24 * 3600

type Placed = { readonly kind: 'done'; readonly r: Ready; readonly value: CashRedeemResult } | { readonly kind: 'failed'; readonly r: Ready; readonly error: CashkitError; readonly nwcCode?: string } | { readonly kind: 'unclear'; readonly r: Ready; readonly error: CashkitError }

/** One request for these redeems: each item done, refused, or unclear (an `INTERNAL`, an omission or a timeout). */
async function placeRedeems(ctx: Ctx, group: readonly Ready[], invoiceAmount: bigint | undefined): Promise<Placed[]> {
  const items: BatchRedeem[] = []
  for (const r of group) {
    items.push({ id: r.holding.id, bill: billFor(decodeToken(r.holding.token)), invoice: r.invoice, credential: await ctx.credentialFor(r.holding), ...(invoiceAmount !== undefined && { amount: invoiceAmount }) })
  }
  let res
  try {
    res = await ctx.client(group[0]!.holding.token).redeemMany(items)
  } catch (err) {
    return group.map((r) => {
      const e = classifySpendError(err, 'redeem', [r.holding.id])
      return e.code === 'indeterminate' ? { kind: 'unclear' as const, r, error: e } : { kind: 'failed' as const, r, error: e }
    })
  }
  const results = new Map(res.outcomes.map((o) => [o.id, o]))
  return group.map((r): Placed => {
    const id = r.holding.id
    const o = results.get(id)
    if (o?.state === 'result' && o.value !== undefined) return { kind: 'done', r, value: o.value }
    if (o?.state === 'error' && o.undecodable) return { kind: 'unclear', r, error: classifySpendError(new NotServedError('cash_redeem'), 'redeem', [id]) }
    if (o?.state === 'error' && o.error !== undefined) {
      const error = fromWalletError(new WalletError('cash_redeem', o.error.code, o.error.message ?? ''), { cashToken: true, input: id })
      return o.error.code === 'INTERNAL' ? { kind: 'unclear', r, error } : { kind: 'failed', r, error, nwcCode: o.error.code }
    }
    return { kind: 'unclear', r, error: classifySpendError(res.error ?? new NotServedError('cash_redeem'), 'redeem', [id]) }
  })
}

/**
 * One node's redeems in one request (`redeemHubGroup`). `PAYMENT_FAILED`
 * is retried once with a fresh invoice and proof; an unclear outcome is
 * never resent: one `cash_status` read of the row decides it.
 */
async function redeemGroup(ctx: Ctx, group: readonly Ready[], into: string, invoiceAmount: bigint | undefined, freshInvoice: ((r: Ready) => Promise<string>) | undefined): Promise<Outcome<RedeemOutcome>[]> {
  const out: Outcome<RedeemOutcome>[] = []
  const done: { id: string; amount: bigint; value: CashRedeemResult; invoice: string }[] = []
  const unclear: { r: Ready; error: CashkitError }[] = []
  let pending = [...group]
  for (let attempt = 0; attempt < 2 && pending.length > 0; attempt++) {
    const retry: Ready[] = []
    for (const p of await placeRedeems(ctx, pending, invoiceAmount)) {
      const id = p.r.holding.id
      if (p.kind === 'done') done.push({ id, amount: p.r.holding.amount ?? p.r.item.amount, value: p.value, invoice: p.r.invoice })
      else if (p.kind === 'unclear') unclear.push({ r: p.r, error: p.error })
      else if (p.nwcCode === 'PAYMENT_FAILED' && freshInvoice !== undefined && attempt === 0) {
        try {
          retry.push({ ...p.r, invoice: await freshInvoice(p.r) })
        } catch {
          out.push({ ok: false, error: p.error, holdingIds: [id] })
        }
      } else out.push({ ok: false, error: p.error, holdingIds: [id] })
    }
    pending = retry
  }
  out.push(...(await readUnclear(ctx, unclear, into)))
  if (done.length === 0) return out
  try {
    await ctx.commit(async (t) => {
      for (const d of done) {
        await updateHolding(t, d.id, (x) => ({ ...x, status: 'redeemed' }))
        await appendActivity(t, ctx.now(), { action: 'redeem', amount: d.amount, feesPaid: d.value.feesPaid, into, holdingIds: [d.id] })
      }
    })
  } catch (err) {
    const lines = done.map((d) => `${d.id} was redeemed (invoice ${d.invoice}, preimage ${d.value.preimage})`)
    const e = new CashkitError('internal', "Redeem succeeded on the Hub, but saving that locally failed — your wallet's local record does not match reality.", {
      cause: err,
      recovery: lines.join('\n'),
      recoveryHandoffs: done.map((d) => d.value.preimage),
    })
    for (const d of done) out.push({ ok: false, error: e, holdingIds: [d.id] })
    return out
  }
  for (const d of done) out.push({ ok: true, holdingId: d.id, amount: d.amount, feesPaid: d.value.feesPaid, preimage: d.value.preimage, invoice: d.invoice })
  return out
}

/**
 * The one `cash_status` read after an unclear redeem: unclaimed ⇒ live
 * (nothing was paid); a tombstone ⇒ spent; claimed, or no answer ⇒
 * `redeeming`, re-read by every `settle()`.
 */
async function readUnclear(ctx: Ctx, unclear: readonly { r: Ready; error: CashkitError }[], into: string): Promise<Outcome<RedeemOutcome>[]> {
  if (unclear.length === 0) return []
  const st = await statusByNode(ctx, unclear.map((u) => u.r.holding))
  const out: Outcome<RedeemOutcome>[] = []
  const now = ctx.nowSeconds()
  for (const { r, error } of unclear) {
    const id = r.holding.id
    const s = st.get(id)
    if (s !== undefined && 'state' in s && s.state === 'spent') {
      await ctx.commit(async (t) => {
        await updateHolding(t, id, (x) => ({ ...x, status: 'spent' }))
        await appendActivity(t, ctx.now(), { action: 'spent', holdingId: id })
      })
      out.push({ ok: false, error: new CashkitError('spent', 'the Hub says this bill is gone: its value has already moved', { input: id }), holdingIds: [id] })
      continue
    }
    if (s !== undefined && 'state' in s && s.state === 'available' && !s.result.recipients.some((x) => x.claimed)) {
      const code = error.code === 'indeterminate' || error.code === 'internal' ? 'network' : error.code
      out.push({ ok: false, error: new CashkitError(code, 'the redeem did not go through and nothing was paid: the bill is still yours, redeem it again', { input: id, ...(error.nwcCode !== undefined && { nwcCode: error.nwcCode }), cause: error }), holdingIds: [id] })
      continue
    }
    await ctx.commit((t) => updateHolding(t, id, (x) => ({ ...x, status: 'redeeming', redeem: { invoice: r.invoice, into, invoiceExpiresAt: now + INVOICE_EXPIRY, since: now } })))
    out.push({
      ok: false,
      error: new CashkitError('indeterminate', 'the Hub has claimed this bill for the payment, but whether it paid is not known yet: settle() checks it again; do not redeem it again', { input: id, reason: 'redeem_in_flight', cause: error }),
      holdingIds: [id],
    })
  }
  return out
}

export interface RedeemingReport {
  /** Back to held: the payment failed (the row is unclaimed); redeem again. */
  readonly released: readonly string[]
  /** Paid: the invoice settled, or the row stayed claimed a day past the invoice's expiry. */
  readonly redeemed: readonly string[]
  /** Gone: the Hub answered with a tombstone. */
  readonly spent: readonly string[]
  readonly stillRedeeming: readonly string[]
}

/** Re-reads every `redeeming` holding (run by `settle()`). */
export async function settleRedeeming(ctx: Ctx): Promise<RedeemingReport> {
  const rows = (await ctx.read((t) => t.list('holdings'))).filter((h) => h.status === 'redeeming')
  const rep = { released: [] as string[], redeemed: [] as string[], spent: [] as string[], stillRedeeming: [] as string[] }
  if (rows.length === 0) return rep
  const st = await statusByNode(ctx, rows)
  const now = ctx.nowSeconds()
  for (const h of rows) {
    const s = st.get(h.id)
    const info = h.redeem
    let next: 'held' | 'redeemed' | 'spent' | undefined
    if (s !== undefined && 'state' in s && s.state === 'spent') next = 'spent'
    else if (s !== undefined && 'state' in s && s.state === 'available' && !s.result.recipients.some((x) => x.claimed)) next = 'held'
    else if (info !== undefined) {
      if (info.into !== 'invoice' && (await invoiceSettled(ctx, info.into, info.invoice))) next = 'redeemed'
      else if (s !== undefined && 'state' in s && now > (info.invoiceExpiresAt ?? info.since + INVOICE_EXPIRY) + CLAIMED_GRACE) next = 'redeemed'
    }
    if (next === undefined) {
      rep.stillRedeeming.push(h.id)
      continue
    }
    const status = next
    await ctx.commit(async (t) => {
      await updateHolding(t, h.id, (x) => {
        const { redeem: _r, ...rest } = x
        return { ...rest, status } as Holding
      })
      if (status === 'spent') await appendActivity(t, ctx.now(), { action: 'spent', holdingId: h.id })
      if (status === 'redeemed') await appendActivity(t, ctx.now(), { action: 'redeem', amount: h.amount ?? 0n, feesPaid: 0n, into: info?.into ?? 'invoice', holdingIds: [h.id] })
    })
    ;(status === 'held' ? rep.released : status === 'redeemed' ? rep.redeemed : rep.spent).push(h.id)
  }
  return rep
}

/** Whether the app's NWC wallet reports the invoice paid; any failure reads as not yet. */
async function invoiceSettled(ctx: Ctx, connection: string, invoice: string): Promise<boolean> {
  try {
    const c = await ctx.read((t) => t.get('connections', connection))
    if (c === undefined || !isLightning(c)) return false
    const r = await (await nwcFor(ctx, c)).lookupInvoice(invoice)
    return typeof r.settled_at === 'number' && r.settled_at > 0
  } catch {
    return false
  }
}
