// Redeem (design §6.3, §7.2). Port of cashctl cmd/cash_redeem.go
// runCashRedeem, resolveHeldTokensForRedeem, selectHeldTokensForRedeemAmount,
// invoiceAmountOverride and makeRedeemInvoices, and cmd/redeem_private.go
// redeemHubGroup, retryWithPendingSecrets and applyRedeemResults.
import { decodeBolt11, decodeToken, type CashRedeemResult } from '../core/index.js'
import { billFor, NotServedError, NwcClient, WalletError, type BatchRedeem } from '../client/index.js'
import { validateRequestedAmount } from './amounts.js'
import { getHeld, getHolding } from './bills.js'
import type { Ctx } from './context.js'
import { CashkitError, classifyReadError, classifySpendError, fromWalletError } from './errors.js'
import { appendActivity, heldHoldings, updateHolding } from './ledger.js'
import type { Connection, Holding } from './model.js'
import { report, type Outcome, type Report } from './report.js'
import { exactSameHubSum } from './select.js'
import { byNode, quoteMany } from './status.js'

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

async function destinationConnection(ctx: Ctx, into: string | undefined): Promise<Connection & { uri: NonNullable<Connection['uri']> }> {
  const rows = (await ctx.read((t) => t.list('connections'))).filter((r) => r.uri !== undefined || r.id === into)
  const c = into !== undefined ? rows.find((r) => r.id === into) : (rows.find((r) => r.isDefault) ?? rows[0])
  if (c === undefined) {
    throw new CashkitError(
      'not_found',
      into !== undefined ? `no connection named "${into}"` : 'no wallet connection to redeem into: add one with wallet.connections.add(), or redeem straight into an invoice',
      into !== undefined ? { input: into } : {},
    )
  }
  if (c.uri === undefined) throw new CashkitError('usage', `"${c.id}" is a Cash Hub connection, not a Lightning wallet to redeem into`, { input: c.id })
  return c as Connection & { uri: NonNullable<Connection['uri']> }
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
    // Invoices first: one per holding, for its net amount (`makeRedeemInvoices`).
    const ready: Ready[] = []
    const into = plan.destination.kind === 'invoice' ? 'invoice' : plan.destination.name
    if (plan.destination.kind === 'invoice') {
      for (const l of live) ready.push({ ...l, invoice: plan.destination.invoice })
    } else {
      const conn = await destinationConnection(ctx, plan.destination.name)
      const nwc = new NwcClient(ctx.clientDeps, await ctx.open(conn.uri))
      for (const l of live) {
        try {
          const r = await nwc.makeInvoice({ amount: l.item.net })
          const invoice = r['invoice']
          if (typeof invoice !== 'string' || invoice === '') throw new CashkitError('internal', 'the wallet answered make_invoice without an invoice')
          ready.push({ ...l, invoice })
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
      outcomes.push(...(await redeemGroup(ctx, group, into, invoiceAmount)))
    }
    const r = report(outcomes)
    ctx.emit({ op: 'redeem', phase: r.firstError === undefined ? 'committed' : 'failed', id: opId })
    return r
  })
}

/** One node's redeems in one request (`redeemHubGroup`). */
async function redeemGroup(ctx: Ctx, group: readonly Ready[], into: string, invoiceAmount: bigint | undefined): Promise<Outcome<RedeemOutcome>[]> {
  const items: BatchRedeem[] = []
  for (const r of group) {
    items.push({ id: r.holding.id, bill: billFor(decodeToken(r.holding.token)), invoice: r.invoice, credential: await ctx.credentialFor(r.holding), ...(invoiceAmount !== undefined && { amount: invoiceAmount }) })
  }
  const ids = group.map((r) => r.holding.id)
  let res
  try {
    res = await ctx.client(group[0]!.holding.token).redeemMany(items)
  } catch (err) {
    return ids.map((id) => ({ ok: false as const, error: classifySpendError(err, 'redeem', [id]), holdingIds: [id] }))
  }
  const results = new Map(res.outcomes.map((o) => [o.id, o]))
  const out: Outcome<RedeemOutcome>[] = []
  const done: { id: string; amount: bigint; value: CashRedeemResult; invoice: string }[] = []
  for (const r of group) {
    const id = r.holding.id
    const o = results.get(id)
    if (o?.state === 'result' && o.value !== undefined) {
      done.push({ id, amount: r.holding.amount ?? r.item.amount, value: o.value, invoice: r.invoice })
    } else if (o?.state === 'error' && o.undecodable) {
      out.push({ ok: false, error: classifySpendError(new NotServedError('cash_redeem'), 'redeem', [id]), holdingIds: [id] })
    } else if (o?.state === 'error' && o.error !== undefined) {
      out.push({ ok: false, error: fromWalletError(new WalletError('cash_redeem', o.error.code, o.error.message ?? ''), { cashToken: true, input: id }), holdingIds: [id] })
    } else {
      out.push({ ok: false, error: classifySpendError(res.error ?? new NotServedError('cash_redeem'), 'redeem', [id]), holdingIds: [id] })
    }
  }
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
