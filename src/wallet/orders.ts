// Orders (NIP-CO): buying a bill from a Cash Hub through its Order
// connection. Placing is a `cash_order` pending call, written ahead with
// its recipient's secret or buyer key, `notify` and request id; the call
// stays `open_order` until the order is finished, read by `cash_lookup` on
// a notice, a poll or demand. Bills that arrive become holdings marked
// ordered; a gift's bills stay with their recipient.
import {
  cashOrderRequest,
  localSigner,
  confirmationsFor,
  decodeLookupDone,
  endedUnpaid,
  finished,
  newBuyerKey,
  newCashOrderTarget,
  newNotify,
  newRequestId,
  orderFee,
  parseOrder,
  validateTerms,
  type MintRecipient,
  type Order,
  type OrderTerms,
  type Payment,
} from '../core/index.js'
import { ClientError, connectOrder, deadlineFor, WalletError, type ConnectOrderOptions, type HubView, type OrderClient } from '../client/index.js'
import { prepareCall, finishCall, type PlainOutput } from './calls.js'
import { tokenFacts, type Ctx } from './context.js'
import { CashkitError, fromWalletError } from './errors.js'
import { addHolding, appendActivity, updateHolding } from './ledger.js'
import type { CallCreated, OrderRecord, PendingCall } from './model.js'
import type { StorageTx } from './ports.js'
import { executeCall, pocketHooks, registerCallKind, type CallKind } from './runner.js'
import { parseTarget } from './target.js'

export type OrderTo = 'cash' | 'self' | string

export interface OrderQuote {
  readonly terms: OrderTerms
  readonly payment: Payment
  readonly amountMillis: bigint
  readonly feeMillis: bigint
  readonly payMillis: bigint
  /** On-chain: the confirmations that apply to `payMillis`. */
  readonly confirmations?: number
  /** The redeem fee the bill will carry, at its full amount. */
  readonly billRedeemFeeMillis: bigint
  readonly minTransferMillis: bigint
  readonly hub: HubView
}

export type OrderWarning = 'pay_before' | 'amount_mints_bill' | 'late_payment_kept' | 'per_output_fee' | 'fee_floor'

/** An order as the app shows it: never the buyer key, a secret, `notify` or the request id. */
export interface OrderView {
  readonly id: string
  readonly state: OrderRecord['state']
  readonly payment: Payment
  readonly amountMillis: bigint
  readonly feeMillis: bigint
  readonly payMillis: bigint
  /** Shown for payment only when the reply was valid. */
  readonly invoice?: string
  readonly address?: string
  readonly confirmations?: number
  readonly payBy: number
  /** Pay before this: `payBy`, or the invoice's own expiry when that comes first. */
  readonly payDeadline: number
  readonly bills: OrderRecord['bills']
  readonly finished: boolean
  readonly endedUnpaid: boolean
  readonly termsChanged: boolean
  readonly invalidReply?: string
  /** A gift: its bills go to someone else, and no holding is made. */
  readonly gift: boolean
  readonly warnings: readonly OrderWarning[]
}

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))

function connectError(err: unknown): CashkitError {
  if (err instanceof CashkitError) return err
  if (err instanceof WalletError) return fromWalletError(err)
  if (err instanceof ClientError) {
    switch (err.code) {
      case 'connection_invalid':
      case 'connection_mismatch':
        return new CashkitError('invalid_input', err.message, { reason: err.code, cause: err })
      case 'connection_unverified':
        return new CashkitError('auth', err.message, { reason: err.code, cause: err })
      case 'order_not_sold':
        return new CashkitError('not_found', err.message, { reason: 'not_selling', cause: err })
      case 'order_unavailable':
      case 'hub_unusable':
        return new CashkitError('not_found', err.message, { reason: err.code, cause: err })
      default:
        return new CashkitError('network', `the Order connection could not be reached, so nothing was sent: ${err.message}`, { cause: err })
    }
  }
  return new CashkitError('network', (err as Error).message, { cause: err })
}

async function connect(ctx: Ctx, s: string, o: ConnectOrderOptions): Promise<OrderClient> {
  try {
    return await connectOrder(ctx.clientDeps, s, o)
  } catch (err) {
    throw connectError(err)
  }
}

function kindTerms(terms: OrderTerms, payment: Payment, amountMillis: bigint) {
  const k = payment === 'lightning' ? terms.lightning : terms.onchain
  if (k === undefined) throw new CashkitError('invalid_input', `this Hub does not sell ${payment} orders`, { reason: 'payment_not_sold' })
  if (amountMillis < k.minMillis || amountMillis > k.maxMillis) throw new CashkitError('invalid_input', `the amount must be from ${k.minMillis} to ${k.maxMillis} millis`, { reason: 'amount_out_of_range' })
  if (payment === 'onchain' && amountMillis % 1000n !== 0n) throw new CashkitError('invalid_input', 'an on-chain order is for a whole number of base units (a multiple of 1000 millis)', { reason: 'amount_out_of_range' })
  return k
}

function quoteOf(terms: OrderTerms, payment: Payment, amountMillis: bigint) {
  const k = kindTerms(terms, payment, amountMillis)
  const { feeMillis, payMillis } = orderFee(payment, k, amountMillis)
  return {
    feeMillis,
    payMillis,
    ...(payment === 'onchain' && { confirmations: confirmationsFor(k.confirmations ?? [], payMillis) }),
    billRedeemFeeMillis: terms.bill.redeemFeeBase + (terms.bill.redeemFeePpm * amountMillis) / 1_000_000n,
    minTransferMillis: terms.bill.minTransferMillis,
  }
}

/** The terms, the order fee, what to pay, the confirmations and the bill's redeem fee. Nothing is written. */
export async function quoteOrder(ctx: Ctx, connection: string, o: { amountMillis: bigint; payment: Payment; confirmUnverified?: (v: HubView) => Promise<boolean> }): Promise<OrderQuote> {
  const c = await connect(ctx, connection, { ...(o.confirmUnverified !== undefined && { confirmUnverified: o.confirmUnverified }) })
  const terms = await c.terms().catch((err: unknown) => {
    throw connectError(err)
  })
  try {
    validateTerms(terms)
  } catch (err) {
    throw new CashkitError('invalid_input', (err as Error).message, { reason: 'terms_invalid', cause: err })
  }
  return { terms, payment: o.payment, amountMillis: o.amountMillis, ...quoteOf(terms, o.payment, o.amountMillis), hub: c.view() }
}

export interface PlaceOrderInput {
  /** The `cashorder1` string. */
  readonly connection: string
  readonly amountMillis: bigint
  readonly payment: Payment
  /** `cash` (default: a cash holding of this wallet), `self` (this wallet's identity), or a pubkey, npub, NIP-05 name or nconnection (a gift). */
  readonly to?: OrderTo
  readonly ia?: string
  readonly confirmUnverified?: (v: HubView) => Promise<boolean>
}

/**
 * Places an order as one `cash_order` pending call: the terms are read
 * again and the amount checked locally; the request id, `notify` and the
 * recipient's secret (whose buyer key it derives) or a fresh buyer key are
 * written ahead with the call before anything is sent. The reply opens the
 * order (`open_order`); a lost reply is settled by lookup, and an `unknown`
 * one waits for the user (a new order asks for a new payment).
 */
export async function placeOrder(ctx: Ctx, o: PlaceOrderInput): Promise<OrderView> {
  const c = await connect(ctx, o.connection, { ...(o.confirmUnverified !== undefined && { confirmUnverified: o.confirmUnverified }) })
  const terms = await c.terms().catch((err: unknown) => {
    throw connectError(err)
  })
  const q = quoteOf(terms, o.payment, o.amountMillis)
  const to = (o.to ?? 'cash').trim()
  let recipient: MintRecipient
  let buyerKey: string
  let output: PlainOutput['destination']
  let keep: 'holding' | 'gift'
  let display: string
  if (to === 'cash') {
    const t = newCashOrderTarget(ctx.random)
    recipient = { identityType: 'cash', identityValue: t.identityValue, amountMillis: o.amountMillis }
    buyerKey = t.buyerKey.secretKey
    output = { kind: 'cash', secret: t.secret }
    keep = 'holding'
    display = 'cash'
  } else if (to === 'self') {
    const pubkey = (await ctx.requireSigner()).pubkey
    recipient = { identityType: 'pubkey', identityValue: pubkey, amountMillis: o.amountMillis }
    buyerKey = newBuyerKey(ctx.random).secretKey
    output = { kind: 'pubkey', pubkey }
    keep = 'holding'
    display = 'self'
  } else {
    const rt = await parseTarget(to, { ...(o.ia !== undefined && { ia: o.ia }), ...(ctx.deps.fetch !== undefined && { fetch: ctx.deps.fetch }), random: ctx.random })
    if (rt.kind === 'cash') throw new CashkitError('usage', 'order cash for yourself with to: "cash"')
    recipient = { identityType: rt.target.identityType as MintRecipient['identityType'], identityValue: rt.target.identityValue, ...(rt.target.iaPubkey !== '' && { iaPubkey: rt.target.iaPubkey }), amountMillis: o.amountMillis }
    buyerKey = newBuyerKey(ctx.random).secretKey
    output = rt.target.identityType === 'connection_key' ? { kind: 'connection_key', key: rt.target.identityValue, platform: '', ia: rt.target.iaPubkey } : { kind: 'pubkey', pubkey: rt.target.identityValue }
    keep = 'gift'
    display = rt.display
  }
  const requestId = newRequestId(ctx.random)
  const notify = newNotify(ctx.random)
  // Validated before anything is written.
  try {
    cashOrderRequest({ recipient, amountMillis: o.amountMillis, payment: o.payment, notify, requestId })
  } catch (err) {
    throw new CashkitError('invalid_input', (err as Error).message, { cause: err })
  }
  const call = await prepareCall(ctx, {
    kind: 'order',
    requestId,
    method: 'cash_order',
    target: c.connection.walletPubkey,
    node: c.connection.hubIdentity,
    relays: c.session.relays,
    deadline: deadlineFor(c.session.maxRequestAge, ctx.nowSeconds()),
    hAtSend: c.session.maxRequestAge!,
    amount: o.amountMillis,
    sources: [],
    authorizer: { kind: 'buyer', key: buyerKey },
    outputs: [{ role: 'new', destination: output }],
    context: { op: 'order' },
    params: {
      connection: o.connection.trim(),
      payment: o.payment,
      recipient: JSON.stringify({ t: recipient.identityType, v: recipient.identityValue, ...(recipient.iaPubkey !== undefined && { ia: recipient.iaPubkey }) }),
      notify,
      keep,
      display,
      quotedFee: q.feeMillis.toString(),
      ...(q.confirmations !== undefined && { quotedConfirmations: String(q.confirmations) }),
      chain: c.chain,
      ...(c.network !== undefined && { network: c.network }),
    },
  })
  await executeCall(ctx, call)
  return orderView((await ctx.read((t) => t.get('pendingCalls', call.id)))!)
}

function requestOf(call: PendingCall) {
  const p = call.params ?? {}
  const r = JSON.parse(p['recipient'] ?? '{}') as { t: MintRecipient['identityType']; v: string; ia?: string }
  return cashOrderRequest({
    recipient: { identityType: r.t, identityValue: r.v, ...(r.ia !== undefined && { iaPubkey: r.ia }), amountMillis: call.amount },
    amountMillis: call.amount,
    payment: p['payment'] as Payment,
    notify: p['notify']!,
    requestId: call.requestId,
  })
}

async function buyerKeyOf(ctx: Ctx, call: PendingCall): Promise<string> {
  if (call.authorizer.kind !== 'buyer') throw new CashkitError('internal', 'an order call is authorized by its buyer key')
  return ctx.open(call.authorizer.buyerKey)
}

/** The record an order reply or lookup gives, merged with what was known. */
function recordOf(call: PendingCall, order: Order, now: number, holdingByWallet: ReadonlyMap<string, string>): OrderRecord {
  const p = call.params ?? {}
  const prev = call.order
  const sawProgress = (prev?.sawProgress ?? false) || order.state === 'paid' || order.state === 'minted' || order.state === 'closed'
  const quotedFee = p['quotedFee'] !== undefined ? BigInt(p['quotedFee']) : undefined
  const quotedConf = p['quotedConfirmations'] !== undefined ? Number(p['quotedConfirmations']) : undefined
  const termsChanged = (prev?.termsChanged ?? false) || (quotedFee !== undefined && order.feeMillis !== quotedFee) || (quotedConf !== undefined && order.confirmations !== undefined && order.confirmations !== quotedConf)
  const ended = endedUnpaid(order, { heldReply: true, sawProgress, now })
  return {
    state: order.state,
    payment: order.payment,
    amountMillis: order.amountMillis,
    feeMillis: order.feeMillis,
    payMillis: order.payMillis,
    ...(order.invoice !== undefined && { invoice: order.invoice }),
    ...(order.invoiceExpiresAt !== undefined && { invoiceExpiresAt: order.invoiceExpiresAt }),
    ...(order.address !== undefined && { address: order.address }),
    ...(order.confirmations !== undefined && { confirmations: order.confirmations }),
    payBy: order.payBy,
    bills: order.bills.map((b) => ({
      walletPubkey: b.walletPubkey,
      amountMillis: b.amountMillis,
      paidMillis: b.paidMillis,
      ...(b.outpoint !== undefined && { outpoint: b.outpoint }),
      ...(holdingByWallet.get(b.walletPubkey) !== undefined && { holdingId: holdingByWallet.get(b.walletPubkey)! }),
      spent: typeof b.token !== 'string',
    })),
    sawProgress,
    ...(termsChanged && { termsChanged: true }),
    ...(ended && { endedUnpaid: true }),
    finished: finished(order) || ended,
    checkedAt: now,
  }
}

/**
 * Applies an order as it stands: each live bill this wallet keeps becomes an
 * ordered holding (once, by its wallet pubkey); a tombstoned bill marks its
 * holding spent; the record replaces the last one. The call stays
 * `open_order` until the order is finished.
 */
async function applyOrder(ctx: Ctx, t: StorageTx, call: PendingCall, order: Order): Promise<CallCreated> {
  const cur = (await t.get('pendingCalls', call.id))!
  const keep = call.params?.['keep'] === 'holding'
  const out = call.outputs[0]?.destination
  const byWallet = new Map<string, string>()
  const all = await t.list('holdings')
  const created: string[] = []
  for (const b of order.bills) {
    const existing = all.find((h) => h.walletPubkey === b.walletPubkey)
    if (existing !== undefined) {
      byWallet.set(b.walletPubkey, existing.id)
      if (typeof b.token !== 'string' && existing.status === 'held') {
        await updateHolding(t, existing.id, (x) => ({ ...x, status: 'spent' }))
        await appendActivity(t, ctx.now(), { action: 'spent', holdingId: existing.id })
      }
      continue
    }
    if (!keep || typeof b.token !== 'string' || out === undefined) continue
    const f = tokenFacts(b.token)
    const h = await addHolding(
      t,
      {
        token: b.token,
        walletPubkey: b.walletPubkey,
        hubGroup: f.hubGroup,
        relayUrls: f.tok.relays,
        amount: b.amountMillis,
        verified: true,
        ...(out.kind === 'cash' ? { mode: 'cash' as const, protection: 'protected' as const, cashSecret: out.secret } : { mode: 'pubkey' as const, protection: 'none' as const }),
        ...(f.minterPubkey !== undefined && { minterPubkey: f.minterPubkey, minterXonly: f.minterPubkey.length === 66 ? f.minterPubkey.slice(2) : f.minterPubkey }),
        origin: 'ordered',
        ordered: true,
      },
      { now: ctx.now(), random: ctx.random },
    )
    byWallet.set(b.walletPubkey, h.id)
    created.push(h.id)
    await appendActivity(t, ctx.now(), { action: 'receive', amount: b.amountMillis, holdingId: h.id, mode: h.mode })
  }
  const record = recordOf(cur, order, ctx.nowSeconds(), byWallet)
  await t.put('pendingCalls', { ...cur, order: record, state: 'open_order', version: cur.version + 1 }, cur.version)
  // A finished order closes its call; the record stays readable (a closed on-chain order may still gain bills).
  if (record.finished) await finishCall(t, call.id, 'applied')
  return { holdingIds: created }
}

const n = (v: unknown) => (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : 0n)

/** A reply the Hub committed but this wallet will not show for payment: the order stays open, flagged. */
function invalidRecord(call: PendingCall, raw: unknown, reason: string, now: number): OrderRecord {
  const o = (raw !== null && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  return {
    state: 'open',
    payment: (call.params?.['payment'] as 'lightning' | 'onchain') ?? 'lightning',
    amountMillis: call.amount,
    feeMillis: n(o['fee_millis']),
    payMillis: n(o['pay_millis']),
    payBy: typeof o['pay_by'] === 'number' ? o['pay_by'] : 0,
    bills: [],
    sawProgress: false,
    invalidReply: reason,
    finished: false,
    checkedAt: now,
  }
}

function parseFor(call: PendingCall, raw: unknown, lookup: boolean): Order {
  const p = call.params ?? {}
  return parseOrder(raw, { request: { payment: p['payment'] as Payment, amount_millis: call.amount }, hubIdentity: call.node, lookup, ...(p['chain'] !== undefined && { chain: p['chain'] }), ...(p['network'] !== undefined && { network: p['network'] }) })
}

const orderKind: CallKind = {
  autoReplace: false,
  async place(ctx, call, beforePublish) {
    const c = await connect(ctx, call.params?.['connection'] ?? '', { confirmUnverified: () => Promise.resolve(true) })
    const outcome = await c.place(requestOf(call), { buyerKey: await buyerKeyOf(ctx, call), send: { notAfter: call.deadline, beforePublish } })
    return { outcome }
  },
  async finish(ctx, call, result, from) {
    const raw = from === 'reply' ? result : decodeLookupDone(result).result
    let order: Order
    try {
      order = parseFor(call, raw, from !== 'reply')
    } catch (err) {
      const reason = (err as Error).message
      return async (t) => {
        const cur = (await t.get('pendingCalls', call.id))!
        await t.put('pendingCalls', { ...cur, order: invalidRecord(call, raw, reason, ctx.nowSeconds()), state: 'open_order', version: cur.version + 1 }, cur.version)
      }
    }
    return (t) => applyOrder(ctx, t, call, order)
  },
  async lookupTarget(ctx, call) {
    const conn = call.params?.['connection'] ?? ''
    const c = await connect(ctx, conn, { purpose: 'lookup', confirmUnverified: () => Promise.resolve(true) })
    return { bill: c.bill, authorizer: { kind: 'signer', signer: localSigner(hexBytes(await buyerKeyOf(ctx, call))) } }
  },
}

registerCallKind('order', orderKind)

/**
 * Reads an open order with `cash_lookup` and applies it. A finished order is
 * closed (`applied`); an order that ended unpaid is finished whatever the
 * lookup says, but only once a lookup sent after `pay_by` was answered.
 */
export async function refreshOrder(ctx: Ctx, id: string): Promise<OrderView> {
  const call = await ctx.read((t) => t.get('pendingCalls', id))
  if (call === undefined || call.kind !== 'order') throw new CashkitError('not_found', `no order ${id}`, { input: id })
  // A finished Lightning order no longer changes; a closed on-chain one may still gain bills.
  if (call.order?.finished === true && call.order.payment === 'lightning') return orderView(call)
  const c = await connect(ctx, call.params?.['connection'] ?? '', { purpose: 'lookup', confirmUnverified: () => Promise.resolve(true) })
  const o = await c.lookup(call.requestId, call.deadline, await buyerKeyOf(ctx, call)).catch(() => undefined)
  const v = o?.state === 'result' ? o.value : undefined
  const now = ctx.nowSeconds()
  if (v?.status === 'done') {
    let order: Order | undefined
    try {
      order = parseFor(call, decodeLookupDone(v.result).result, true)
    } catch (err) {
      await ctx.commit(async (t) => {
        const cur = (await t.get('pendingCalls', id))!
        if (cur.order !== undefined) await t.put('pendingCalls', { ...cur, order: { ...cur.order, invalidReply: (err as Error).message, checkedAt: now }, version: cur.version + 1 }, cur.version)
      })
    }
    if (order !== undefined) {
      await ctx.commit((t) => applyOrder(ctx, t, call, order))
      if (ctx.deps.pocket !== undefined) await pocketHooks.after?.(ctx, id).catch(() => undefined)
    }
  } else if (o?.state === 'error' && o.error?.code === 'UNAUTHORIZED') {
    throw new CashkitError('auth', 'the Hub does not recognise this order’s buyer key', { nwcCode: 'UNAUTHORIZED', input: id })
  } else if (v !== undefined && call.order !== undefined && now > call.order.payBy && !call.order.sawProgress && call.order.bills.length === 0) {
    // Any answer after pay_by settles an order that never progressed.
    await ctx.commit(async (t) => {
      const cur = (await t.get('pendingCalls', id))!
      await t.put('pendingCalls', { ...cur, order: { ...cur.order!, endedUnpaid: true, finished: true, checkedAt: now }, version: cur.version + 1 }, cur.version)
      await finishCall(t, id, 'applied')
    })
  }
  return orderView((await ctx.read((t) => t.get('pendingCalls', id)))!)
}

export function orderView(call: PendingCall): OrderView {
  const r = call.order
  const payment = (r?.payment ?? call.params?.['payment'] ?? 'lightning') as Payment
  const valid = r !== undefined && r.invalidReply === undefined
  const warnings: OrderWarning[] = ['pay_before', 'amount_mints_bill']
  if (payment === 'onchain') warnings.push('late_payment_kept', 'per_output_fee', 'fee_floor')
  return {
    id: call.id,
    state: r?.state ?? 'open',
    payment,
    amountMillis: r?.amountMillis ?? call.amount,
    feeMillis: r?.feeMillis ?? 0n,
    payMillis: r?.payMillis ?? 0n,
    ...(valid && r.invoice !== undefined && { invoice: r.invoice }),
    ...(valid && r.address !== undefined && { address: r.address }),
    ...(r?.confirmations !== undefined && { confirmations: r.confirmations }),
    payBy: r?.payBy ?? 0,
    payDeadline: Math.min(r?.payBy ?? 0, r?.invoiceExpiresAt ?? Number.MAX_SAFE_INTEGER),
    bills: r?.bills ?? [],
    finished: r?.finished ?? false,
    endedUnpaid: r?.endedUnpaid ?? false,
    termsChanged: r?.termsChanged ?? false,
    ...(r?.invalidReply !== undefined && { invalidReply: r.invalidReply }),
    gift: call.params?.['keep'] === 'gift',
    warnings,
  }
}

export async function listOrders(ctx: Ctx): Promise<OrderView[]> {
  return (await ctx.read((t) => t.list('pendingCalls'))).filter((c) => c.kind === 'order' && (c.order !== undefined || c.state !== 'done')).map(orderView)
}

/**
 * Watches an order while the app shows it: each notice reads it; a
 * Lightning order is also read every `pollMs` (default 5 s) until `pay_by`.
 * Stops when the order is finished or `signal` aborts.
 */
export async function watchOrder(ctx: Ctx, id: string, o: { signal?: AbortSignal; pollMs?: number; onUpdate?: (v: OrderView) => void } = {}): Promise<() => void> {
  const call = await ctx.read((t) => t.get('pendingCalls', id))
  if (call === undefined || call.kind !== 'order') throw new CashkitError('not_found', `no order ${id}`, { input: id })
  const c = await connect(ctx, call.params?.['connection'] ?? '', { purpose: 'lookup', confirmUnverified: () => Promise.resolve(true) })
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  const read = async () => {
    if (stopped) return
    const v = await refreshOrder(ctx, id).catch(() => undefined)
    if (v !== undefined) o.onUpdate?.(v)
    if (v?.finished === true) stop()
  }
  const unsub = c.watch(call.params?.['notify'] ?? '', () => void read(), call.relays)
  const poll = () => {
    if (stopped) return
    const r = call.order
    if ((r?.payment ?? call.params?.['payment']) !== 'lightning' || (r !== undefined && ctx.nowSeconds() > r.payBy)) return
    timer = setTimeout(() => void read().then(poll), o.pollMs ?? 5000)
  }
  const stop = () => {
    stopped = true
    unsub()
    if (timer !== undefined) clearTimeout(timer)
  }
  o.signal?.addEventListener('abort', stop)
  poll()
  return stop
}

