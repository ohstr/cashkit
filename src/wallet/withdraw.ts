// On-chain withdrawals (NIP-CASH §Redeeming On-chain). A quote is read and
// checked (nothing written, nothing locked); `send` asks the app to confirm,
// then runs `cash_withdraw` as a pending call written ahead with the quote,
// request id, `notify` and, for a cash-mode bill, the remint secret. A valid
// receipt ends the bill and keeps the call `open_withdraw` while the payout
// is followed by lookups; `final` closes it, `cancelled` re-mints the whole
// amount as a new holding. Never moves money to an address the user has
// not just confirmed, never says more than the Hub committed to.
import {
  addressGroups,
  bySecret,
  bySigning,
  CANCEL_GRACE,
  CANCEL_REQUEST_AFTER,
  cashCommitment,
  cashWithdrawCancelRequest,
  cashWithdrawQuoteRequest,
  cashWithdrawRequest,
  classifyAddressAmong,
  CoreError,
  decodeLookupDone,
  decryptDelivery,
  nearMatch,
  newCashTarget,
  newNotify,
  newRequestId,
  normalizeAddressText,
  parseCashWithdrawQuoteResult,
  parseDetail,
  parsePayout,
  parseWithdrawQuote,
  payoutFinished,
  paysScriptType,
  quoteFeeMillis,
  verifyPayoutTx,
  verifyQuoteAnswer,
  verifyWithdrawReceipt,
  withdrawHrps,
  type Credential,
  type Detail,
  type Payout,
  type WithdrawQuote,
  type WithdrawTerms,
} from '../core/index.js'
import { cancelWithdraw, deadlineFor, lookupWithdraw, placeWithdraw, quoteWithdraw, watchPayout, WalletError, type LookupAuthorizer } from '../client/index.js'
import { getHeld, lockedHoldings } from './bills.js'
import { prepareCall, finishCall, type PlainOutput } from './calls.js'
import { billOf, tokenFacts, type Ctx } from './context.js'
import { CashkitError, codeForNwc, fromWalletError } from './errors.js'
import { addHolding, appendActivity, updateHolding } from './ledger.js'
import type { CallCreated, Holding, PendingCall, WithdrawalRecord } from './model.js'
import type { StorageTx } from './ports.js'
import { executeCall, pocketHooks, registerCallKind, type CallKind } from './runner.js'

/** Every witness HRP this SDK knows: the network is left to the Hub when the bill's chain is not known. */
const KNOWN_HRPS = [...(withdrawHrps('bitcoin') ?? []), ...(withdrawHrps('flokicoin') ?? [])]

/** Public wording for a refusal's `detail` (design §13.5). */
const DETAIL_MESSAGES: Readonly<Record<Detail, string>> = {
  own_address: 'This address belongs to the Hub. Redeem over Lightning instead.',
  script_type: "This Hub can't pay this kind of address.",
  network: "This Hub can't pay this kind of address.",
  below_min: 'Too small to send on-chain.',
  too_slow: "The Hub can't send it before your deadline. Pay over Lightning.",
  quote_expired: 'The price expired. Get a new quote and confirm again.',
  quote_invalid: 'The Hub refused its own quote. Get a new quote.',
  unfinal: "This bill's payment isn't final yet. Try later.",
}

function refusal(code: string, message: string | undefined, detail: unknown, where: 'quote' | 'call'): CashkitError {
  const d = parseDetail(detail)
  if (where === 'quote' && code === 'NOT_IMPLEMENTED') return new CashkitError('internal', 'this Hub does not offer on-chain withdrawals', { nwcCode: code, reason: 'withdraw_not_offered' })
  if (where === 'quote' && code === 'QUOTA_EXCEEDED') return new CashkitError('conflict', 'Too large for one on-chain withdrawal. Split it first?', { nwcCode: code })
  if (code === 'RATE_LIMITED' || code === 'INSUFFICIENT_BALANCE') return new CashkitError('conflict', "The Hub can't take on-chain withdrawals now. Redeem over Lightning or try later.", { nwcCode: code })
  const base = fromWalletError(new WalletError(where === 'quote' ? 'cash_withdraw_quote' : 'cash_withdraw', code, message ?? ''))
  return new CashkitError(base.code, d !== undefined ? DETAIL_MESSAGES[d] : base.message, { nwcCode: code, ...(d !== undefined && { reason: d }), ...(message !== undefined && { rawMessage: message }) })
}

export interface WithdrawTermsView {
  readonly offered: boolean
  readonly terms?: WithdrawTerms
  readonly amountMillis: bigint
  readonly redeemFeeMillis: bigint
  readonly netRedeemableMillis: bigint
  readonly inRange: 'below_min' | 'above_max' | 'ok'
  readonly expiresAt?: number
  /** The bill's amount is known to others: split it first so only this wallet and the Hub know the piece's. */
  readonly privacy: readonly WithdrawPrivacy[]
}

export type WithdrawPrivacy = { readonly kind: 'known_amount'; readonly splitFirst: true } | { readonly kind: 'address_reuse' } | { readonly kind: 'near_match'; readonly match: readonly string[] }

/** A checked quote, held in memory only: confirm it, then `send` it. */
export interface WithdrawQuoteView {
  readonly handle: string
  readonly holdingId: string
  readonly address: string
  readonly addressGroups: readonly string[]
  readonly amountMillis: bigint
  readonly networkFeeMillis: bigint
  readonly hubFeeMillis: bigint
  readonly feeMillis: bigint
  /** Exactly what the address receives. */
  readonly payoutMillis: bigint
  readonly sentBy: number
  readonly holdsUntil: number
  readonly finalDepth: number
  readonly lightningNetMillis: bigint
  readonly gapMillis: bigint
  /** The fee is above a quarter of the amount. */
  readonly highFee: boolean
  readonly expiresAt?: number
  readonly expiringSoon: boolean
  readonly privacy: readonly WithdrawPrivacy[]
  /** A cash-mode bill: a lost local record cannot be recovered. */
  readonly unrecoverable: boolean
  readonly irreversible: true
}

export type WithdrawPhase = 'sending' | 'accepted' | 'broadcast' | 'confirmed' | 'confirming_again' | 'late_unsigned' | 'late_signed' | 'final' | 'cancelled' | 'refused' | 'not_sent'

/** A withdrawal as the app shows it: never the request id, `notify`, quote, receipt or secrets; the address only until it ends. */
export interface WithdrawalView {
  readonly id: string
  readonly holdingId: string
  readonly amountMillis: bigint
  readonly feeMillis: bigint
  readonly payoutMillis: bigint
  readonly sentBy: number
  readonly state?: Payout['state']
  readonly phase: WithdrawPhase
  readonly signed: boolean
  readonly depth?: number
  readonly finalDepth: number
  readonly address?: string
  readonly txid?: string
  readonly vout?: number
  readonly cancelAvailableAt?: number
  readonly returnsBy?: number
  readonly remintHoldingId?: string
  readonly txCheck?: 'ok' | 'mismatch'
}

const quotes = new Map<string, { view: WithdrawQuoteView; quote: WithdrawQuote; holding: Holding; terms: WithdrawTerms; used: boolean }>()

async function sliceIdentity(ctx: Ctx, h: Holding): Promise<{ identityValue: string; iaPubkey?: string; credential: Credential }> {
  const credential = await ctx.credentialFor(h)
  if (credential.kind === 'secret') return { identityValue: cashCommitment(credential.secret), credential }
  if (credential.kind === 'signing') return { identityValue: credential.signer.pubkey, credential }
  throw new CashkitError('usage', 'on-chain withdrawals from connection-key bills are not supported yet', { reason: 'withdraw_not_offered' })
}

async function statusRow(ctx: Ctx, h: Holding) {
  const credential = await ctx.credentialFor(h)
  const r = await ctx.clientFor(h).statusMany([{ id: '1', bill: billOf(h), credential, scope: 'mine' }])
  const o = r.outcomes[0]
  if (o?.state !== 'result' || o.value === undefined) throw new CashkitError('network', "the bill's Hub did not answer its status; try again", { input: h.id })
  const row = o.value.recipients[0]
  if (row === undefined) throw new CashkitError('not_found', 'no slice of this bill answers to this wallet', { input: h.id })
  return { row, withdraw: o.value.withdraw }
}

/** A bill someone else knows the amount of: received (the default origin) or a zap. */
const privacyOf = (h: Holding): WithdrawPrivacy[] => (h.origin === undefined || h.origin === 'received' || h.origin === 'zap' ? [{ kind: 'known_amount', splitFirst: true }] : [])

/** The Hub's withdrawal terms for a bill, from one status read; nothing written. */
export async function withdrawTerms(ctx: Ctx, holdingId: string): Promise<WithdrawTermsView> {
  const h = await getHeld(ctx, holdingId)
  const { row, withdraw } = await statusRow(ctx, h)
  const terms = withdraw
  const amt = row.amount_millis
  const inRange = terms?.minMillis !== undefined && amt < terms.minMillis ? 'below_min' : terms?.maxMillis !== undefined && amt > terms.maxMillis ? 'above_max' : 'ok'
  return {
    offered: terms !== undefined,
    ...(terms !== undefined && { terms }),
    amountMillis: amt,
    redeemFeeMillis: row.redeem_fee_millis,
    netRedeemableMillis: row.net_redeemable_millis,
    inRange,
    ...(row.expires_at !== undefined && { expiresAt: row.expires_at }),
    privacy: privacyOf(h),
  }
}

/**
 * Quotes a withdrawal of a whole bill to `address`. Refused locally before
 * any Hub contact: a malformed or mixed-case address, one with no witness
 * program, of a network this SDK knows is not the coin's, of a script type
 * the Hub does not pay, one of this wallet's own order addresses, a bill an
 * open call holds, or a cash note still shared with its sender. The answer
 * is checked against what was asked (`quote_mismatch`). Nothing is written.
 */
export async function quoteWithdrawal(ctx: Ctx, holdingId: string, rawAddress: string, o: { sendBefore?: number } = {}): Promise<WithdrawQuoteView> {
  const h = await getHeld(ctx, holdingId)
  if ((await lockedHoldings(ctx)).has(h.id)) throw new CashkitError('conflict', 'this bill is in a call that has not finished; settle() resolves it', { input: h.id })
  if (h.mode === 'cash' && h.protection === 'shared') throw new CashkitError('usage', 'protect this cash note first: its sender still holds its secret', { reason: 'protect_first', input: h.id })
  let address: string
  let st
  try {
    address = normalizeAddressText(rawAddress)
    st = classifyAddressAmong(address, KNOWN_HRPS).scriptType
  } catch (err) {
    const c = err instanceof CoreError ? err.code : 'address_malformed'
    throw new CashkitError('invalid_input', (err as Error).message, { reason: 'address_invalid', input: c === 'address_malformed' && /case/.test((err as Error).message) ? 'mixed_case' : c.replace('address_', '') })
  }
  const orderAddresses = (await ctx.read((t) => t.list('pendingCalls'))).flatMap((c) => (c.order?.address !== undefined ? [c.order.address] : []))
  if (orderAddresses.includes(address)) throw new CashkitError('invalid_input', 'this is one of your own order addresses', { reason: 'own_order_address' })
  const { row, withdraw } = await statusRow(ctx, h)
  const terms = withdraw
  if (terms === undefined) throw new CashkitError('internal', 'this Hub does not offer on-chain withdrawals', { reason: 'withdraw_not_offered' })
  try {
    paysScriptType(terms.scriptTypes, st)
  } catch (err) {
    throw new CashkitError('invalid_input', (err as Error).message, { reason: 'address_invalid', input: 'script_type_not_paid' })
  }
  const slice = await sliceIdentity(ctx, h)
  const session = await ctx.clientFor(h).session()
  const out = await quoteWithdraw(session, ctx.clientDeps, { bill: billOf(h), credential: slice.credential, params: cashWithdrawQuoteRequest({ address, ...(o.sendBefore !== undefined && { sendBefore: o.sendBefore }) }) })
  if (out?.state === 'error' && out.error !== undefined) throw refusal(out.error.code, out.error.message, (out.error as { detail?: unknown }).detail, 'quote')
  if (out?.state !== 'result') throw new CashkitError('network', 'the Hub did not answer the quote; nothing moved, ask again', { input: h.id })
  let r
  try {
    r = parseCashWithdrawQuoteResult(out.value)
    verifyQuoteAnswer(r, { hubXOnly: session.hub, wallet: h.walletPubkey, identityValue: slice.identityValue, address, ...(o.sendBefore !== undefined && { sendBefore: o.sendBefore }), amountMillis: row.amount_millis, redeemFeeMillis: row.redeem_fee_millis })
  } catch (err) {
    throw new CashkitError('invalid_input', `the Hub's quote does not check out: ${(err as Error).message}`, { reason: 'quote_mismatch', cause: err })
  }
  const now = ctx.nowSeconds()
  const open = (await ctx.read((t) => t.list('pendingCalls'))).flatMap((c) => (c.withdrawal?.address !== undefined && c.state !== 'done' ? [c.withdrawal.address] : []))
  const near = [...open, ...orderAddresses].filter((a) => nearMatch(a, address))
  const privacy: WithdrawPrivacy[] = [...privacyOf(h), ...(open.includes(address) ? [{ kind: 'address_reuse' as const }] : []), ...near.map((m) => ({ kind: 'near_match' as const, match: addressGroups(m) }))]
  const fee = quoteFeeMillis(r.quote)
  const handle = `wq-${Array.from(ctx.random(8), (b) => b.toString(16).padStart(2, '0')).join('')}`
  const view: WithdrawQuoteView = {
    handle,
    holdingId: h.id,
    address,
    addressGroups: addressGroups(address),
    amountMillis: r.amountMillis,
    networkFeeMillis: r.networkFeeMillis,
    hubFeeMillis: r.hubFeeMillis,
    feeMillis: fee,
    payoutMillis: r.payoutMillis,
    sentBy: r.sentBy,
    holdsUntil: r.holdsUntil,
    finalDepth: terms.finalDepth,
    lightningNetMillis: row.net_redeemable_millis,
    gapMillis: row.net_redeemable_millis - r.payoutMillis,
    highFee: 4n * fee > r.amountMillis,
    ...(row.expires_at !== undefined && { expiresAt: row.expires_at }),
    expiringSoon: row.expires_at !== undefined && row.expires_at - now <= 120,
    privacy,
    unrecoverable: h.mode === 'cash',
    irreversible: true,
  }
  quotes.set(handle, { view, quote: r.quote, holding: h, terms, used: false })
  return view
}

/**
 * Sends a quote the user confirmed: `confirm(view)` must resolve true (no
 * confirmation, no withdrawal). The bill must not expire within 120 s.
 * Written ahead with the quote, request id, `notify` and, for a cash-mode
 * bill, a fresh remint secret; then placed. The quote handle is consumed.
 */
export async function sendWithdrawal(ctx: Ctx, view: WithdrawQuoteView, o: { confirm?: (v: WithdrawQuoteView) => Promise<boolean> } = {}): Promise<WithdrawalView> {
  const q = quotes.get(view.handle)
  if (q === undefined || q.used) throw new CashkitError('usage', 'this quote was already sent or is unknown: get a new quote', { reason: 'quote_used' })
  if (o.confirm === undefined || !(await o.confirm(q.view))) throw new CashkitError('usage', 'the withdrawal was not confirmed; nothing was sent', { reason: 'not_confirmed' })
  q.used = true
  const h = await getHeld(ctx, q.holding.id)
  if (h.expiresAt !== undefined && h.expiresAt - ctx.nowSeconds() <= 120) throw new CashkitError('invalid_input', 'this bill expires within two minutes: redeem it over Lightning', { reason: 'expiring' })
  if ((await lockedHoldings(ctx)).has(h.id)) throw new CashkitError('conflict', 'this bill is in a call that has not finished; settle() resolves it', { input: h.id })
  const session = await ctx.clientFor(h).session()
  if (!session.usableForBills) throw new CashkitError('internal', "this bill's Hub announces no usable max_request_age; nothing was sent", { reason: 'hub_unusable' })
  const slice = await sliceIdentity(ctx, h)
  const remint = slice.credential.kind === 'secret' ? newCashTarget(ctx.random) : undefined
  const remintOut: PlainOutput['destination'] = remint !== undefined ? { kind: 'cash', secret: remint.secret } : { kind: 'pubkey', pubkey: slice.identityValue }
  const call = await prepareCall(ctx, {
    kind: 'withdraw',
    requestId: newRequestId(ctx.random),
    method: 'cash_withdraw',
    target: h.walletPubkey,
    node: session.hub,
    relays: session.relays,
    deadline: deadlineFor(session.maxRequestAge, ctx.nowSeconds()),
    hAtSend: session.maxRequestAge!,
    amount: q.view.amountMillis,
    sources: [h.id],
    authorizer: h.mode === 'cash' ? { kind: 'cash', holdingId: h.id } : { kind: 'identity' },
    outputs: [{ role: 'remint', destination: remintOut }],
    context: { op: 'withdraw' },
    params: {
      quote: JSON.stringify(q.quote.event),
      address: q.view.address,
      payout: q.view.payoutMillis.toString(),
      fee: q.view.feeMillis.toString(),
      sentBy: String(q.view.sentBy),
      finalDepth: String(q.view.finalDepth),
      notify: newNotify(ctx.random),
    },
  })
  await executeCall(ctx, call)
  return withdrawalView((await ctx.read((t) => t.get('pendingCalls', call.id)))!)
}

async function credentialOfCall(ctx: Ctx, call: PendingCall): Promise<{ credential: Credential; holding: Holding }> {
  const h = await ctx.read((t) => t.get('holdings', call.sources[0]!))
  if (h === undefined) throw new CashkitError('internal', 'the withdrawal’s bill is gone from storage')
  return { credential: await ctx.credentialFor(h), holding: h }
}

async function lookupAuth(ctx: Ctx, call: PendingCall, h: Holding): Promise<LookupAuthorizer> {
  if (call.authorizer.kind === 'cash') return { kind: 'bearer', cashSecret: await ctx.open(h.cashSecret!), stage: 'without' }
  return { kind: 'signer', signer: await ctx.requireSigner() }
}

const recordOf = (call: PendingCall): Partial<WithdrawalRecord> => call.withdrawal ?? {}

/**
 * Applies a payout as it stands, after its receipt checked out against the
 * call as written ahead: the bill is spent once the Hub owes the payout; a
 * `tx` is checked (a mismatch is a warning, never a payout failure);
 * `final` closes the call and scrubs the address; `cancelled` imports the
 * re-minted bill and closes it.
 */
async function applyPayout(ctx: Ctx, t: StorageTx, call: PendingCall, p: Payout, remint: { token: string; secret?: string } | undefined): Promise<CallCreated> {
  const cur = (await t.get('pendingCalls', call.id))!
  const prev = recordOf(cur)
  const src = await t.get('holdings', call.sources[0]!)
  if (src !== undefined && src.status === 'held') {
    await updateHolding(t, src.id, (x) => ({ ...x, status: 'spent' }))
    await appendActivity(t, ctx.now(), { action: 'withdraw', amount: p.amountMillis, holdingId: src.id })
  }
  let txCheck = prev.txCheck
  if (p.tx !== undefined && p.txid !== undefined && p.vout !== undefined) {
    try {
      verifyPayoutTx(p.tx, p.txid, p.vout, p.address, '', p.payoutMillis)
      txCheck = 'ok'
    } catch {
      txCheck = 'mismatch'
    }
  }
  const finishedNow = payoutFinished(p)
  let remintId: string | undefined
  if (p.state === 'cancelled' && remint !== undefined && src !== undefined) {
    const f = tokenFacts(remint.token)
    const out = call.outputs.find((x) => x.role === 'remint')
    const added = await addHolding(
      t,
      {
        token: remint.token,
        walletPubkey: p.newWalletPubkey ?? f.tok.walletPubkey,
        hubGroup: f.hubGroup,
        relayUrls: f.tok.relays,
        amount: p.amountMillis,
        verified: false,
        ...(out?.destination.kind === 'cash' ? { mode: 'cash' as const, protection: 'protected' as const, cashSecret: out.destination.secret } : { mode: 'pubkey' as const, protection: 'none' as const }),
        ...(f.minterPubkey !== undefined && { minterPubkey: f.minterPubkey }),
        ...(src.expiresAt !== undefined && { expiresAt: src.expiresAt }),
        origin: 'reminted',
        ...(src.ordered === true && { ordered: true }),
      },
      { now: ctx.now(), random: ctx.random },
    )
    remintId = added.id
  }
  const record: WithdrawalRecord = {
    ...(finishedNow ? {} : { address: p.address, receipt: p.receipt }),
    amountMillis: p.amountMillis,
    feeMillis: p.feeMillis,
    payoutMillis: p.payoutMillis,
    sentBy: p.sentBy,
    finalDepth: p.finalDepth,
    state: p.state,
    signed: p.signed,
    ...(p.depth !== undefined && { depth: p.depth }),
    ...(!finishedNow && p.tx !== undefined && { tx: p.tx }),
    ...(!finishedNow && p.txid !== undefined && { txid: p.txid }),
    ...(!finishedNow && p.vout !== undefined && { vout: p.vout }),
    sawConfirmed: (prev.sawConfirmed ?? false) || p.state === 'confirmed' || p.state === 'final',
    ...(txCheck !== undefined && { txCheck }),
    ...((remintId ?? prev.remintHoldingId) !== undefined && { remintHoldingId: (remintId ?? prev.remintHoldingId)! }),
    checkedAt: ctx.nowSeconds(),
  }
  await t.put('pendingCalls', { ...cur, withdrawal: record, state: 'open_withdraw', version: cur.version + 1 }, cur.version)
  if (finishedNow) await finishCall(t, call.id, 'applied')
  return remintId !== undefined ? { holdingIds: [remintId] } : {}
}

/** Checks a payout's receipt against the call as written ahead; opens a re-minted bill's token. */
async function checkPayout(ctx: Ctx, call: PendingCall, raw: unknown, from: 'reply' | 'lookup'): Promise<{ payout: Payout; remint?: { token: string } }> {
  const p = parsePayout(raw)
  if (from === 'reply' && p.state !== 'queued') throw new CoreError('invalid_payload', 'a new payout is queued')
  const q = parseWithdrawQuote(call.params?.['quote'] ?? '')
  verifyWithdrawReceipt(p.receipt, { hubXOnly: call.node, target: call.target, quoteId: q.id, requestId: call.requestId, address: call.params?.['address'] ?? '', payoutMillis: BigInt(call.params?.['payout'] ?? '0'), sentBy: Number(call.params?.['sentBy'] ?? '0') })
  let remint: { token: string } | undefined
  if (p.state === 'cancelled' && typeof p.newWalletToken === 'string' && p.newWalletPubkey !== undefined) {
    const { credential } = await credentialOfCall(ctx, call)
    remint = { token: await decryptDelivery(credential, p.newWalletPubkey, p.newWalletToken) }
  }
  return { payout: p, ...(remint !== undefined && { remint }) }
}

const withdrawKind: CallKind = {
  autoReplace: false,
  async place(ctx, call, beforePublish) {
    const { credential, holding } = await credentialOfCall(ctx, call)
    const q = parseWithdrawQuote(call.params?.['quote'] ?? '')
    const remint = call.outputs.find((x) => x.role === 'remint')?.destination
    const params = await cashWithdrawRequest({
      walletPubkey: holding.walletPubkey,
      quote: q,
      credential,
      requestId: call.requestId,
      notify: call.params?.['notify'] ?? '',
      ...(remint?.kind === 'cash' && { remintCommitment: cashCommitment(await ctx.open(remint.secret)) }),
      ...(credential.kind === 'secret' && { sliceCommitment: cashCommitment(credential.secret) }),
      now: ctx.nowSeconds(),
    })
    const outcome = await placeWithdraw(await ctx.clientFor(holding).session(), ctx.clientDeps, { bill: billOf(holding), credential, params, send: { notAfter: call.deadline, beforePublish } })
    return { outcome }
  },
  async finish(ctx, call, result, from) {
    const raw = from === 'reply' ? result : decodeLookupDone(result).result
    const { payout, remint } = await checkPayout(ctx, call, raw, from)
    return (t) => applyPayout(ctx, t, call, payout, remint)
  },
  async lookupTarget(ctx, call) {
    const { holding } = await credentialOfCall(ctx, call)
    return { bill: billOf(holding), authorizer: await lookupAuth(ctx, call, holding) }
  },
}

registerCallKind('withdraw', withdrawKind)

async function withdrawalCall(ctx: Ctx, id: string): Promise<PendingCall> {
  const c = await ctx.read((t) => t.get('pendingCalls', id))
  if (c === undefined || c.kind !== 'withdraw') throw new CashkitError('not_found', `no withdrawal ${id}`, { input: id })
  return c
}

/** One lookup: the payout as the Hub reports it, its receipt re-checked on every `done`. */
export async function refreshWithdrawal(ctx: Ctx, id: string): Promise<WithdrawalView> {
  const call = await withdrawalCall(ctx, id)
  if (call.state !== 'open_withdraw') return withdrawalView(call)
  const { holding } = await credentialOfCall(ctx, call)
  const o = await lookupWithdraw(await ctx.clientFor(holding).session(), ctx.clientDeps, { bill: billOf(holding), requestId: call.requestId, deadline: call.deadline, authorizer: await lookupAuth(ctx, call, holding) }).catch(() => undefined)
  const v = o?.state === 'result' ? o.value : undefined
  if (v?.status === 'done') {
    const checked = await checkPayout(ctx, call, decodeLookupDone(v.result).result, 'lookup').catch(() => undefined)
    if (checked !== undefined) {
      await ctx.commit((t) => applyPayout(ctx, t, call, checked.payout, checked.remint))
      if (ctx.deps.pocket !== undefined) await pocketHooks.after?.(ctx, id).catch(() => undefined)
    }
  }
  return withdrawalView(await withdrawalCall(ctx, id))
}

/**
 * Asks the Hub to cancel a payout still unconfirmed 7 days after `sent_by`.
 * Refused locally before then (`cancel_not_due`, nothing sent); a Hub
 * refusal is definitive, and no answer is `network`: both harmless to repeat.
 */
export async function cancelWithdrawal(ctx: Ctx, id: string): Promise<WithdrawalView> {
  const call = await withdrawalCall(ctx, id)
  const r = call.withdrawal
  if (r === undefined || r.state !== 'broadcast' || ctx.nowSeconds() < r.sentBy + CANCEL_REQUEST_AFTER) throw new CashkitError('invalid_input', 'a payout can be cancelled only while it is broadcast and unconfirmed, from 7 days after its send-by time', { reason: 'cancel_not_due' })
  const { holding } = await credentialOfCall(ctx, call)
  const auth = await lookupAuth(ctx, call, holding)
  const credential: Credential = auth.kind === 'signer' ? bySigning(auth.signer) : bySecret((auth as { cashSecret: string }).cashSecret)
  const out = await cancelWithdraw(await ctx.clientFor(holding).session(), ctx.clientDeps, {
    bill: billOf(holding),
    credential,
    params: cashWithdrawCancelRequest({ requestId: call.requestId, ...(credential.kind === 'secret' && { cashSecret: credential.secret }) }),
  }).catch((err: unknown) => {
    throw new CashkitError('network', 'the cancel request got no answer; asking again is harmless', { cause: err })
  })
  if (out?.state === 'error' && out.error !== undefined) throw new CashkitError(codeForNwc(out.error.code), out.error.message ?? 'the Hub refused the cancel request', { nwcCode: out.error.code })
  if (out?.state !== 'result') throw new CashkitError('network', 'the cancel request got no answer; asking again is harmless')
  const checked = await checkPayout(ctx, call, out.value, 'lookup')
  await ctx.commit((t) => applyPayout(ctx, t, call, checked.payout, checked.remint))
  return withdrawalView(await withdrawalCall(ctx, id))
}

/** The signed payout transaction, offered only when it is late and checked: the app may broadcast it with its own node. */
export async function signedTx(ctx: Ctx, id: string): Promise<{ tx: string; txid: string; vout: number }> {
  const r = (await withdrawalCall(ctx, id)).withdrawal
  if (r === undefined || !r.signed || r.state === 'cancelled' || ctx.nowSeconds() <= r.sentBy || r.txCheck !== 'ok' || r.tx === undefined || r.txid === undefined || r.vout === undefined) {
    throw new CashkitError('usage', 'the payout transaction is offered only once it is late, signed and checked', { reason: 'tx_not_offered' })
  }
  return { tx: r.tx, txid: r.txid, vout: r.vout }
}

export function withdrawalView(call: PendingCall): WithdrawalView {
  const r = call.withdrawal
  const p = call.params ?? {}
  const sentBy = r?.sentBy ?? Number(p['sentBy'] ?? '0')
  const now = Math.floor(Date.now() / 1000)
  let phase: WithdrawPhase
  if (r === undefined) phase = call.state === 'done' ? (call.outcome === 'not_applied' ? 'refused' : 'not_sent') : 'sending'
  else if (r.state === 'final') phase = 'final'
  else if (r.state === 'cancelled') phase = 'cancelled'
  else if (r.state === 'confirmed') phase = 'confirmed'
  else if (r.state === 'broadcast') phase = r.sawConfirmed ? 'confirming_again' : 'broadcast'
  else phase = now > sentBy ? (r.signed ? 'late_signed' : 'late_unsigned') : 'accepted'
  return {
    id: call.id,
    holdingId: call.sources[0] ?? '',
    amountMillis: r?.amountMillis ?? call.amount,
    feeMillis: r?.feeMillis ?? BigInt(p['fee'] ?? '0'),
    payoutMillis: r?.payoutMillis ?? BigInt(p['payout'] ?? '0'),
    sentBy,
    ...(r?.state !== undefined && { state: r.state }),
    phase,
    signed: r?.signed ?? false,
    ...(r?.depth !== undefined && { depth: r.depth }),
    finalDepth: r?.finalDepth ?? Number(p['finalDepth'] ?? '0'),
    ...(r?.address !== undefined && { address: r.address }),
    ...(r?.txid !== undefined && { txid: r.txid }),
    ...(r?.vout !== undefined && { vout: r.vout }),
    ...(r?.state === 'broadcast' && { cancelAvailableAt: sentBy + CANCEL_REQUEST_AFTER }),
    ...(phase === 'late_unsigned' && { returnsBy: sentBy + CANCEL_GRACE }),
    ...(r?.remintHoldingId !== undefined && { remintHoldingId: r.remintHoldingId }),
    ...(r?.txCheck !== undefined && { txCheck: r.txCheck }),
  }
}

export async function listWithdrawals(ctx: Ctx): Promise<WithdrawalView[]> {
  return (await ctx.read((t) => t.list('pendingCalls'))).filter((c) => c.kind === 'withdraw').map(withdrawalView)
}

/** The verified receipt, while the withdrawal is open: the Hub's signed promise to pay this amount to this address. */
export async function withdrawalReceipt(ctx: Ctx, id: string): Promise<string> {
  const r = (await withdrawalCall(ctx, id)).withdrawal
  if (r?.receipt === undefined) throw new CashkitError('not_found', 'no receipt is kept for this withdrawal', { input: id })
  return r.receipt
}

/** Reads the payout on each state notice while the app watches. Returns the stop. */
export async function watchWithdrawal(ctx: Ctx, id: string, o: { signal?: AbortSignal; onUpdate?: (v: WithdrawalView) => void } = {}): Promise<() => void> {
  const call = await withdrawalCall(ctx, id)
  const stop = watchPayout(ctx.clientDeps, call.params?.['notify'] ?? '', call.relays, () => {
    void refreshWithdrawal(ctx, id)
      .then((v) => {
        o.onUpdate?.(v)
        if (v.phase === 'final' || v.phase === 'cancelled') stop()
      })
      .catch(() => undefined)
  })
  o.signal?.addEventListener('abort', stop)
  return stop
}
