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
  decodeToken,
  decryptDelivery,
  eventJSON,
  nearMatch,
  newCashTarget,
  newNotify,
  newRequestId,
  ownRow,
  ownScope,
  normalizeAddressText,
  parseCashWithdrawQuoteResult,
  parseDetail,
  parsePayout,
  parseWithdrawQuote,
  payoutFinished,
  paysScriptType,
  quoteFeeMillis,
  verifyPayoutTx,
  verifyProvenance,
  verifyQuoteAnswer,
  verifyWithdrawReceipt,
  withdrawHrps,
  type Credential,
  type Detail,
  type Payout,
  type WithdrawQuote,
  type WithdrawTerms,
} from '../core/index.js'
import { cancelWithdraw, deadlineFor, lookupWithdraw, placeWithdraw, quoteWithdraw, statusUnreadable, watchPayout, WalletError, type LookupAuthorizer } from '../client/index.js'
import { getHeld, lockedHoldings } from './bills.js'
import { prepareCall, finishCall, type PlainOutput } from './calls.js'
import { billOf, tokenFacts, type Ctx } from './context.js'
import { CashkitError, codeForNwc, fromWalletError, statusUnreadableError } from './errors.js'
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
  /**
   * On a re-quote (`requote`): the fields that differ from the quote it
   * replaces, for the app to highlight before the user confirms again.
   */
  readonly quoteChanged?: readonly WithdrawQuoteField[]
}

/** The quote fields a re-quote compares. */
export type WithdrawQuoteField = 'amountMillis' | 'networkFeeMillis' | 'hubFeeMillis' | 'feeMillis' | 'payoutMillis' | 'sentBy' | 'holdsUntil'
const QUOTE_FIELDS: readonly WithdrawQuoteField[] = ['amountMillis', 'networkFeeMillis', 'hubFeeMillis', 'feeMillis', 'payoutMillis', 'sentBy', 'holdsUntil']

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
  /**
   * `remint_gone`: the payout was cancelled, but its re-minted bill was
   * already destroyed (a tombstone, with its reason when the Hub gave one)
   * when this wallet learned of it, so nothing came back. Informational: the
   * call is closed and needs no answer.
   */
  readonly remintGone?: { readonly reason?: string }
}

const quotes = new Map<string, { view: WithdrawQuoteView; quote: WithdrawQuote; holding: Holding; terms: WithdrawTerms; used: boolean; sendBefore?: number }>()

async function sliceIdentity(ctx: Ctx, h: Holding): Promise<{ identityValue: string; iaPubkey?: string; credential: Credential }> {
  const credential = await ctx.credentialFor(h)
  if (credential.kind === 'secret') return { identityValue: cashCommitment(credential.secret), credential }
  if (credential.kind === 'signing') return { identityValue: credential.signer.pubkey, credential }
  const att = credential.attestation!
  return { identityValue: att.connectionKey, iaPubkey: att.event.pubkey, credential }
}

async function statusRow(ctx: Ctx, h: Holding) {
  const credential = await ctx.credentialFor(h)
  const r = await ctx.clientFor(h).statusMany([{ id: '1', bill: billOf(h), credential, scope: ownScope(credential) }])
  const o = r.outcomes[0]
  // A connection-key holder is answered NOT_FOUND by a spec Hub: no terms, no row, nothing quoted.
  if (o?.state === 'error' && statusUnreadable(credential, o.error)) throw statusUnreadableError(h.id)
  if (o?.state !== 'result' || o.value === undefined) throw new CashkitError('network', "the bill's Hub did not answer its status; try again", { input: h.id })
  let row
  try {
    row = ownRow(o.value.recipients, credential, ownScope(credential))
  } catch {
    throw new CashkitError('not_found', 'no slice of this bill answers to this wallet', { input: h.id })
  }
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
 * A bill held under a one-time merge key is not withdrawn: its lookups,
 * cancel request and re-minted bill would all need that key. The merge it
 * is part of (or its fallback to a cash note) finishes first.
 */
function refuseMidMerge(h: Holding): void {
  if (h.throwawayKey !== undefined) throw new CashkitError('conflict', 'this bill is part of a merge that has not finished; settle() or the next send finishes it', { reason: 'mid_merge', input: h.id })
}

/**
 * Quotes a withdrawal of a whole bill to `address`. Refused locally before
 * any Hub contact: a malformed or mixed-case address, one with no witness
 * program, of a network this SDK knows is not the coin's, of a script type
 * the Hub does not pay, one of this wallet's own order addresses, a bill an
 * open call holds, a bill in an unfinished merge, or a cash note still
 * shared with its sender. The answer
 * is checked against what was asked (`quote_mismatch`). Nothing is written.
 */
export async function quoteWithdrawal(ctx: Ctx, holdingId: string, rawAddress: string, o: { sendBefore?: number } = {}): Promise<WithdrawQuoteView> {
  const h = await getHeld(ctx, holdingId)
  if ((await lockedHoldings(ctx)).has(h.id)) throw new CashkitError('conflict', 'this bill is in a call that has not finished; settle() resolves it', { input: h.id })
  refuseMidMerge(h)
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
  const out = await quoteWithdraw(session, ctx.clientDeps, { bill: billOf(h), credential: slice.credential, params: cashWithdrawQuoteRequest({
      address,
      ...(o.sendBefore !== undefined && { sendBefore: o.sendBefore }),
      ...(slice.credential.kind === 'connection_key' && { connectionKey: { identityValue: slice.identityValue, iaPubkey: slice.iaPubkey!, attestationEvent: eventJSON(slice.credential.attestation!.event) } }),
    }),
  })
  if (out?.state === 'error' && out.error !== undefined) throw refusal(out.error.code, out.error.message, (out.error as { detail?: unknown }).detail, 'quote')
  if (out?.state !== 'result') throw new CashkitError('network', 'the Hub did not answer the quote; nothing moved, ask again', { input: h.id })
  let r
  try {
    r = parseCashWithdrawQuoteResult(out.value)
    verifyQuoteAnswer(r, { hubXOnly: session.hub, wallet: h.walletPubkey, identityValue: slice.identityValue, ...(slice.iaPubkey !== undefined && { iaPubkey: slice.iaPubkey }), address, ...(o.sendBefore !== undefined && { sendBefore: o.sendBefore }), amountMillis: row.amount_millis, redeemFeeMillis: row.redeem_fee_millis })
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
  quotes.set(handle, { view, quote: r.quote, holding: h, terms, used: false, ...(o.sendBefore !== undefined && { sendBefore: o.sendBefore }) })
  if (view.expiringSoon && view.expiresAt !== undefined) ctx.confirmations.notify({ type: 'expiringSoon', holdingId: view.holdingId, expiresAt: view.expiresAt })
  return view
}

/**
 * Quotes the same withdrawal again (the bill, address and send-by of
 * `view`), as a new handle whose `quoteChanged` lists what differs from
 * `view`; the old handle can no longer be sent. A re-quote with nothing
 * changed in address, amount, fee and payout needs no new confirmation;
 * any other does.
 */
export async function requoteWithdrawal(ctx: Ctx, view: WithdrawQuoteView): Promise<WithdrawQuoteView> {
  const old = quotes.get(view.handle)
  if (old === undefined || old.used) throw new CashkitError('usage', 'this quote was already sent or is unknown: get a new quote', { reason: 'quote_used' })
  const next = await quoteWithdrawal(ctx, old.view.holdingId, old.view.address, { ...(old.sendBefore !== undefined && { sendBefore: old.sendBefore }) })
  old.used = true
  const quoteChanged = QUOTE_FIELDS.filter((f) => next[f] !== old.view[f])
  const withChanges: WithdrawQuoteView = { ...next, quoteChanged }
  quotes.get(next.handle)!.view = withChanges
  return withChanges
}

/**
 * Sends a quote the user confirmed: `confirm(view)` (else the wallet's
 * `confirmWithdraw` request) must resolve true (no confirmation, no
 * withdrawal). The bill must not expire within 120 s.
 * Written ahead with the quote, request id, `notify` and, for a cash-mode
 * bill, a fresh remint secret; then placed. The quote handle is consumed.
 */
export async function sendWithdrawal(ctx: Ctx, view: WithdrawQuoteView, o: { confirm?: (v: WithdrawQuoteView) => Promise<boolean> } = {}): Promise<WithdrawalView> {
  const q = quotes.get(view.handle)
  if (q === undefined || q.used) throw new CashkitError('usage', 'this quote was already sent or is unknown: get a new quote', { reason: 'quote_used' })
  const ok = o.confirm !== undefined ? await o.confirm(q.view) : await ctx.confirmations.ask({ type: 'confirmWithdraw', quote: { ...q.view, deliberate: true } })
  if (!ok) throw new CashkitError('usage', 'the withdrawal was not confirmed; nothing was sent', { reason: 'not_confirmed' })
  q.used = true
  const h = await getHeld(ctx, q.holding.id)
  if (h.expiresAt !== undefined && h.expiresAt - ctx.nowSeconds() <= 120) throw new CashkitError('invalid_input', 'this bill expires within two minutes: redeem it over Lightning', { reason: 'expiring' })
  if ((await lockedHoldings(ctx)).has(h.id)) throw new CashkitError('conflict', 'this bill is in a call that has not finished; settle() resolves it', { input: h.id })
  refuseMidMerge(h)
  const session = await ctx.clientFor(h).session()
  if (!session.usableForBills) throw new CashkitError('internal', "this bill's Hub announces no usable max_request_age; nothing was sent", { reason: 'hub_unusable' })
  const slice = await sliceIdentity(ctx, h)
  const remint = slice.credential.kind === 'secret' ? newCashTarget(ctx.random) : undefined
  const remintOut: PlainOutput['destination'] =
    remint !== undefined
      ? { kind: 'cash', secret: remint.secret }
      : slice.iaPubkey !== undefined
        ? { kind: 'connection_key', key: slice.identityValue, platform: h.connectionKey?.platform ?? '', ia: slice.iaPubkey }
        : { kind: 'pubkey', pubkey: slice.identityValue }
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
      // A recovered call confirmed no quote here: its receipt-checked payout is the reference.
      const want = call.params?.['recovered'] === '1' ? { address: p.address, payoutMillis: p.payoutMillis } : confirmedOf(call)
      verifyPayoutTx(p.tx, p.txid, p.vout, want.address, '', want.payoutMillis)
      txCheck = 'ok'
    } catch {
      txCheck = 'mismatch'
    }
  }
  const finishedNow = payoutFinished(p)
  let remintId: string | undefined
  const out = call.outputs.find((x) => x.role === 'remint')
  // A recovered cash-mode withdrawal never knew its remint secret: the re-minted bill cannot be kept.
  if (p.state === 'cancelled' && remint !== undefined && src !== undefined && out !== undefined) {
    const f = tokenFacts(remint.token)
    const added = await addHolding(
      t,
      {
        token: remint.token,
        walletPubkey: p.newWalletPubkey ?? f.tok.walletPubkey,
        hubGroup: f.hubGroup,
        relayUrls: f.tok.relays,
        amount: p.amountMillis,
        verified: false,
        ...(out?.destination.kind === 'cash'
          ? { mode: 'cash' as const, protection: 'protected' as const, cashSecret: out.destination.secret }
          : out?.destination.kind === 'connection_key' && src.connectionKey !== undefined
            ? { mode: 'connection_key' as const, protection: 'none' as const, connectionKey: src.connectionKey }
            : { mode: 'pubkey' as const, protection: 'none' as const }),
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
    // A cancelled payout whose re-minted bill is already a tombstone brought nothing back: kept on the record, and the user is told once (a notice, no question).
    ...(p.state === 'cancelled' && typeof p.newWalletToken === 'object' && { remintGone: { ...(p.newWalletToken.reason !== undefined && { reason: p.newWalletToken.reason }) } }),
    ...(prev.remintGone !== undefined && { remintGone: prev.remintGone }),
    checkedAt: ctx.nowSeconds(),
  }
  await t.put('pendingCalls', { ...cur, withdrawal: record, state: 'open_withdraw', version: cur.version + 1 }, cur.version)
  if (finishedNow) {
    const done = await finishCall(t, call.id, 'applied')
    // A cancelled payout whose re-minted bill is already a tombstone brought nothing back: the user is told, not left with a silent close.
    void done
  }
  return remintId !== undefined ? { holdingIds: [remintId] } : {}
}

/** The address, payout and send-by time the user confirmed, as written ahead. */
const confirmedOf = (call: PendingCall) => ({ address: call.params?.['address'] ?? '', payoutMillis: BigInt(call.params?.['payout'] ?? '0'), sentBy: Number(call.params?.['sentBy'] ?? '0') })

/**
 * Checks a payout against the call as written ahead: its receipt, and its
 * own address, payout, send-by time and amount, which must be the ones the
 * user confirmed. Opens a re-minted bill's token and checks it names the
 * wallet the payout names and was minted by this Hub.
 */
async function checkPayout(ctx: Ctx, call: PendingCall, raw: unknown, from: 'reply' | 'lookup'): Promise<{ payout: Payout; remint?: { token: string } }> {
  const p = parsePayout(raw)
  if (from === 'reply' && p.state !== 'queued') throw new CoreError('invalid_payload', 'a new payout is queued')
  if (call.params?.['recovered'] === '1') {
    // Nothing was written ahead: the receipt must still be this Hub's, for this bill and this request id, and agree with the payout it came with.
    verifyWithdrawReceipt(p.receipt, { hubXOnly: call.node, target: call.target, quoteId: '', requestId: call.requestId, address: p.address, payoutMillis: p.payoutMillis, sentBy: p.sentBy })
  } else {
    const q = parseWithdrawQuote(call.params?.['quote'] ?? '')
    const want = confirmedOf(call)
    verifyWithdrawReceipt(p.receipt, { hubXOnly: call.node, target: call.target, quoteId: q.id, requestId: call.requestId, ...want })
    if (p.address !== want.address || p.payoutMillis !== want.payoutMillis || p.sentBy !== want.sentBy || p.amountMillis !== call.amount) {
      throw new CoreError('receipt_invalid', 'the payout does not match the quote the user confirmed')
    }
  }
  let remint: { token: string } | undefined
  if (p.state === 'cancelled' && typeof p.newWalletToken === 'string' && p.newWalletPubkey !== undefined) {
    const { credential } = await credentialOfCall(ctx, call)
    const token = await decryptDelivery(credential, p.newWalletPubkey, p.newWalletToken)
    let tok
    try {
      tok = decodeToken(token)
    } catch {
      throw new CoreError('invalid_payload', 'the re-minted token does not decode')
    }
    if (tok.walletPubkey !== p.newWalletPubkey) throw new CoreError('invalid_payload', 'the re-minted token names another wallet')
    if (verifyProvenance(tok)?.xonly !== call.node) throw new CoreError('invalid_payload', 'the re-minted bill was not minted by this Hub')
    remint = { token }
  }
  return { payout: p, ...(remint !== undefined && { remint }) }
}

/** A refusal that ends a quote's validity (NIP-CASH §Processing Algorithm, step 3). */
const QUOTE_ENDED: ReadonlySet<string> = new Set(['quote_expired', 'quote_invalid'])

const withdrawKind: CallKind = {
  // NIP-CP §Lookups: placed again automatically only after no answer and an `unknown` lookup, while its quote is
  // valid; after REQUEST_REUSED only once the user confirms (confirmWithdrawReplace, default no).
  autoReplace: (call) => call.sawReused !== true,
  replaceRequest: 'confirmWithdrawReplace',
  async replaceBlocked(ctx, call) {
    // No chain view here: a quote counts as valid until a call of this withdrawal (this one or one it replaced) was
    // refused quote_expired or quote_invalid. Such a refusal already closes its own call; this walks the chain too.
    for (let c: PendingCall | undefined = call; c !== undefined; c = c.derivedFrom === undefined ? undefined : await ctx.read((t) => t.get('pendingCalls', c!.derivedFrom!))) {
      if (c.lastDetail !== undefined && QUOTE_ENDED.has(c.lastDetail)) return { code: c.lastCode ?? 'RESTRICTED', detail: c.lastDetail }
    }
    return undefined
  },
  async place(ctx, call, beforePublish) {
    if (call.params?.['recovered'] === '1') throw new CashkitError('usage', 'a recovered withdrawal is only looked up, never placed again', { reason: 'recovered' })
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
    // A lookup's `done` is read as the payout itself: parsePayout takes a tombstone in place of the re-minted token.
    const { payout, remint } = await checkPayout(ctx, call, result, from)
    return (t) => applyPayout(ctx, t, call, payout, remint)
  },
  async lookupTarget(ctx, call) {
    const { holding } = await credentialOfCall(ctx, call)
    return { bill: billOf(holding), authorizer: await lookupAuth(ctx, call, holding) }
  },
  async afterApply(ctx, callId) {
    // A payout settled by a lookup (not by refresh) is noticed here: a cancel, and a re-mint that was already gone, are told once.
    const c = await ctx.read((t) => t.get('pendingCalls', callId))
    if (c !== undefined && c.withdrawal?.state === 'cancelled') noticeWithdrawal(ctx, withdrawalView(c))
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
  if (call.state !== 'open_withdraw') return noticeWithdrawal(ctx, withdrawalView(call))
  const { holding } = await credentialOfCall(ctx, call)
  const o = await lookupWithdraw(await ctx.clientFor(holding).session(), ctx.clientDeps, { bill: billOf(holding), requestId: call.requestId, deadline: call.deadline, authorizer: await lookupAuth(ctx, call, holding) }).catch(() => undefined)
  const v = o?.state === 'result' ? o.value : undefined
  if (v?.status === 'done') {
    const checked = await checkPayout(ctx, call, v.result, 'lookup').catch(() => undefined)
    if (checked !== undefined) {
      await ctx.commit((t) => applyPayout(ctx, t, call, checked.payout, checked.remint))
      if (ctx.deps.pocket !== undefined) await pocketHooks.after?.(ctx, id).catch(() => undefined)
    }
  }
  return noticeWithdrawal(ctx, withdrawalView(await withdrawalCall(ctx, id)))
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
  return noticeWithdrawal(ctx, withdrawalView(await withdrawalCall(ctx, id)))
}

/** The signed payout transaction, offered only when it is late and checked: the app may broadcast it with its own node. */
export async function signedTx(ctx: Ctx, id: string): Promise<{ tx: string; txid: string; vout: number }> {
  const r = (await withdrawalCall(ctx, id)).withdrawal
  if (r === undefined || !r.signed || r.state === 'cancelled' || ctx.nowSeconds() <= r.sentBy || r.txCheck !== 'ok' || r.tx === undefined || r.txid === undefined || r.vout === undefined) {
    throw new CashkitError('usage', 'the payout transaction is offered only once it is late, signed and checked', { reason: 'tx_not_offered' })
  }
  return { tx: r.tx, txid: r.txid, vout: r.vout }
}

const noticed = new WeakMap<Ctx, Set<string>>()

/** Raises `withdrawLate` or `withdrawCancelled` once per withdrawal and phase. */
function noticeWithdrawal(ctx: Ctx, v: WithdrawalView): WithdrawalView {
  if (v.phase !== 'late_unsigned' && v.phase !== 'late_signed' && v.phase !== 'cancelled') return v
  const seen = noticed.get(ctx) ?? new Set<string>()
  noticed.set(ctx, seen)
  const key = `${v.id}:${v.phase}`
  if (seen.has(key)) return v
  seen.add(key)
  if (v.phase === 'cancelled') ctx.confirmations.notify({ type: 'withdrawCancelled', id: v.id, amountMillis: v.amountMillis, ...(v.remintHoldingId !== undefined && { remintHoldingId: v.remintHoldingId }), ...(v.remintGone !== undefined && { remintGone: v.remintGone }) })
  else if (v.phase === 'late_unsigned') ctx.confirmations.notify({ type: 'withdrawLate', id: v.id, signed: false, returnsBy: v.sentBy + CANCEL_GRACE })
  else ctx.confirmations.notify({ type: 'withdrawLate', id: v.id, signed: true, owed: true, cancelAvailableAt: v.sentBy + CANCEL_REQUEST_AFTER, canSendItMyself: true })
  return v
}

/**
 * Recovers a withdrawal this wallet has no record of: the bill's own row (or
 * tombstone), read with the holding's credential, names the `cash_withdraw`
 * that ended it. A `recovered` withdrawal is created with that request id
 * and looked up at once (deadline now); it is never placed again. A
 * cash-mode bill's re-mint, should the payout be cancelled, cannot be kept:
 * its secret was in the lost record.
 */
/** Where a recovered withdrawal's re-mint goes: the slice's own identity; a cash-mode remint secret was never known here. */
function remintOf(credential: Credential, h: Holding): PlainOutput[] {
  if (credential.kind === 'signing') return [{ role: 'remint', destination: { kind: 'pubkey', pubkey: credential.signer.pubkey } }]
  const att = credential.kind === 'connection_key' ? credential.attestation : undefined
  if (att !== undefined) return [{ role: 'remint', destination: { kind: 'connection_key', key: att.connectionKey, platform: h.connectionKey?.platform ?? '', ia: att.event.pubkey } }]
  return []
}

export async function recoverWithdrawal(ctx: Ctx, holdingId: string): Promise<WithdrawalView> {
  const h = await ctx.read((t) => t.get('holdings', holdingId))
  if (h === undefined) throw new CashkitError('not_found', `no holding ${holdingId}`, { input: holdingId })
  const credential = await ctx.credentialFor(h)
  const scope = ownScope(credential)
  const r = await ctx.clientFor(h).statusMany([{ id: '1', bill: billOf(h), credential, scope }])
  const o = r.outcomes[0]
  // A spec Hub answers a connection-key holder NOT_FOUND: the status, and so the withdrawal's id, cannot be read.
  if (o?.state === 'error' && statusUnreadable(credential, o.error)) throw statusUnreadableError(h.id)
  if (o?.state !== 'result' || o.value === undefined) throw new CashkitError('network', "the bill's Hub did not answer its status; try again", { input: h.id })
  let row: { withdraw_request_id?: string } | undefined
  if (o.value.tombstone === undefined) {
    try {
      row = ownRow(o.value.recipients, credential, scope)
    } catch {
      throw new CashkitError('not_found', 'no slice of this bill answers to this wallet', { input: h.id })
    }
  }
  const rid = o.value.tombstone?.withdrawRequestId ?? row?.withdraw_request_id
  if (rid === undefined || rid === '') throw new CashkitError('not_found', 'the Hub names no on-chain withdrawal of this bill for this wallet', { input: h.id, reason: 'no_withdrawal' })
  // A recovery that never got past its write-ahead (closed not_sent) is no record of the withdrawal: recover again.
  const known = (await ctx.read((t) => t.list('pendingCalls'))).find((c) => c.requestId === rid && !(c.state === 'done' && c.outcome === 'not_sent'))
  if (known !== undefined) return withdrawalView(known)
  const session = await ctx.clientFor(h).session()
  const now = ctx.nowSeconds()
  const call = await prepareCall(ctx, {
    kind: 'withdraw',
    requestId: rid,
    method: 'cash_withdraw',
    target: h.walletPubkey,
    node: session.hub,
    relays: session.relays,
    deadline: now,
    hAtSend: session.maxRequestAge ?? 0,
    amount: h.amount ?? 0n,
    sources: [h.id],
    authorizer: h.mode === 'cash' ? { kind: 'cash', holdingId: h.id } : { kind: 'identity' },
    outputs: remintOf(credential, h),
    context: { op: 'withdraw' },
    params: { recovered: '1' },
  })
  await ctx.commit(async (t) => {
    const cur = (await t.get('pendingCalls', call.id))!
    await t.put('pendingCalls', { ...cur, state: 'open_withdraw', version: cur.version + 1 }, cur.version)
  })
  return refreshWithdrawal(ctx, call.id)
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
    ...(r?.remintGone !== undefined && { remintGone: r.remintGone }),
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
