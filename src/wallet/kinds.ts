// The wallet's id-bearing calls (design §5): `cash_transfer` and
// `cash_consolidate`, each written ahead as a pending call, placed with its
// deadline and request id, and finished by the same writes whether the
// answer is the reply or a later lookup's `done`. Every operation (send,
// split, protect, a move onto a merge key, consolidate) is a sequence of
// these single calls.
import {
  bySecret,
  bySigning,
  cashCommitment,
  decodeLookupDone,
  localSigner,
  newCashTarget,
  newRequestId,
  parseCashConsolidateResult,
  parseCashTransferResult,
  type CashConsolidateResult,
  type CashTransferResult,
  type ConsolidateSource,
  type Credential,
  type Target,
  decodeToken,
} from '../core/index.js'
import { consolidateMany, deadlineFor, transferMany, type LookupAuthorizer } from '../client/index.js'
import { prepareCall, type PlainAuthorizer, type PlainOutput } from './calls.js'
import { billOf, tokenFacts, type Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { addHandoff, addHolding, appendActivity, updateHolding } from './ledger.js'
import type { CallCreated, CallOutput, Holding, PendingCall, Sealed } from './model.js'
import type { StorageTx } from './ports.js'
import { executeCall, registerCallKind, type CallKind } from './runner.js'

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))

/** The minter every source shares, else undefined. */
function sharedMinterOf(minters: readonly (string | undefined)[]): string | undefined {
  let m: string | undefined
  for (const x of minters) {
    if (x === undefined || (m !== undefined && m !== x)) return undefined
    m = x
  }
  return m
}

/** A handoff's value sealed before the transaction: a cash note `<token>#<secret>`, or the token. */
async function sealedHandoff(ctx: Ctx, token: string, d: CallOutput['destination']): Promise<{ sealed: Sealed; isCash: boolean; wallet: string }> {
  const isCash = d.kind === 'cash'
  const value = isCash ? `${token}#${await ctx.open(d.secret)}` : token
  let wallet = ''
  try {
    wallet = decodeToken(token).walletPubkey
  } catch {
    // kept verbatim
  }
  return { sealed: await ctx.seal(value), isCash, wallet }
}

/** Where the value of a call lands: a holding of this wallet, a handoff for someone else, or nothing local. */
export type Keep = 'holding' | 'handoff' | 'none'

async function holding(ctx: Ctx, id: string): Promise<Holding> {
  const h = await ctx.read((t) => t.get('holdings', id))
  if (h === undefined) throw new CashkitError('internal', `no holding ${id}`)
  return h
}

/** The credential a holding's calls are authorized with. */
async function credentialOf(ctx: Ctx, h: Holding): Promise<Credential> {
  return ctx.credentialFor(h)
}

/** How a call on `h` is authorized, as written ahead (a merge key in the clear, sealed by prepareCall). */
async function authorizerOf(ctx: Ctx, h: Holding): Promise<PlainAuthorizer> {
  if (h.throwawayKey !== undefined) return { kind: 'throwaway', key: await ctx.open(h.throwawayKey) }
  if (h.mode === 'cash') return { kind: 'cash', holdingId: h.id }
  return { kind: 'identity' }
}

/** Who signs a lookup of a call on `h`. */
async function lookupAuthorizerOf(ctx: Ctx, call: PendingCall, h: Holding): Promise<LookupAuthorizer> {
  const a = call.authorizer
  if (a.kind === 'throwaway') return { kind: 'signer', signer: localSigner(hexBytes(await ctx.open(a.authorizerKey))) }
  if (a.kind === 'cash') return { kind: 'bearer', cashSecret: await ctx.open(h.cashSecret!), stage: 'without' }
  return { kind: 'signer', signer: await ctx.requireSigner() }
}

/** The credential the call was authorized with, from its written-ahead record. */
async function callCredential(ctx: Ctx, call: PendingCall, h: Holding): Promise<Credential> {
  const a = call.authorizer
  if (a.kind === 'throwaway') return bySigning(localSigner(hexBytes(await ctx.open(a.authorizerKey))))
  if (a.kind === 'cash') return bySecret(await ctx.open(h.cashSecret!))
  if (h.mode === 'connection_key') return ctx.credentialFor(h)
  return bySigning(await ctx.requireSigner())
}

/** The target as the wire names it, from the call's params. */
function targetOf(call: PendingCall): Target {
  const p = call.params ?? {}
  return { identityType: p['toType'] as Target['identityType'], identityValue: p['toValue'] ?? '', iaPubkey: p['toIa'] ?? '' }
}

const targetParams = (t: Target): Record<string, string> => ({ toType: t.identityType, toValue: t.identityValue, toIa: t.iaPubkey })

/** The holding fields an output's destination gives a bill this wallet keeps. */
function identityFields(d: CallOutput['destination']): Pick<Holding, 'mode' | 'protection'> & Partial<Pick<Holding, 'cashSecret' | 'throwawayKey'>> {
  switch (d.kind) {
    case 'cash':
      return { mode: 'cash', protection: 'protected', cashSecret: d.secret }
    case 'throwaway':
      return { mode: 'pubkey', protection: 'none', throwawayKey: d.key }
    case 'connection_key':
      return { mode: 'connection_key', protection: 'none' }
    default:
      return { mode: 'pubkey', protection: 'none' }
  }
}

function withoutKeys(h: Holding): Holding {
  const { cashSecret: _c, throwawayKey: _k, ...rest } = h
  return rest as Holding
}

const output = (call: PendingCall, role: CallOutput['role']) => call.outputs.find((o) => o.role === role)

/** `<token>#<secret>` for each created bill whose destination is a cash secret. */
async function cashNotes(ctx: Ctx, call: PendingCall, tokens: readonly [CallOutput['role'], string][]): Promise<string[]> {
  const out: string[] = []
  for (const [role, token] of tokens) {
    const d = output(call, role)?.destination
    if (token !== '' && d?.kind === 'cash') out.push(`${token}#${await ctx.open(d.secret)}`)
  }
  return out
}

// ---- cash_transfer

export interface TransferInput {
  /** `send`, `protect`, `move` (onto a merge key) or `to_cash` (off it). */
  readonly op: string
  readonly source: Holding
  /** The destination; a cash one carries its secret, written ahead. */
  readonly to: Target & { readonly secret?: string }
  /** What the destination is to this wallet: a merge key it holds, or just a public key. */
  readonly destination: PlainOutput['destination']
  readonly keep: Keep
  readonly amount: bigint
  /** A partial split: the amount carved off (less than the source's). */
  readonly split?: bigint
  readonly zapTarget?: string
  /** The recipient as shown in activity and handoffs. */
  readonly display?: string
  /** A Cash Zap: what its 9522 needs once the bill exists (published by `afterApply`). */
  readonly zap?: string
}

/** A remainder kept by this wallet, under a fresh secret for a cash source, else the source's own key. */
async function remainderOf(ctx: Ctx, h: Holding): Promise<PlainOutput['destination']> {
  if (h.throwawayKey !== undefined) {
    const key = await ctx.open(h.throwawayKey)
    return { kind: 'throwaway', pubkey: localSigner(hexBytes(key)).pubkey, key }
  }
  if (h.mode === 'cash') return { kind: 'cash', secret: newCashTarget(ctx.random).secret }
  if (h.mode === 'connection_key' && h.connectionKey?.key !== undefined) return { kind: 'connection_key', key: h.connectionKey.key, platform: h.connectionKey.platform, ia: h.connectionKey.iaPubkey }
  return { kind: 'pubkey', pubkey: (await ctx.requireSigner()).pubkey }
}

/**
 * Runs one `cash_transfer` as a pending call: written ahead with every
 * secret it creates, placed with its deadline and id, finished (or left
 * open for `settle()`). Returns what it created.
 */
export async function runTransfer(ctx: Ctx, x: TransferInput): Promise<CallCreated> {
  const h = x.source
  if (h.amount === undefined) throw new CashkitError('invalid_input', 'this holding has no known amount to move', { input: h.id })
  const session = await ctx.clientFor(h).session()
  if (!session.usableForBills) throw new CashkitError('internal', "this bill's Hub announces no usable max_request_age, so no call that creates a bill may go to it; nothing was sent", { input: h.id })
  const partial = x.split !== undefined && x.split < h.amount
  const outputs: PlainOutput[] = [{ role: 'new', destination: x.destination }]
  if (partial) outputs.push({ role: 'remainder', destination: await remainderOf(ctx, h) })
  const call = await prepareCall(ctx, {
    kind: 'transfer',
    requestId: newRequestId(ctx.random),
    method: 'cash_transfer',
    target: h.walletPubkey,
    node: session.hub,
    relays: session.relays,
    deadline: deadlineFor(session.maxRequestAge, ctx.nowSeconds()),
    hAtSend: session.maxRequestAge!,
    amount: x.amount,
    sources: [h.id],
    authorizer: await authorizerOf(ctx, h),
    outputs,
    context: { op: x.op },
    params: {
      ...targetParams(x.to),
      current: h.amount.toString(),
      keep: x.keep,
      op: x.op,
      ...(partial && { split: x.split!.toString() }),
      ...(x.zapTarget !== undefined && { zapTarget: x.zapTarget }),
      ...(x.display !== undefined && { display: x.display }),
      ...(x.zap !== undefined && { zap: x.zap }),
    },
  })
  return executeCall(ctx, call)
}

/** Publishes a zap's 9522 once its bill exists; set by the zap module. */
let zapPublisher: ((ctx: Ctx, callId: string) => Promise<void>) | undefined
export const setZapPublisher = (f: (ctx: Ctx, callId: string) => Promise<void>): void => {
  zapPublisher = f
}

const transferKind: CallKind = {
  async afterApply(ctx, callId) {
    if (zapPublisher !== undefined) await zapPublisher(ctx, callId)
  },
  autoReplace: true,
  async place(ctx, call, beforePublish) {
    const h = await holding(ctx, call.sources[0]!)
    const p = call.params ?? {}
    const rem = output(call, 'remainder')
    const remainderCommitment = rem?.destination.kind === 'cash' && h.mode === 'cash' && call.authorizer.kind === 'cash' ? cashCommitment(await ctx.open(rem.destination.secret)) : undefined
    const c = ctx.clientFor(h)
    const r = await transferMany(
      await c.session(),
      [
        {
          id: '1',
          bill: c.bill,
          credential: await callCredential(ctx, call, h),
          to: targetOf(call),
          currentAmount: BigInt(p['current']!),
          requestId: call.requestId,
          ...(p['split'] !== undefined && { splitAmount: BigInt(p['split']) }),
          ...(p['zapTarget'] !== undefined && { zapTarget: p['zapTarget'] }),
          ...(remainderCommitment !== undefined && { remainderCommitment }),
        },
      ],
      () => ctx.nowSeconds(),
      { notAfter: call.deadline, beforePublish },
    )
    return { outcome: r.outcomes[0], ...(r.error !== undefined && { error: r.error }) }
  },
  async finish(ctx, call, result, from) {
    const src = await holding(ctx, call.sources[0]!)
    const r: CashTransferResult = from === 'reply' ? (result as CashTransferResult) : await parseCashTransferResult(decodeLookupDone(result).result, await callCredential(ctx, call, src))
    // Everything that needs the vault happens here: a transaction awaits only storage.
    const ho = call.params?.['keep'] === 'handoff' ? await sealedHandoff(ctx, r.newWalletToken === '' ? src.token : r.newWalletToken, output(call, 'new')!.destination) : undefined
    return (t) => applyTransfer(ctx, t, call, r, ho)
  },
  async recovery(ctx, call, result) {
    const r = result as CashTransferResult
    const src = await holding(ctx, call.sources[0]!)
    return cashNotes(ctx, call, [
      ['new', r.newWalletToken === '' ? src.token : r.newWalletToken],
      ['remainder', r.remainderWalletToken],
    ])
  },
  async lookupTarget(ctx, call) {
    const h = await holding(ctx, call.sources[0]!)
    return { bill: billOf(h), authorizer: await lookupAuthorizerOf(ctx, call, h) }
  },
}

async function applyTransfer(ctx: Ctx, t: StorageTx, call: PendingCall, r: CashTransferResult, ho: Awaited<ReturnType<typeof sealedHandoff>> | undefined): Promise<CallCreated> {
  const src = await t.get('holdings', call.sources[0]!)
  if (src === undefined) throw new CashkitError('internal', `no holding ${call.sources[0]}`)
  const p = call.params ?? {}
  const keep = p['keep'] as Keep
  const op = p['op'] ?? 'send'
  const newOut = output(call, 'new')!
  const remOut = output(call, 'remainder')
  const inPlace = r.newWalletToken === ''
  const now = ctx.now()
  if (keep === 'holding') {
    // Moved to a key or secret this wallet holds: the same holding, its identity (and, on a spin-off, its bill) replaced.
    const moved = await updateHolding(t, src.id, (h) => ({
      ...withoutKeys(h),
      ...identityFields(newOut.destination),
      ...(!inPlace && { token: r.newWalletToken.toLowerCase(), walletPubkey: r.newWalletPubkey !== '' ? r.newWalletPubkey : h.walletPubkey }),
    }))
    if (op === 'protect') await appendActivity(t, now, { action: 'protect', holdingId: moved.id })
    return { movedHoldingId: moved.id }
  }
  await updateHolding(t, src.id, (h) => ({ ...h, status: 'transferred' }))
  const created: { holdingIds: string[]; handoffId?: string; zap?: { issuedAt: number; expiresAt: number } } = { holdingIds: [], ...(r.issuedAt !== undefined && { zap: { issuedAt: r.issuedAt, expiresAt: r.zapExpiresAt ?? 0 } }) }
  if (keep === 'handoff' && ho !== undefined) {
    const row = await addHandoff(t, { kind: ho.isCash ? 'cash_note' : 'gift', handoff: ho.sealed, amount: call.amount, target: p['display'] ?? '', walletPubkey: ho.wallet }, { now, random: ctx.random })
    created.handoffId = row.id
  }
  let remainderId: string | undefined
  if (r.remainderWalletToken !== '' && remOut !== undefined) {
    const f = tokenFacts(r.remainderWalletToken)
    const rem = await addHolding(
      t,
      {
        ...identityFields(remOut.destination),
        // A connection-key source's remainder stays with the same account and attestation.
        ...(remOut.destination.kind === 'connection_key' && src.connectionKey !== undefined && { connectionKey: src.connectionKey }),
        token: r.remainderWalletToken,
        walletPubkey: r.remainderWalletPubkey,
        hubGroup: f.hubGroup,
        relayUrls: f.tok.relays,
        verified: false,
        ...(r.remainingAmountMillis !== undefined && { amount: r.remainingAmountMillis }),
        ...(src.expiresAt !== undefined && { expiresAt: src.expiresAt }),
        ...(f.minterPubkey !== undefined && { minterPubkey: f.minterPubkey }),
        origin: 'remainder',
        ...(src.ordered === true && { ordered: true }),
      },
      { now, random: ctx.random },
    )
    remainderId = rem.id
    created.holdingIds.push(rem.id)
  }
  await appendActivity(t, now, {
    action: 'send',
    amount: call.amount,
    to: p['display'] ?? '',
    ...(created.handoffId !== undefined && { handoffId: created.handoffId }),
    holdingIds: [src.id],
    ...(remainderId !== undefined && { remainderId }),
  })
  return created
}

// ---- cash_consolidate

export interface ConsolidateInput {
  readonly sources: readonly Holding[]
  readonly to: Target & { readonly secret?: string }
  readonly destination: PlainOutput['destination']
  readonly keep: Keep
  readonly display?: string
}

/** Runs one `cash_consolidate` (target `sources[0]`) as a pending call. */
export async function runConsolidate(ctx: Ctx, x: ConsolidateInput): Promise<CallCreated> {
  const first = x.sources[0]!
  const session = await ctx.clientFor(first).session()
  if (!session.usableForBills) throw new CashkitError('internal', "this bill's Hub announces no usable max_request_age, so no call that creates a bill may go to it; nothing was sent", { input: first.id })
  let amount = 0n
  for (const h of x.sources) amount += h.amount ?? 0n
  const call = await prepareCall(ctx, {
    kind: 'consolidate',
    requestId: newRequestId(ctx.random),
    method: 'cash_consolidate',
    target: first.walletPubkey,
    node: session.hub,
    relays: session.relays,
    deadline: deadlineFor(session.maxRequestAge, ctx.nowSeconds()),
    hAtSend: session.maxRequestAge!,
    amount,
    sources: x.sources.map((h) => h.id),
    authorizer: await authorizerOf(ctx, first),
    outputs: [{ role: 'new', destination: x.destination }],
    context: { op: 'consolidate' },
    params: { ...targetParams(x.to), keep: x.keep, ...(x.display !== undefined && { display: x.display }) },
  })
  return executeCall(ctx, call)
}

async function consolidateSources(ctx: Ctx, call: PendingCall): Promise<{ holdings: Holding[]; sources: ConsolidateSource[] }> {
  const holdings: Holding[] = []
  const sources: ConsolidateSource[] = []
  for (const id of call.sources) {
    const h = await holding(ctx, id)
    holdings.push(h)
    sources.push({ walletPubkey: h.walletPubkey, amount: h.amount!, credential: await credentialOf(ctx, h) })
  }
  return { holdings, sources }
}

const consolidateKind: CallKind = {
  autoReplace: true,
  async place(ctx, call, beforePublish) {
    const { holdings, sources } = await consolidateSources(ctx, call)
    const first = holdings[0]!
    const r = await consolidateMany(
      await ctx.clientFor(first).session(),
      [{ id: '1', bill: billOf(first), credential: sources[0]!.credential, sources, to: targetOf(call), requestId: call.requestId }],
      () => ctx.nowSeconds(),
      { notAfter: call.deadline, beforePublish },
    )
    return { outcome: r.outcomes[0], ...(r.error !== undefined && { error: r.error }) }
  },
  async finish(ctx, call, result, from) {
    let r: CashConsolidateResult
    if (from === 'reply') r = result as CashConsolidateResult
    else {
      const { sources } = await consolidateSources(ctx, call)
      r = await parseCashConsolidateResult(decodeLookupDone(result).result, { sources, to: targetOf(call) })
    }
    const minters = await Promise.all(call.sources.map(async (id) => (await holding(ctx, id)).minterPubkey))
    const ho = call.params?.['keep'] === 'handoff' ? await sealedHandoff(ctx, r.newWalletToken, output(call, 'new')!.destination) : undefined
    return (t) => applyConsolidate(ctx, t, call, r, sharedMinterOf(minters), ho)
  },
  recovery: (ctx, call, result) => cashNotes(ctx, call, [['new', (result as CashConsolidateResult).newWalletToken]]),
  async lookupTarget(ctx, call) {
    const h = await holding(ctx, call.sources[0]!)
    return { bill: billOf(h), authorizer: await lookupAuthorizerOf(ctx, call, h) }
  },
}

async function applyConsolidate(ctx: Ctx, t: StorageTx, call: PendingCall, r: CashConsolidateResult, minter: string | undefined, ho: Awaited<ReturnType<typeof sealedHandoff>> | undefined): Promise<CallCreated> {
  const p = call.params ?? {}
  const keep = p['keep'] as Keep
  const newOut = output(call, 'new')!
  const now = ctx.now()
  let ordered = true
  for (const id of call.sources) {
    const h = await t.get('holdings', id)
    if (h?.ordered !== true) ordered = false
    await updateHolding(t, id, (x) => ({ ...x, status: 'consolidated' }))
  }
  const created: { holdingIds: string[]; handoffId?: string } = { holdingIds: [] }
  if (keep === 'holding') {
    const f = tokenFacts(r.newWalletToken)
    const added = await addHolding(
      t,
      {
        ...identityFields(newOut.destination),
        token: r.newWalletToken,
        walletPubkey: r.newWalletPubkey,
        hubGroup: f.hubGroup,
        relayUrls: f.tok.relays,
        amount: r.amountMillis,
        verified: true,
        ...(minter !== undefined && { minterPubkey: minter }),
        ...(r.expiresAt !== undefined && { expiresAt: r.expiresAt }),
        origin: 'consolidated',
        ...(ordered && { ordered: true }),
      },
      { now, random: ctx.random },
    )
    created.holdingIds.push(added.id)
  } else if (keep === 'handoff' && ho !== undefined) {
    const row = await addHandoff(t, { kind: ho.isCash ? 'cash_note' : 'gift', handoff: ho.sealed, amount: r.amountMillis, target: p['display'] ?? '', walletPubkey: ho.wallet }, { now, random: ctx.random })
    created.handoffId = row.id
  }
  await appendActivity(t, now, { action: 'consolidate', amount: r.amountMillis, from: [...call.sources], ...(created.holdingIds[0] !== undefined && { into: created.holdingIds[0] }) })
  return created
}

registerCallKind('transfer', transferKind)
registerCallKind('consolidate', consolidateKind)
