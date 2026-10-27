// Minting over a Cash Hub's own connection (NIP-CASH §Minting Cash): the
// owner's `mint_cash`, written ahead as a pending call (a cash recipient's
// secret included), sent with its deadline as the NIP-47 `expiration`, and
// finished by the same writes from the reply or a later lookup's `done`. An
// `unknown` lookup asks the user before placing it again.
import {
  CoreError,
  decodeLookupDone,
  mintCashRequest,
  newRequestId,
  parseMintCashResult,
  sniff,
  type MintCashResult,
  type MintRecipient,
} from '../core/index.js'
import { CashHubClient, ClientError, deadlineFor, WalletError } from '../client/index.js'
import { prepareCall, type PlainOutput } from './calls.js'
import { tokenFacts, type Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { addHandoff, addHolding, appendActivity } from './ledger.js'
import type { CallCreated, CallOutput, Connection, PendingCall, Sealed } from './model.js'
import type { StorageTx } from './ports.js'
import { executeCall, registerCallKind, type CallKind } from './runner.js'
import { parseTarget } from './target.js'

export interface MintInput {
  /** The name of a stored `cashhub` connection. */
  readonly hub: string
  /** One recipient: this amount to `to`. */
  readonly amount?: bigint
  /**
   * `cash` (default: a cash note, returned as `cashNote`), `self` (a bill
   * this wallet holds), or a pubkey, npub, NIP-05 name or nconnection.
   */
  readonly to?: string
  /** Several pubkey or connection-key recipients of one bill (no cash recipient). */
  readonly recipients?: readonly { readonly to: string; readonly amount: bigint; readonly ia?: string }[]
  /** Seconds until the bill expires; default (and 0) the Hub's ceiling. */
  readonly expirySeconds?: number
}

export interface MintResult {
  readonly amount: bigint
  readonly walletPubkey: string
  /** `<token>#<secret>`, for a cash recipient. */
  readonly cashNote?: string
  /** The token, for recipients other than this wallet. */
  readonly recipientToken?: string
  /** The holding, for `to: 'self'`. */
  readonly holdingId?: string
  readonly handoffId?: string
}

/** The stored `cashhub` connection named `name`. */
export async function cashHubRow(ctx: Ctx, name: string): Promise<Connection> {
  const c = await ctx.read((t) => t.get('connections', name))
  if (c === undefined) throw new CashkitError('not_found', `no connection named "${name}"`, { input: name })
  if (c.kind !== 'cashhub' || c.connection === undefined) throw new CashkitError('usage', `"${name}" is not a Cash Hub connection: add its cashhub1 string first`, { input: name })
  return c
}

/** A client over a stored `cashhub` connection; an unverified string counts as confirmed only if it was. */
export async function cashHubClient(ctx: Ctx, c: Connection): Promise<CashHubClient> {
  const text = await ctx.open(c.connection!)
  return new CashHubClient(ctx.clientDeps, text, c.confirmedUnverifiedAt !== undefined ? { confirmUnverified: () => Promise.resolve(true) } : {})
}

/** A connection-string client error as a wallet error, its client code kept as the reason. */
export function fromConnectionError(err: unknown): unknown {
  if (!(err instanceof ClientError)) return err
  switch (err.code) {
    case 'connection_invalid':
    case 'connection_mismatch':
      return new CashkitError('invalid_input', err.message, { reason: err.code, cause: err })
    case 'connection_unverified':
      return new CashkitError('auth', err.message, { reason: err.code, cause: err })
    default:
      return err
  }
}

/**
 * Decodes a `cashhub1` string, runs its online check (and, for an unverified
 * one, `confirmUnverified`), and returns the fields to store. A URI or any
 * other form is `connection_invalid`.
 */
export async function verifyCashHubString(ctx: Ctx, value: string, confirmUnverified?: (v: ReturnType<CashHubClient['view']>) => Promise<boolean>): Promise<Pick<Connection, 'hubIdentity' | 'chain' | 'verified' | 'network'> & { confirmed: boolean; walletPubkey: string; relays: readonly string[] }> {
  const s = value.trim()
  if (sniff(s) !== 'cashhub') throw new CashkitError('invalid_input', 'not a cashhub1 connection string (a URI form is never accepted)', { reason: 'connection_invalid' })
  try {
    const c = new CashHubClient(ctx.clientDeps, s, confirmUnverified !== undefined ? { confirmUnverified } : {})
    await c.ensureUsable()
    const v = c.view()
    return {
      hubIdentity: c.connection.hubIdentity,
      ...(c.connection.chain !== undefined && { chain: c.connection.chain }),
      verified: c.verdict.verified,
      ...(v.network !== undefined && { network: v.network }),
      confirmed: !c.verdict.verified,
      walletPubkey: c.connection.walletPubkey,
      relays: c.connection.relays,
    }
  } catch (err) {
    throw fromConnectionError(err)
  }
}

interface WireRecipient {
  readonly t: MintRecipient['identityType']
  readonly v: string
  readonly ia?: string
  readonly a: string
}

const recipientsOf = (call: PendingCall): MintRecipient[] =>
  (JSON.parse(call.params?.['recipients'] ?? '[]') as WireRecipient[]).map((r) => ({ identityType: r.t, identityValue: r.v, ...(r.ia !== undefined && { iaPubkey: r.ia }), amountMillis: BigInt(r.a) }))

type Keep = 'holding' | 'handoff'

/** Mints through the stored `cashhub` connection `o.hub`, as one pending call. */
export async function mint(ctx: Ctx, o: MintInput): Promise<MintResult> {
  if ((o.amount === undefined) === (o.recipients === undefined)) throw new CashkitError('usage', 'say what to mint: an amount (with to), or recipients')
  const row = await cashHubRow(ctx, o.hub)
  const client = await cashHubClient(ctx, row)
  const outputs: PlainOutput[] = []
  const recipients: MintRecipient[] = []
  let keep: Keep = 'handoff'
  let display = ''
  let isCash = false
  if (o.amount !== undefined) {
    const to = (o.to ?? 'cash').trim()
    if (to === 'self') {
      const pubkey = (await ctx.requireSigner()).pubkey
      recipients.push({ identityType: 'pubkey', identityValue: pubkey, amountMillis: o.amount })
      outputs.push({ role: 'new', destination: { kind: 'pubkey', pubkey } })
      keep = 'holding'
      display = 'self'
    } else {
      const rt = await parseTarget(to, { ...(ctx.deps.fetch !== undefined && { fetch: ctx.deps.fetch }), random: ctx.random })
      display = rt.display
      if (rt.kind === 'cash') {
        const secret = (rt.target as unknown as { secret: string }).secret
        isCash = true
        recipients.push({ identityType: 'cash', identityValue: rt.target.identityValue, amountMillis: o.amount })
        outputs.push({ role: 'new', destination: { kind: 'cash', secret } })
      } else {
        recipients.push({ identityType: rt.target.identityType as MintRecipient['identityType'], identityValue: rt.target.identityValue, ...(rt.target.iaPubkey !== '' && { iaPubkey: rt.target.iaPubkey }), amountMillis: o.amount })
        outputs.push({ role: 'new', destination: rt.target.identityType === 'connection_key' ? { kind: 'connection_key', key: rt.target.identityValue, platform: '', ia: rt.target.iaPubkey } : { kind: 'pubkey', pubkey: rt.target.identityValue } })
      }
    }
  } else {
    const shown: string[] = []
    for (const r of o.recipients!) {
      const rt = await parseTarget(r.to, { ...(r.ia !== undefined && { ia: r.ia }), ...(ctx.deps.fetch !== undefined && { fetch: ctx.deps.fetch }), random: ctx.random })
      if (rt.kind === 'cash') throw new CashkitError('usage', 'a cash recipient must be the only one: mint it with amount and to: "cash"')
      recipients.push({ identityType: rt.target.identityType as MintRecipient['identityType'], identityValue: rt.target.identityValue, ...(rt.target.iaPubkey !== '' && { iaPubkey: rt.target.iaPubkey }), amountMillis: r.amount })
      outputs.push({ role: 'new', destination: rt.target.identityType === 'connection_key' ? { kind: 'connection_key', key: rt.target.identityValue, platform: '', ia: rt.target.iaPubkey } : { kind: 'pubkey', pubkey: rt.target.identityValue } })
      shown.push(rt.display)
    }
    display = shown.join(', ')
  }
  const requestId = newRequestId(ctx.random)
  // Validates everything locally before anything is written.
  try {
    mintCashRequest({ recipients, requestId, ...(o.expirySeconds !== undefined && { expirySeconds: o.expirySeconds }) })
  } catch (err) {
    throw new CashkitError('invalid_input', (err as Error).message, { cause: err })
  }
  let session
  try {
    await client.ensureUsable()
    session = await client.session()
  } catch (err) {
    throw fromConnectionError(err)
  }
  if (!session.usableForBills) throw new CashkitError('internal', 'this Hub announces no usable max_request_age, so no mint may go to it; nothing was sent', { reason: 'hub_unusable' })
  const amount = recipients.reduce((a, r) => a + r.amountMillis, 0n)
  const wire: WireRecipient[] = recipients.map((r) => ({ t: r.identityType, v: r.identityValue, ...(r.iaPubkey !== undefined && { ia: r.iaPubkey }), a: r.amountMillis.toString() }))
  const call = await prepareCall(ctx, {
    kind: 'mint',
    requestId,
    method: 'mint_cash',
    target: client.connection.walletPubkey,
    node: client.connection.hubIdentity,
    relays: client.connection.relays,
    deadline: deadlineFor(session.maxRequestAge, ctx.nowSeconds()),
    hAtSend: session.maxRequestAge!,
    amount,
    sources: [],
    authorizer: { kind: 'hub' },
    outputs,
    context: { op: 'mint' },
    params: {
      connection: o.hub,
      recipients: JSON.stringify(wire),
      keep,
      display,
      ...(o.expirySeconds !== undefined && { expiry: String(o.expirySeconds) }),
    },
  })
  const created = await executeCall(ctx, call)
  return mintResult(ctx, amount, created, isCash)
}

async function mintResult(ctx: Ctx, amount: bigint, created: CallCreated, isCash: boolean): Promise<MintResult> {
  const holdingId = created.holdingIds?.[0]
  const ho = created.handoffId !== undefined ? await ctx.read((t) => t.get('handoffs', created.handoffId!)) : undefined
  const value = ho !== undefined ? await ctx.open(ho.handoff) : undefined
  const h = holdingId !== undefined ? await ctx.read((t) => t.get('holdings', holdingId)) : undefined
  return {
    amount,
    walletPubkey: h?.walletPubkey ?? ho?.walletPubkey ?? '',
    ...(value !== undefined && (isCash ? { cashNote: value } : { recipientToken: value })),
    ...(holdingId !== undefined && { holdingId }),
    ...(created.handoffId !== undefined && { handoffId: created.handoffId }),
  }
}

async function sealedValue(ctx: Ctx, token: string, d: CallOutput['destination'] | undefined): Promise<{ sealed: Sealed; isCash: boolean }> {
  const isCash = d?.kind === 'cash'
  return { sealed: await ctx.seal(isCash ? `${token}#${await ctx.open(d.secret)}` : token), isCash }
}

const mintKind: CallKind = {
  autoReplace: false,
  replaceRequest: 'confirmMintReplace',
  async place(ctx, call, beforePublish) {
    const row = await cashHubRow(ctx, call.params?.['connection'] ?? '')
    const client = await cashHubClient(ctx, row)
    const expiry = call.params?.['expiry']
    let published = false
    try {
      const value = await client.mint(recipientsOf(call), {
        requestId: call.requestId,
        deadline: call.deadline,
        ...(expiry !== undefined && { expirySeconds: Number(expiry) }),
        beforePublish: async () => {
          await beforePublish()
          published = true
        },
      })
      return { outcome: { id: '1', state: 'result', undecodable: false, envelope: 0, value } }
    } catch (err) {
      if (err instanceof WalletError) return { outcome: { id: '1', state: 'error', error: { code: err.walletCode, message: err.walletMessage }, undecodable: false, envelope: 0 } }
      if (!published || (err instanceof ClientError && err.code === 'deadline_too_close')) throw fromConnectionError(err)
      // A success that does not parse: it ran, and the lookup reads it.
      if (err instanceof CoreError) return { outcome: { id: '1', state: 'result', undecodable: true, envelope: 0 }, error: err }
      return { outcome: undefined, error: err as Error }
    }
  },
  async finish(ctx, call, result, from) {
    const recipients = recipientsOf(call)
    const r: MintCashResult = from === 'reply' ? (result as MintCashResult) : parseMintCashResult(decodeLookupDone(result).result, mintCashRequest({ recipients, requestId: call.requestId }))
    const keep = call.params?.['keep'] as Keep
    const ho = keep === 'handoff' ? await sealedValue(ctx, r.cashToken, call.outputs[0]?.destination) : undefined
    const row = await ctx.read((t) => t.get('connections', call.params?.['connection'] ?? ''))
    return (t) => applyMint(ctx, t, call, r, ho, row?.hubIdentity)
  },
  async lookupTarget(ctx, call) {
    const client = await cashHubClient(ctx, await cashHubRow(ctx, call.params?.['connection'] ?? ''))
    return { bill: client.bill, authorizer: { kind: 'connection' } }
  },
  async recovery(ctx, call, result) {
    const d = call.outputs[0]?.destination
    return d?.kind === 'cash' ? [`${(result as MintCashResult).cashToken}#${await ctx.open(d.secret)}`] : []
  },
}

async function applyMint(ctx: Ctx, t: StorageTx, call: PendingCall, r: MintCashResult, ho: { sealed: Sealed; isCash: boolean } | undefined, hubIdentity: string | undefined): Promise<CallCreated> {
  const now = ctx.now()
  const display = call.params?.['display'] ?? ''
  if (ho !== undefined) {
    const row = await addHandoff(t, { kind: ho.isCash ? 'cash_note' : 'gift', handoff: ho.sealed, amount: call.amount, target: display, walletPubkey: r.walletPubkey, ...(r.expiresAt !== undefined && { expiresAt: r.expiresAt }) }, { now, random: ctx.random })
    await appendActivity(t, now, { action: 'mint', amount: call.amount, to: display, handoffId: row.id })
    return { handoffId: row.id }
  }
  const f = tokenFacts(r.cashToken)
  // The minter is the Hub this connection names: anything else is a bill this wallet cannot trust as minted here.
  const xonly = f.minterPubkey?.length === 66 ? f.minterPubkey.slice(2) : f.minterPubkey
  const verified = xonly !== undefined && xonly === hubIdentity
  const h = await addHolding(
    t,
    {
      token: r.cashToken,
      walletPubkey: r.walletPubkey,
      hubGroup: f.hubGroup,
      relayUrls: f.tok.relays,
      amount: call.amount,
      verified,
      mode: 'pubkey',
      protection: 'none',
      ...(r.expiresAt !== undefined && { expiresAt: r.expiresAt }),
      ...(f.minterPubkey !== undefined && { minterPubkey: f.minterPubkey }),
      ...(xonly !== undefined && { minterXonly: xonly }),
      origin: 'minted',
    },
    { now, random: ctx.random },
  )
  await appendActivity(t, now, { action: 'mint', amount: call.amount, to: display, holdingId: h.id })
  return { holdingIds: [h.id] }
}

registerCallKind('mint', mintKind)
