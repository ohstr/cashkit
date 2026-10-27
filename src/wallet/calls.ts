// Pending calls (design §5): every call that carries a request_id is
// written ahead, with its exact deadline and every secret it creates, and
// read back before its first byte is sent (NIP-CASH §`request_id`: "save it
// durably, with the call, its exact deadline and any cash secret it
// generated"). A crash or a lost reply is then settled by lookup.
import { toHex } from '../core/index.js'
import type { Ctx } from './context.js'
import { CashkitError } from './errors.js'
import type { CallAuthorizer, CallOutcome, CallOutput, DerivedIdRow, PendingCall, Sealed } from './model.js'
import type { StorageTx } from './ports.js'

/** A call's output with its secret still in the clear, as the caller generated it. */
export type PlainDestination =
  | Exclude<CallOutput['destination'], { kind: 'cash' } | { kind: 'throwaway' }>
  | { readonly kind: 'cash'; readonly secret: string }
  | { readonly kind: 'throwaway'; readonly pubkey: string; readonly key: string }

export interface PlainOutput {
  readonly role: CallOutput['role']
  readonly destination: PlainDestination
}

export type PlainAuthorizer = Exclude<CallAuthorizer, { kind: 'throwaway' } | { kind: 'buyer' }> | { readonly kind: 'throwaway'; readonly key: string } | { readonly kind: 'buyer'; readonly key: string }

export interface CallSpec {
  readonly kind: string
  readonly requestId: string
  readonly method: PendingCall['method']
  readonly target: string
  readonly node: string
  readonly relays: readonly string[]
  readonly deadline: number
  readonly hAtSend: number
  readonly amount: bigint
  readonly chain?: string
  readonly sources: readonly string[]
  readonly authorizer: PlainAuthorizer
  readonly outputs: readonly PlainOutput[]
  readonly derivedFrom?: string
  readonly attempts?: number
  readonly context?: Readonly<Record<string, string>>
  readonly params?: Readonly<Record<string, string>>
}

const dec = new TextDecoder()

/** Every sealed field of a call, in a fixed order, with its plaintext when known. */
function sealedFields(c: Pick<PendingCall, 'authorizer' | 'outputs'>): Sealed[] {
  const out: Sealed[] = []
  if (c.authorizer.kind === 'throwaway') out.push(c.authorizer.authorizerKey)
  if (c.authorizer.kind === 'buyer') out.push(c.authorizer.buyerKey)
  for (const o of c.outputs) {
    if (o.destination.kind === 'cash') out.push(o.destination.secret)
    if (o.destination.kind === 'throwaway') out.push(o.destination.key)
  }
  return out
}

function plainFields(s: CallSpec): string[] {
  const out: string[] = []
  if (s.authorizer.kind === 'throwaway' || s.authorizer.kind === 'buyer') out.push(s.authorizer.key)
  for (const o of s.outputs) {
    if (o.destination.kind === 'cash') out.push(o.destination.secret)
    if (o.destination.kind === 'throwaway') out.push(o.destination.key)
  }
  return out
}

/**
 * Seals the call's secrets, writes the call (`prepared`) in one
 * transaction, then reads it back in another and opens every sealed field,
 * comparing plaintexts. On any mismatch the row is deleted and nothing may
 * be sent (`internal`).
 */
export async function prepareCall(ctx: Ctx, spec: CallSpec): Promise<PendingCall> {
  ctx.requireUnlocked()
  const seal = async (v: string) => ctx.seal(v)
  const authorizer: CallAuthorizer =
    spec.authorizer.kind === 'throwaway'
      ? { kind: 'throwaway', authorizerKey: await seal(spec.authorizer.key) }
      : spec.authorizer.kind === 'buyer'
        ? { kind: 'buyer', buyerKey: await seal(spec.authorizer.key) }
        : spec.authorizer
  const outputs: CallOutput[] = []
  for (const o of spec.outputs) {
    const d = o.destination
    if (d.kind === 'cash') outputs.push({ role: o.role, destination: { kind: 'cash', secret: await seal(d.secret) } })
    else if (d.kind === 'throwaway') outputs.push({ role: o.role, destination: { kind: 'throwaway', pubkey: d.pubkey, key: await seal(d.key) } })
    else outputs.push({ role: o.role, destination: d })
  }
  const row: PendingCall = {
    id: `pc-${toHex(ctx.random(8))}`,
    kind: spec.kind,
    requestId: spec.requestId,
    method: spec.method,
    target: spec.target,
    node: spec.node,
    relays: [...spec.relays],
    deadline: spec.deadline,
    hAtSend: spec.hAtSend,
    device: ctx.deviceId,
    attempts: spec.attempts ?? 1,
    ...(spec.derivedFrom !== undefined && { derivedFrom: spec.derivedFrom }),
    amount: spec.amount,
    ...(spec.chain !== undefined && { chain: spec.chain }),
    sources: [...spec.sources],
    authorizer,
    outputs,
    ...(spec.context !== undefined && { context: spec.context }),
    ...(spec.params !== undefined && { params: spec.params }),
    state: 'prepared',
    createdAt: ctx.now(),
    version: 1,
  }
  try {
    await ctx.commit((t) => t.put('pendingCalls', row, 0))
  } catch (err) {
    throw new CashkitError('internal', 'could not record the call before placing it, so it was not placed (your funds have not moved)', { cause: err })
  }
  const back = await ctx.read((t) => t.get('pendingCalls', row.id))
  const want = plainFields(spec)
  let ok = back !== undefined && back.requestId === spec.requestId && back.deadline === spec.deadline && back.target === spec.target
  if (ok) {
    const sealed = sealedFields(back!)
    ok = sealed.length === want.length
    for (let i = 0; ok && i < sealed.length; i++) {
      try {
        ok = dec.decode(await ctx.deps.vault.open(sealed[i]!)) === want[i]
      } catch {
        ok = false
      }
    }
  }
  if (!ok) {
    await ctx.commit((t) => t.delete('pendingCalls', row.id)).catch(() => undefined)
    throw new CashkitError('internal', 'the call read back from storage did not match what was written, so it was not placed (your funds have not moved)')
  }
  return back!
}

/**
 * Marks a call sent: the body of the session's `beforePublish`, after its
 * write-ahead was read back. Only a `prepared` call may be sent: one that a
 * concurrent settle has already closed (`not_sent`, sources released) or
 * removed throws, and nothing is published.
 */
export async function markSent(ctx: Ctx, call: Pick<PendingCall, 'id' | 'version'>): Promise<PendingCall> {
  return ctx.commit(async (t) => {
    const cur = await t.get('pendingCalls', call.id)
    if (cur === undefined) throw new CashkitError('internal', `no pending call ${call.id}`)
    if (cur.state !== 'prepared') throw new CashkitError('internal', `pending call ${call.id} is no longer waiting to be sent, so it was not sent`)
    const next = { ...cur, state: 'sent' as const, version: cur.version + 1 }
    await t.put('pendingCalls', next, cur.version)
    return next
  })
}

/** Closes a call in the transaction that commits its result. */
export async function finishCall(t: StorageTx, callId: string, outcome: CallOutcome, o: { readonly code?: string; readonly detail?: string } = {}): Promise<PendingCall> {
  const cur = await t.get('pendingCalls', callId)
  if (cur === undefined) throw new CashkitError('internal', `no pending call ${callId}`)
  const { needsUser: _n, ...rest } = cur
  const next: PendingCall = {
    ...rest,
    state: 'done',
    outcome,
    ...(o.code !== undefined && { lastCode: o.code }),
    ...(o.detail !== undefined && { lastDetail: o.detail }),
    version: cur.version + 1,
  }
  await t.put('pendingCalls', next, cur.version)
  return next
}

/** Open calls (not `done`) naming a holding as source or authorizer: that holding is locked (I-4). */
export async function openCallsFor(ctx: Ctx, holdingId: string): Promise<PendingCall[]> {
  const calls = await ctx.read((t) => t.list('pendingCalls'))
  return calls.filter((c) => c.state !== 'done' && (c.sources.includes(holdingId) || (c.authorizer.kind === 'cash' && c.authorizer.holdingId === holdingId)))
}

/** Whether this device placed the call; another device's call is foreign and never re-placed from here. */
export const isOwnCall = (ctx: Ctx, c: Pick<PendingCall, 'device'>): boolean => c.device === ctx.deviceId

/** Records a derived id before it is sent, kept until deadline + the largest H seen. */
export async function recordDerivedId(t: StorageTx, p: { readonly derivedId: string; readonly parentCallId: string; readonly deadline: number; readonly hMax: number }): Promise<DerivedIdRow> {
  const row: DerivedIdRow = { id: p.derivedId, parentCallId: p.parentCallId, deadline: p.deadline, keepUntil: p.deadline + p.hMax, version: 1 }
  await t.put('derivedIds', row, 0)
  return row
}

/** Remembers the largest `max_request_age` seen for a Hub (never lowered). */
export async function noteHub(t: StorageTx, node: string, h: number, announcementCreatedAt?: number): Promise<void> {
  const cur = await t.get('hubs', node)
  if (cur !== undefined && cur.hMax >= h && (announcementCreatedAt === undefined || (cur.announcementCreatedAt ?? 0) >= announcementCreatedAt)) return
  await t.put('hubs', { id: node, hMax: Math.max(cur?.hMax ?? 0, h), ...((announcementCreatedAt ?? cur?.announcementCreatedAt) !== undefined && { announcementCreatedAt: announcementCreatedAt ?? cur!.announcementCreatedAt! }), version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
}
