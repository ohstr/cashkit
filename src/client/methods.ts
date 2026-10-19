// Batched bill methods over a session. Port of nmilat nipcash/client/
// batch_methods.go and nipcash/transport_item.go.
import {
  cashConsolidateRequest,
  cashRedeemRequest,
  cashTransferRequest,
  parseCashConsolidateResult,
  parseCashRedeemResult,
  parseCashStatusResult,
  parseCashTransferResult,
  type CashConsolidateResult,
  type CashRedeemResult,
  type CashStatusResult,
  type CashTransferResult,
  type ConsolidateSource,
  type Credential,
  type Target,
} from '../core/index.js'
import {
  buildBillProof,
  buildItemProof,
  isServableMethod,
  paramsHash,
  parseJSONValue,
  toJSONText,
  type Item,
  type ProofBinding,
} from '../transport/index.js'
import { checkBill, type Bill } from './bill.js'
import { ClientError } from './errors.js'
import { succeeded, type ItemOutcome } from './outcome.js'
import type { BatchSession, ItemBinding, ItemBuilder } from './session.js'

/**
 * One transport item: params as JSON text, the bill proof signed with the
 * bill's connection secret, and, unless the credential is a cash secret, a
 * slice proof signed by the holder's identity.
 */
export async function buildItem(id: string, bill: Bill, method: string, wireParams: object, credential: Credential, b: ItemBinding, now: number): Promise<Item> {
  if (id === '') throw new ClientError('bad_input', 'item needs an id')
  if (!isServableMethod(method)) throw new ClientError('bad_input', `${method} is not servable over the private transport`)
  const params = toJSONText(wireParams)
  const binding: ProofBinding = { target: bill.target, hub: b.hub, method, paramsHash: paramsHash(params), nonce: b.nonce, notAfter: b.notAfter }
  const billProof = buildBillProof(bill.connectionSecret, binding, now)
  if (credential.kind === 'secret') return { id, target: bill.target, method, params, billProof }
  const proof = await buildItemProof(credential.signer, binding, now)
  return { id, target: bill.target, method, params, proof, billProof }
}

const itemId = (given: string | undefined, i: number) => (given !== undefined && given !== '' ? given : `#${i}`)

/** An outcome with its decoded result, or `undecodable` if the body did not parse. */
export type TypedOutcome<R> = ItemOutcome & { readonly value?: R }

async function decodeOutcomes<R>(outcomes: readonly ItemOutcome[], parse: (o: ItemOutcome, value: unknown) => Promise<R> | R): Promise<TypedOutcome<R>[]> {
  const out: TypedOutcome<R>[] = []
  for (const o of outcomes) {
    if (!succeeded(o)) {
      out.push(o)
      continue
    }
    try {
      out.push({ ...o, value: await parse(o, parseJSONValue(o.result ?? 'null')) })
    } catch {
      out.push({ ...o, state: 'error', error: { code: 'INTERNAL', message: `hub answered item ${o.id} with a body this client could not decode` }, undecodable: true })
    }
  }
  return out
}

export interface BatchResult<R> {
  readonly outcomes: TypedOutcome<R>[]
  readonly error?: Error
}

async function run<R>(session: BatchSession, builders: ItemBuilder[], parse: (o: ItemOutcome, value: unknown) => Promise<R> | R): Promise<BatchResult<R>> {
  const r = await session.send(builders)
  if (r.error && r.outcomes.length === 0) throw r.error
  const outcomes = await decodeOutcomes(r.outcomes, parse)
  return r.error ? { outcomes, error: r.error } : { outcomes }
}


export interface BatchStatus {
  readonly id?: string
  readonly bill: Bill
  readonly credential: Credential
  /** 'mine' (the default here), 'all', or '' for the Hub's default. */
  readonly scope?: '' | 'mine' | 'all'
  /** The IA attestation JSON, for a connection_key holder. */
  readonly attestationEvent?: string
}

export function statusMany(session: BatchSession, items: readonly BatchStatus[], now: () => number): Promise<BatchResult<CashStatusResult>> {
  const builders = items.map((it, i): ItemBuilder => ({
    id: itemId(it.id, i),
    build: (id, b) => {
      checkBill(it.bill, id, session.hub)
      const params = {
        ...(it.scope && { scope: it.scope }),
        ...(it.credential.kind === 'secret' && { cash_secret: it.credential.secret }),
        ...(it.attestationEvent && { attestation_event: it.attestationEvent }),
      }
      return buildItem(id, it.bill, 'cash_status', params, it.credential, b, now())
    },
  }))
  return run(session, builders, (_o, v) => parseCashStatusResult(v))
}

export interface BatchRedeem {
  readonly id?: string
  readonly bill: Bill
  readonly invoice: string
  readonly credential: Credential
  readonly amount?: bigint
}

export function redeemMany(session: BatchSession, items: readonly BatchRedeem[], now: () => number): Promise<BatchResult<CashRedeemResult>> {
  const builders = items.map((it, i): ItemBuilder => ({
    id: itemId(it.id, i),
    build: async (id, b) => {
      checkBill(it.bill, id, session.hub)
      const req = await cashRedeemRequest({
        walletPubkey: it.bill.target,
        invoice: it.invoice,
        credential: it.credential,
        ...(it.amount !== undefined && { amount: it.amount }),
        now: now(),
      })
      return buildItem(id, it.bill, 'cash_redeem', req, it.credential, b, now())
    },
  }))
  return run(session, builders, (_o, v) => parseCashRedeemResult(v))
}

export interface BatchTransfer {
  readonly id?: string
  readonly bill: Bill
  readonly credential: Credential
  readonly to: Target
  readonly currentAmount: bigint
  readonly splitAmount?: bigint
}

export function transferMany(session: BatchSession, items: readonly BatchTransfer[], now: () => number): Promise<BatchResult<CashTransferResult>> {
  const byId = new Map<string, BatchTransfer>()
  const builders = items.map((it, i): ItemBuilder => {
    const id = itemId(it.id, i)
    byId.set(id, it)
    return {
      id,
      build: async (itemIdArg, b) => {
        checkBill(it.bill, itemIdArg, session.hub)
        const req = await cashTransferRequest({
          walletPubkey: it.bill.target,
          credential: it.credential,
          to: it.to,
          currentAmount: it.currentAmount,
          ...(it.splitAmount !== undefined && { splitAmount: it.splitAmount }),
          now: now(),
        })
        return buildItem(itemIdArg, it.bill, 'cash_transfer', req, it.credential, b, now())
      },
    }
  })
  return run(session, builders, (o, v) => parseCashTransferResult(v, byId.get(o.id)!.credential))
}

export interface BatchConsolidate {
  readonly id?: string
  /** The bill the item targets: one of the sources, whose connection secret signs the bill proof. */
  readonly bill: Bill
  /** Authorizes the item itself (its slice proof). */
  readonly credential: Credential
  readonly sources: readonly ConsolidateSource[]
  readonly to: Target
}

export function consolidateMany(session: BatchSession, items: readonly BatchConsolidate[], now: () => number): Promise<BatchResult<CashConsolidateResult>> {
  const byId = new Map<string, BatchConsolidate>()
  const builders = items.map((it, i): ItemBuilder => {
    const id = itemId(it.id, i)
    byId.set(id, it)
    return {
      id,
      build: async (itemIdArg, b) => {
        checkBill(it.bill, itemIdArg, session.hub)
        const req = await cashConsolidateRequest({ sources: it.sources, to: it.to, now: now() })
        return buildItem(itemIdArg, it.bill, 'cash_consolidate', req, it.credential, b, now())
      },
    }
  })
  return run(session, builders, (o, v) => {
    const it = byId.get(o.id)!
    return parseCashConsolidateResult(v, { sources: it.sources, to: it.to })
  })
}
