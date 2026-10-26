// cash_lookup over the private transport (NIP-CASH §Looking Up a Call):
// asks what became of a call by its request_id, signed as the original call
// was authorized. Port of nmilat nipcash/client lookup.go.
import { bySecret, bySigning, cashLookupParams, localSigner, parseCashLookupResult, type CashLookupResult, type Signer } from '../core/index.js'
import { checkBill, type Bill } from './bill.js'
import { buildItem, run, type BatchResult, type TypedOutcome } from './methods.js'
import type { BatchSession, ItemBuilder } from './session.js'

/**
 * Who authorized the original call, and so signs the lookup:
 * - `signer`: the claim-proof key (also a join's or an order's item-proof key);
 * - `bearer`: a cash-authorized call, looked up first `without` the secret,
 *   and `with` it only after that was refused `UNAUTHORIZED`;
 * - `connection`: a `mint_cash`, whose target and both proofs are the Cash
 *   Hub connection's own (its client key signs the item proof too).
 */
export type LookupAuthorizer =
  | { readonly kind: 'signer'; readonly signer: Signer }
  | { readonly kind: 'bearer'; readonly cashSecret: string; readonly stage: 'without' | 'with' }
  | { readonly kind: 'connection' }

export interface BatchLookup {
  readonly id?: string
  /** The original call's target: the bill, `sources[0]`, or the Hub connection; its secret signs the bill proof. */
  readonly bill: Bill
  readonly by: { readonly requestId: string } | { readonly connectionPubkey: string }
  /** The original call's deadline, exactly as sent. */
  readonly deadline: number
  readonly authorizer: LookupAuthorizer
}

/**
 * Sends lookup items. A `REQUEST_REUSED` answering one is not an answer
 * about the call (a Hub answers a lookup naming a used id), so it is routed
 * as `not_served`: asked again, never read as `unknown`.
 */
export async function lookupMany(session: BatchSession, items: readonly BatchLookup[], now: () => number): Promise<BatchResult<CashLookupResult>> {
  const builders = items.map((it, i): ItemBuilder => ({
    id: it.id !== undefined && it.id !== '' ? it.id : `#${i}`,
    method: 'cash_lookup',
    build: (id, b) => {
      checkBill(it.bill, id, session.hub)
      const a = it.authorizer
      const params = cashLookupParams(it.by, it.deadline, a.kind === 'bearer' && a.stage === 'with' ? a.cashSecret : undefined)
      const credential = a.kind === 'signer' ? bySigning(a.signer) : a.kind === 'bearer' ? bySecret(a.cashSecret) : bySigning(localSigner(it.bill.connectionSecret))
      return buildItem(id, it.bill, 'cash_lookup', params, credential, b, now())
    },
  }))
  const r = await run(session, builders, (_o, v) => parseCashLookupResult(v))
  return { ...r, outcomes: r.outcomes.map((o): TypedOutcome<CashLookupResult> => (o.state === 'error' && o.error?.code === 'REQUEST_REUSED' ? { id: o.id, state: 'not_served', undecodable: false, envelope: o.envelope } : o)) }
}

/**
 * One lookup, with the bearer two-step: without the secret first, then with
 * it only when that was refused `UNAUTHORIZED`.
 */
export async function lookupOne(session: BatchSession, item: BatchLookup, now: () => number): Promise<TypedOutcome<CashLookupResult>> {
  const first = (await lookupMany(session, [{ ...item, id: '1' }], now)).outcomes[0]!
  const a = item.authorizer
  if (a.kind === 'bearer' && a.stage === 'without' && first.state === 'error' && first.error?.code === 'UNAUTHORIZED') {
    return (await lookupMany(session, [{ ...item, id: '1', authorizer: { ...a, stage: 'with' } }], now)).outcomes[0]!
  }
  return first
}
