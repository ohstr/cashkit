// On-chain withdrawals over the bill's private transport (NIP-CASH §Redeeming
// On-chain): the quote, the call, its lookups, a cancel request and the
// payout's state notices. One item per request. Port of nmilat
// nipcash/client withdraw flows.
import { isOrderNotice, METHOD_CASH_WITHDRAW, METHOD_CASH_WITHDRAW_QUOTE, orderNoticeFilter, type CashLookupResult, type Credential } from '../core/index.js'
import { checkBill, type Bill } from './bill.js'
import type { LookupAuthorizer } from './lookup.js'
import { lookupOne } from './lookup.js'
import { buildItem, run, type TypedOutcome } from './methods.js'
import type { ClientDeps } from './ports.js'
import { nowSeconds } from './ports.js'
import type { BatchSession, SendOptions } from './session.js'

async function one(session: BatchSession, deps: ClientDeps, bill: Bill, method: string, params: object, credential: Credential, send?: SendOptions): Promise<TypedOutcome<unknown> | undefined> {
  const r = await run(
    session,
    [
      {
        id: '1',
        method,
        build: (id, b) => {
          checkBill(bill, id, session.hub)
          return buildItem(id, bill, method, params, credential, b, nowSeconds(deps))
        },
      },
    ],
    (_o, v) => v,
    { tombstones: false, ...(send !== undefined && { send }) },
  )
  return r.outcomes[0]
}

/** `cash_withdraw_quote`: a cash-mode slice's carries neither proof nor secret (the bill proof alone). */
export const quoteWithdraw = (session: BatchSession, deps: ClientDeps, p: { bill: Bill; credential: Credential; params: Record<string, unknown> }): Promise<TypedOutcome<unknown> | undefined> => one(session, deps, p.bill, METHOD_CASH_WITHDRAW_QUOTE, p.params, p.credential)

/** `cash_withdraw` with its request id, deadline and write-ahead hook. */
export const placeWithdraw = (session: BatchSession, deps: ClientDeps, p: { bill: Bill; credential: Credential; params: Record<string, unknown>; send: SendOptions }): Promise<TypedOutcome<unknown> | undefined> =>
  one(session, deps, p.bill, METHOD_CASH_WITHDRAW, p.params, p.credential, p.send)

/** A cancel request: authorized as a lookup of the call; not a call, harmless to repeat. */
export const cancelWithdraw = (session: BatchSession, deps: ClientDeps, p: { bill: Bill; credential: Credential; params: Record<string, unknown> }): Promise<TypedOutcome<unknown> | undefined> => one(session, deps, p.bill, METHOD_CASH_WITHDRAW, p.params, p.credential)

/** Reads a withdrawal by its request id and the deadline it was sent with. */
export const lookupWithdraw = (session: BatchSession, deps: ClientDeps, p: { bill: Bill; requestId: string; deadline: number; authorizer: LookupAuthorizer }): Promise<TypedOutcome<CashLookupResult>> =>
  lookupOne(session, { bill: p.bill, by: { requestId: p.requestId }, deadline: p.deadline, authorizer: p.authorizer }, () => nowSeconds(deps))

/** Calls `onNotice` on each state notice for `notify` (kind 23189); a notice only schedules a lookup. Returns the stop. */
export function watchPayout(deps: ClientDeps, notify: string, relays: readonly string[], onNotice: () => void): () => void {
  return deps.relays.subscribe(relays, orderNoticeFilter(notify), {
    onEvent: (e) => {
      if (isOrderNotice(e, notify)) onNotice()
    },
    onEose: () => {},
  })
}
