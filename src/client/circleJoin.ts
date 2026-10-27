// create_circle_wallet over NIP-CASH's private transport, the only transport
// a join takes (NIP-CW §Private Join). Port of nmilat nipcw/private_join.go.
import { bySigning, claimPreparedJoin, METHOD_CREATE_CIRCLE_WALLET, parseCreateCircleWalletResult, type CircleWalletDetails, type JoinTerms, type PreparedJoin, type Signer } from '../core/index.js'
import type { Item } from '../transport/index.js'
import { checkBill, type Bill } from './bill.js'
import { buildItem, run, type BatchResult, type TypedOutcome } from './methods.js'
import type { BatchSession, ItemBinding, ItemBuilder, SendOptions } from './session.js'

/**
 * A prepared join as a private-transport item: it targets the Hub (`hub` =
 * `billFromParts(hubPubkey, hubSecret)`), its bill proof is signed with the
 * Hub connection's secret, and its item proof by the requester, the same
 * key that signed the kind-23199 proof. Single use: a second item from the
 * same join is refused, so one proof is never sent twice.
 */
export async function createCircleWalletItem(id: string, hub: Bill, signer: Signer, join: PreparedJoin, b: ItemBinding, now: number): Promise<Item> {
  claimPreparedJoin(join)
  return buildItem(id, hub, METHOD_CREATE_CIRCLE_WALLET, join.request, bySigning(signer), b, now)
}

export interface BatchCircleJoin {
  readonly id?: string
  /** The Hub connection, as `billFromParts(hubPubkey, hubSecret)`. */
  readonly hub: Bill
  readonly signer: Signer
  /** Signed once; a retry needs a new one (NIP-CW §Errors). */
  readonly join: PreparedJoin
  readonly terms?: JoinTerms
}

export type CircleJoinOutcome = TypedOutcome<CircleWalletDetails>

/**
 * Sends one or more joins in one request; the Hub evaluates each on its own.
 * A refusal is an `error` outcome with the join's code. An omission is not a
 * refusal: the join may have run and its reply been lost, so it is looked
 * up. Details that do not decrypt from the Hub connection key, or that name
 * another connection key, are `undecodable`.
 */
export function createCircleWalletMany(session: BatchSession, items: readonly BatchCircleJoin[], now: () => number, send?: SendOptions): Promise<BatchResult<CircleWalletDetails>> {
  const byId = new Map<string, BatchCircleJoin>()
  const builders = items.map((it, i): ItemBuilder => {
    const id = it.id !== undefined && it.id !== '' ? it.id : `#${i}`
    byId.set(id, it)
    let claimed = false
    return {
      id,
      // Claimed on the first build only: an item that did not fit one envelope is rebuilt for the next.
      build: (itemId, b) => {
        checkBill(it.hub, itemId, session.hub)
        if (!claimed) {
          claimPreparedJoin(it.join)
          claimed = true
        }
        return buildItem(itemId, it.hub, METHOD_CREATE_CIRCLE_WALLET, it.join.request, bySigning(it.signer), b, now())
      },
    }
  })
  return run(
    session,
    builders,
    (o, v) => {
      const it = byId.get(o.id)!
      return parseCreateCircleWalletResult(v, { signer: it.signer, hubPubkey: it.hub.target, connectionPubkey: it.join.request.connection_pubkey, ...(it.terms !== undefined && { requested: it.terms }) })
    },
    { tombstones: false, ...(send !== undefined && { send }) },
  )
}
