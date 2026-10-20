// create_circle_wallet over NIP-CASH's private transport (NIP-CW §Private
// Join). Port of nmilat nipcw/private_join.go and
// nipcash/client/batch_circle_join.go.
import {
  bySigning,
  createCircleWalletRequest,
  METHOD_CREATE_CIRCLE_WALLET,
  parseCreateCircleWalletResult,
  type CircleWallet,
  type ConnectionKeyPair,
  type Signer,
} from '../core/index.js'
import type { Item } from '../transport/index.js'
import { checkBill, type Bill } from './bill.js'
import { buildItem, run, type BatchResult, type TypedOutcome } from './methods.js'
import type { BatchSession, ItemBinding, ItemBuilder } from './session.js'

export interface CreateCircleWalletParams {
  readonly signer: Signer
  readonly maxAmountMillis: bigint
  readonly expirySeconds: number
  readonly budgetRenewal?: string
  /** Supplied to resume a join; otherwise one is generated. Secret-bearing. */
  readonly connection?: ConnectionKeyPair
}

/**
 * The join as a private-transport item. `hub` is the Hub connection,
 * `billFromParts(hubPubkey, hubSecret)`: the item targets the Hub pubkey and
 * its bill proof is signed with the connection secret, since a join has no
 * bill. The params are the standard request unchanged, so its kind-23199
 * proof still binds to the Hub pubkey; the kind-23192 item proof is signed by
 * the requester, as the spec requires of a join. `p.connection` must be set.
 */
export async function createCircleWalletItem(id: string, hub: Bill, p: CreateCircleWalletParams, b: ItemBinding, now: number): Promise<Item> {
  const req = await createCircleWalletRequest({
    signer: p.signer,
    connection: p.connection,
    hubPubkey: hub.target,
    maxAmountMillis: p.maxAmountMillis,
    expirySeconds: p.expirySeconds,
    ...(p.budgetRenewal !== undefined && { budgetRenewal: p.budgetRenewal }),
    now,
  })
  return buildItem(id, hub, METHOD_CREATE_CIRCLE_WALLET, req, bySigning(p.signer), b, now)
}

export interface BatchCircleJoin {
  readonly id?: string
  /** The Hub connection, as `billFromParts(hubPubkey, hubSecret)`. */
  readonly hub: Bill
  /** `params.connection` must be set: its secret is what the result pairs over. */
  readonly params: CreateCircleWalletParams
}

export type CircleJoinOutcome = TypedOutcome<CircleWallet>

/**
 * Sends one or more joins in one request. Every Hub must run on this
 * session's node, and the Hub evaluates each join on its own. A refusal is an
 * `error` outcome with the standard join's codes (NOT_READY, RESTRICTED,
 * WALLET_EXISTS, RATE_LIMITED). An omission is not a refusal: the join may
 * have run and its reply been lost. A result whose details do not decrypt
 * from the Hub connection key (never the inbox that carried it) is
 * `undecodable`.
 */
export function createCircleWalletMany(session: BatchSession, items: readonly BatchCircleJoin[], now: () => number): Promise<BatchResult<CircleWallet>> {
  const byId = new Map<string, BatchCircleJoin>()
  const builders = items.map((it, i): ItemBuilder => {
    const id = it.id !== undefined && it.id !== '' ? it.id : `#${i}`
    byId.set(id, it)
    return {
      id,
      build: (itemId, b) => {
        checkBill(it.hub, itemId, session.hub)
        return createCircleWalletItem(itemId, it.hub, it.params, b, now())
      },
    }
  })
  return run(session, builders, (o, v) => {
    const it = byId.get(o.id)!
    return parseCreateCircleWalletResult(v, { signer: it.params.signer, connection: it.params.connection, hubPubkey: it.hub.target })
  })
}
