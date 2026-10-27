// A Circle Wallet Hub, reached through its `circlehub1…` string (NIP-CW
// §The Circle Wallet Hub Connection, §Private Join). Port of nmilat
// nipcw/client Connect and Join: the string is decoded and verified, the
// Hub's `get_info` is checked against it, and joins and their lookups go
// over the private transport only, after the announcement of its `identity`
// was fetched and verified. Nothing ever travels on the standard transport.
import {
  CoreError,
  createCircleWalletRequest,
  decodeCircleHubConnection,
  onlineCheck,
  readNetworkChain,
  sniff,
  verifyCircleHubConnection,
  type CashLookupResult,
  type CircleWalletDetails,
  type CircleWalletInfo,
  type ConnVerdict,
  type HubConnection,
  type JoinTerms,
  type PreparedJoin,
  type Signer,
} from '../core/index.js'
import { billFromParts, type Bill } from './bill.js'
import { createCircleWalletMany } from './circleJoin.js'
import { ClientError } from './errors.js'
import { hubView, type HubView } from './hubView.js'
import { lookupOne } from './lookup.js'
import type { BatchResult, TypedOutcome } from './methods.js'
import { NwcClient, type GetInfoResult } from './nwcClient.js'
import { nowSeconds, type ClientDeps } from './ports.js'
import { BatchSession, type SendOptions } from './session.js'

export interface ConnectCircleOptions {
  /** Asked once, after the online check passed, for a string whose signature does not verify. */
  readonly confirmUnverified?: (view: HubView) => Promise<boolean>
  /**
   * `lookup` (a pending join's lookup, `circles.recover`) skips the
   * `accepting` check: a closed Hub still serves lookups and its members.
   */
  readonly purpose?: 'join' | 'lookup'
}

/** A connected Circle Wallet Hub: its string, terms and private transport. */
export interface CircleHub {
  readonly connection: HubConnection
  readonly verdict: ConnVerdict
  readonly info: GetInfoResult
  readonly circle: CircleWalletInfo
  readonly session: BatchSession
  /** The join's target: the Hub connection, its secret signing the bill proof. */
  readonly bill: Bill
  view(): HubView
  /** Signs a join (once): its proof binds the Hub pubkey, the connection key and the terms. */
  prepareJoin(signer: Signer, connectionPubkey: string, terms: JoinTerms): Promise<PreparedJoin>
  /** Sends a prepared join on the private transport; `send.beforePublish` is the caller's write-ahead. */
  join(signer: Signer, join: PreparedJoin, terms?: JoinTerms, send?: SendOptions): Promise<BatchResult<CircleWalletDetails>>
  /** Looks a join up by its connection key and deadline, signed by the join's `pubkey`. */
  lookupJoin(signer: Signer, connectionPubkey: string, deadline: number): Promise<TypedOutcome<CashLookupResult>>
}

/**
 * Connects to a Circle Wallet Hub: decodes `circlehub` (`connection_invalid`
 * for anything else, a URI included), verifies it, reads `get_info` and
 * checks its `circle_wallet.identity` and `chain` against the string
 * (`connection_mismatch`; a `get_info` without a `circle_wallet` block or its
 * `identity` is no Circle Wallet Hub), asks `confirmUnverified` for an
 * unverified string (`connection_unverified`), refuses a Hub not accepting
 * joins (`not_accepting`, joins only), and opens the private transport from
 * the announcement of `identity` (`join_unavailable` when none verifies).
 * Nothing is signed or sent before all of this passes.
 */
export async function connectCircle(deps: ClientDeps, circlehub: string, o: ConnectCircleOptions = {}): Promise<CircleHub> {
  const s = circlehub.trim()
  if (sniff(s) !== 'circlehub') throw new ClientError('connection_invalid', 'not a circlehub1 connection string')
  let connection: HubConnection
  try {
    connection = decodeCircleHubConnection(s)
  } catch (err) {
    throw new ClientError('connection_invalid', (err as Error).message, { cause: err })
  }
  const verdict = verifyCircleHubConnection(connection)
  const nwc = new NwcClient(deps, { walletPubkey: connection.walletPubkey, relays: connection.relays, secret: connection.secret, extra: {} })
  const info = await nwc.getInfo()
  const circle = info.circle_wallet
  if (circle?.identity === undefined) throw new ClientError('connection_mismatch', 'this connection’s get_info carries no circle_wallet identity, so it is no Circle Wallet Hub')
  const nc = readNetworkChain(info)
  try {
    onlineCheck(connection, { identity: circle.identity, ...(nc.chain !== undefined && { chain: nc.chain }) })
  } catch (err) {
    throw new ClientError('connection_mismatch', (err as CoreError).message, { cause: err })
  }
  const network = nc.network ?? (nc.networkRaw !== undefined ? String(nc.networkRaw) : undefined)
  const view = () => hubView('circlehub', s, connection, verdict, 'pass', network)
  if (!verdict.verified && (o.confirmUnverified === undefined || !(await o.confirmUnverified(view())))) {
    throw new ClientError('connection_unverified', "this connection string's signature does not verify, and it was not confirmed")
  }
  if (o.purpose !== 'lookup' && !circle.accepting) throw new ClientError('not_accepting', 'this circle is not taking new members now')
  let session: BatchSession
  try {
    session = await BatchSession.open(deps, connection.hubIdentity, connection.relays)
  } catch (err) {
    throw new ClientError('join_unavailable', `the Hub's announcement could not be found or verified, so nothing was sent; try again later: ${(err as Error).message}`, { cause: err })
  }
  const bill = billFromParts(connection.walletPubkey, connection.secret)
  const now = () => nowSeconds(deps)
  return {
    connection,
    verdict,
    info,
    circle,
    session,
    bill,
    view,
    prepareJoin: (signer, connectionPubkey, terms) => createCircleWalletRequest({ signer, connectionPubkey, hubPubkey: connection.walletPubkey, terms, now: now() }),
    join: (signer, join, terms, send) => createCircleWalletMany(session, [{ id: 'join', hub: bill, signer, join, ...(terms !== undefined && { terms }) }], now, send),
    lookupJoin: (signer, connectionPubkey, deadline) => lookupOne(session, { bill, by: { connectionPubkey }, deadline, authorizer: { kind: 'signer', signer } }, now),
  }
}
