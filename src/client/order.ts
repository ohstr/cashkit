// Ordering from a Cash Hub through its Order connection (`cashorder1…`, NIP-CO).
// Port of nmilat nipCO/client: the string is decoded and verified, `get_info`
// is checked against it (TLV 4 and 6) on every terms read, and `cash_order`
// and its lookups go over the private transport only, signed by the order's
// buyer key with the connection's public secret on the bill proof.
import {
  bySigning,
  CoreError,
  decodeOrderConnection,
  localSigner,
  METHOD_CASH_ORDER,
  onlineCheck,
  orderNoticeFilter,
  parseOrderInfo,
  readNetworkChain,
  sellsNothing,
  sniff,
  verifyOrderConnection,
  isOrderNotice,
  type CashLookupResult,
  type CashOrderRequest,
  type ConnVerdict,
  type HubConnection,
  type OrderTerms,
} from '../core/index.js'
import { billFromParts, type Bill } from './bill.js'
import { ClientError } from './errors.js'
import { hubView, type HubView } from './hubView.js'
import { lookupOne } from './lookup.js'
import { buildItem, run, type TypedOutcome } from './methods.js'
import { NwcClient, type GetInfoResult } from './nwcClient.js'
import { nowSeconds, type ClientDeps } from './ports.js'
import { BatchSession, type SendOptions } from './session.js'

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))

export interface ConnectOrderOptions {
  /** Asked once, after the online check passed, for a string whose signature does not verify. */
  readonly confirmUnverified?: (view: HubView) => Promise<boolean>
  /** `lookup` reads an order already placed: a retired connection's empty terms do not stop it. */
  readonly purpose?: 'order' | 'lookup'
}

export interface OrderClient {
  readonly connection: HubConnection
  readonly verdict: ConnVerdict
  readonly verified: boolean
  readonly session: BatchSession
  /** The order's target: the Order connection, its public secret signing bill proofs. */
  readonly bill: Bill
  readonly network?: string
  readonly chain: string
  view(): HubView
  /** The terms, read (and checked online) again. */
  terms(): Promise<OrderTerms>
  /** One `cash_order` item, its item proof signed by the buyer key. The raw reply value comes back. */
  place(request: CashOrderRequest, o: { buyerKey: string; send?: SendOptions }): Promise<TypedOutcome<unknown> | undefined>
  /** Reads an order by its `request_id` and stored deadline, signed by the buyer key. */
  lookup(requestId: string, deadline: number, buyerKey: string): Promise<TypedOutcome<CashLookupResult>>
  /** Calls `onNotice` on each order notice for `notify`; a notice proves nothing and only schedules a lookup. Returns the stop. */
  watch(notify: string, onNotice: () => void, relays?: readonly string[]): () => void
}

async function readTerms(nwc: NwcClient, connection: HubConnection): Promise<{ info: GetInfoResult; terms: OrderTerms; network?: string; chain?: string }> {
  const info = await nwc.getInfo()
  const nc = readNetworkChain(info)
  try {
    onlineCheck(connection, { ...(typeof info.pubkey === 'string' && { identity: info.pubkey }), ...(nc.chain !== undefined && { chain: nc.chain }) })
  } catch (err) {
    throw new ClientError('connection_mismatch', (err as CoreError).message, { cause: err })
  }
  let terms: OrderTerms
  try {
    terms = parseOrderInfo(info)
  } catch (err) {
    throw new ClientError('reply_malformed', (err as Error).message, { cause: err })
  }
  const network = nc.network ?? (nc.networkRaw !== undefined ? String(nc.networkRaw) : undefined)
  return { info, terms, ...(network !== undefined && { network }), ...(nc.chain !== undefined && { chain: nc.chain }) }
}

/**
 * Connects to an Order connection: decodes (`connection_invalid`, a URI
 * included), verifies its signature, reads `get_info` and checks `pubkey`
 * and `chain` against TLV 4 and 6 (`connection_mismatch`), asks
 * `confirmUnverified` for an unverified string (`connection_unverified`),
 * refuses a connection that sells nothing (`order_not_sold`) or does not
 * list `cash_order` privately (`order_unavailable`), and opens the private
 * transport from the announcement of TLV 4 (`hub_unusable` when it takes no
 * bill-creating call). Nothing is written or sent before this passes.
 */
export async function connectOrder(deps: ClientDeps, cashorder: string, o: ConnectOrderOptions = {}): Promise<OrderClient> {
  const s = cashorder.trim()
  if (sniff(s) !== 'cashorder') throw new ClientError('connection_invalid', 'not a cashorder1 connection string')
  let connection: HubConnection
  try {
    connection = decodeOrderConnection(s)
  } catch (err) {
    throw new ClientError('connection_invalid', (err as Error).message, { cause: err })
  }
  const verdict = verifyOrderConnection(connection)
  const nwc = new NwcClient(deps, { walletPubkey: connection.walletPubkey, relays: connection.relays, secret: connection.secret, extra: {} })
  const first = await readTerms(nwc, connection)
  const view = () => hubView('cashorder', s, connection, verdict, 'pass', first.network)
  if (!verdict.verified && (o.confirmUnverified === undefined || !(await o.confirmUnverified(view())))) {
    throw new ClientError('connection_unverified', "this connection string's signature does not verify, and it was not confirmed")
  }
  if (o.purpose !== 'lookup') {
    if (sellsNothing(first.terms)) throw new ClientError('order_not_sold', 'this Order connection sells nothing now')
    const priv = first.info['private_methods']
    if (!Array.isArray(priv) || !priv.includes(METHOD_CASH_ORDER)) throw new ClientError('order_unavailable', 'this Order connection does not list cash_order on the private transport')
  }
  const session = await BatchSession.open(deps, connection.hubIdentity, connection.relays)
  if (o.purpose !== 'lookup' && !session.usableForBills) throw new ClientError('hub_unusable', 'this Hub announces no usable max_request_age, so no order may go to it')
  const bill = billFromParts(connection.walletPubkey, connection.secret)
  const now = () => nowSeconds(deps)
  return {
    connection,
    verdict,
    verified: verdict.verified,
    session,
    bill,
    ...(first.network !== undefined && { network: first.network }),
    chain: connection.chain,
    view,
    terms: async () => (await readTerms(nwc, connection)).terms,
    async place(request, p) {
      const signer = localSigner(hexBytes(p.buyerKey))
      const r = await run(
        session,
        [{ id: '1', method: METHOD_CASH_ORDER, build: (id, b) => buildItem(id, bill, METHOD_CASH_ORDER, request, bySigning(signer), b, now()) }],
        (_o, v) => v,
        { tombstones: false, ...(p.send !== undefined && { send: p.send }) },
      )
      return r.outcomes[0]
    },
    lookup: (requestId, deadline, buyerKey) => lookupOne(session, { bill, by: { requestId }, deadline, authorizer: { kind: 'signer', signer: localSigner(hexBytes(buyerKey)) } }, now),
    watch(notify, onNotice, relays) {
      const where = [...new Set([...(relays ?? []), ...session.relays, ...connection.relays])]
      return deps.relays.subscribe(where, orderNoticeFilter(notify), {
        onEvent: (e) => {
          if (isOrderNotice(e, notify)) onNotice()
        },
        onEose: () => {},
      })
    },
  }
}
