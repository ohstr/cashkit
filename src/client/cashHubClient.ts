// A Cash Hub's own connection (`cashhub1…`): its owner mints over it with
// `mint_cash` (standard transport, NIP-47 `expiration` as deadline) and looks
// a mint up with `cash_lookup` (private transport). Port of nmilat
// nipcash/client cash_hub.go.
import {
  CoreError,
  decodeCashHubConnection,
  mintCashRequest,
  onlineCheck,
  parseMintCashResult,
  readNetworkChain,
  sniff,
  verifyCashHubConnection,
  type CashLookupResult,
  type ConnVerdict,
  type HubConnection,
  type MintCashResult,
  type MintRecipient,
} from '../core/index.js'
import { billFromParts, type Bill } from './bill.js'
import { ClientError, WalletError } from './errors.js'
import { hubView, type HubView } from './hubView.js'
import { lookupOne } from './lookup.js'
import type { TypedOutcome } from './methods.js'
import { NwcClient, type GetInfoResult } from './nwcClient.js'
import { nowSeconds, type ClientDeps } from './ports.js'
import { BatchSession, deadlineFor, MIN_PUBLISH_MARGIN } from './session.js'

export interface CashHubClientOptions {
  /**
   * Asked once, after the online check passed, before anything is sent over
   * a string whose signature does not verify. Without it such a string is
   * refused (`connection_unverified`).
   */
  readonly confirmUnverified?: (view: HubView) => Promise<boolean>
}

export class CashHubClient {
  readonly connection: HubConnection
  readonly verdict: ConnVerdict
  readonly nwc: NwcClient
  private readonly text: string
  private online: 'unchecked' | 'pass' | 'fail' = 'unchecked'
  private network: string | undefined
  private confirmed = false
  private sessionPromise: Promise<BatchSession> | undefined

  /** Takes a `cashhub1` string only; any other form (a URI included) is refused before anything is dialled. */
  constructor(
    private readonly deps: ClientDeps,
    cashhub: string,
    private readonly o: CashHubClientOptions = {},
  ) {
    const s = cashhub.trim()
    if (sniff(s) !== 'cashhub') throw new ClientError('connection_invalid', 'not a cashhub1 connection string')
    try {
      this.connection = decodeCashHubConnection(s)
    } catch (err) {
      throw new ClientError('connection_invalid', (err as Error).message, { cause: err })
    }
    this.text = s
    this.verdict = verifyCashHubConnection(this.connection)
    this.nwc = new NwcClient(deps, { walletPubkey: this.connection.walletPubkey, relays: this.connection.relays, secret: this.connection.secret, extra: {} })
  }

  /** The Hub identity (TLV 4, x-only): the node whose announcement carries the inbox. */
  node(): string {
    return this.connection.hubIdentity
  }

  view(): HubView {
    return hubView('cashhub', this.text, this.connection, this.verdict, this.online, this.network)
  }

  /**
   * `get_info`, checked online on every read: its `pubkey` must name TLV 4
   * and its `chain` TLV 6 (`connection_mismatch` otherwise).
   */
  async getInfo(): Promise<GetInfoResult> {
    const info = await this.nwc.getInfo()
    const nc = readNetworkChain(info)
    try {
      onlineCheck(this.connection, { ...(typeof info.pubkey === 'string' && { identity: info.pubkey }), ...(nc.chain !== undefined && { chain: nc.chain }) })
    } catch (err) {
      this.online = 'fail'
      throw new ClientError('connection_mismatch', (err as CoreError).message, { cause: err })
    }
    this.online = 'pass'
    this.network = nc.network ?? (nc.networkRaw !== undefined ? String(nc.networkRaw) : undefined)
    return info
  }

  /** The online check (once per client), then, for an unverified string, the user's confirmation. */
  async ensureUsable(): Promise<void> {
    if (this.online !== 'pass') await this.getInfo()
    if (this.verdict.verified || this.confirmed) return
    if (this.o.confirmUnverified === undefined || !(await this.o.confirmUnverified(this.view()))) {
      throw new ClientError('connection_unverified', "this connection string's signature does not verify, and it was not confirmed")
    }
    this.confirmed = true
  }

  /** The Hub's private transport, its announcement read from the connection's relays and checked against TLV 4. */
  session(): Promise<BatchSession> {
    this.sessionPromise ??= BatchSession.open(this.deps, this.connection.hubIdentity, this.connection.relays).catch((err: unknown) => {
      this.sessionPromise = undefined
      throw err
    })
    return this.sessionPromise
  }

  /** The bill a mint lookup targets: the connection itself. */
  get bill(): Bill {
    return billFromParts(this.connection.walletPubkey, this.connection.secret)
  }

  /**
   * `mint_cash` with the caller's `requestId`, its deadline as the NIP-47
   * `expiration` (default `deadlineFor(H, now)`). `beforePublish` is the
   * caller's write-ahead; with less than 20 s left after it nothing is sent.
   */
  async mint(
    recipients: readonly MintRecipient[],
    p: { readonly requestId: string; readonly deadline?: number; readonly expirySeconds?: number; readonly beforePublish?: (x: { readonly deadline: number }) => Promise<void> },
  ): Promise<MintCashResult> {
    await this.ensureUsable()
    const session = await this.session()
    if (!session.usableForBills) throw new ClientError('hub_unusable', 'this hub announces no usable max_request_age, so no mint may go to it')
    const req = mintCashRequest({ recipients, requestId: p.requestId, ...(p.expirySeconds !== undefined && { expirySeconds: p.expirySeconds }) })
    const deadline = p.deadline ?? deadlineFor(session.maxRequestAge, nowSeconds(this.deps))
    if (p.beforePublish !== undefined) await p.beforePublish({ deadline })
    if (deadline - nowSeconds(this.deps) < MIN_PUBLISH_MARGIN) throw new ClientError('deadline_too_close', 'less than 20 s were left before the deadline, so nothing was sent')
    const untilDeadline = Math.max((deadline - nowSeconds(this.deps)) * 1000, 0)
    const resp = await this.nwc.call('mint_cash', req, { expiration: deadline, timeoutMs: Math.min(untilDeadline, this.deps.nwcTimeoutMs ?? untilDeadline) })
    if (resp.error) throw new WalletError('mint_cash', resp.error.code, resp.error.message)
    return parseMintCashResult(resp.result, req)
  }

  /** Looks a mint up by its request_id and the deadline it was sent with. */
  async lookupMint(requestId: string, deadline: number): Promise<TypedOutcome<CashLookupResult>> {
    return lookupOne(await this.session(), { bill: this.bill, by: { requestId }, deadline, authorizer: { kind: 'connection' } }, () => nowSeconds(this.deps))
  }
}
