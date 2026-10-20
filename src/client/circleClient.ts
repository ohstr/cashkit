// Joining a Circle Hub. Port of nmilat nipcw/client: create_circle_wallet
// travels over NIP-CASH's private transport when the Hub offers it (NIP-CW
// §Private Join) and over the Hub's own NWC connection otherwise. The
// connection key is generated here so only its pubkey ever leaves the device.
import {
  connectionKeyFromSecret,
  createCircleWalletRequest,
  parseCreateCircleWalletResult,
  toHex,
  type CircleWallet,
  type ConnectionKeyPair,
  type PairingInfo,
} from '../core/index.js'
import { billFromParts } from './bill.js'
import { createCircleWalletMany, type CreateCircleWalletParams } from './circleJoin.js'
import { ClientError, PrivateJoinUnavailableError, WalletError } from './errors.js'
import type { BatchResult } from './methods.js'
import { oneItemError } from './outcome.js'
import { nowSeconds, randomOf, type ClientDeps } from './ports.js'
import { NwcClient, type GetInfoResult } from './nwcClient.js'
import { openBatchSession, type BatchSession } from './session.js'

export interface JoinOptions {
  /**
   * Refuse with PrivateJoinUnavailableError rather than join over the shared
   * Hub connection, where the requester's pubkey is visible to every
   * co-member and the join to every relay observer.
   */
  readonly requirePrivate?: boolean
}

/** How a join travels, chosen once so that a retry never changes it. */
export interface JoinTransport {
  /** The Hub's private-transport session; absent means the standard transport. */
  readonly session?: BatchSession
  /** Why the join goes over the standard transport although the Hub offers Private Join. */
  readonly fallbackReason?: Error
  readonly requirePrivate: boolean
}

export interface CircleJoinResult {
  readonly wallet: CircleWallet
  /** The key the wallet pairs over: persist it before relying on the result. Secret-bearing. */
  readonly connection: ConnectionKeyPair
  /** Whether the join went over the private transport. */
  readonly private: boolean
  /**
   * Set when the Hub offers Private Join but the join went over the standard
   * transport. A client should tell the member the join was not private
   * (NIP-CW §Finding the Private Transport).
   */
  readonly fallbackReason?: Error
}

const X_ONLY = /^[0-9a-f]{64}$/

export class CircleClient {
  private readonly nwc: NwcClient

  constructor(
    private readonly deps: ClientDeps,
    hubConnection: PairingInfo | string,
  ) {
    this.nwc = new NwcClient(deps, hubConnection)
  }

  get hubPubkey(): string {
    return this.nwc.walletPubkey
  }

  /** The Hub's terms, and its node identity when it offers Private Join. */
  getInfo(): Promise<GetInfoResult> {
    return this.nwc.getInfo()
  }

  /** A fresh member connection key, from the deps' randomness. */
  newConnectionKey(): ConnectionKeyPair {
    for (;;) {
      try {
        return connectionKeyFromSecret(toHex(randomOf(this.deps)(32)))
      } catch {
        // an out-of-range draw; astronomically rare
      }
    }
  }

  /**
   * Requests the caller's circle wallet, over the private transport when the
   * Hub offers it and the standard one otherwise. Refusals carry the standard
   * join's codes either way (NOT_READY, RESTRICTED, WALLET_EXISTS,
   * RATE_LIMITED) as a WalletError.
   */
  async join(p: CreateCircleWalletParams, o: JoinOptions = {}): Promise<CircleJoinResult> {
    return this.createCircleWallet(p, await this.chooseTransport(o))
  }

  /**
   * Picks the transport. The node identity is read only from this
   * connection's get_info, whose reply the Hub connection key authenticates;
   * its announcement is then fetched and verified against it. An identity
   * that is absent, or a get_info the Hub refuses, means the standard transport; one whose announcement
   * cannot be found or verified means the standard transport with a
   * fallbackReason, or PrivateJoinUnavailableError under `requirePrivate`.
   */
  async chooseTransport(o: JoinOptions = {}): Promise<JoinTransport> {
    const requirePrivate = o.requirePrivate === true
    let info: GetInfoResult
    try {
      info = await this.nwc.getInfo()
    } catch (err) {
      // A Hub that offers Private Join must report its identity in get_info, so one that refuses get_info does not.
      if (!(err instanceof WalletError)) throw err
      info = {}
    }
    const identity = info.circle_wallet?.identity
    if (identity === undefined) {
      if (requirePrivate) throw new PrivateJoinUnavailableError('the Hub does not offer it')
      return { requirePrivate }
    }
    try {
      if (!X_ONLY.test(identity)) throw new ClientError('bad_input', 'the identity in get_info is not an x-only pubkey')
      const relays = this.nwc.pairing.relays.filter((r) => r.trim() !== '')
      return { session: await openBatchSession(this.deps, identity, relays), requirePrivate }
    } catch (err) {
      return unavailable(err, requirePrivate)
    }
  }

  /**
   * Requests a circle wallet over `via` (default: the standard transport).
   * A private join that fails before anything is sent falls back to the
   * standard transport, and says so in fallbackReason; once the private
   * request is out it never falls back, since a missing reply may mean the
   * join ran.
   */
  async createCircleWallet(p: CreateCircleWalletParams, via?: JoinTransport): Promise<CircleJoinResult> {
    const connection = p.connection ?? this.newConnectionKey()
    const params = { ...p, connection }
    let fallbackReason = via?.fallbackReason
    if (via?.session !== undefined) {
      const r = await this.privateJoin(via.session, params)
      if ('wallet' in r) return { wallet: r.wallet, connection, private: true }
      const t = unavailable(r.notSent, via.requirePrivate)
      fallbackReason = t.fallbackReason
    }
    const wallet = await this.standardJoin(params, connection)
    return { wallet, connection, private: false, ...(fallbackReason !== undefined && { fallbackReason }) }
  }

  private async standardJoin(p: CreateCircleWalletParams, connection: ConnectionKeyPair): Promise<CircleWallet> {
    const req = await createCircleWalletRequest({
      signer: p.signer,
      connection,
      hubPubkey: this.hubPubkey,
      maxAmountMillis: p.maxAmountMillis,
      expirySeconds: p.expirySeconds,
      ...(p.budgetRenewal !== undefined && { budgetRenewal: p.budgetRenewal }),
      now: nowSeconds(this.deps),
    })
    const result = await this.nwc.request('create_circle_wallet', req)
    return parseCreateCircleWalletResult(result, { signer: p.signer, connection, hubPubkey: this.hubPubkey })
  }

  /** One join over the private transport; `notSent` is a failure before anything went out. */
  private async privateJoin(session: BatchSession, params: CreateCircleWalletParams): Promise<{ wallet: CircleWallet } | { notSent: unknown }> {
    let r: BatchResult<CircleWallet>
    try {
      const hub = billFromParts(this.hubPubkey, this.nwc.pairing.secret)
      r = await createCircleWalletMany(session, [{ id: 'join', hub, params }], () => nowSeconds(this.deps))
    } catch (err) {
      // No outcome means the item was never packed, so nothing was sent.
      return { notSent: err }
    }
    const o = r.outcomes[0]
    const err = oneItemError(o, r.error, 'create_circle_wallet')
    if (err !== undefined) throw err
    return { wallet: o!.value! }
  }
}

function unavailable(err: unknown, requirePrivate: boolean): JoinTransport & { fallbackReason: Error } {
  const reason = err instanceof Error ? err : new Error(String(err))
  if (requirePrivate) throw new PrivateJoinUnavailableError(reason.message, { cause: reason })
  return { requirePrivate, fallbackReason: reason }
}
