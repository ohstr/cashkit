// A client bound to one bill. Port of nmilat nipcash/client/{client,
// cash_status,cash_redeem,cash_transfer,cash_consolidate,check_claim,
// bill_state,transfer_from_sources,rekey_cash_slice}.go.
//
// Bill methods travel over the private transport, to the Hub identified by
// the bill's own mint signature. The client is stateless about the wallet:
// it persists nothing, and returns what the engine needs to journal.
import {
  decodeToken,
  isSpent,
  ownClaim,
  ownScope,
  type NotClaimableReason,
  type CashConsolidateResult,
  type CashRedeemResult,
  type CashStatusResult,
  type CashTransferResult,
  type ConsolidateSource,
  type Credential,
  type Target,
  type Token,
  type ZapFields,
} from '../core/index.js'
import { billFor, minterOf, type Bill } from './bill.js'
import { ClientError, WalletError } from './errors.js'
import {
  consolidateMany,
  redeemMany,
  statusMany,
  transferMany,
  type BatchConsolidate,
  type BatchRedeem,
  type BatchResult,
  type BatchStatus,
  type BatchTransfer,
  type TypedOutcome,
} from './methods.js'
import { oneItemError, statusUnreadable, type BillState } from './outcome.js'
import { nowSeconds, type ClientDeps } from './ports.js'
import { BatchSession } from './session.js'

export interface CheckClaimResult {
  readonly isCash: boolean
  /** Authoritative, from cash_status. */
  readonly amountMillis: bigint
  /** Set only when the token carries a mint signature that verifies. */
  readonly minterPubkey?: string
  readonly redeemFeeMillis: bigint
  readonly netRedeemableMillis: bigint
  readonly expiresAt?: number
  /**
   * Whether the caller's row can still be spent. A claimed, withdrawn or
   * expired row is reported here (with `reason`), never as not found.
   */
  readonly claimable: boolean
  readonly reason: NotClaimableReason
}

export class CashClient {
  readonly token: Token
  readonly bill: Bill
  private sessionPromise: Promise<BatchSession> | undefined

  /**
   * `zap` carries a zap bill's Cash Zap fields: without them its provenance
   * cannot verify, and the client refuses to contact any relay.
   */
  constructor(
    private readonly deps: ClientDeps,
    token: Token | string,
    private readonly zap?: ZapFields,
  ) {
    this.token = typeof token === 'string' ? decodeToken(token) : token
    this.bill = billFor(this.token, zap)
  }

  get walletPubkey(): string {
    return this.token.walletPubkey
  }

  private readonly now = () => nowSeconds(this.deps)

  /** The bill's Hub session, opened on first use and reused. */
  session(): Promise<BatchSession> {
    if (this.sessionPromise === undefined) {
      if (this.token.scheme === 'zap_v1' && this.zap === undefined) {
        return Promise.reject(new ClientError('no_zap_event', "this is a zap bill: its mint signature verifies only with the Cash Zap that carries it, so its hub cannot be identified without it"))
      }
      const minter = minterOf(this.token, this.zap)
      if (minter === undefined) {
        return Promise.reject(new ClientError('no_provenance', 'this bill carries no verifiable mint signature, so its hub cannot be identified'))
      }
      this.sessionPromise = BatchSession.open(this.deps, minter.minter, this.token.relays).catch((err: unknown) => {
        this.sessionPromise = undefined
        throw err
      })
    }
    return this.sessionPromise
  }

  async statusMany(items: readonly BatchStatus[]): Promise<BatchResult<CashStatusResult>> {
    return statusMany(await this.session(), items, this.now)
  }
  async redeemMany(items: readonly BatchRedeem[]): Promise<BatchResult<CashRedeemResult>> {
    return redeemMany(await this.session(), items, this.now)
  }
  async transferMany(items: readonly BatchTransfer[]): Promise<BatchResult<CashTransferResult>> {
    return transferMany(await this.session(), items, this.now)
  }
  async consolidateMany(items: readonly BatchConsolidate[]): Promise<BatchResult<CashConsolidateResult>> {
    return consolidateMany(await this.session(), items, this.now)
  }

  private static one<R>(r: BatchResult<R>, method: string): R {
    const o: TypedOutcome<R> | undefined = r.outcomes[0]
    const err = oneItemError(o, r.error, method)
    if (err) throw err
    return o!.value as R
  }

  cashStatus(credential: Credential, scope: '' | 'mine' | 'all' = 'mine'): Promise<CashStatusResult> {
    return this.statusMany([{ id: '1', bill: this.bill, credential, scope }]).then((r) => CashClient.one(r, 'cash_status'))
  }

  cashRedeem(p: { invoice: string; credential: Credential; amount?: bigint }): Promise<CashRedeemResult> {
    return this.redeemMany([{ id: '1', bill: this.bill, ...p }]).then((r) => CashClient.one(r, 'cash_redeem'))
  }

  /** A bill-creating call: `requestId` is the caller's, saved before sending (`bad_input` without it). */
  cashTransfer(p: { credential: Credential; to: Target; currentAmount: bigint; splitAmount?: bigint; zapTarget?: string; remainderCommitment?: string; requestId: string }): Promise<CashTransferResult> {
    return this.transferMany([{ id: '1', bill: this.bill, ...p }]).then((r) => CashClient.one(r, 'cash_transfer'))
  }

  /** A bill-creating call: `requestId` is the caller's, saved before sending (`bad_input` without it). */
  cashConsolidate(credential: Credential, p: { sources: readonly ConsolidateSource[]; to: Target; requestId: string }): Promise<CashConsolidateResult> {
    return this.consolidateMany([{ id: '1', bill: this.bill, credential, ...p }]).then((r) => CashClient.one(r, 'cash_consolidate'))
  }

  /**
   * What the bill is: `available` with its roster, `spent` only when the Hub
   * says so, `unreadable` when a connection-key holder is answered
   * `NOT_FOUND` (`statusUnreadable`), and `indeterminate` for anything else,
   * a timeout included. The error is returned for logging, never to infer
   * that the bill is gone.
   */
  async state(credential: Credential): Promise<{ state: BillState; result?: CashStatusResult; error?: Error }> {
    try {
      const result = await this.cashStatus(credential, ownScope(credential))
      return { state: isSpent(result) ? 'spent' : 'available', result }
    } catch (err) {
      return { state: statusUnreadable(credential, err) ? 'unreadable' : 'indeterminate', error: err as Error }
    }
  }

  /**
   * The caller's own row and whether it can be spent (port of nmilat
   * CheckClaim). The row is found from the credential, never from the
   * caller's word: a pubkey, a connection_key with its IA, or the cash row
   * the secret commits to. NOT_FOUND, or an answer that is not exactly that
   * row, is `claim_not_found`, except for a connection-key holder, whose
   * NOT_FOUND is `status_unreadable` (`statusUnreadable`); a destroyed bill
   * is `spent`; a claimed, withdrawn or expired row comes back with
   * `claimable` false.
   */
  async checkClaim(credential: Credential): Promise<CheckClaimResult> {
    let result: CashStatusResult
    try {
      result = await this.cashStatus(credential, ownScope(credential))
    } catch (err) {
      if (statusUnreadable(credential, err)) throw new ClientError('status_unreadable', "this Hub does not show a connection-key holder its bill's status", { cause: err })
      if (err instanceof WalletError && err.walletCode === 'NOT_FOUND') throw new ClientError('claim_not_found', 'no matching, unclaimed recipient on this hub')
      throw err
    }
    if (isSpent(result)) throw new ClientError('spent', 'this bill has been spent')
    let own
    try {
      own = ownClaim(result.recipients, credential, this.now())
    } catch (err) {
      const message = credential.kind === 'secret' ? 'the cash secret does not match this bill' : "the Hub's answer is not this holder's row"
      throw new ClientError('claim_not_found', message, { cause: err })
    }
    const { row } = own
    const minter = minterOf(this.token, this.zap)?.minter
    return {
      isCash: row.identity_type === 'cash',
      amountMillis: row.amount_millis,
      ...(minter !== undefined && { minterPubkey: minter }),
      redeemFeeMillis: row.redeem_fee_millis,
      netRedeemableMillis: row.net_redeemable_millis,
      ...(row.expires_at !== undefined && { expiresAt: row.expires_at }),
      claimable: own.claimable,
      reason: own.reason,
    }
  }
}
