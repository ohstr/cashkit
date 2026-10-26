// A client bound to one bill. Port of nmilat nipcash/client/{client,
// cash_status,cash_redeem,cash_transfer,cash_consolidate,check_claim,
// bill_state,transfer_from_sources,rekey_cash_slice}.go.
//
// Bill methods travel over the private transport, to the Hub identified by
// the bill's own mint signature. The client is stateless about the wallet:
// it persists nothing, and returns what the engine needs to journal.
import {
  cashCommitment,
  decodeToken,
  isCashSecret,
  isSpent,
  matchClaimAuto,
  type CashConsolidateResult,
  type CashRedeemResult,
  type CashStatusResult,
  type CashTarget,
  type CashTransferResult,
  type ConsolidateSource,
  type Credential,
  type Target,
  type Token,
  type ZapFields,
} from '../core/index.js'
import { billFor, minterOf, type Bill } from './bill.js'
import { ClientError, PartialProgressError, WalletError } from './errors.js'
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
import { oneItemError, type BillState } from './outcome.js'
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
}

export interface TransferFromSourcesParams {
  /** At least one, with live amounts and credentials. */
  readonly sources: readonly ConsolidateSource[]
  readonly amount: bigint
  readonly to: Target
  /** Where the sources consolidate first, when there are several. */
  readonly interimIdentity: Target
  /** Proves control of the interim identity afterwards. */
  readonly interimCredential: Credential
}

export interface TransferFromSourcesResult {
  readonly consolidatedFirst?: CashConsolidateResult
  readonly transfer: CashTransferResult
}

export interface RekeyCashSliceParams {
  readonly cashSlice: ConsolidateSource
  /** A pubkey target, used when consolidating with other bills. */
  readonly interimIdentity?: Target
  readonly interimCredential?: Credential
  /** Bills to merge in; none may be cash-mode. */
  readonly consolidateWith?: readonly ConsolidateSource[]
  /** Minted (and recorded) by the caller before the call. */
  readonly newTarget: CashTarget
}

export interface RekeyCashSliceResult {
  readonly newSecret: string
  readonly newWalletPubkey: string
  /** "" when the slice moved in place. */
  readonly newToken: string
  readonly amountMillis: bigint
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

  cashTransfer(p: { credential: Credential; to: Target; currentAmount: bigint; splitAmount?: bigint; zapTarget?: string; remainderCommitment?: string; requestId?: string }): Promise<CashTransferResult> {
    return this.transferMany([{ id: '1', bill: this.bill, ...p }]).then((r) => CashClient.one(r, 'cash_transfer'))
  }

  cashConsolidate(credential: Credential, p: { sources: readonly ConsolidateSource[]; to: Target; requestId?: string }): Promise<CashConsolidateResult> {
    return this.consolidateMany([{ id: '1', bill: this.bill, credential, ...p }]).then((r) => CashClient.one(r, 'cash_consolidate'))
  }

  /**
   * What the bill is: `available` with its roster, `spent` only when the Hub
   * says so, and `indeterminate` for anything else, a timeout included. The
   * error is returned for logging, never to infer that the bill is gone.
   */
  async state(credential: Credential): Promise<{ state: BillState; result?: CashStatusResult; error?: Error }> {
    try {
      const result = await this.cashStatus(credential, 'mine')
      return { state: isSpent(result) ? 'spent' : 'available', result }
    } catch (err) {
      return { state: 'indeterminate', error: err as Error }
    }
  }

  /** Whether this holder can claim the bill, and for how much. */
  async checkClaim(credential: Credential, asPubkey: string): Promise<CheckClaimResult> {
    let result: CashStatusResult
    try {
      result = await this.cashStatus(credential, 'mine')
    } catch (err) {
      if (err instanceof WalletError && err.walletCode === 'NOT_FOUND') throw new ClientError('claim_not_found', 'no matching, unclaimed recipient on this hub')
      throw err
    }
    if (isSpent(result)) throw new ClientError('spent', 'this bill has been spent')
    const row = matchClaimAuto(result.recipients, asPubkey)
    if (row === undefined) throw new ClientError('claim_not_found', 'no matching, unclaimed recipient on this hub')
    // A cash-mode status carries no secret, so the secret is checked against the row's commitment when the Hub shows it.
    if (credential.kind === 'secret' && row.identity_type === 'cash' && row.identity_value !== undefined && (!isCashSecret(credential.secret) || row.identity_value !== cashCommitment(credential.secret))) {
      throw new ClientError('claim_not_found', 'the cash secret does not match this bill')
    }
    const full = result.recipients.find((r) => r === row)!
    const minter = minterOf(this.token, this.zap)?.minter
    return {
      isCash: row.identity_type === 'cash',
      amountMillis: row.amount_millis,
      ...(minter !== undefined && { minterPubkey: minter }),
      redeemFeeMillis: full.redeem_fee_millis,
      netRedeemableMillis: full.net_redeemable_millis,
      ...(full.expires_at !== undefined && { expiresAt: full.expires_at }),
    }
  }

  /** A client for another bill on the same Hub (used after a consolidate). */
  reconnect(token: Token | string): CashClient {
    return new CashClient(this.deps, token)
  }

  /**
   * Sends `amount` to `to` from one or more bills. One source: a split
   * transfer. Several: consolidate into the interim identity, reconnect to
   * the new bill, then split-transfer from it. A failure after the
   * consolidate is a PartialProgressError holding the consolidated bill.
   */
  async transferFromSources(p: TransferFromSourcesParams): Promise<TransferFromSourcesResult> {
    if (p.sources.length === 0) throw new ClientError('bad_input', 'transferFromSources needs at least one source')
    if (p.sources.length === 1) {
      const src = p.sources[0]!
      const transfer = await this.cashTransfer({ credential: src.credential, to: p.to, currentAmount: src.amount, splitAmount: p.amount })
      return { transfer }
    }
    const consolidated = await this.cashConsolidate(p.sources[0]!.credential, { sources: p.sources, to: p.interimIdentity })
    let transfer: CashTransferResult
    try {
      const next = this.reconnect(consolidated.newWalletToken)
      transfer = await next.cashTransfer({ credential: p.interimCredential, to: p.to, currentAmount: consolidated.amountMillis, splitAmount: p.amount })
    } catch (err) {
      throw new PartialProgressError({ consolidated }, err)
    }
    if (transfer.newWalletToken === '' && transfer.remainderWalletToken === '') {
      transfer = { ...transfer, newWalletToken: consolidated.newWalletToken, newWalletPubkey: consolidated.newWalletPubkey }
    }
    return { consolidatedFirst: consolidated, transfer }
  }

  /**
   * Moves a cash slice to a new cash secret the caller already recorded.
   * Alone: one transfer, in place. With other bills: transfer to the interim
   * pubkey, then consolidate everything to the new secret.
   */
  async rekeyCashSlice(p: RekeyCashSliceParams): Promise<RekeyCashSliceResult> {
    const others = p.consolidateWith ?? []
    if (others.length === 0) {
      const r = await this.cashTransfer({ credential: p.cashSlice.credential, to: p.newTarget, currentAmount: p.cashSlice.amount })
      return { newSecret: p.newTarget.secret, newWalletPubkey: p.cashSlice.walletPubkey, newToken: '', amountMillis: r.amountMillis }
    }
    if (p.interimIdentity?.identityType !== 'pubkey' || p.interimCredential === undefined) {
      throw new ClientError('bad_input', 'rekeyCashSlice needs a pubkey interim identity and its credential to consolidate')
    }
    const transferred = await this.cashTransfer({ credential: p.cashSlice.credential, to: p.interimIdentity, currentAmount: p.cashSlice.amount })
    const self: ConsolidateSource = { walletPubkey: p.cashSlice.walletPubkey, amount: p.cashSlice.amount, credential: p.interimCredential }
    let merged: CashConsolidateResult
    try {
      merged = await this.cashConsolidate(p.interimCredential, { sources: [self, ...others], to: p.newTarget })
    } catch (err) {
      throw new PartialProgressError({ transferred }, err)
    }
    return { newSecret: p.newTarget.secret, newWalletPubkey: merged.newWalletPubkey, newToken: merged.newWalletToken, amountMillis: merged.amountMillis }
  }
}
