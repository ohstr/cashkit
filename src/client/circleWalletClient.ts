// A member's own Circle Wallet (NIP-CW §What a Circle Wallet Connection
// Allows), spoken to directly over NIP-47 from its fields: the Hub's
// `wallet_pubkey` and `relays` and the member's own secret. A Circle Wallet
// has no URI form, and none is built here.
import { maxPaymentCost, METHOD_DELETE_CIRCLE_WALLET, readNetworkChain, type CircleWalletConnection } from '../core/index.js'
import { ClientError } from './errors.js'
import { NwcClient, type GetInfoResult } from './nwcClient.js'
import type { ClientDeps } from './ports.js'

/** `get_budget`: the send cap in NIP-47's fields, the receive cap beside them. */
export interface CircleBudget {
  readonly totalBudget: bigint
  readonly usedBudget: bigint
  readonly renewsAt?: number
  readonly renewalPeriod?: string
  readonly totalReceiveBudget: bigint
  readonly usedReceiveBudget: bigint
}

/** An advisory worst case for a Lightning payment: a payment on the node carries no fee and counts against no cap. */
export interface PaymentPreview {
  readonly maxCost: bigint
  readonly withinBalance: boolean
  /** Undefined unless the wallet is Active and its budget is known. */
  readonly withinSendRoom?: boolean
}

const big = (v: unknown): bigint => (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : typeof v === 'bigint' && v >= 0n ? v : 0n)

export class CircleWalletClient {
  readonly nwc: NwcClient

  constructor(
    deps: ClientDeps,
    readonly connection: CircleWalletConnection,
  ) {
    if (connection.secret === '' || connection.relays.length === 0) throw new ClientError('bad_input', 'a circle wallet connection needs its relays and the member’s secret')
    this.nwc = new NwcClient(deps, { walletPubkey: connection.walletPubkey, relays: connection.relays, secret: connection.secret, extra: {} })
  }

  /** `get_info` with its `network` and `chain`; anything but mainnet is a test network. */
  async getInfo(): Promise<GetInfoResult & { readonly testNetwork: boolean }> {
    const info = await this.nwc.getInfo()
    const nc = readNetworkChain(info)
    return { ...info, testNetwork: nc.network !== 'mainnet' }
  }

  async getBalance(): Promise<bigint> {
    return big((await this.nwc.getBalance()).balance)
  }

  async getBudget(): Promise<CircleBudget> {
    const r = (await this.nwc.request('get_budget')) as Record<string, unknown>
    return {
      totalBudget: big(r['total_budget']),
      usedBudget: big(r['used_budget']),
      ...(typeof r['renews_at'] === 'number' && { renewsAt: r['renews_at'] }),
      ...(typeof r['renewal_period'] === 'string' && { renewalPeriod: r['renewal_period'] }),
      totalReceiveBudget: big(r['total_receive_budget']),
      usedReceiveBudget: big(r['used_receive_budget']),
    }
  }

  /** An invoice needs an amount above zero: a Hub refuses an amountless one. */
  makeInvoice(p: { amount: bigint; description?: string; expiry?: number }): Promise<Record<string, unknown>> {
    if (p.amount <= 0n) throw new ClientError('bad_input', 'a circle wallet invoice needs an amount above zero')
    return this.nwc.makeInvoice(p)
  }

  payInvoice(invoice: string, amount?: bigint): Promise<{ preimage: string; fees_paid?: number }> {
    return this.nwc.payInvoice(invoice, amount)
  }

  payKeysend(p: { amount: bigint; pubkey: string; preimage?: string }): Promise<{ preimage: string; fees_paid?: number }> {
    return this.nwc.request('pay_keysend', { amount: p.amount, pubkey: p.pubkey, ...(p.preimage !== undefined && { preimage: p.preimage }) })
  }

  lookupInvoice(invoice: string): Promise<{ settled_at?: number; state?: string }> {
    return this.nwc.lookupInvoice(invoice)
  }

  listTransactions(p: { from?: number; until?: number; limit?: number; offset?: number; unpaid?: boolean; type?: string } = {}): Promise<{ transactions: unknown[] }> {
    return this.nwc.listTransactions(p)
  }

  /** `delete_circle_wallet`: the wallet's dust goes to the host. The caller checks the balance first. */
  deleteWallet(): Promise<unknown> {
    return this.nwc.request(METHOD_DELETE_CIRCLE_WALLET, {})
  }

  /**
   * The Lightning worst case: the amount, the wallet's own `fees_ppm` fee
   * and the Hub's current routing-fee reserve, against the balance and,
   * while Active, the send room. Advisory only: the Hub decides.
   */
  static previewPayment(amount: bigint, p: { feesPpm: number; feeReserve: { ppm: number; min_millis: bigint }; balance: bigint; budget?: CircleBudget; active: boolean }): PaymentPreview {
    const maxCost = maxPaymentCost(amount, p.feesPpm, p.feeReserve)
    return {
      maxCost,
      withinBalance: maxCost <= p.balance,
      ...(p.active && p.budget !== undefined && { withinSendRoom: maxCost <= p.budget.totalBudget - p.budget.usedBudget }),
    }
  }
}
