// Joining a Circle Hub. Port of nmilat nipcw/client: create_circle_wallet
// travels over the Hub's own NWC connection, and the connection key is
// generated here so only its pubkey ever leaves the device.
import {
  connectionKeyFromSecret,
  createCircleWalletRequest,
  parseCreateCircleWalletResult,
  toHex,
  type CircleWallet,
  type ConnectionKeyPair,
  type PairingInfo,
  type Signer,
} from '../core/index.js'
import { nowSeconds, randomOf, type ClientDeps } from './ports.js'
import { NwcClient } from './nwcClient.js'

export interface CreateCircleWalletParams {
  readonly signer: Signer
  readonly maxAmountMillis: bigint
  readonly expirySeconds: number
  readonly budgetRenewal?: string
  /** Supplied to resume a join; otherwise one is generated. Secret-bearing. */
  readonly connection?: ConnectionKeyPair
}

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
   * Requests a circle wallet. Returns the wallet and the connection key it
   * pairs over: persist the key before relying on the result.
   */
  async createCircleWallet(p: CreateCircleWalletParams): Promise<{ wallet: CircleWallet; connection: ConnectionKeyPair }> {
    const connection = p.connection ?? this.newConnectionKey()
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
    const wallet = await parseCreateCircleWalletResult(result, { signer: p.signer, connection, hubPubkey: this.hubPubkey })
    return { wallet, connection }
  }
}
