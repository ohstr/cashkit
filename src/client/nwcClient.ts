// A NIP-47 client for one wallet connection (kind 23194/23195, nip44_v2).
// Port of the parts of nmilat relay/client/nwc.go that cashkit uses.
import {
  chooseEncryption,
  ENCRYPTION_NIP44_V2,
  fromHex,
  KIND_NWC_INFO,
  KIND_NWC_RESPONSE,
  finalizeEvent,
  nwcRequestEvent,
  parseInfoEvent,
  parsePairingURI,
  parseResponseEvent,
  verifyEvent,
  type NWCEncryption,
  type NWCResponse,
  type PairingInfo,
} from '../core/index.js'
import { ClientError, WalletError } from './errors.js'
import { nowMs, nowSeconds, randomOf, type ClientDeps } from './ports.js'
import { EventQueue, readEvents } from './relayIO.js'

/** How long to look for the wallet's info event before assuming nip44_v2. */
export const NWC_INFO_WAIT_MS = 3000

/** How long a call waits for the wallet's response by default. */
export const NWC_CALL_TIMEOUT_MS = 60_000

export interface MakeInvoiceParams {
  readonly amount: bigint
  readonly description?: string
  readonly descriptionHash?: string
  readonly expiry?: number
}

export class NwcClient {
  readonly pairing: PairingInfo
  private readonly secret: Uint8Array
  private encryptionPromise: Promise<NWCEncryption> | undefined

  constructor(
    private readonly deps: ClientDeps,
    pairing: PairingInfo | string,
    /** Skip negotiation and always use this scheme. */
    encryption?: NWCEncryption,
  ) {
    this.pairing = typeof pairing === 'string' ? parsePairingURI(pairing) : pairing
    if (this.pairing.relays.every((r) => r.trim() === '')) throw new ClientError('no_relay', 'pairing info has no usable relay urls')
    this.secret = fromHex(this.pairing.secret, 'connection secret')
    if (encryption !== undefined) this.encryptionPromise = Promise.resolve(encryption)
  }

  get walletPubkey(): string {
    return this.pairing.walletPubkey
  }

  /**
   * The scheme this wallet speaks (NIP-47 §Encryption), from its newest
   * signed kind 13194 info event: nip44_v2 when listed, nip04 when that is
   * all it lists or it lists nothing. A wallet that publishes no info event
   * is spoken to in nip44_v2. Looked up once per client.
   */
  encryption(): Promise<NWCEncryption> {
    this.encryptionPromise ??= (async () => {
      const relays = this.pairing.relays.filter((r) => r.trim() !== '')
      const events = await readEvents(this.deps.relays, relays, { kinds: [KIND_NWC_INFO], authors: [this.walletPubkey] }, NWC_INFO_WAIT_MS)
      let newest: (typeof events)[number] | undefined
      for (const e of events) if (e.pubkey === this.walletPubkey && verifyEvent(e) && (newest === undefined || e.created_at > newest.created_at)) newest = e
      if (newest === undefined) return ENCRYPTION_NIP44_V2
      const chosen = chooseEncryption(parseInfoEvent(newest))
      if (chosen === undefined) throw new ClientError('bad_input', 'the wallet supports neither nip44_v2 nor nip04 encryption')
      return chosen
    })().catch((err: unknown) => {
      this.encryptionPromise = undefined
      throw err
    })
    return this.encryptionPromise
  }

  /**
   * Sends one request and waits for its response. Only a response authored
   * by the wallet itself and correctly signed is accepted: anyone can tag an
   * event with the request id and encrypt it to this connection.
   */
  async call(method: string, params?: unknown, timeoutMs = this.deps.nwcTimeoutMs ?? NWC_CALL_TIMEOUT_MS): Promise<NWCResponse> {
    const encryption = await this.encryption()
    const unsigned = nwcRequestEvent({
      connectionSecret: this.secret,
      walletPubkey: this.walletPubkey,
      method,
      ...(params !== undefined && { params }),
      createdAt: nowSeconds(this.deps),
      nonce: randomOf(this.deps)(encryption === ENCRYPTION_NIP44_V2 ? 32 : 16),
      encryption,
    })
    const request = finalizeEvent(unsigned, this.secret)
    const relays = this.pairing.relays.filter((r) => r.trim() !== '')
    const queue = new EventQueue()
    queue.opened()
    const stop = this.deps.relays.subscribe(relays, { kinds: [KIND_NWC_RESPONSE], '#e': [request.id] }, {
      onEvent: (e) => queue.push(e),
      onEose: () => {},
    })
    try {
      let sent = false
      const failures: string[] = []
      for (const relay of relays) {
        try {
          const res = await this.deps.relays.publish(relay, request)
          if (res.ok) {
            sent = true
            break
          }
          failures.push(`${relay}: refused${res.message ? `: ${res.message}` : ''}`)
        } catch (err) {
          failures.push(`${relay}: ${(err as Error).message}`)
        }
      }
      if (!sent) throw new ClientError('no_relay', `no relay took the request (${failures.join('; ')})`)
      const deadline = nowMs(this.deps) + timeoutMs
      for (;;) {
        const e = await queue.next(deadline - nowMs(this.deps))
        if (e === undefined) throw new ClientError('timeout', `${method}: no response from the wallet`)
        if (e.pubkey !== this.walletPubkey || !verifyEvent(e)) continue
        let resp: NWCResponse
        try {
          resp = parseResponseEvent(e, this.secret, encryption)
        } catch {
          continue
        }
        if (resp.requestEventId !== request.id) continue
        return resp
      }
    } finally {
      stop()
    }
  }

  /** `call`, turning a wallet error into WalletError and returning the result. */
  async request<T = unknown>(method: string, params?: unknown, timeoutMs?: number): Promise<T> {
    const resp = await this.call(method, params, timeoutMs)
    if (resp.error) throw new WalletError(method, resp.error.code, resp.error.message)
    return resp.result as T
  }

  getInfo<T = Record<string, unknown>>(): Promise<T> {
    return this.request('get_info')
  }
  getBalance(): Promise<{ balance: number }> {
    return this.request('get_balance')
  }
  makeInvoice(p: MakeInvoiceParams): Promise<Record<string, unknown>> {
    return this.request('make_invoice', {
      amount: p.amount,
      ...(p.description !== undefined && { description: p.description }),
      ...(p.descriptionHash !== undefined && { description_hash: p.descriptionHash }),
      ...(p.expiry !== undefined && { expiry: p.expiry }),
    })
  }
  payInvoice(invoice: string, amount?: bigint): Promise<{ preimage: string; fees_paid?: number }> {
    return this.request('pay_invoice', { invoice, ...(amount !== undefined && { amount }) })
  }
  listTransactions(p: { from?: number; until?: number; limit?: number; offset?: number; unpaid?: boolean; type?: string } = {}): Promise<{ transactions: unknown[] }> {
    return this.request('list_transactions', p)
  }
  signMessage(message: string): Promise<{ message: string; signature: string }> {
    return this.request('sign_message', { message })
  }
}
