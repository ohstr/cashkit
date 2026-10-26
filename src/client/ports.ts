// The side-effecting interfaces the client layer runs over (design §3). The
// client never opens a socket itself; an adapter implements RelayPool.
import type { NostrEvent } from '../core/index.js'

/** A NIP-01 subscription filter. Tag filters use `#<letter>` keys. */
export interface Filter {
  readonly ids?: readonly string[]
  readonly authors?: readonly string[]
  readonly kinds?: readonly number[]
  readonly since?: number
  readonly until?: number
  readonly limit?: number
  readonly '#p'?: readonly string[]
  readonly '#e'?: readonly string[]
  readonly '#P'?: readonly string[]
  readonly '#w'?: readonly string[]
  readonly '#a'?: readonly string[]
  readonly '#k'?: readonly string[]
  readonly '#d'?: readonly string[]
}

export interface SubscriptionHandlers {
  onEvent(e: NostrEvent, relay: string): void
  /** End of stored events on `relay`: the subscription is live from here. */
  onEose(relay: string): void
  /** The relay closed the subscription (CLOSED) or the connection dropped. */
  onClose?(relay: string, reason: string): void
}

export interface RelayPool {
  /** Subscribes on every relay; returns a function that unsubscribes. */
  subscribe(relays: readonly string[], filter: Filter, h: SubscriptionHandlers): () => void
  /** Publishes to one relay and resolves with its OK. */
  publish(relay: string, e: NostrEvent): Promise<{ ok: boolean; message?: string }>
}

export interface ClientDeps {
  readonly relays: RelayPool
  /** Milliseconds since the epoch. Default Date.now. */
  readonly clock?: () => number
  /** Default crypto.getRandomValues. */
  readonly random?: (n: number) => Uint8Array
  /**
   * The longest a send waits for its reply, in ms. The wait never outlasts
   * the envelope's own deadline, which comes from the Hub's
   * `max_request_age` and is never an app setting.
   */
  readonly replyWaitMs?: number
  /** How long an NWC call waits for the wallet's response. Default 60 s. */
  readonly nwcTimeoutMs?: number
}

export const nowMs = (d: Pick<ClientDeps, 'clock'>): number => (d.clock ?? Date.now)()
export const nowSeconds = (d: Pick<ClientDeps, 'clock'>): number => Math.floor(nowMs(d) / 1000)
export const randomOf = (d: Pick<ClientDeps, 'random'>) =>
  d.random ?? ((n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)))
