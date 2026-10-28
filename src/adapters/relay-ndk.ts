// A RelayPool over NDK (an optional peer dependency), for apps that already
// run one. cashkit does not import NDK: pass your instance and its classes.
//
//   import NDK, { NDKEvent, NDKRelaySet } from '@nostr-dev-kit/ndk'
//   const relays = new NdkPool(ndk, { NDKEvent, NDKRelaySet })
//
// One NDK subscription per relay, never grouped or answered from cache, so
// EOSE is per relay and every event really came from the relay named.
import type { NostrEvent } from '../core/index.js'
import { fetchRelayInfo, type Filter, type RelayPool, type SubscriptionHandlers } from '../client/index.js'

interface NdkEventLike {
  rawEvent(): unknown
  publish(relaySet?: unknown, timeoutMs?: number, requiredRelayCount?: number): Promise<Set<unknown>>
}

interface NdkSubscriptionLike {
  stop(): void
}

interface NdkRelayLike {
  readonly connected: boolean
  connect(timeoutMs?: number): Promise<void>
}

/** The slices of NDK this needs (v2/v3). */
export interface NdkLike {
  readonly pool: { getRelay(url: string, connect?: boolean): NdkRelayLike }
  subscribe(
    filters: object,
    opts: object,
    handlers: { onEvent?: (e: NdkEventLike) => void; onEose?: () => void; onClose?: () => void },
  ): NdkSubscriptionLike
}

export interface NdkClasses {
  // NDK wants mutable tags; cashkit events are readonly, so the slot takes anything.
  readonly NDKEvent: new (ndk: never, raw: never) => NdkEventLike
  readonly NDKRelaySet: { fromRelayUrls(urls: readonly string[], ndk: never): unknown }
}

export interface NdkPoolOptions {
  /** How long a publish waits for the relay's OK. Default 10 s. */
  readonly publishTimeoutMs?: number
  /** How long to wait for a relay to connect. Default 10 s. */
  readonly connectTimeoutMs?: number
}

export class NdkPool implements RelayPool {
  constructor(
    private readonly ndk: NdkLike,
    private readonly classes: NdkClasses,
    private readonly o: NdkPoolOptions = {},
  ) {}

  /**
   * The relay, connected. NDK reports EOSE at once for a relay it has not
   * connected yet, which would read as "nothing stored", so every
   * subscription waits for the connection first.
   */
  private async connected(url: string): Promise<void> {
    const r = this.ndk.pool.getRelay(url, false)
    if (!r.connected) await r.connect(this.o.connectTimeoutMs ?? 10_000)
  }

  subscribe(relays: readonly string[], filter: Filter, h: SubscriptionHandlers): () => void {
    let stopped = false
    const subs: NdkSubscriptionLike[] = []
    for (const relay of relays) {
      this.connected(relay).then(
        () => {
          if (stopped) return
          subs.push(
            this.ndk.subscribe(
              { ...filter },
              { closeOnEose: false, groupable: false, relayUrls: [relay], cacheUsage: 'ONLY_RELAY', dontSaveToCache: true },
              {
                onEvent: (e) => h.onEvent(e.rawEvent() as NostrEvent, relay),
                onEose: () => h.onEose(relay),
                onClose: () => h.onClose?.(relay, 'closed'),
              },
            ),
          )
        },
        (err: unknown) => {
          if (!stopped) h.onClose?.(relay, err instanceof Error ? err.message : 'connection failed')
        },
      )
    }
    return () => {
      stopped = true
      subs.forEach((s) => s.stop())
    }
  }

  /** The relay's NIP-11 document over HTTP(S), or undefined. */
  relayInfo(relay: string): Promise<unknown> {
    return fetchRelayInfo(relay)
  }

  /**
   * A refusal keeps the relay's own OK message when NDK exposes it per relay;
   * otherwise `message` is undefined (never NDK's own wording), and a caller
   * re-reads NIP-11 before re-mining.
   */
  async publish(relay: string, e: NostrEvent): Promise<{ ok: boolean; message?: string }> {
    try {
      await this.connected(relay)
      const ev = new this.classes.NDKEvent(this.ndk as never, { ...e, tags: e.tags.map((t) => [...t]) } as never)
      const set = this.classes.NDKRelaySet.fromRelayUrls([relay], this.ndk as never)
      const acked = await ev.publish(set, this.o.publishTimeoutMs ?? 10_000, 1)
      return acked.size > 0 ? { ok: true } : { ok: false }
    } catch (err) {
      // NDK's publish error keeps each relay's own reason in `errors`.
      const perRelay = (err as { errors?: unknown }).errors
      if (perRelay instanceof Map && perRelay.size > 0) {
        const first = [...perRelay.values()][0]
        const m = first instanceof Error ? first.message : typeof first === 'string' ? first : undefined
        return { ok: false, ...(m !== undefined && m !== '' && { message: m }) }
      }
      return { ok: false }
    }
  }
}
