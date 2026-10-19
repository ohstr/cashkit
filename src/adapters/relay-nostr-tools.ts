// A RelayPool over nostr-tools' SimplePool (an optional peer dependency),
// for apps that already run one. cashkit does not import nostr-tools: pass
// your pool in.
//
//   import { SimplePool } from 'nostr-tools/pool'
//   const relays = new NostrToolsPool(new SimplePool())
//
// One SimplePool subscription per relay, so EOSE and CLOSED are reported per
// relay, as the batch session needs (it publishes to a relay only after that
// relay's EOSE, SD-34).
import type { NostrEvent } from '../core/index.js'
import type { Filter, RelayPool, SubscriptionHandlers } from '../client/index.js'

/** The slice of nostr-tools' SimplePool this needs (2.x). */
export interface SimplePoolLike {
  subscribe(
    relays: string[],
    filter: Record<string, unknown>,
    params: {
      onevent?: (e: NostrEvent) => void
      oneose?: () => void
      onclose?: (reasons: { url: string; reason: string }[] | string[]) => void
    },
  ): { close(reason?: string): void }
  publish(relays: string[], event: NostrEvent): Promise<string>[]
}

export class NostrToolsPool implements RelayPool {
  constructor(private readonly pool: SimplePoolLike) {}

  subscribe(relays: readonly string[], filter: Filter, h: SubscriptionHandlers): () => void {
    const subs = relays.map((relay) =>
      this.pool.subscribe([relay], { ...filter } as Record<string, unknown>, {
        onevent: (e) => h.onEvent(e, relay),
        oneose: () => h.onEose(relay),
        onclose: (reasons) => {
          const first = reasons[0]
          h.onClose?.(relay, typeof first === 'string' ? first : (first?.reason ?? 'closed'))
        },
      }),
    )
    return () => subs.forEach((s) => s.close())
  }

  async publish(relay: string, e: NostrEvent): Promise<{ ok: boolean; message?: string }> {
    try {
      const reason = await this.pool.publish([relay], e)[0]
      return { ok: true, ...(reason !== undefined && reason !== '' && { message: reason }) }
    } catch (err) {
      return { ok: false, message: err instanceof Error ? err.message : String(err) }
    }
  }
}
