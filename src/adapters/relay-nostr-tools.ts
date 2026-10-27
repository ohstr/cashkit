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
import type { EventTemplate, NostrEvent } from '../core/index.js'
import { fetchRelayInfo, type AuthSigner, type Filter, type RelayPool, type SubscriptionHandlers } from '../client/index.js'

/** The slice of nostr-tools' SimplePool this needs (2.x). */
export interface SimplePoolLike {
  subscribe(
    relays: string[],
    filter: Record<string, unknown>,
    params: {
      onevent?: (e: NostrEvent) => void
      oneose?: () => void
      onclose?: (reasons: { url: string; reason: string }[] | string[]) => void
      onauth?: (t: EventTemplate) => Promise<NostrEvent>
    },
  ): { close(reason?: string): void }
  publish(relays: string[], event: NostrEvent, params?: { onauth?: (t: EventTemplate) => Promise<NostrEvent> }): Promise<string>[]
}

export class NostrToolsPool implements RelayPool {
  private signer: AuthSigner | undefined
  constructor(private readonly pool: SimplePoolLike) {}

  /** NIP-42: nostr-tools answers a relay's AUTH challenge with `sign` (passed as `onauth`). */
  setAuth(sign: AuthSigner | undefined): void {
    this.signer = sign
  }

  private get auth(): { onauth?: (t: EventTemplate) => Promise<NostrEvent> } {
    const sign = this.signer
    return sign !== undefined ? { onauth: (t) => sign(t) } : {}
  }

  subscribe(relays: readonly string[], filter: Filter, h: SubscriptionHandlers): () => void {
    const subs = relays.map((relay) =>
      this.pool.subscribe([relay], { ...filter } as Record<string, unknown>, {
        onevent: (e) => h.onEvent(e, relay),
        oneose: () => h.onEose(relay),
        onclose: (reasons) => {
          const first = reasons[0]
          h.onClose?.(relay, typeof first === 'string' ? first : (first?.reason ?? 'closed'))
        },
        ...this.auth,
      }),
    )
    return () => subs.forEach((s) => s.close())
  }

  /** The relay's NIP-11 document over HTTP(S), or undefined. */
  relayInfo(relay: string): Promise<unknown> {
    return fetchRelayInfo(relay)
  }

  /** A refusal keeps the relay's own OK message verbatim (nostr-tools rejects with it as the error's message). */
  async publish(relay: string, e: NostrEvent): Promise<{ ok: boolean; message?: string }> {
    try {
      const reason = await this.pool.publish([relay], e, this.auth)[0]
      return { ok: true, ...(reason !== undefined && reason !== '' && { message: reason }) }
    } catch (err) {
      const m = err instanceof Error ? err.message : typeof err === 'string' ? err : undefined
      return { ok: false, ...(m !== undefined && m !== '' && { message: m }) }
    }
  }
}
