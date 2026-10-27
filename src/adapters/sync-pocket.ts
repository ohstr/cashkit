// A Cash Pocket over relays (NIP-CP §Wrapping, §Reading): wraps go to the
// user's inbox relays and are read back by id; a sync reads every wrap
// addressed to the user (incrementally, from two days before the last).
import { readEvents, type RelayPool } from '../client/index.js'
import type { NostrEvent } from '../core/index.js'
import type { Pocket } from '../wallet/ports.js'

export interface SyncPocketOptions {
  readonly pool: RelayPool
  /** The user's kind-10050 inbox relays, else their NIP-65 write relays, plus any relay of their own. */
  readonly relays: readonly string[]
  /** Default 2, capped at the relays given. */
  readonly minRelays?: number
  readonly readTimeoutMs?: number
}

export function syncPocket(o: SyncPocketOptions): Pocket {
  const wait = o.readTimeoutMs ?? 2500
  return {
    minRelays: Math.min(o.minRelays ?? 2, o.relays.length),
    async publish(wrap) {
      const r = await Promise.all(o.relays.map(async (url) => ((await o.pool.publish(url, wrap).catch(() => ({ ok: false }))).ok ? url : undefined)))
      return r.filter((x): x is string => x !== undefined)
    },
    async has(wrapId) {
      return (await readEvents(o.pool, o.relays, { ids: [wrapId] }, wait).catch(() => [])).some((e) => e.id === wrapId)
    },
    fetch(pubkey, since) {
      return readEvents(o.pool, o.relays, { kinds: [1059], '#p': [pubkey], ...(since !== undefined && { since: since - 172800 }) }, wait).catch(() => [] as NostrEvent[])
    },
    async remove(deletion) {
      await Promise.all(o.relays.map((url) => o.pool.publish(url, deletion).catch(() => undefined)))
    },
  }
}
