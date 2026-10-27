// A Cash Pocket over relays (NIP-CP §Wrapping, §Reading): wraps go to the
// user's NIP-17 inbox relays (kind 10050), else their NIP-65 write relays
// (kind 10002), else the relays configured here, plus any relay of the
// user's own; they are read back by id, and a sync reads every wrap
// addressed to the user (incrementally, from two days before the last).
// With `auth`, the pool answers a pocket relay's NIP-42 AUTH challenge when
// that relay refuses `auth-required:`, so a relay that serves a 1059 only to
// its `p` serves the user's wraps. Only the pocket relays (configured, own
// and those found in the user's lists) are answered: a Hub inbox, listing,
// order or zap relay on the same pool is never signed in to as the user.
import { readEvents, type AuthSigner, type RelayPool } from '../client/index.js'
import { verifyEvent, type EventTemplate, type NostrEvent } from '../core/index.js'
import type { Pocket } from '../wallet/ports.js'

export interface SyncPocketOptions {
  readonly pool: RelayPool
  /** The relays used when the user publishes neither a 10050 nor a NIP-65 list (and, without `discovery`, always). */
  readonly relays?: readonly string[]
  /** Where to read the user's kind-10050 and kind-10002 lists; without it, `relays` are used as given. */
  readonly discovery?: readonly string[]
  /** A relay the user runs or controls, always written to and read from. */
  readonly ownRelays?: readonly string[]
  /**
   * Signs the NIP-42 answer to a pocket relay's AUTH challenge as the user;
   * passed to the pool's `setAuth` when the adapter supports it, limited to
   * the pocket relays.
   */
  readonly auth?: AuthSigner
  /** Default 2, capped at the relays in use. */
  readonly minRelays?: number
  readonly readTimeoutMs?: number
}

const relayKey = (u: string) => u.trim().replace(/\/+$/, '').toLowerCase()
const relayOf = (t: EventTemplate) => t.tags.find((x) => x[0] === 'relay')?.[1]

const recipientOf = (e: NostrEvent) => e.tags.find((t) => t[0] === 'p')?.[1] ?? ''
const isRelayUrl = (u: unknown): u is string => typeof u === 'string' && /^wss?:\/\/\S+$/.test(u)

/** The newest event of `kind` by `pubkey` among `events`; one whose id or signature does not check is ignored. */
function newest(events: readonly NostrEvent[], kind: number, pubkey: string): NostrEvent | undefined {
  let best: NostrEvent | undefined
  for (const e of events) if (e.kind === kind && e.pubkey === pubkey && verifyEvent(e, { checkPow: false }) && (best === undefined || e.created_at > best.created_at || (e.created_at === best.created_at && e.id < best.id))) best = e
  return best
}

/**
 * The user's pocket relays from their lists: the `relay` tags of the newest
 * kind 10050, else the write relays (`r` with no marker or `write`) of the
 * newest kind 10002; empty when neither names one. Only events signed by
 * `pubkey` count: a relay cannot redirect the pocket with a forged list.
 */
export function pocketRelaysFrom(events: readonly NostrEvent[], pubkey: string): string[] {
  const inbox = newest(events, 10050, pubkey)
  const fromInbox = inbox?.tags.filter((t) => t[0] === 'relay' && isRelayUrl(t[1])).map((t) => t[1]!) ?? []
  if (fromInbox.length > 0) return [...new Set(fromInbox)]
  const outbox = newest(events, 10002, pubkey)
  const writes = outbox?.tags.filter((t) => t[0] === 'r' && isRelayUrl(t[1]) && (t[2] === undefined || t[2] === 'write')).map((t) => t[1]!) ?? []
  return [...new Set(writes)]
}

export function syncPocket(o: SyncPocketOptions): Pocket {
  const wait = o.readTimeoutMs ?? 2500
  const configured = o.relays ?? []
  const own = o.ownRelays ?? []
  const resolved = new Map<string, Promise<string[]>>()
  let last: string[] = [...new Set([...configured, ...own])]
  // The relays this pocket writes to or reads from; AUTH goes to these only.
  const pocketRelays = new Set(last.map(relayKey))
  const auth = o.auth
  if (auth !== undefined) {
    o.pool.setAuth?.(async (t) => {
      const relay = relayOf(t)
      if (relay === undefined || !pocketRelays.has(relayKey(relay))) throw new Error('not a pocket relay')
      return auth(t)
    })
  }

  const relaysFor = (pubkey: string): Promise<string[]> => {
    let p = resolved.get(pubkey)
    if (p === undefined) {
      p = (async () => {
        let found: string[] = []
        if (o.discovery !== undefined && o.discovery.length > 0) {
          const lists = await readEvents(o.pool, o.discovery, { kinds: [10050, 10002], authors: [pubkey] }, wait).catch(() => [] as NostrEvent[])
          found = pocketRelaysFrom(lists, pubkey)
        }
        const relays = [...new Set([...(found.length > 0 ? found : configured), ...own])]
        for (const r of relays) pocketRelays.add(relayKey(r))
        return relays
      })()
      resolved.set(pubkey, p)
    }
    return p.then((r) => (last = r))
  }

  return {
    get minRelays() {
      return Math.max(1, Math.min(o.minRelays ?? 2, last.length))
    },
    async publish(wrap) {
      const relays = await relaysFor(recipientOf(wrap))
      const r = await Promise.all(relays.map(async (url) => ((await o.pool.publish(url, wrap).catch(() => ({ ok: false }))).ok ? url : undefined)))
      return r.filter((x): x is string => x !== undefined)
    },
    async has(wrapId) {
      return (await readEvents(o.pool, last, { ids: [wrapId] }, wait).catch(() => [])).some((e) => e.id === wrapId)
    },
    async fetch(pubkey, since) {
      const relays = await relaysFor(pubkey)
      return readEvents(o.pool, relays, { kinds: [1059], '#p': [pubkey], ...(since !== undefined && { since: since - 172800 }) }, wait).catch(() => [] as NostrEvent[])
    },
    async remove(deletion) {
      await Promise.all(last.map((url) => o.pool.publish(url, deletion).catch(() => undefined)))
    },
  }
}
