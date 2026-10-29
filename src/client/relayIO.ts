// Small async helpers over the RelayPool port.
import { verifyEvent, type NostrEvent } from '../core/index.js'
import type { Filter, RelayPool } from './ports.js'

/**
 * Collects stored events from every relay until each has sent EOSE (or
 * closed), or `timeoutMs` passes. An event whose id is not the hash of its
 * content or whose signature does not verify is dropped before anything
 * else, so a relay cannot forge an author or shadow a real event's id.
 * Duplicates across relays are then dropped.
 */
export function readEvents(pool: RelayPool, relays: readonly string[], filter: Filter, timeoutMs: number): Promise<NostrEvent[]> {
  return readEventsAnswered(pool, relays, filter, timeoutMs).then((r) => r.events)
}

/** `readEvents`, also saying which relays answered (sent EOSE) rather than closing or timing out. */
export function readEventsAnswered(pool: RelayPool, relays: readonly string[], filter: Filter, timeoutMs: number): Promise<{ events: NostrEvent[]; answered: string[] }> {
  const answered: string[] = []
  return new Promise((resolve) => {
    const seen = new Map<string, NostrEvent>()
    const pending = new Set(relays)
    let done = false
    let unsubscribe: (() => void) | undefined
    const finish = () => {
      if (done) return
      done = true
      clearTimeout(timer)
      unsubscribe?.()
      resolve({ events: [...seen.values()], answered: [...answered] })
    }
    const settle = (relay: string) => {
      pending.delete(relay)
      if (pending.size === 0) finish()
    }
    const timer = setTimeout(finish, timeoutMs)
    unsubscribe = pool.subscribe(relays, filter, {
      onEvent: (e) => {
        if (seen.has(e.id) || !verifyEvent(e, { checkPow: false })) return
        seen.set(e.id, e)
      },
      onEose: (relay) => {
        if (pending.has(relay)) answered.push(relay)
        settle(relay)
      },
      onClose: settle,
    })
    if (done) unsubscribe?.()
    if (relays.length === 0) finish()
  })
}

/**
 * A queue of events from a live subscription, awaited one at a time with a
 * deadline. `closed` reports whether every source has gone away.
 */
export class EventQueue {
  private readonly items: NostrEvent[] = []
  private waiter: ((e: NostrEvent | undefined) => void) | undefined
  private open = 0
  private everOpened = false

  push(e: NostrEvent): void {
    if (this.waiter) {
      const w = this.waiter
      this.waiter = undefined
      w(e)
    } else this.items.push(e)
  }

  /** A source started feeding the queue. */
  opened(): void {
    this.open++
    this.everOpened = true
  }

  /** A source stopped; once all have, waiting ends. */
  sourceClosed(): void {
    this.open = Math.max(this.open - 1, 0)
    if (this.closed && this.waiter) {
      const w = this.waiter
      this.waiter = undefined
      w(undefined)
    }
  }

  get closed(): boolean {
    return this.everOpened && this.open === 0 && this.items.length === 0
  }

  /** The next event, or undefined on timeout or when every source has closed. */
  next(timeoutMs: number): Promise<NostrEvent | undefined> {
    const queued = this.items.shift()
    if (queued) return Promise.resolve(queued)
    if (this.closed || timeoutMs <= 0) return Promise.resolve(undefined)
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.waiter = undefined
        resolve(undefined)
      }, timeoutMs)
      this.waiter = (e) => {
        clearTimeout(timer)
        resolve(e)
      }
    })
  }
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, Math.max(ms, 0)))

/** A relay's NIP-11 document, read over HTTP(S) with `Accept: application/nostr+json`; undefined when it cannot be read in time. */
export async function fetchRelayInfo(url: string, o: { readonly fetch?: typeof globalThis.fetch; readonly timeoutMs?: number } = {}): Promise<unknown> {
  const f = o.fetch ?? globalThis.fetch
  if (typeof f !== 'function') return undefined
  const http = url.replace(/^ws(s?):\/\//i, 'http$1://')
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), o.timeoutMs ?? 3000)
  try {
    const res = await f(http, { headers: { Accept: 'application/nostr+json' }, signal: ctrl.signal })
    if (!res.ok) return undefined
    return (await res.json()) as unknown
  } catch {
    return undefined
  } finally {
    clearTimeout(timer)
  }
}
