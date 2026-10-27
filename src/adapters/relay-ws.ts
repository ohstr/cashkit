// RelayPool over the global WebSocket (browsers, Node >= 22, Bun): one
// connection per relay, opened on demand and shared by every subscription.
import type { NostrEvent } from '../core/index.js'
import { fetchRelayInfo, type Filter, type RelayPool, type SubscriptionHandlers } from '../client/index.js'

/** The slice of the WebSocket API this adapter uses. */
export interface WebSocketLike {
  readonly readyState: number
  send(data: string): void
  close(): void
  addEventListener(type: 'open' | 'close' | 'error', listener: () => void): void
  addEventListener(type: 'message', listener: (ev: { data: unknown }) => void): void
}

export type WebSocketFactory = (url: string) => WebSocketLike

export interface RelayWsOptions {
  /** Default: `new WebSocket(url)` from the global. */
  readonly connect?: WebSocketFactory
  /** How long a publish waits for the relay's OK. Default 10 s. */
  readonly publishTimeoutMs?: number
  /** How long to wait for a connection to open. Default 10 s. */
  readonly connectTimeoutMs?: number
}

const OPEN = 1

interface Conn {
  readonly ws: WebSocketLike
  readonly ready: Promise<void>
  readonly subs: Map<string, SubscriptionHandlers>
  readonly oks: Map<string, (r: { ok: boolean; message?: string }) => void>
  closed: boolean
}

export class RelayWs implements RelayPool {
  private readonly conns = new Map<string, Conn>()
  private nextId = 0
  private readonly connectFn: WebSocketFactory
  private readonly publishTimeoutMs: number
  private readonly connectTimeoutMs: number

  constructor(opts: RelayWsOptions = {}) {
    this.connectFn = opts.connect ?? ((url) => new (globalThis as unknown as { WebSocket: new (u: string) => WebSocketLike }).WebSocket(url))
    this.publishTimeoutMs = opts.publishTimeoutMs ?? 10_000
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 10_000
  }

  private conn(url: string): Conn {
    const existing = this.conns.get(url)
    if (existing && !existing.closed) return existing
    const ws = this.connectFn(url)
    const subs = new Map<string, SubscriptionHandlers>()
    const oks = new Map<string, (r: { ok: boolean; message?: string }) => void>()
    let opened!: () => void
    let failed!: (e: Error) => void
    const ready = new Promise<void>((res, rej) => {
      opened = res
      failed = rej
    })
    ready.catch(() => {})
    const timer = setTimeout(() => failed(new Error('connect timeout')), this.connectTimeoutMs)
    const c: Conn = { ws, ready, subs, oks, closed: false }
    const shutdown = (reason: string) => {
      if (c.closed) return
      c.closed = true
      clearTimeout(timer)
      failed(new Error(reason))
      for (const h of subs.values()) h.onClose?.(url, reason)
      for (const ok of oks.values()) ok({ ok: false, message: reason })
      subs.clear()
      oks.clear()
      this.conns.delete(url)
    }
    ws.addEventListener('open', () => {
      clearTimeout(timer)
      opened()
    })
    ws.addEventListener('error', () => shutdown('connection error'))
    ws.addEventListener('close', () => shutdown('connection closed'))
    ws.addEventListener('message', (ev) => this.onMessage(url, c, ev.data))
    this.conns.set(url, c)
    return c
  }

  private onMessage(url: string, c: Conn, data: unknown): void {
    let msg: unknown
    try {
      msg = JSON.parse(typeof data === 'string' ? data : String(data))
    } catch {
      return
    }
    if (!Array.isArray(msg)) return
    const [type, a, b, m] = msg as [string, unknown, unknown, unknown]
    if (type === 'EVENT' && typeof a === 'string') c.subs.get(a)?.onEvent(b as NostrEvent, url)
    else if (type === 'EOSE' && typeof a === 'string') c.subs.get(a)?.onEose(url)
    else if (type === 'CLOSED' && typeof a === 'string') {
      const h = c.subs.get(a)
      c.subs.delete(a)
      h?.onClose?.(url, typeof b === 'string' ? b : 'closed')
    } else if (type === 'OK' && typeof a === 'string') {
      const done = c.oks.get(a)
      c.oks.delete(a)
      done?.({ ok: b === true, ...(typeof m === 'string' && m !== '' && { message: m }) })
    }
  }

  subscribe(relays: readonly string[], filter: Filter, h: SubscriptionHandlers): () => void {
    const id = `ck${this.nextId++}`
    const live: [string, Conn][] = []
    for (const url of relays) {
      let c: Conn
      try {
        c = this.conn(url)
      } catch {
        queueMicrotask(() => h.onClose?.(url, 'connect failed'))
        continue
      }
      c.subs.set(id, h)
      live.push([url, c])
      c.ready.then(
        () => {
          if (c.subs.has(id)) c.ws.send(JSON.stringify(['REQ', id, filter]))
        },
        () => {},
      )
    }
    return () => {
      for (const [, c] of live) {
        if (!c.subs.delete(id)) continue
        if (!c.closed && c.ws.readyState === OPEN) c.ws.send(JSON.stringify(['CLOSE', id]))
      }
    }
  }

  /** The relay's NIP-11 document over HTTP(S), or undefined. */
  relayInfo(url: string): Promise<unknown> {
    return fetchRelayInfo(url)
  }

  async publish(url: string, e: NostrEvent): Promise<{ ok: boolean; message?: string }> {
    const c = this.conn(url)
    await c.ready
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        c.oks.delete(e.id)
        resolve({ ok: false, message: 'publish timeout' })
      }, this.publishTimeoutMs)
      c.oks.set(e.id, (r) => {
        clearTimeout(timer)
        resolve(r)
      })
      c.ws.send(JSON.stringify(['EVENT', e]))
    })
  }

  /** Closes every connection. */
  close(): void {
    for (const c of this.conns.values()) c.ws.close()
    this.conns.clear()
  }
}
