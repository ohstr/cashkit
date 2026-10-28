// RelayPool over the global WebSocket (browsers, Node >= 22, Bun): one
// connection per relay, opened on demand and shared by every subscription
// of this pool; `isolated()` gives a pool with connections of its own.
// With `setAuth`, a REQ or EVENT that a relay refuses `auth-required:` is
// sent once more after answering that relay's NIP-42 AUTH challenge. A
// challenge alone is never answered: a relay that does not ask learns no
// identity.
import { authEventTemplate, isAuthRequired, type NostrEvent } from '../core/index.js'
import { fetchRelayInfo, type AuthSigner, type Filter, type RelayPool, type SubscriptionHandlers } from '../client/index.js'

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
  readonly filters: Map<string, Filter>
  readonly oks: Map<string, (r: { ok: boolean; message?: string }) => void>
  closed: boolean
  /** The relay's latest AUTH challenge. */
  challenge?: string
  /** The answer to that challenge: whether the relay accepted it. */
  authed?: Promise<boolean> | undefined
}

export class RelayWs implements RelayPool {
  private readonly conns = new Map<string, Conn>()
  private nextId = 0
  private readonly connectFn: WebSocketFactory
  private readonly publishTimeoutMs: number
  private readonly connectTimeoutMs: number
  private signer: AuthSigner | undefined

  constructor(private readonly opts: RelayWsOptions = {}) {
    this.connectFn = opts.connect ?? ((url) => new (globalThis as unknown as { WebSocket: new (u: string) => WebSocketLike }).WebSocket(url))
    this.publishTimeoutMs = opts.publishTimeoutMs ?? 10_000
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 10_000
  }

  private conn(url: string): Conn {
    const existing = this.conns.get(url)
    if (existing && !existing.closed) return existing
    const ws = this.connectFn(url)
    const subs = new Map<string, SubscriptionHandlers>()
    const filters = new Map<string, Filter>()
    const oks = new Map<string, (r: { ok: boolean; message?: string }) => void>()
    let opened!: () => void
    let failed!: (e: Error) => void
    const ready = new Promise<void>((res, rej) => {
      opened = res
      failed = rej
    })
    ready.catch(() => {})
    const timer = setTimeout(() => failed(new Error('connect timeout')), this.connectTimeoutMs)
    const c: Conn = { ws, ready, subs, filters, oks, closed: false }
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
    else if (type === 'AUTH' && typeof a === 'string') {
      // Kept for when the relay refuses something `auth-required:`; not answered now.
      c.challenge = a
      c.authed = undefined
    } else if (type === 'CLOSED' && typeof a === 'string') {
      const reason = typeof b === 'string' ? b : 'closed'
      if (isAuthRequired(reason) && this.signer !== undefined && c.subs.has(a)) {
        void this.reauthed(url, c).then((ok) => {
          const h = c.subs.get(a)
          if (h === undefined) return
          if (ok && !c.closed) c.ws.send(JSON.stringify(['REQ', a, c.filters.get(a)]))
          else {
            c.subs.delete(a)
            c.filters.delete(a)
            h.onClose?.(url, reason)
          }
        })
        return
      }
      const h = c.subs.get(a)
      c.subs.delete(a)
      c.filters.delete(a)
      h?.onClose?.(url, reason)
    } else if (type === 'OK' && typeof a === 'string') {
      const done = c.oks.get(a)
      c.oks.delete(a)
      done?.({ ok: b === true, ...(typeof m === 'string' && m !== '' && { message: m }) })
    }
  }

  /**
   * NIP-42: answer a relay's AUTH challenge with `sign`, only once that relay
   * refuses a REQ or EVENT `auth-required:` (undefined stops answering). A
   * `sign` that throws declines, and the refusal stands.
   */
  setAuth(sign: AuthSigner | undefined): void {
    this.signer = sign
  }

  /** Signs the answer to `challenge` and sends it; resolves with the relay's OK. */
  private async authenticate(url: string, c: Conn, challenge: string): Promise<boolean> {
    try {
      const ev = await this.signer!(authEventTemplate(url, challenge, Math.floor(Date.now() / 1000)))
      await c.ready
      return await this.sendAndWait(c, ['AUTH', ev], ev.id).then((r) => r.ok)
    } catch {
      return false
    }
  }

  /** The current authentication, or a fresh one for the last challenge; false without a challenge. */
  private reauthed(url: string, c: Conn): Promise<boolean> {
    if (c.challenge === undefined) return Promise.resolve(false)
    c.authed ??= this.authenticate(url, c, c.challenge)
    return c.authed
  }

  private sendAndWait(c: Conn, msg: unknown[], id: string): Promise<{ ok: boolean; message?: string }> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        c.oks.delete(id)
        resolve({ ok: false, message: 'publish timeout' })
      }, this.publishTimeoutMs)
      c.oks.set(id, (r) => {
        clearTimeout(timer)
        resolve(r)
      })
      c.ws.send(JSON.stringify(msg))
    })
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
      c.filters.set(id, filter)
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
        c.filters.delete(id)
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
    const r = await this.sendAndWait(c, ['EVENT', e], e.id)
    if (r.ok || !isAuthRequired(r.message) || this.signer === undefined) return r
    // Refused until the client authenticates: answer the challenge, then send once more.
    if (!(await this.reauthed(url, c)) || c.closed) return r
    return this.sendAndWait(c, ['EVENT', e], e.id)
  }

  /** A pool with the same options and connections of its own (no socket, challenge or signer shared with this one). */
  isolated(): RelayWs {
    return new RelayWs(this.opts)
  }

  /** Closes every connection. */
  close(): void {
    for (const c of this.conns.values()) c.ws.close()
    this.conns.clear()
  }
}
