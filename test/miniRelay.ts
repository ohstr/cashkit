// A minimal NIP-01 relay over a real WebSocket server (ws), for testing the
// relay adapters end to end: EVENT with OK, REQ with stored events then
// EOSE, live delivery, CLOSE, and an optional refusal. Test support only.
import { createServer, type Server } from 'node:http'
import { WebSocketServer, type WebSocket } from 'ws'
import { powDifficulty, verifyEvent, type NostrEvent } from '../src/core/index.js'
import { matches } from './fakeHub.js'
import type { Filter } from '../src/client/index.js'

export class MiniRelay {
  readonly stored: NostrEvent[] = []
  /** When set, EVENTs are refused with this message. */
  refuse: string | undefined
  /** NIP-13 minimum for kind 23190, served in NIP-11 and enforced with `pow: difficulty <n> required`. */
  powMinimum = 0
  private readonly http: Server
  private readonly server: WebSocketServer
  private readonly subs = new Map<WebSocket, Map<string, Filter[]>>()

  private constructor(http: Server, server: WebSocketServer) {
    this.http = http
    this.server = server
    server.on('connection', (ws) => {
      this.subs.set(ws, new Map())
      ws.on('message', (data) => this.onMessage(ws, String(data)))
      ws.on('close', () => this.subs.delete(ws))
    })
  }

  static async start(): Promise<MiniRelay> {
    let relay: MiniRelay | undefined
    // NIP-11 over HTTP on the same port as the WebSocket.
    const http = createServer((req, res) => {
      if (req.headers.accept !== 'application/nostr+json') return void res.writeHead(404).end()
      res.writeHead(200, { 'content-type': 'application/nostr+json' }).end(JSON.stringify({ supported_nips: [1, 11, 13], limitation: { min_pow_difficulty: relay?.powMinimum ?? 0 } }))
    })
    const server = new WebSocketServer({ server: http })
    await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
    relay = new MiniRelay(http, server)
    return relay
  }

  get url(): string {
    const a = this.http.address()
    return `ws://127.0.0.1:${typeof a === 'object' && a !== null ? a.port : 0}`
  }

  private onMessage(ws: WebSocket, text: string) {
    let msg: unknown[]
    try {
      msg = JSON.parse(text) as unknown[]
    } catch {
      return
    }
    const [type, ...rest] = msg
    if (type === 'EVENT') {
      const e = rest[0] as NostrEvent
      if (this.refuse !== undefined) return ws.send(JSON.stringify(['OK', e.id, false, this.refuse]))
      if (e.kind === 23190 && powDifficulty(e.id) < this.powMinimum) return ws.send(JSON.stringify(['OK', e.id, false, `pow: difficulty ${this.powMinimum} required`]))
      if (!verifyEvent(e)) return ws.send(JSON.stringify(['OK', e.id, false, 'invalid: bad signature']))
      const ephemeral = e.kind >= 20000 && e.kind < 30000
      if (!ephemeral) this.stored.push(e)
      ws.send(JSON.stringify(['OK', e.id, true, '']))
      for (const [client, subs] of this.subs) {
        for (const [id, filters] of subs) if (filters.some((f) => matches(f, e))) client.send(JSON.stringify(['EVENT', id, e]))
      }
    } else if (type === 'REQ') {
      const [id, ...filters] = rest as [string, ...Filter[]]
      this.subs.get(ws)?.set(id, filters)
      for (const e of this.stored) if (filters.some((f) => matches(f, e))) ws.send(JSON.stringify(['EVENT', id, e]))
      ws.send(JSON.stringify(['EOSE', id]))
    } else if (type === 'CLOSE') {
      this.subs.get(ws)?.delete(rest[0] as string)
    }
  }

  async stop(): Promise<void> {
    for (const ws of this.subs.keys()) ws.terminate()
    await new Promise<void>((r) => this.server.close(() => r()))
    await new Promise<void>((r) => this.http.close(() => r()))
  }
}
