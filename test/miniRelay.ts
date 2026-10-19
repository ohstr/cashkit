// A minimal NIP-01 relay over a real WebSocket server (ws), for testing the
// relay adapters end to end: EVENT with OK, REQ with stored events then
// EOSE, live delivery, CLOSE, and an optional refusal. Test support only.
import { WebSocketServer, type WebSocket } from 'ws'
import { verifyEvent, type NostrEvent } from '../src/core/index.js'
import { matches } from './fakeHub.js'
import type { Filter } from '../src/client/index.js'

export class MiniRelay {
  readonly stored: NostrEvent[] = []
  /** When set, EVENTs are refused with this message. */
  refuse: string | undefined
  private readonly server: WebSocketServer
  private readonly subs = new Map<WebSocket, Map<string, Filter[]>>()

  private constructor(server: WebSocketServer) {
    this.server = server
    server.on('connection', (ws) => {
      this.subs.set(ws, new Map())
      ws.on('message', (data) => this.onMessage(ws, String(data)))
      ws.on('close', () => this.subs.delete(ws))
    })
  }

  static async start(): Promise<MiniRelay> {
    const server = new WebSocketServer({ port: 0, host: '127.0.0.1' })
    await new Promise<void>((r) => server.on('listening', () => r()))
    return new MiniRelay(server)
  }

  get url(): string {
    const a = this.server.address()
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
  }
}
