// adapters/relay-ws against a scripted socket.
import { describe, expect, test } from 'vitest'
import { finalizeEvent } from '../src/core/index.js'
import { RelayWs, type WebSocketLike } from '../src/adapters/relay-ws.js'
import { fill } from './helpers.js'

class FakeSocket implements WebSocketLike {
  readyState = 0
  sent: unknown[] = []
  private readonly listeners = new Map<string, ((ev: { data: unknown }) => void)[]>()
  constructor(readonly url: string) {}
  addEventListener(type: string, listener: (ev: { data: unknown }) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener])
  }
  private emit(type: string, data?: unknown) {
    for (const l of this.listeners.get(type) ?? []) l({ data })
  }
  open() {
    this.readyState = 1
    this.emit('open')
  }
  send(data: string) {
    this.sent.push(JSON.parse(data))
  }
  close() {
    this.readyState = 3
    this.emit('close')
  }
  receive(msg: unknown) {
    this.emit('message', JSON.stringify(msg))
  }
}

const tick = () => new Promise((r) => setTimeout(r, 0))
const ev = finalizeEvent({ kind: 1, created_at: 1, tags: [], content: 'x' }, fill(1, 32))

function setup() {
  const sockets: FakeSocket[] = []
  const pool = new RelayWs({
    connect: (url) => {
      const s = new FakeSocket(url)
      sockets.push(s)
      return s
    },
    publishTimeoutMs: 50,
  })
  return { pool, sockets }
}

describe('RelayWs', () => {
  test('subscribe sends REQ once open, routes EVENT and EOSE, and CLOSE on unsubscribe', async () => {
    const { pool, sockets } = setup()
    const got: string[] = []
    const stop = pool.subscribe(['wss://a'], { kinds: [1] }, { onEvent: (e) => got.push(e.id), onEose: (r) => got.push(`eose:${r}`) })
    const s = sockets[0]!
    s.open()
    await tick()
    const [type, id, filter] = s.sent[0] as [string, string, unknown]
    expect([type, filter]).toEqual(['REQ', { kinds: [1] }])
    s.receive(['EVENT', id, ev])
    s.receive(['EOSE', id])
    s.receive(['EVENT', 'other', ev])
    expect(got).toEqual([ev.id, 'eose:wss://a'])
    stop()
    expect(s.sent[1]).toEqual(['CLOSE', id])
  })
  test('one connection per relay, shared by subscriptions', async () => {
    const { pool, sockets } = setup()
    pool.subscribe(['wss://a'], {}, { onEvent() {}, onEose() {} })
    pool.subscribe(['wss://a', 'wss://b'], {}, { onEvent() {}, onEose() {} })
    expect(sockets.map((s) => s.url)).toEqual(['wss://a', 'wss://b'])
  })
  test('publish resolves with the relay OK', async () => {
    const { pool, sockets } = setup()
    const p = pool.publish('wss://a', ev)
    sockets[0]!.open()
    await tick()
    expect(sockets[0]!.sent[0]).toEqual(['EVENT', ev])
    sockets[0]!.receive(['OK', ev.id, false, 'blocked: spam'])
    expect(await p).toEqual({ ok: false, message: 'blocked: spam' })
  })
  test('publish without an OK times out as not ok', async () => {
    const { pool, sockets } = setup()
    const p = pool.publish('wss://a', ev)
    sockets[0]!.open()
    expect(await p).toEqual({ ok: false, message: 'publish timeout' })
  })
  test('a dropped connection closes its subscriptions and fails pending publishes', async () => {
    const { pool, sockets } = setup()
    const closed: string[] = []
    pool.subscribe(['wss://a'], {}, { onEvent() {}, onEose() {}, onClose: (r, why) => closed.push(`${r}:${why}`) })
    sockets[0]!.open()
    const p = pool.publish('wss://a', ev)
    await tick()
    sockets[0]!.close()
    expect(closed).toEqual(['wss://a:connection closed'])
    expect(await p).toMatchObject({ ok: false })
  })
  test('a relay CLOSED ends that subscription', async () => {
    const { pool, sockets } = setup()
    const closed: string[] = []
    pool.subscribe(['wss://a'], {}, { onEvent() {}, onEose() {}, onClose: (_r, why) => closed.push(why) })
    sockets[0]!.open()
    await tick()
    const id = (sockets[0]!.sent[0] as string[])[1]
    sockets[0]!.receive(['CLOSED', id, 'auth-required: no'])
    expect(closed).toEqual(['auth-required: no'])
  })
})
