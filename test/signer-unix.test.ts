// The local signer adapter (NIP-LS) against a fake signer on a real unix
// socket: addressing, framing, id matching, abandon ⇒ reconnect, error
// prefixes, attestations and the returned-event check.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { createServer, type Server, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'
import { getPublicKey, localSigner, nip44, type EventTemplate, type NostrEvent } from '../src/core/index.js'
import { approvedEventId, MAX_MESSAGE_BYTES, parseUnixSignerUri, signerFromUri, unixSigner } from '../src/adapters/signer-unix.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const userKey = fill(0x31, 32)
const user = localSigner(userKey)

type Req = { id: string; method: string; params: string[] }
type Behaviour = (req: Req, sock: Socket) => Promise<object | undefined> | object | undefined

interface FakeSigner {
  readonly path: string
  readonly seen: Req[]
  connections: number
  behaviour: Behaviour
  /** Raw lines to write instead of answering (one call). */
  raw?: string | undefined
  close(): Promise<void>
}

const defaults: Behaviour = async (req) => {
  switch (req.method) {
    case 'get_public_key':
      return { result: user.pubkey }
    case 'ping':
      return { result: 'pong' }
    case 'sign_event':
      return { result: JSON.stringify(await user.signEvent(JSON.parse(req.params[0]!) as EventTemplate)) }
    case 'nip44_encrypt':
      return { result: await user.nip44Encrypt(req.params[0]!, req.params[1]!) }
    case 'nip44_decrypt':
      return { result: await user.nip44Decrypt(req.params[0]!, req.params[1]!) }
    default:
      return { error: `invalid: unknown method ${req.method}` }
  }
}

let dir: string
let servers: Server[] = []
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'cashkit-ls-'))
})
afterEach(async () => {
  await Promise.all(servers.map((s) => new Promise((r) => s.close(r))))
  servers = []
  rmSync(dir, { recursive: true, force: true })
})

async function fakeSigner(behaviour: Behaviour = defaults): Promise<FakeSigner> {
  const path = join(dir, 's.sock')
  const f: FakeSigner = { path, seen: [], connections: 0, behaviour, close: async () => {} }
  const socks = new Set<Socket>()
  const server = createServer((sock) => {
    f.connections++
    socks.add(sock)
    sock.on('close', () => socks.delete(sock))
    let buf = ''
    sock.on('data', (d) => {
      buf += d.toString('utf8')
      for (let i = buf.indexOf('\n'); i !== -1; i = buf.indexOf('\n')) {
        const line = buf.slice(0, i)
        buf = buf.slice(i + 1)
        if (line.trim() === '') continue
        const req = JSON.parse(line) as Req
        f.seen.push(req)
        void (async () => {
          if (f.raw !== undefined) {
            const raw = f.raw
            f.raw = undefined
            sock.write(raw)
            return
          }
          const ans = await f.behaviour(req, sock)
          if (ans !== undefined && !sock.destroyed) sock.write(`${JSON.stringify({ id: req.id, ...ans })}\n`)
        })()
      }
    })
  })
  servers.push(server)
  await new Promise<void>((r) => server.listen(path, r))
  f.close = async () => {
    for (const s of socks) s.destroy()
  }
  return f
}

const files = (d: string): string[] => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(d, e.name)) : [join(d, e.name)]))

const tpl: EventTemplate = { kind: 1, created_at: 1_700_000_000, tags: [['t', 'x']], content: 'hello' }

describe('addressing', () => {
  test('bunker+unix:///abs, unix:///abs and a bare absolute path name the socket', () => {
    expect(parseUnixSignerUri('bunker+unix:///tmp/s.sock')).toBe('/tmp/s.sock')
    expect(parseUnixSignerUri('unix:///tmp/s.sock')).toBe('/tmp/s.sock')
    expect(parseUnixSignerUri('/tmp/s.sock')).toBe('/tmp/s.sock')
  })
  test.each(['bunker+unix://rel/s.sock', 'bunker+unix:///tmp/s.sock?x=1', 'bunker+unix:///tmp/s.sock#f', 's.sock', 'unix://', 'https://x/s.sock'])('refused: %s', (u) => {
    expect(() => parseUnixSignerUri(u)).toThrow()
  })
  test('signerFromUri takes every form; bunker:// goes to the relay adapter', async () => {
    const f = await fakeSigner()
    for (const u of [`bunker+unix://${f.path}`, `unix://${f.path}`, f.path]) {
      const s = await signerFromUri(u)
      expect(s.pubkey).toBe(user.pubkey)
      s.close()
    }
    await expect(signerFromUri(`bunker://${'ab'.repeat(32)}?relay=wss://r`)).rejects.toThrow(/relay pool/)
    // With a pool, the bunker:// form reaches the NIP-46 adapter (nothing answers here).
    await expect(signerFromUri(`bunker://${'ab'.repeat(32)}?relay=wss://r`, { relays: new MemoryRelayPool(), timeoutMs: 20 })).rejects.toThrow(/signer-nip46/)
    await expect(signerFromUri('nsec1whatever')).rejects.toThrow()
  })
  test('the socket code stays out of every other module', () => {
    const src = join(__dirname, '..', 'src')
    const users = files(src).filter((p) => /from '(node:net|\.\/signer-unix\.js)'/.test(readFileSync(p, 'utf8')))
    expect(users.map((p) => p.slice(src.length + 1))).toEqual(['adapters/signer-unix.ts'])
  })
})

describe('the wire', () => {
  test('signs, encrypts and decrypts; each line is one JSON request', async () => {
    const f = await fakeSigner()
    const s = await unixSigner({ uri: `bunker+unix://${f.path}` })
    const ev = await s.signEvent(tpl)
    expect(ev).toMatchObject({ pubkey: user.pubkey, content: 'hello' })
    const peer = fill(0x55, 32)
    const ct = await s.nip44Encrypt(getPublicKey(peer), 'to peer')
    expect(nip44.decrypt(ct, nip44.getConversationKey(peer, user.pubkey))).toBe('to peer')
    expect(await s.nip44Decrypt(getPublicKey(peer), nip44.encrypt('back', nip44.getConversationKey(peer, user.pubkey)))).toBe('back')
    expect(f.seen.map((r) => r.method)).toEqual(['get_public_key', 'sign_event', 'nip44_encrypt', 'nip44_decrypt'])
    // The unsigned event goes without a pubkey: the signer sets its own.
    expect(JSON.parse(f.seen[1]!.params[0]!)).toEqual({ kind: 1, content: 'hello', tags: [['t', 'x']], created_at: 1_700_000_000 })
    expect(f.seen[1]!.params).toHaveLength(1)
    s.close()
  })
  test('string results come back as they are (ack, pong, {}, null)', async () => {
    const f = await fakeSigner(async (req) => {
      const fixed: Record<string, string> = { connect: 'ack', logout: 'ack', ping: 'pong', get_relays: '{}', switch_relays: 'null' }
      return fixed[req.method] !== undefined ? { result: fixed[req.method] } : defaults(req, undefined as never)
    })
    const s = await unixSigner({ uri: f.path })
    for (const [m, want] of [['connect', 'ack'], ['ping', 'pong'], ['get_relays', '{}'], ['switch_relays', 'null'], ['logout', 'ack']]) expect(await s.call(m!, [])).toBe(want)
    s.close()
  })
  test('pipelined requests are matched by id, whatever order the answers come in', async () => {
    const f = await fakeSigner(async (req) => {
      if (req.method === 'get_public_key') return { result: user.pubkey }
      const n = Number(req.params[0])
      await new Promise((r) => setTimeout(r, 40 - n * 10))
      return { result: `answer ${n}` }
    })
    const s = await unixSigner({ uri: f.path })
    const got = await Promise.all([1, 2, 3].map((n) => s.call('echo', [String(n)])))
    expect(got).toEqual(['answer 1', 'answer 2', 'answer 3'])
    expect(f.connections).toBe(1)
    s.close()
  })
  test('an abandoned request closes the connection; the next call reconnects', async () => {
    const f = await fakeSigner(async (req) => (req.method === 'slow' ? undefined : defaults(req, undefined as never)))
    const s = await unixSigner({ uri: f.path, timeoutMs: 50 })
    await expect(s.call('slow', [])).rejects.toMatchObject({ name: 'SignerError', code: 'failed', message: expect.stringMatching(/no answer/) })
    expect(await s.call('ping', [])).toBe('pong')
    expect(f.connections).toBe(2)
    s.close()
  })
  test('a request over 1 MiB is not sent', async () => {
    const f = await fakeSigner()
    const s = await unixSigner({ uri: f.path })
    await expect(s.nip44Encrypt(user.pubkey, 'a'.repeat(MAX_MESSAGE_BYTES))).rejects.toMatchObject({ code: 'invalid', message: expect.stringMatching(/1 MiB/) })
    expect(f.seen.map((r) => r.method)).toEqual(['get_public_key'])
    s.close()
  })
  test('an answer over 1 MiB drops the connection and fails what waits on it', async () => {
    const f = await fakeSigner()
    const s = await unixSigner({ uri: f.path })
    f.raw = `${'x'.repeat(MAX_MESSAGE_BYTES + 1)}\n`
    await expect(s.call('ping', [])).rejects.toMatchObject({ code: 'failed', message: expect.stringMatching(/over 1 MiB/) })
    expect(await s.call('ping', [])).toBe('pong')
    s.close()
  })
  test('an answer that never ends its line is cut off at 1 MiB, not buffered without bound', async () => {
    const f = await fakeSigner()
    const s = await unixSigner({ uri: f.path })
    f.raw = 'x'.repeat(MAX_MESSAGE_BYTES + 1)
    await expect(s.call('ping', [])).rejects.toMatchObject({ code: 'failed', message: expect.stringMatching(/over 1 MiB/) })
    expect(await s.call('ping', [])).toBe('pong')
    s.close()
  })
  test('a long answer that arrives in many pieces, under 1 MiB, is read whole', async () => {
    const big = 'y'.repeat(MAX_MESSAGE_BYTES - 64)
    const f = await fakeSigner(async (req) => (req.method === 'get_public_key' ? { result: user.pubkey } : { result: big }))
    const s = await unixSigner({ uri: f.path })
    expect(await s.call('ping', [])).toBe(big)
    s.close()
  })
  test('blank lines are skipped; an empty-id invalid answer resets the connection', async () => {
    const f = await fakeSigner()
    const s = await unixSigner({ uri: f.path })
    f.raw = '\n\n{"id":"","error":"invalid: not a JSON object"}\n'
    await expect(s.call('ping', [])).rejects.toMatchObject({ code: 'failed', message: expect.stringMatching(/could not read a request/) })
    expect(await s.call('ping', [])).toBe('pong')
    s.close()
  })
  test('a signer that is not there fails plainly', async () => {
    await expect(unixSigner({ uri: join(dir, 'none.sock') })).rejects.toMatchObject({ name: 'SignerError', code: 'failed', message: expect.stringMatching(/cannot connect/) })
  })
})

describe('errors and checks', () => {
  test('denied: and invalid: prefixes classify the failure; anything else is failed', async () => {
    const f = await fakeSigner(async (req) => {
      if (req.method === 'get_public_key') return { result: user.pubkey }
      if (req.method === 'sign_event') return { error: 'denied: kind 1 is not allowed' }
      if (req.method === 'nip44_encrypt') return { error: 'invalid: params' }
      return { error: 'disk full' }
    })
    const s = await unixSigner({ uri: f.path })
    await expect(s.signEvent(tpl)).rejects.toMatchObject({ name: 'SignerError', code: 'denied', message: 'signer-unix: denied: kind 1 is not allowed' })
    await expect(s.nip44Encrypt(user.pubkey, 'x')).rejects.toMatchObject({ code: 'invalid' })
    await expect(s.nip44Decrypt(user.pubkey, 'x')).rejects.toMatchObject({ code: 'failed' })
    s.close()
  })
  test.each([
    ['uppercase', () => user.pubkey.toUpperCase()],
    ['63 characters', () => user.pubkey.slice(1)],
    ['compressed (66)', () => `02${user.pubkey}`],
    ['not hex', () => 'z'.repeat(64)],
  ])('get_public_key answered with a pubkey that is %s is refused', async (_, bad) => {
    const f = await fakeSigner(async (req) => (req.method === 'get_public_key' ? { result: bad() } : { result: 'pong' }))
    await expect(unixSigner({ uri: f.path })).rejects.toMatchObject({ code: 'failed', message: expect.stringMatching(/invalid pubkey/) })
  })
  test('get_public_key answered with 64 lowercase hex is the identity', async () => {
    const f = await fakeSigner()
    const s = await unixSigner({ uri: f.path })
    expect(s.pubkey).toBe(user.pubkey)
    s.close()
  })
  test('a returned event is checked: another event, another key or a bad signature is refused', async () => {
    const other = localSigner(fill(0x32, 32))
    let mode = ''
    const f = await fakeSigner(async (req) => {
      if (req.method === 'get_public_key') return { result: user.pubkey }
      const t = JSON.parse(req.params[0]!) as EventTemplate
      if (mode === 'content') return { result: JSON.stringify(await user.signEvent({ ...t, content: 'swapped' })) }
      if (mode === 'key') return { result: JSON.stringify(await other.signEvent(t)) }
      const ev = await user.signEvent(t)
      return { result: JSON.stringify({ ...ev, sig: ev.sig.replace(/^./, ev.sig[0] === 'a' ? 'b' : 'a') }) }
    })
    const s = await unixSigner({ uri: f.path })
    mode = 'content'
    await expect(s.signEvent(tpl)).rejects.toThrow(/different event/)
    mode = 'key'
    await expect(s.signEvent(tpl)).rejects.toThrow(/different identity/)
    mode = 'sig'
    await expect(s.signEvent(tpl)).rejects.toThrow(/does not verify/)
    s.close()
  })
  test('attestations travel in params[1] as a JSON array string; the approved id is computable in advance', async () => {
    const f = await fakeSigner()
    const s = await unixSigner({ uri: f.path })
    const id = approvedEventId(tpl, user.pubkey)
    const approval: NostrEvent = await localSigner(fill(0x44, 32)).signEvent({ kind: 1, created_at: 1_700_000_000, tags: [], content: `approve ${id}` })
    const ev = await s.signEventWithAttestations(tpl, [approval])
    expect(ev.id).toBe(id)
    const sent = f.seen.find((r) => r.method === 'sign_event')!
    expect(typeof sent.params[1]).toBe('string')
    expect(JSON.parse(sent.params[1]!)).toEqual([approval])
    s.close()
  })
})
