// A Signer over a local signer process (NIP-LS): NIP-46's request and
// response objects, one JSON object per line, over a unix socket, with no
// relay and no encryption. Node only (node:net); browsers use NIP-07 or
// NIP-46.
//
// Requests are pipelined on one connection and answers matched by `id`. A
// request that times out leaves the connection's answers out of step, so
// the connection is closed (every request still on it fails) and the next
// call reconnects. No message over 1 MiB is sent or read.
import { createConnection, type Socket } from 'node:net'
import { getEventHash, SignerError, signerErrorFrom, toHex, type EventTemplate, type NostrEvent, type Signer } from '../core/index.js'
import type { RelayPool } from '../client/index.js'
import { nip46Signer, type Nip46Options } from './signer-nip46.js'
import { checkSigned } from './signer-verify.js'

/** The largest message either side may send, newline excluded. */
export const MAX_MESSAGE_BYTES = 1 << 20

const WHO = 'signer-unix'

/**
 * The socket path a NIP-LS address names: `bunker+unix:///abs/path`,
 * `unix:///abs/path` or a bare absolute path. A relative path, a host part,
 * a query or a fragment is refused.
 */
export function parseUnixSignerUri(uri: string): string {
  const u = uri.trim()
  const m = /^(?:bunker\+unix|unix):\/\/(.*)$/i.exec(u)
  const path = m !== null ? m[1]! : u
  if (m === null && !u.startsWith('/')) throw new Error(`${WHO}: not a bunker+unix://, unix:// or absolute socket path`)
  if (!path.startsWith('/')) throw new Error(`${WHO}: the socket path must be absolute (bunker+unix:///abs/path)`)
  if (path.includes('?') || path.includes('#')) throw new Error(`${WHO}: a signer address carries no query or fragment`)
  if (path.length < 2) throw new Error(`${WHO}: the socket path is empty`)
  return path
}

/**
 * The id the signer will give `t` once it sets its own pubkey: what a
 * third party's approval (an attestation) names before the event exists.
 */
export function approvedEventId(t: EventTemplate, signerPubkey: string): string {
  return getEventHash({ ...t, pubkey: signerPubkey })
}

export interface UnixSignerOptions {
  /** `bunker+unix:///abs`, `unix:///abs` or an absolute path. */
  readonly uri: string
  /** How long one request waits for its answer. Default 60 s. */
  readonly timeoutMs?: number
}

export interface UnixSigner extends Signer {
  /** The socket path. */
  readonly path: string
  /** `sign_event` with attestation events in `params[1]` (a JSON array as a string). */
  signEventWithAttestations(t: EventTemplate, attestations: readonly NostrEvent[]): Promise<NostrEvent>
  /** Any NIP-46 method; the answer is the raw `result` string. */
  call(method: string, params: readonly string[]): Promise<string>
  /** Closes the connection; requests still waiting fail. */
  close(): void
}

interface Pending {
  readonly method: string
  resolve(v: string): void
  reject(e: Error): void
  timer: ReturnType<typeof setTimeout>
}

/** One connection at a time, opened on demand. */
class Line {
  private sock: Socket | undefined
  private ready: Promise<Socket> | undefined
  private buf: Buffer[] = []
  private bufLen = 0
  private readonly pending = new Map<string, Pending>()
  private seq = 0
  private readonly prefix = toHex(globalThis.crypto.getRandomValues(new Uint8Array(4)))

  constructor(
    private readonly path: string,
    private readonly timeoutMs: number,
  ) {}

  async call(method: string, params: readonly string[]): Promise<string> {
    const id = `${this.prefix}-${++this.seq}`
    const line = JSON.stringify({ id, method, params })
    if (Buffer.byteLength(line, 'utf8') > MAX_MESSAGE_BYTES) throw new SignerError('invalid', `${WHO}: ${method}: the request exceeds 1 MiB`)
    const sock = await this.connect()
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new SignerError('failed', `${WHO}: ${method}: no answer from the signer`))
        // Abandoned: this connection's answers are out of step from here on.
        this.reset(sock, `${WHO}: the connection was reset after an abandoned request`)
      }, this.timeoutMs)
      this.pending.set(id, { method, resolve, reject, timer })
      sock.write(`${line}\n`)
    })
  }

  close(): void {
    if (this.sock !== undefined) this.reset(this.sock, `${WHO}: closed`)
  }

  private connect(): Promise<Socket> {
    if (this.ready !== undefined) return this.ready
    const ready = new Promise<Socket>((resolve, reject) => {
      const sock = createConnection(this.path)
      const fail = (err: Error) => {
        this.ready = undefined
        reject(new SignerError('failed', `${WHO}: cannot connect to ${this.path}: ${err.message}`, { cause: err }))
      }
      sock.once('error', fail)
      sock.once('connect', () => {
        sock.off('error', fail)
        this.sock = sock
        this.buf = []
        this.bufLen = 0
        sock.on('data', (d: Buffer) => this.onData(sock, d))
        sock.on('error', () => this.reset(sock, `${WHO}: the connection failed`))
        sock.on('close', () => this.reset(sock, `${WHO}: the signer closed the connection`))
        resolve(sock)
      })
    })
    this.ready = ready
    return ready
  }

  /** Drops `sock` and fails every request still waiting on it. */
  private reset(sock: Socket, why: string): void {
    sock.destroy()
    if (this.sock !== sock) return // already dropped; its requests failed then
    this.sock = undefined
    this.ready = undefined
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer)
      p.reject(new SignerError('failed', `${why} (${p.method})`))
      this.pending.delete(id)
    }
  }

  private onData(sock: Socket, d: Buffer): void {
    let start = 0
    for (let i = d.indexOf(10); i !== -1; i = d.indexOf(10, start)) {
      const part = d.subarray(start, i)
      start = i + 1
      if (this.bufLen + part.length > MAX_MESSAGE_BYTES) return this.reset(sock, `${WHO}: the signer sent a message over 1 MiB`)
      const line = Buffer.concat([...this.buf, part]).toString('utf8')
      this.buf = []
      this.bufLen = 0
      this.onLine(sock, line)
      if (this.sock !== sock) return
    }
    const rest = d.subarray(start)
    if (this.bufLen + rest.length > MAX_MESSAGE_BYTES) return this.reset(sock, `${WHO}: the signer sent a message over 1 MiB`)
    if (rest.length > 0) {
      this.buf.push(rest)
      this.bufLen += rest.length
    }
  }

  private onLine(sock: Socket, line: string): void {
    if (line.trim() === '') return
    let msg: { id?: unknown; result?: unknown; error?: unknown }
    try {
      msg = JSON.parse(line)
    } catch {
      return this.reset(sock, `${WHO}: the signer sent a line that is not JSON`)
    }
    if (msg === null || typeof msg !== 'object' || typeof msg.id !== 'string') return this.reset(sock, `${WHO}: the signer sent an answer without an id`)
    const p = this.pending.get(msg.id)
    if (p === undefined) {
      // An empty id answers a line the signer could not read: which request it was is unknown.
      if (msg.id === '') return this.reset(sock, `${WHO}: the signer could not read a request${typeof msg.error === 'string' ? `: ${msg.error}` : ''}`)
      return // an answer to an abandoned request
    }
    this.pending.delete(msg.id)
    clearTimeout(p.timer)
    if (typeof msg.error === 'string' && msg.error !== '') p.reject(signerErrorFrom(WHO, msg.error))
    else if (typeof msg.result === 'string') p.resolve(msg.result)
    else p.reject(new SignerError('failed', `${WHO}: ${p.method}: the signer answered without a result`))
  }
}

/** Connects to the local signer and resolves the user's pubkey once. */
export async function unixSigner(o: UnixSignerOptions): Promise<UnixSigner> {
  const path = parseUnixSignerUri(o.uri)
  const line = new Line(path, o.timeoutMs ?? 60_000)
  const call = (method: string, params: readonly string[]) => line.call(method, params)
  let pubkey: string
  try {
    pubkey = await call('get_public_key', [])
  } catch (err) {
    line.close()
    throw err
  }
  if (!/^[0-9a-f]{64}$/.test(pubkey)) {
    line.close()
    throw new SignerError('failed', `${WHO}: the signer returned an invalid pubkey`)
  }
  const sign = async (t: EventTemplate, attestations: readonly NostrEvent[]): Promise<NostrEvent> => {
    const params = [JSON.stringify({ kind: t.kind, content: t.content, tags: t.tags, created_at: t.created_at })]
    if (attestations.length > 0) params.push(JSON.stringify(attestations))
    const raw = await call('sign_event', params)
    let got: unknown
    try {
      got = JSON.parse(raw)
    } catch {
      throw new SignerError('failed', `${WHO}: sign_event answered with something that is not an event`)
    }
    return checkSigned(t, got, pubkey, WHO)
  }
  return {
    pubkey,
    path,
    signEvent: (t) => sign(t, []),
    signEventWithAttestations: sign,
    nip44Decrypt: (peer, ct) => call('nip44_decrypt', [peer, ct]),
    nip44Encrypt: (peer, pt) => call('nip44_encrypt', [peer, pt]),
    call,
    close: () => line.close(),
  }
}

/** Options for `signerFromUri`: the NIP-46 options apply to a `bunker://` URI only. */
export interface SignerFromUriOptions extends Omit<Nip46Options, 'bunker' | 'relays' | 'timeoutMs'> {
  /** Needed for a `bunker://` URI. */
  readonly relays?: RelayPool
  readonly timeoutMs?: number
}

/**
 * A signer from any address a user may paste: `bunker://…` (NIP-46, over
 * relays), or a local signer's `bunker+unix:///abs`, `unix:///abs` or bare
 * absolute path (NIP-LS). Anything else is refused.
 */
export async function signerFromUri(uri: string, o: SignerFromUriOptions = {}): Promise<Signer & { close(): void }> {
  const u = uri.trim()
  if (/^bunker:\/\//i.test(u)) {
    if (o.relays === undefined) throw new Error(`${WHO}: a bunker:// URI needs a relay pool`)
    const { relays, ...rest } = o
    return nip46Signer({ ...rest, bunker: u, relays })
  }
  return unixSigner({ uri: u, ...(o.timeoutMs !== undefined && { timeoutMs: o.timeoutMs }) })
}
