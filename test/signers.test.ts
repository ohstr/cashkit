// External signers: NIP-07 (browser extension) and NIP-46 (bunker), against
// fakes, plus a wallet spending through a bunker.
import { describe, expect, test } from 'vitest'
import { finalizeEvent, getPublicKey, localSigner, nip44, signerErrorFrom, toHex, type EventTemplate, type NostrEvent } from '../src/core/index.js'
import { nip07Signer, type Nip07 } from '../src/adapters/signer-nip07.js'
import { KIND_NIP46, nip46Signer, parseBunkerUri } from '../src/adapters/signer-nip46.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'
import { harness } from './walletHarness.js'

const userKey = fill(0x31, 32)
const user = localSigner(userKey)

const ext = (o: Partial<Nip07> = {}): Nip07 => ({
  getPublicKey: async () => user.pubkey,
  signEvent: (t) => user.signEvent(t),
  nip44: { encrypt: async (p, pt) => nip44.encrypt(pt, nip44.getConversationKey(userKey, p)), decrypt: (p, ct) => user.nip44Decrypt(p, ct) },
  ...o,
})

describe('nip07Signer', () => {
  const tpl: EventTemplate = { kind: 23198, created_at: 1_700_000_000, tags: [['d', 'ab'.repeat(32)]], content: '' }
  test('resolves the pubkey once and signs through the extension', async () => {
    const s = await nip07Signer(ext())
    expect(s.pubkey).toBe(user.pubkey)
    expect((await s.signEvent(tpl)).pubkey).toBe(user.pubkey)
    const peer = fill(0x55, 32)
    const ct = await s.nip44Encrypt(getPublicKey(peer), 'to peer')
    expect(nip44.decrypt(ct, nip44.getConversationKey(peer, user.pubkey))).toBe('to peer')
  })
  test('refuses an event other than the one asked for, or from another identity', async () => {
    const other = localSigner(fill(0x32, 32))
    await expect((await nip07Signer(ext({ signEvent: (t) => user.signEvent({ ...t, content: 'swapped' }) }))).signEvent(tpl)).rejects.toThrow(/different event/)
    await expect((await nip07Signer(ext({ signEvent: (t) => other.signEvent(t) }))).signEvent(tpl)).rejects.toThrow(/different identity/)
  })
  test('without window.nostr, or without NIP-44, it says so', async () => {
    await expect(nip07Signer()).rejects.toThrow(/window.nostr/)
    const { nip44: _n, ...noNip44 } = ext()
    await expect((await nip07Signer(noNip44)).nip44Decrypt('ab'.repeat(32), 'x')).rejects.toThrow(/NIP-44/)
  })
})

const R = 'wss://bunker.test'
const remoteKey = fill(0x41, 32)
const REMOTE = getPublicKey(remoteKey)

/** A NIP-46 bunker holding the user's key, answering over the pool. */
function startBunker(pool: MemoryRelayPool, o: { secret?: string; authUrlFirst?: boolean; tamper?: boolean; forge?: boolean } = {}) {
  const seen: string[] = []
  pool.subscribe([R], { kinds: [KIND_NIP46], '#p': [REMOTE] }, {
    onEvent: (e: NostrEvent) => {
      const ck = nip44.getConversationKey(remoteKey, e.pubkey)
      const req = JSON.parse(nip44.decrypt(e.content, ck)) as { id: string; method: string; params: string[] }
      seen.push(req.method)
      const reply = (body: object, key = remoteKey) =>
        void pool.publish(R, finalizeEvent({ kind: KIND_NIP46, created_at: e.created_at, tags: [['p', e.pubkey]], content: nip44.encrypt(JSON.stringify({ id: req.id, ...body }), nip44.getConversationKey(key, e.pubkey)) }, key))
      if (o.forge) reply({ result: 'ff'.repeat(32) }, fill(0x77, 32))
      void (async () => {
        switch (req.method) {
          case 'connect':
            return reply(o.secret !== undefined && req.params[1] !== o.secret ? { error: 'bad secret' } : { result: 'ack' })
          case 'get_public_key':
            return reply({ result: user.pubkey })
          case 'sign_event': {
            if (o.authUrlFirst) {
              reply({ result: 'auth_url', error: 'https://bunker.test/approve/1' })
              await new Promise((r) => setTimeout(r, 10))
            }
            const t = JSON.parse(req.params[0]!) as EventTemplate
            const signed = await user.signEvent(o.tamper ? { ...t, content: 'swapped' } : t)
            return reply({ result: JSON.stringify(signed) })
          }
          case 'nip44_decrypt':
            if (req.params[0] === 'denied') return reply({ error: 'denied: policy says no' })
            if (req.params[0] === 'invalid') return reply({ error: 'invalid: bad params' })
            if (req.params[0] === 'other') return reply({ error: 'decrypt failed' })
            return reply({ result: await user.nip44Decrypt(req.params[0]!, req.params[1]!) })
          case 'nip44_encrypt':
            return reply({ result: await user.nip44Encrypt(req.params[0]!, req.params[1]!) })
          default:
            return reply({ error: `unsupported ${req.method}` })
        }
      })()
    },
    onEose: () => {},
  })
  return seen
}

const uri = (secret?: string) => `bunker://${REMOTE}?relay=${encodeURIComponent(R)}${secret ? `&secret=${secret}` : ''}`

describe('nip46Signer', () => {
  test('parses bunker URIs', () => {
    expect(parseBunkerUri(`bunker://${REMOTE.toUpperCase()}?relay=wss://a&relay=wss://b&secret=s3`)).toEqual({ remotePubkey: REMOTE, relays: ['wss://a', 'wss://b'], secret: 's3' })
    expect(() => parseBunkerUri('bunker://nothex?relay=wss://a')).toThrow()
    expect(() => parseBunkerUri(`bunker://${REMOTE}`)).toThrow(/no relay/)
  })
  test('a local signer address is refused here, naming the unix adapter', () => {
    for (const u of ['bunker+unix:///tmp/s.sock', 'unix:///tmp/s.sock', '/tmp/s.sock']) expect(() => parseBunkerUri(u)).toThrow(/\.\/adapters\/signer-unix/)
  })
  test('encrypts through the bunker, and sorts its errors by prefix', async () => {
    const pool = new MemoryRelayPool()
    startBunker(pool)
    const s = await nip46Signer({ bunker: uri(), relays: pool })
    const peer = fill(0x55, 32)
    const ct = await s.nip44Encrypt(getPublicKey(peer), 'to peer')
    expect(nip44.decrypt(ct, nip44.getConversationKey(peer, user.pubkey))).toBe('to peer')
    for (const code of ['denied', 'invalid'] as const) {
      await expect(s.nip44Decrypt(code, 'x')).rejects.toMatchObject({ name: 'SignerError', code })
    }
    await expect(s.nip44Decrypt('other', 'x')).rejects.toMatchObject({ name: 'SignerError', code: 'failed', message: 'signer-nip46: decrypt failed' })
    s.close()
  })
  test('connects with the secret, learns the user pubkey (not the bunker key), signs and decrypts', async () => {
    const pool = new MemoryRelayPool()
    const seen = startBunker(pool, { secret: 'one-time' })
    const s = await nip46Signer({ bunker: uri('one-time'), relays: pool })
    expect(s.pubkey).toBe(user.pubkey)
    expect(s.remotePubkey).toBe(REMOTE)
    const ev = await s.signEvent({ kind: 1, created_at: 1_700_000_000, tags: [], content: 'hi' })
    expect(ev.pubkey).toBe(user.pubkey)
    const peer = fill(0x55, 32)
    const ct = nip44.encrypt('secret', nip44.getConversationKey(peer, user.pubkey))
    expect(await s.nip44Decrypt(getPublicKey(peer), ct)).toBe('secret')
    expect(seen).toEqual(['connect', 'get_public_key', 'sign_event', 'nip44_decrypt'])
    s.close()
  })
  test('a wrong secret is refused at connect', async () => {
    const pool = new MemoryRelayPool()
    startBunker(pool, { secret: 'right' })
    await expect(nip46Signer({ bunker: uri('wrong'), relays: pool })).rejects.toThrow(/bad secret/)
  })
  test('auth_url is handed to the app, and the request waits for its real answer', async () => {
    const pool = new MemoryRelayPool()
    startBunker(pool, { authUrlFirst: true })
    const urls: string[] = []
    const s = await nip46Signer({ bunker: uri(), relays: pool, onAuthUrl: (u) => urls.push(u) })
    expect((await s.signEvent({ kind: 1, created_at: 1, tags: [], content: 'x' })).content).toBe('x')
    expect(urls).toEqual(['https://bunker.test/approve/1'])
    s.close()
  })
  test('replies from anyone but the bunker are ignored', async () => {
    const pool = new MemoryRelayPool()
    startBunker(pool, { forge: true })
    const s = await nip46Signer({ bunker: uri(), relays: pool })
    expect(s.pubkey).toBe(user.pubkey)
    s.close()
  })
  test('a bunker that signs a different event is refused', async () => {
    const pool = new MemoryRelayPool()
    startBunker(pool, { tamper: true })
    const s = await nip46Signer({ bunker: uri(), relays: pool })
    await expect(s.signEvent({ kind: 1, created_at: 1, tags: [], content: 'x' })).rejects.toThrow(/different event/)
    s.close()
  })
  test('no answer times out plainly; the client key can be kept to stay paired', async () => {
    const pool = new MemoryRelayPool()
    await expect(nip46Signer({ bunker: uri(), relays: pool, timeoutMs: 30 })).rejects.toThrow(/no answer/)
    startBunker(pool)
    const key = fill(0x66, 32)
    const s = await nip46Signer({ bunker: uri(), relays: pool, clientSecret: key })
    expect(toHex(s.clientSecret)).toBe(toHex(key))
    s.close()
  })
})

test('a wallet whose identity lives in a bunker receives and spends', async () => {
  const h0 = await harness({ identity: false })
  const pool = h0.pool
  const pool2 = new MemoryRelayPool()
  startBunker(pool2)
  const signer = await nip46Signer({ bunker: uri(), relays: pool2 })
  const h = await harness({ identity: false, pool, bank: h0.bank, deps: { signer } })
  expect((await h.wallet.identity.get())).toMatchObject({ pubkey: user.pubkey, source: 'signer' })
  const r = await h.wallet.receive(h.bank.mintToPubkey(5000n, user.pubkey).token)
  expect(r.received).toBe(true)
  expect((await h.wallet.send({ amount: 2000n })).sent).toBe(2000n)
  signer.close()
})

describe('a signer error reason is untrusted text', () => {
  test('terminal escapes, controls and bidi marks are removed, breaks become spaces, and it is capped; the code still classifies', () => {
    const e = signerErrorFrom('signer-nip46', 'denied: \u001b[31mred\u001b[0m\u0007 line\nnext ‮evil‎\u009b')
    expect(e).toMatchObject({ code: 'denied', message: 'signer-nip46: denied: [31mred[0m line next evil' })
    expect(signerErrorFrom('x', 'a'.repeat(5000)).message.length).toBe('x: '.length + 300)
  })
})
