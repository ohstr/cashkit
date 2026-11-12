// Cross-client LIVE-SOCKET proof (fork, not committed): cashkit's syncPocket
// dials cashctl's `cash pocket serve` over a REAL WebSocket, answers the
// recipient-only NIP-42 AUTH challenge as the owner (same identity key), fetches
// the kind-1059 wrap and resolves A's bill — all over the wire.
//
// The byte-level content interop is already proven (xclient-interop.test.ts reads
// a cashctl-sealed wrap off disk). This proves the TRANSPORT: WS framing + the
// NIP-42 AUTH handshake between cashkit (client) and cashctl (serve).
//
// The Go half (cash-e2e/.wt-cashctl-pocket cmd/liveserve_test.go,
// TestLiveServeForXClient) serves one 40 000 held bill and writes its ws:// URL
// to $XSERVE_URLFILE. This test waits for that URL, dials it, and asserts.
// Skips cleanly when $XSERVE_URLFILE is unset (normal `vitest` sweeps).
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import WebSocket from 'ws'
import { describe, test, expect } from 'vitest'
import {
  finalizeEvent,
  getPublicKey,
  nip44,
  unwrap,
  parsePocketEntry,
  resolveEntries,
  type EventTemplate,
  type NostrEvent,
} from '../src/core/index.js'
import { RelayWs, type WebSocketLike } from '../src/adapters/relay-ws.js'
import { syncPocket } from '../src/adapters/sync-pocket.js'

const K = new Uint8Array(32).fill(0x11) // == cashctl testPocketKey ("11"*32)
const pub = getPublicKey(K)

// unwrap needs pubkey + NIP-44 decrypt (encrypt-to-self: sender==recipient==pub).
const signer = {
  pubkey: pub,
  signEvent: async () => {
    throw new Error('unused')
  },
  nip44Decrypt: async (sender: string, ct: string) =>
    nip44.decrypt(ct, nip44.getConversationKey(K, sender)),
  nip44Encrypt: async (rcpt: string, pt: string) =>
    nip44.encrypt(pt, nip44.getConversationKey(K, rcpt)),
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function waitForUrl(file: string, timeoutMs: number): Promise<string> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (existsSync(file)) {
      const u = readFileSync(file, 'utf8').trim()
      if (u.startsWith('ws://')) return u
    }
    await sleep(200)
  }
  throw new Error(`cashctl serve URL never appeared at ${file}`)
}

// A real node `ws` socket, adapted to the WebSocketLike seam RelayWs dials.
function connect(url: string): WebSocketLike {
  return new WebSocket(url) as unknown as WebSocketLike
}

// The AUTH answer is signed as the owner (same key cashctl seals to), so the
// isolated signed-in pool can talk to the serve. Module-scoped: it captures no
// per-test state (lint: consistent-function-scoping).
const auth = async (t: EventTemplate): Promise<NostrEvent> => finalizeEvent(t, K)

const urlFile = process.env.XSERVE_URLFILE
const stopFile = process.env.XSERVE_STOPFILE

const describeLive = urlFile !== undefined ? describe : describe.skip
describeLive('cross-client LIVE socket: cashkit syncs off cashctl serve', () => {
  test('dial ws://, answer NIP-42 AUTH as owner, fetch + resolve A\'s bill over the wire', async () => {
    const url = await waitForUrl(urlFile!, 20_000)

    const pool = new RelayWs({ connect, connectTimeoutMs: 8_000, publishTimeoutMs: 8_000 })
    // The isolated signed-in pool (auth, module scope) is what talks to the serve.
    const pocket = syncPocket({ pool, relays: [url], auth, minRelays: 1, readTimeoutMs: 6_000 })

    // Live read over the socket: the serve refuses kind-1059 auth-required, the
    // pool answers the challenge as `pub`, retries, and returns the owner's wraps.
    const wraps = await pocket.fetch(pub)
    expect(wraps.length, 'cashkit fetched 0 wraps off the live socket (AUTH or transport failed)').toBeGreaterThanOrEqual(1)

    // Decode + resolve exactly as the proven byte-interop path does.
    const resolvable = [] as { rumor: { id: string; created_at: number }; entry: ReturnType<typeof parsePocketEntry> }[]
    for (const wrap of wraps) {
      const rumor = await unwrap(wrap as NostrEvent, signer as never)
      if (rumor === undefined) continue
      const entry = parsePocketEntry(rumor)
      if (!entry.recognised) continue
      resolvable.push({ rumor: { id: rumor.id, created_at: rumor.created_at }, entry })
    }
    expect(resolvable.length, 'no recognised pocket entry in the live wraps').toBeGreaterThanOrEqual(1)

    const { entries } = resolveEntries(resolvable)
    const live = [...entries.values()].filter((e) => e.state === 'live')
    expect(live.length, 'no live bill resolved off the live socket').toBeGreaterThanOrEqual(1)
    expect(live.some((e) => e.amountMillis === 40_000n), 'the served 40 000 bill did not resolve live').toBe(true)

    if (stopFile !== undefined) writeFileSync(stopFile, 'done')
  }, 30_000)
})
