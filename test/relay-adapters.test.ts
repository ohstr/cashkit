// Every RelayPool adapter (relay-ws, nostr-tools, NDK) against one real
// WebSocket relay (test/miniRelay.ts), with the same contract, then a whole
// cash flow through the private transport on each.
import NDK, { NDKEvent, NDKRelaySet } from '@nostr-dev-kit/ndk'
import { SimplePool } from 'nostr-tools/pool'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { finalizeEvent, type NostrEvent } from '../src/core/index.js'
import type { RelayPool } from '../src/client/index.js'
import { RelayWs } from '../src/adapters/relay-ws.js'
import { NostrToolsPool } from '../src/adapters/relay-nostr-tools.js'
import { NdkPool } from '../src/adapters/relay-ndk.js'
import { FakeBank } from './fakeBank.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'
import { MiniRelay } from './miniRelay.js'
import { harness } from './walletHarness.js'

let relay: MiniRelay
beforeAll(async () => {
  relay = await MiniRelay.start()
})
afterAll(async () => {
  await relay.stop()
})

const ev = (n: number, kind = 1) => finalizeEvent({ kind, created_at: 1_700_000_000 + n, tags: [['t', 'cashkit']], content: `n${n}` }, fill(0x21, 32))
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))
/** Polls `done` for up to 2 s. */
async function until(done: () => boolean): Promise<void> {
  for (let i = 0; i < 100 && !done(); i++) await wait(20)
}

interface Adapter {
  readonly name: string
  make(): RelayPool
  close?(p: RelayPool): void
}

const adapters: Adapter[] = [
  { name: 'relay-ws', make: () => new RelayWs() },
  { name: 'nostr-tools SimplePool', make: () => new NostrToolsPool(new SimplePool() as never) },
  {
    name: 'NDK',
    make: () => {
      const ndk = new NDK({ explicitRelayUrls: [] })
      return new NdkPool(ndk as never, { NDKEvent: NDKEvent as never, NDKRelaySet: NDKRelaySet as never })
    },
  },
]

for (const a of adapters) {
  describe(`RelayPool contract: ${a.name}`, () => {
    test('publish is acknowledged; stored events arrive, then EOSE, then live events', async () => {
      const pool = a.make()
      const stored = ev(Math.floor(Math.random() * 1e6))
      expect(await pool.publish(relay.url, stored)).toMatchObject({ ok: true })
      const got: string[] = []
      let eose = false
      const stop = pool.subscribe([relay.url], { ids: [stored.id] }, { onEvent: (e, r) => (got.push(e.id), expect(r).toBe(relay.url)), onEose: (r) => ((eose = true), expect(r).toBe(relay.url)) })
      await until(() => eose)
      expect(eose).toBe(true)
      expect(got).toEqual([stored.id])
      const live = ev(Math.floor(Math.random() * 1e6) + 1e6, 23191)
      const got2: string[] = []
      let eose2 = false
      const stop2 = pool.subscribe([relay.url], { kinds: [23191], ids: [live.id] }, { onEvent: (e) => got2.push(e.id), onEose: () => (eose2 = true) })
      await until(() => eose2)
      await pool.publish(relay.url, live)
      await until(() => got2.length > 0)
      expect(got2).toEqual([live.id])
      stop()
      stop2()
    })
    test('a refused publish is ok: false with the relay message', async () => {
      const pool = a.make()
      relay.refuse = 'blocked: test'
      try {
        const r = await pool.publish(relay.url, ev(Math.floor(Math.random() * 1e6) + 2e6))
        expect(r.ok).toBe(false)
        expect(r.message).toMatch(/blocked/)
      } finally {
        relay.refuse = undefined
      }
    })
  })
}

describe('a wallet over each adapter, against a Hub on the real relay', () => {
  for (const a of adapters) {
    test(`${a.name}: receive and send through the private transport`, async () => {
      // The Hub itself is served from the in-memory pool, bridged to the real relay.
      const memory = new MemoryRelayPool()
      const bank = new FakeBank(memory, [relay.url], { seed: 0x30 + adapters.indexOf(a) })
      const bridge = a.make()
      // Forward the Hub's traffic to the real relay, and requests from it to the Hub.
      const realPublish = memory.publish.bind(memory)
      memory.publish = async (url, e: NostrEvent) => {
        await realPublish(url, e)
        return bridge.publish(url, e)
      }
      bridge.subscribe([relay.url], { kinds: [23190] }, { onEvent: (e) => void realPublish(relay.url, e), onEose: () => {} })
      await bank.start()
      const h = await harness({ bank, pool: memory, deps: { relays: a.make(), replyWaitMs: 10000 } })
      const r = await h.wallet.receive(bank.mintToPubkey(5000n, h.me).token)
      expect(r.received).toBe(true)
      expect((await h.wallet.send({ amount: 2000n })).sent).toBe(2000n)
    }, 30_000)
  }
})
