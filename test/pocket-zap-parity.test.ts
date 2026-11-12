// Cross-impl parity for NIP-CZ (Cash Zaps) against the shared golden corpus
// (cash-e2e/glue/vectors/pocket/zap_payload.json + zap_9522.json), generated
// from nmilat's encoders. Asserts cashkit builds the SAME `cash-zap:v1` payload
// and the SAME canonical kind-9522 (event id + parsed tags) as cashctl/nmilat.
//
// Full verifyCashZap (rules 1-8: the event signature + the token's minter
// signature over the rebuilt payload) is integration-tier: the corpus ships
// unsigned events with fixed keys (BIP-340 signatures are not pinned), and a
// real zap bill needs a Hub transfer-reply, so the signed round-trip is covered
// by the e2e (CC-24), not here. Here we pin everything deterministic.
import { existsSync, readFileSync } from 'node:fs'
import { describe, expect, test } from 'vitest'
import { checkCashZapTags, getEventHash, zapPayloadV1 } from '../src/core/index.js'

const PAYLOADS = new URL('../../cash-e2e/glue/vectors/pocket/zap_payload.json', import.meta.url)
const EVENTS = new URL('../../cash-e2e/glue/vectors/pocket/zap_9522.json', import.meta.url)

interface PayloadVec {
  name: string
  hrp: string
  wallet: string
  amount: number
  recipient: string
  sender: string
  zap_target: string
  issued_at: number
  expires_at: number
  relay_hash: string
  payload: string
}
interface EventVec {
  name: string
  cash: string
  event: { id: string; pubkey: string; created_at: number; kind: number; content: string; tags: string[][] }
}

const load = <T>(u: URL): T[] => (existsSync(u) ? (JSON.parse(readFileSync(u, 'utf8')) as T[]) : [])

// The golden corpus lives in the sibling cash-e2e repo (glue/vectors/pocket),
// absent in an isolated cashkit checkout (CI) — skip cleanly then, mirroring the
// xclient interop/live proofs. When present (full worktree / e2e), everything
// deterministic is pinned below.
const payloads = load<PayloadVec>(PAYLOADS)
const events = load<EventVec>(EVENTS)
const describeParity = payloads.length > 0 && events.length > 0 ? describe : describe.skip

describeParity('NIP-CZ golden parity (shared cross-impl corpus)', () => {
  describe('cash-zap:v1 payload', () => {
    for (const v of payloads) {
      test(`${v.name}: cashkit builds the vector payload byte-for-byte`, () => {
        const built = zapPayloadV1({
          hrp: v.hrp,
          walletPubkey: v.wallet,
          amountMillis: BigInt(v.amount),
          relayHash: v.relay_hash,
          recipient: v.recipient,
          sender: v.sender,
          zapTarget: v.zap_target,
          issuedAt: v.issued_at,
          expiresAt: v.expires_at,
        })
        expect(built).toBe(v.payload)
      })
    }
  })

  describe('kind-9522 event', () => {
    for (const v of events) {
      test(`${v.name}: cashkit recomputes the canonical event id`, () => {
        const { pubkey, created_at, kind, content, tags } = v.event
        expect(getEventHash({ pubkey, created_at, kind, content, tags })).toBe(v.event.id)
      })

      test(`${v.name}: cashkit parses the 9522 tags to the vector's fields`, () => {
        const t = checkCashZapTags({ tags: v.event.tags })
        const tag = (name: string) => v.event.tags.find((x) => x[0] === name)?.[1]
        expect(t.cash).toBe(v.cash)
        expect(t.cash).toBe(tag('cash'))
        expect(t.w).toBe(tag('w'))
        expect(t.chain).toBe(tag('chain'))
        expect(t.amountMillis).toBe(BigInt(tag('amount')!))
        expect(t.p.value).toBe(tag('p'))
      })
    }
  })
})
