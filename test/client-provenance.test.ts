// The client dials a bill's Hub only through provenance that verifies
// (NIP-CASH §Mint Provenance): copies of one bill, and zap bills that need
// their Cash Zap's fields. Cases follow nmilat nipcash/client
// client_test.go (copies) and nipCZ verify_test.go (rule 6, no event).
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { beforeEach, describe, expect, test } from 'vitest'
import { utf8 } from '../src/core/bytes.js'
import {
  bySecret,
  decodeToken,
  encodeToken,
  getPublicKey,
  relayHashOf,
  signCompact,
  signedMessageDigest,
  toHex,
  zapPayloadV1,
  type NostrEvent,
  type ZapFields,
} from '../src/core/index.js'
import { CashClient, ClientError, selectVerifiedCopy, type Filter, type RelayPool, type SubscriptionHandlers } from '../src/client/index.js'
import { FakeHub, MemoryRelayPool } from './fakeHub.js'
import { fill, signedToken } from './helpers.js'

const R1 = 'wss://r1.test'
const EVIL = 'wss://evil.test'

/** Records every relay the client touches. */
class SpyPool implements RelayPool {
  readonly touched = new Set<string>()
  constructor(readonly inner: MemoryRelayPool) {}
  subscribe(relays: readonly string[], f: Filter, h: SubscriptionHandlers): () => void {
    relays.forEach((r) => this.touched.add(r))
    return this.inner.subscribe(relays, f, h)
  }
  publish(relay: string, e: NostrEvent) {
    this.touched.add(relay)
    return this.inner.publish(relay, e)
  }
}

let pool: MemoryRelayPool
let spy: SpyPool
let hub: FakeHub
beforeEach(async () => {
  pool = new MemoryRelayPool()
  spy = new SpyPool(pool)
  hub = new FakeHub(pool, [R1])
  await hub.start()
})
const minter = () => toHex(secp256k1.getPublicKey(hub.nodeKey, true))

describe('T-012 copies of one bill', () => {
  test('a verifying copy is selected; a copy whose hints were swapped is never dialled', async () => {
    const good = decodeToken(hub.mintBill({ walletKey: fill(0x41, 32), connSecret: fill(0x61, 32), amount: 5000n }))
    const forged = { ...good, relays: [EVIL], relayBytes: [utf8(EVIL)] }
    expect(selectVerifiedCopy([forged, good], minter())).toBe(good)
    expect(selectVerifiedCopy([forged], minter())).toBeUndefined()
    const c = new CashClient({ relays: spy }, selectVerifiedCopy([forged, good], minter())!)
    await c.cashStatus(bySecret('ab'.repeat(32)), 'mine').catch(() => undefined)
    expect(spy.touched.has(EVIL)).toBe(false)
  })
  test('a reissued copy with other hints, signed afresh, also verifies', () => {
    const fields = { hrp: 'lokicash', walletPubkey: getPublicKey(fill(0x42, 32)), secret: toHex(fill(0x62, 32)), amount: 7000n }
    const a = decodeToken(signedToken({ ...fields, relays: [R1] }, hub.nodeKey))
    const b = decodeToken(signedToken({ ...fields, relays: ['wss://other.test', R1] }, hub.nodeKey))
    expect(selectVerifiedCopy([b, a], minter())).toBe(b)
    expect(selectVerifiedCopy([b], minter().slice(2))).toBe(b)
  })
  test('a copy signed by another minter is not this Hub’s bill', () => {
    const fields = { hrp: 'lokicash', walletPubkey: getPublicKey(fill(0x43, 32)), secret: toHex(fill(0x63, 32)), relays: [R1] }
    expect(selectVerifiedCopy([decodeToken(signedToken(fields, fill(0x12, 32)))], minter())).toBeUndefined()
  })
  test('a token with no valid provenance is refused before any relay is contacted', async () => {
    const t = decodeToken(hub.mintBill({ walletKey: fill(0x44, 32), connSecret: fill(0x64, 32), amount: 1000n }))
    const unsigned = { ...t, scheme: 'malformed' as const }
    const err = await new CashClient({ relays: spy }, unsigned).cashStatus(bySecret('ab'.repeat(32)), 'mine').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).code).toBe('no_provenance')
    expect(spy.touched.size).toBe(0)
  })
})

function zapToken(z: ZapFields) {
  const walletKey = fill(0x45, 32)
  const connSecret = fill(0x65, 32)
  hub.mintBill({ walletKey, connSecret, amount: 5000n })
  const wallet = getPublicKey(walletKey)
  const payload = zapPayloadV1({ hrp: 'lokicash', walletPubkey: wallet, amountMillis: 5000n, relayHash: relayHashOf([utf8(R1)], connSecret), ...z })
  return encodeToken({ hrp: 'lokicash', walletPubkey: wallet, secret: toHex(connSecret), relays: [R1], scheme: 'zap_v1', mintSignature: signCompact(signedMessageDigest('lokicash', payload)!, hub.nodeKey), attestedAmountMillis: 5000n })
}

const zap: ZapFields = { recipient: getPublicKey(fill(5, 32)), sender: getPublicKey(fill(6, 32)), zapTarget: 'note1target', issuedAt: 1720000000, expiresAt: 0 }

describe('T-013 zap bills', () => {
  test('without the Cash Zap fields: no_zap_event, before any relay', async () => {
    const err = await new CashClient({ relays: spy }, zapToken(zap)).cashStatus(bySecret('ab'.repeat(32)), 'mine').catch((e: unknown) => e)
    expect((err as ClientError).code).toBe('no_zap_event')
    expect(spy.touched.size).toBe(0)
  })
  test('with them: verified, and the bill reaches its Hub', async () => {
    const c = new CashClient({ relays: spy }, zapToken(zap), zap)
    expect(c.bill.node).toBe(hub.node)
    await c.session()
    expect(spy.touched.has(R1)).toBe(true)
  })
  test('with fields of another zap: no provenance, nothing dialled', async () => {
    const c = new CashClient({ relays: spy }, zapToken(zap), { ...zap, zapTarget: 'note1other' })
    expect(c.bill.node).not.toBe(hub.node)
    expect(selectVerifiedCopy([c.token], minter(), { ...zap, zapTarget: 'note1other' })).toBeUndefined()
    expect(selectVerifiedCopy([c.token], minter(), zap)).toBe(c.token)
  })
})
