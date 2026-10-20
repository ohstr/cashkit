// Circle joins over the private transport. Cases follow nmilat
// nipcw/private_join_test.go and nipcash/client/batch_circle_join_test.go.
import { beforeEach, describe, expect, test } from 'vitest'
import {
  connectionKeyFromSecret,
  CoreError,
  getPublicKey,
  KIND_CIRCLE_IDENTITY_PROOF,
  localSigner,
  nip44,
  toHex,
  verifyEvent,
  type NostrEvent,
} from '../src/core/index.js'
import { billFromParts, ClientError, createCircleWalletItem, createCircleWalletMany, openBatchSession } from '../src/client/index.js'
import { newNonce, paramsHash, validateEnvelope, verifyBillProof, verifyItemProof } from '../src/transport/index.js'
import { FakeHub, MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const R1 = 'wss://r1.test'
const now = () => Math.floor(Date.now() / 1000)
const member = localSigner(fill(0x24, 32))
const stranger = localSigner(fill(0x25, 32))
const hubKey = fill(0x26, 32)
const HUB = getPublicKey(hubKey)
const hubSecret = fill(0x27, 32)
const hubConn = () => billFromParts(HUB, toHex(hubSecret))
const key = (b: number) => connectionKeyFromSecret(toHex(fill(b, 32)))
const params = (signer = member, connection = key(0x31)) => ({ signer, connection, maxAmountMillis: 1000n, expirySeconds: 0 })

describe('createCircleWalletItem (private_join_test.go)', () => {
  const node = getPublicKey(fill(0x28, 32))
  const binding = { hub: node, nonce: newNonce(), notAfter: now() + 60 }

  // TestCreateCircleWalletParams_Item.
  test('targets the Hub; the item proof is the requester’s, the bill proof the Hub connection secret’s', async () => {
    const item = await createCircleWalletItem('join', hubConn(), params(), binding, now())
    expect([item.target, item.method]).toEqual([HUB, 'create_circle_wallet'])
    const req = JSON.parse(item.params!) as Record<string, unknown>
    expect(req['pubkey']).toBe(member.pubkey)
    const identity = JSON.parse(req['identity_event'] as string) as NostrEvent
    expect(verifyEvent(identity)).toBe(true)
    expect(identity.kind).toBe(KIND_CIRCLE_IDENTITY_PROOF)
    expect(identity.tags).toEqual([['d', HUB], ['connection', key(0x31).pubkey]])

    const want = { target: HUB, hub: node, method: 'create_circle_wallet', paramsHash: paramsHash(item.params!), nonce: binding.nonce, notAfter: binding.notAfter }
    expect(verifyItemProof(item.proof!, want, now())).toBe(member.pubkey)
    expect(verifyBillProof(item.billProof!, want, now())).toBe(getPublicKey(hubSecret))
    const tags = (JSON.parse(item.proof!) as NostrEvent).tags
    expect(tags.filter((t) => t[0] === 'd' || t[0] === 'h')).toEqual([['d', HUB], ['h', node]])
    expect(() => validateEnvelope({ v: 1, notAfter: binding.notAfter, nonce: binding.nonce, replyTo: newNonce(), items: [item] }, node, now())).not.toThrow()
  })
  // TestCreateCircleWalletParams_Item_NeedsHubSecret.
  test('a join without the Hub connection secret has no bill proof and is refused', () => {
    expect(() => billFromParts(HUB, '')).toThrow(ClientError)
  })
  test('a join without a member connection key is refused', async () => {
    await expect(createCircleWalletItem('join', hubConn(), { signer: member, maxAmountMillis: 1n, expirySeconds: 0 }, binding, now())).rejects.toThrow(CoreError)
  })
})

describe('createCircleWalletMany (batch_circle_join_test.go)', () => {
  let pool: MemoryRelayPool
  let hub: FakeHub
  const details = `{"wallet_pubkey":"${'ab'.repeat(32)}","relays":["wss://w"],"expires_at":1,"fees_ppm":0,"budget_renewal":"never"}`
  const sealFrom = (from: Uint8Array, to: string) => ({ encrypted_details: nip44.encrypt(details, nip44.getConversationKey(from, to)) })

  beforeEach(async () => {
    pool = new MemoryRelayPool()
    hub = new FakeHub(pool, [R1])
    hub.bills.set(HUB, getPublicKey(hubSecret)) // the bill proof must come from the Hub connection secret
    await hub.start()
  })

  // TestCreateCircleWalletMany_EndToEnd: the Hub checks both proofs as
  // §Private Join says, admits one join and refuses the other.
  test('two joins in one envelope: one admitted and decrypted, one refused with its code', async () => {
    hub.handler = (_m, info) => {
      if (info.item.target !== HUB || info.signer !== info.params['pubkey']) return 'omit'
      if (info.params['pubkey'] !== member.pubkey) return { error: { code: 'RESTRICTED' } }
      return { result: sealFrom(hubKey, member.pubkey) }
    }
    const s = await openBatchSession({ relays: pool }, hub.node, [R1])
    const r = await createCircleWalletMany(s, [{ id: 'member', hub: hubConn(), params: params() }, { id: 'stranger', hub: hubConn(), params: params(stranger, key(0x32)) }], now)
    expect(r.error).toBeUndefined()
    expect(r.outcomes.map((o) => o.state)).toEqual(['result', 'error'])
    expect(r.outcomes[0]!.value?.walletPubkey).toBe('ab'.repeat(32))
    expect(r.outcomes[1]!.error?.code).toBe('RESTRICTED')
    expect(pool.published.filter((x) => x.event.kind === 23190)).toHaveLength(1)
  })
  test('details sealed by the inbox key, not the Hub connection key, are undecodable', async () => {
    hub.handler = () => ({ result: sealFrom(hub.inboxKey, member.pubkey) })
    const s = await openBatchSession({ relays: pool }, hub.node, [R1])
    const r = await createCircleWalletMany(s, [{ hub: hubConn(), params: params() }], now)
    expect(r.outcomes[0]).toMatchObject({ id: '#0', state: 'error', undecodable: true })
  })
  test('a join bound to another node than the session’s is refused before sending', async () => {
    const s = await openBatchSession({ relays: pool }, hub.node, [R1])
    const elsewhere = { ...hubConn(), node: getPublicKey(fill(0x29, 32)) }
    await expect(createCircleWalletMany(s, [{ hub: elsewhere, params: params() }], now)).rejects.toThrow(/another node/)
    expect(pool.published.filter((x) => x.event.kind === 23190)).toHaveLength(0)
  })
})
