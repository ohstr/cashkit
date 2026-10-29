// NIP-CASH §Item Proofs: the item proof is signed by the key that signed the
// claim proof in params, in pubkey and connection_key mode alike; a cash
// secret item carries no item proof.
import { describe, expect, test } from 'vitest'
import {
  bySecret,
  bySigning,
  bySigningConnectionKey,
  connectionKeyFromAttested,
  decodeToken,
  finalizeEvent,
  getPublicKey,
  localSigner,
  newRequestId,
  parseAttestation,
  pubkeyTarget,
  toHex,
  type Credential,
} from '../src/core/index.js'
import { billFor, redeemMany, transferMany, type BatchSession } from '../src/client/index.js'
import type { Item } from '../src/transport/index.js'
import { bech32Encode, toWords } from '../src/core/bech32.js'
import { FakeHub, MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const now = () => Math.floor(Date.now() / 1000)
const holder = localSigner(fill(2, 32))
const iaKey = fill(3, 32)

function invoice(): string {
  const w = [...Array(7).fill(0), 1, 1, 20, ...toWords(fill(0xaa, 32)), ...Array(104).fill(0)]
  return bech32Encode('lnfc10u', Uint8Array.from(w))
}

function ckCredential(): Credential {
  const ev = finalizeEvent({
    kind: 35522,
    created_at: now(),
    tags: [
      ['d', connectionKeyFromAttested('github', '12345')],
      ['p', holder.pubkey],
      ['platform', 'github'],
      ['evidence', '{"version":1,"platform":"github","auth_type":"oauth","user_id":"12345","username":"alice","verified_at":1759999000}'],
      ['expiration', String(now() + 86400)],
    ],
    content: '',
  }, iaKey)
  return bySigningConnectionKey(holder, 'github', '12345', parseAttestation(ev))
}

/** A session that only builds the items and keeps them, answering none. */
async function capture(run: (s: BatchSession) => Promise<unknown>, hub: string): Promise<Item[]> {
  const items: Item[] = []
  const session = {
    hub,
    send: async (builders: readonly { id: string; build: (id: string, b: { hub: string; nonce: string; notAfter: number }) => Promise<Item> }[]) => {
      for (const b of builders) items.push(await b.build(b.id, { hub, nonce: 'ab'.repeat(16), notAfter: now() + 60 }))
      return { outcomes: [] }
    },
  } as unknown as BatchSession
  await run(session)
  return items
}

async function setup() {
  const pool = new MemoryRelayPool()
  const fake = new FakeHub(pool, ['wss://r1.test'])
  await fake.start()
  const bill = billFor(decodeToken(fake.mintBill({ walletKey: fill(0x41, 32), connSecret: fill(0x61, 32), amount: 21000n, relays: ['wss://r1.test'] })))
  return { fake, bill }
}

const signerOf = (json: string | undefined) => (JSON.parse(json!) as { pubkey: string }).pubkey

describe('the item proof is signed by the claim proof signer', () => {
  test.each([
    ['pubkey', () => bySigning(holder)],
    ['connection_key', ckCredential],
  ])('%s mode: transfer and redeem items name one signer for both proofs', async (_mode, cred) => {
    const { fake, bill } = await setup()
    const credential = cred()
    const items = await capture(async (s) => {
      await transferMany(s, [{ id: 't', bill, credential, to: pubkeyTarget(getPublicKey(fill(9, 32))), currentAmount: 21000n, requestId: newRequestId() }], now)
      await redeemMany(s, [{ id: 'r', bill, credential, invoice: invoice() }], now)
    }, fake.node)
    expect(items).toHaveLength(2)
    for (const it of items) {
      const params = JSON.parse(it.params!) as { identity_event: string }
      expect(signerOf(params.identity_event)).toBe(holder.pubkey)
      expect(signerOf(it.proof)).toBe(holder.pubkey)
      // The bill proof is the bill's own key, never the holder's.
      expect(signerOf(it.billProof)).not.toBe(holder.pubkey)
    }
  })
  test('a cash secret item carries the secret and no item proof', async () => {
    const { fake, bill } = await setup()
    const items = await capture((s) => transferMany(s, [{ id: 't', bill, credential: bySecret(toHex(fill(7, 32))), to: pubkeyTarget(getPublicKey(fill(9, 32))), currentAmount: 21000n, requestId: newRequestId() }], now), fake.node)
    expect(items[0]!.proof).toBeUndefined()
    expect(JSON.parse(items[0]!.params!)).toMatchObject({ cash_secret: toHex(fill(7, 32)) })
  })
})
