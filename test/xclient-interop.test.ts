// Cross-client interop proof (fork, not committed): cashkit reads + resolves the
// EXACT kind-1059 gift-wrap that cashctl's pocket (Go nipCP.Seal) produced for the
// same identity key — proving the two clients share one NIP-CP pocket wire format.
// The Go side emits /tmp/ccpk-xclient/{wrap.json,expected.json}
// (internal/pocket/xclient_interop_test.go, run with XCLIENT_OUT=/tmp/ccpk-xclient).
import { readFileSync } from 'node:fs'
import { describe, test, expect } from 'vitest'
import {
  getPublicKey,
  nip44,
  unwrap,
  parsePocketEntry,
  resolveEntries,
  type NostrEvent,
} from '../src/core/index.js'

const K = new Uint8Array(32).fill(0x11) // == cashctl SaveLocalKey("11"*32)
const pub = getPublicKey(K)

// A minimal Signer over K — unwrap only needs pubkey + nip44Decrypt.
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

describe('cross-client: cashkit reads a cashctl-sealed pocket wrap', () => {
  test('unwrap + parse + resolve the exact 1059 cashctl produced (same key)', async () => {
    const dir = process.env.XCLIENT_OUT ?? '/tmp/ccpk-xclient'
    const wrap = JSON.parse(readFileSync(`${dir}/wrap.json`, 'utf8')) as NostrEvent
    const expected = JSON.parse(readFileSync(`${dir}/expected.json`, 'utf8')) as {
      w: string
      amount: number
      state: string
      ownerPub: string
    }

    // 1. Key-derivation parity: cashkit's x-only pubkey == cashctl's (same secp256k1 key).
    expect(pub).toBe(expected.ownerPub)

    // 2. cashkit unwraps the gift-wrap cashctl sealed (verifies wrap+seal sigs, NIP-44 decrypts).
    const rumor = await unwrap(wrap, signer as never)
    expect(rumor, 'cashkit could not unwrap cashctl 1059').toBeDefined()

    // 3. cashkit parses the 9525 rumor into a pocket entry.
    const entry = parsePocketEntry(rumor!)
    expect(entry.recognised).toBe(true)

    // 4. cashkit resolves it to the same winner cashctl encoded.
    const { entries } = resolveEntries([
      { rumor: { id: rumor!.id, created_at: rumor!.created_at }, entry },
    ])
    const won = entries.get(expected.w)
    expect(won, 'resolved entry missing for w').toBeDefined()
    expect(won!.w).toBe(expected.w)
    expect(won!.state).toBe(expected.state) // 'live'
    expect(won!.amountMillis).toBe(BigInt(expected.amount)) // 50000n
  })
})
