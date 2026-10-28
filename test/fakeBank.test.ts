// The FakeBank behaves like a Hub through the real client: these pin the
// NIP-CASH outcomes the wallet scenarios rely on.
import { beforeEach, describe, expect, test } from 'vitest'
import { bySecret, bySigning, decodeBolt11, localSigner, newCashTarget, pubkeyTarget, toHex } from '../src/core/index.js'
import { newRequestId } from '../src/core/index.js'
import { CashClient, ClientError, WalletError } from '../src/client/index.js'
import { FakeBank, commitment } from './fakeBank.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill, invoice } from './helpers.js'

const R = 'wss://bank.test'
const alice = localSigner(fill(0x61, 32))
const bob = localSigner(fill(0x62, 32))

let pool: MemoryRelayPool
let bank: FakeBank
const client = (token: string) => new CashClient({ relays: pool, replyWaitMs: 2000 }, token)

beforeEach(async () => {
  pool = new MemoryRelayPool()
  bank = new FakeBank(pool, [R])
  await bank.start()
})

test('invoice helper decodes to the asked amount', () => {
  expect(decodeBolt11(invoice(1234n)).amountMillis).toBe(1234n)
  expect(decodeBolt11(invoice()).amountMillis).toBe(0n)
})

describe('FakeBank', () => {
  test('status: the holder sees its row; a stranger is NOT_FOUND', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    const r = await client(w.token).checkClaim(bySigning(alice))
    expect(r).toMatchObject({ isCash: false, amountMillis: 5000n, netRedeemableMillis: 5000n })
    await expect(client(w.token).checkClaim(bySigning(bob))).rejects.toMatchObject({ code: 'claim_not_found' })
  })
  test("cash: the right secret matches; a wrong one is lokihub's NOT_FOUND", async () => {
    const t = newCashTarget()
    const w = bank.mintToCash(700n, t.secret)
    expect((await client(w.token).checkClaim(bySecret(t.secret))).isCash).toBe(true)
    // A cash-mode status carries no secret; the secret is checked against the row's commitment.
    const err = await client(w.token).checkClaim(bySecret('ab'.repeat(32))).catch((e: unknown) => e)
    expect((err as { code?: string }).code).toBe('claim_not_found')
    const spend = await client(w.token).cashTransfer({ requestId: newRequestId(), credential: bySecret('ab'.repeat(32)), to: pubkeyTarget(bob.pubkey), currentAmount: 700n }).catch((e: unknown) => e)
    expect(spend).toBeInstanceOf(WalletError)
    expect((spend as WalletError).walletCode).toBe('NOT_FOUND')
  })
  test('a split spins off two wallets and spends the source', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    const r = await client(w.token).cashTransfer({ requestId: newRequestId(), credential: bySigning(alice), to: pubkeyTarget(bob.pubkey), currentAmount: 5000n, splitAmount: 2000n })
    expect(r.remainingAmountMillis).toBe(3000n)
    expect(bank.wallet(r.newWalletToken)?.identity.value).toBe(bob.pubkey)
    expect(bank.wallet(r.remainderWalletToken)?.identity.value).toBe(alice.pubkey)
    expect(w.spent).toBe(true)
    expect((await client(w.token).state(bySigning(alice))).state).toBe('spent')
  })
  test('a full transfer to a pubkey moves in place', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    const r = await client(w.token).cashTransfer({ requestId: newRequestId(), credential: bySigning(alice), to: pubkeyTarget(bob.pubkey), currentAmount: 5000n })
    expect(r.newWalletToken).toBe('')
    expect(w.identity.value).toBe(bob.pubkey)
  })
  test('a full transfer to cash: in place on a lifetime-solo wallet, a spin-off otherwise', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    const t1 = newCashTarget()
    await client(w.token).cashTransfer({ requestId: newRequestId(), credential: bySigning(alice), to: t1, currentAmount: 5000n })
    expect(w.identity).toEqual({ type: 'cash', value: commitment(t1.secret) })
    const t2 = newCashTarget()
    const r = await client(w.token).cashTransfer({ requestId: newRequestId(), credential: bySecret(t1.secret), to: t2, currentAmount: 5000n })
    expect(r.newWalletToken).not.toBe('')
    expect(w.spent).toBe(true)
    expect(bank.wallet(r.newWalletToken)?.identity.value).toBe(commitment(t2.secret))
  })
  test('consolidate merges same-identity sources into one wallet', async () => {
    const a = bank.mintToPubkey(1000n, alice.pubkey)
    const b = bank.mintToPubkey(2000n, alice.pubkey)
    const r = await client(a.token).cashConsolidate(bySigning(alice), {
      requestId: newRequestId(),
      sources: [
        { walletPubkey: a.walletPubkey, amount: 1000n, credential: bySigning(alice) },
        { walletPubkey: b.walletPubkey, amount: 2000n, credential: bySigning(alice) },
      ],
      to: pubkeyTarget(alice.pubkey),
    })
    expect(r.amountMillis).toBe(3000n)
    expect(bank.wallet(r.newWalletToken)?.amount).toBe(3000n)
    expect([a.spent, b.spent]).toEqual([true, true])
  })
  test('redeem pays and spends; a fee is reported', async () => {
    bank.fee = (a) => a / 100n
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    const r = await client(w.token).cashRedeem({ invoice: invoice(4950n), credential: bySigning(alice) })
    expect(r.feesPaid).toBe(50n)
    expect(bank.redeemed).toHaveLength(1)
  })
  test('an expired wallet answers EXPIRED', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey, { expiresAt: 1 })
    await expect(client(w.token).cashStatus(bySigning(alice))).rejects.toMatchObject({ walletCode: 'EXPIRED' })
  })
  test('loseReplyFor applies the call but answers nothing', async () => {
    const w = bank.mintToPubkey(5000n, alice.pubkey)
    bank.loseReplyFor.add('cash_transfer')
    const err = await client(w.token).cashTransfer({ requestId: newRequestId(), credential: bySigning(alice), to: pubkeyTarget(bob.pubkey), currentAmount: 5000n }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect(w.identity.value).toBe(bob.pubkey)
  })
  test('hub group is stamped on every bill', () => {
    const w = bank.mintToPubkey(1n, alice.pubkey)
    expect(toHex(bank.hubGroup)).toHaveLength(8)
    expect(w.token.startsWith('lokicash1')).toBe(true)
  })
})
