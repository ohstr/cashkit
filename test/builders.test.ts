// Request builders and result parsers on the final NIP-CASH rules: request
// ids, commitments, claim-proof tags, transfer/consolidate/status/mint
// builders, tombstones, lookups, fees and network/chain. The literals are the
// NIP's own (§Claim Proofs, §Looking Up a Call, §Minting Cash). Cases follow
// nmilat nipcash/{request_id,claim,cash_transfer,cash_consolidate,mint_cash,
// cash_lookup,tombstone,fee}_test.go and nip47/request_test.go.
import { describe, expect, test } from 'vitest'
import { bech32Encode, toWords } from '../src/core/bech32.js'
import {
  bySecret,
  bySigning,
  bySigningConnectionKey,
  cashCommitment,
  cashConsolidateRequest,
  cashLookupParams,
  cashRedeemRequest,
  cashStatusRequest,
  cashTargetFromSecret,
  cashTransferRequest,
  checkAttestationForClaim,
  claimProofTags,
  CoreError,
  decideLookup,
  decodeLookupDone,
  derivedRequestId,
  expectedTransferOutcome,
  finalizeEvent,
  getEventHash,
  getPublicKey,
  isCashSecret,
  isRequestId,
  localSigner,
  mintCashRequest,
  newCashTarget,
  newConnectionKey,
  newIdentityHash,
  newRequestId,
  nwcRequestEvent,
  parseBillResult,
  parseCashLookupResult,
  parseCashRedeemResult,
  parseCashStatusResult,
  parseCashTransferResult,
  parseMintCashResult,
  parseTombstone,
  pubkeyTarget,
  readNetworkChain,
  redeemFeeQuote,
  sourcesHash,
  toHex,
  type ProofBinding,
} from '../src/core/index.js'
import { fill } from './helpers.js'

const RID = '00112233445566778899aabbccddeeff'
const KEY1 = Uint8Array.of(...fill(0, 31), 1)
const PK1 = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const W1 = '1'.repeat(64)
const W2 = '2'.repeat(64)
const signer = localSigner(fill(2, 32))
const NOW = 1_760_000_000

const invoice = (hash: Uint8Array, amount = true) => bech32Encode(amount ? 'lnfc10u' : 'lnfc', Uint8Array.from([...Array(7).fill(0), 1, 1, 20, ...toWords(hash), ...Array(104).fill(0)]))
const tagsOf = (j: string | undefined) => (JSON.parse(j!) as { tags: string[][] }).tags
const idOf = (tags: string[][]) => getEventHash({ pubkey: PK1, created_at: 1720000000, kind: 23198, tags, content: '' })

describe('T-101 request ids (K-RID-1, K-DID-1..2)', () => {
  test('valid and invalid forms', () => {
    expect(isRequestId(RID)).toBe(true)
    expect(isRequestId('ab'.repeat(17))).toBe(true)
    expect(isRequestId('ab'.repeat(32))).toBe(true)
    for (const bad of [RID.slice(1), 'ab'.repeat(33), 'a'.repeat(63), RID.toUpperCase(), 'zz'.repeat(16), '', 'ab'.repeat(15)]) expect(isRequestId(bad)).toBe(false)
  })
  test('newRequestId with injected randomness is 64 lowercase hex', () => {
    expect(newRequestId(() => fill(0xab, 32))).toBe('ab'.repeat(32))
    expect(isRequestId(newRequestId())).toBe(true)
  })
  test('derived ids chain', () => {
    const d1 = derivedRequestId(RID)
    expect(d1).toBe('1f0d61013abef39098ffb0a7c72008a17099c52aca3d5ee8d6ce8de065db5d37')
    expect(derivedRequestId(d1)).toBe('c4c6d6c4893cca6283c95ea32a0b6bef6be796804e62e21e30113b63c676457e')
  })
})

describe('T-102 commitments and secrets (K-CMT-1..3)', () => {
  test('the commitment is over the secret bytes, never the hex text', () => {
    const s = toHex(Uint8Array.from({ length: 32 }, (_, i) => i))
    expect(cashCommitment(s)).toBe('630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd')
    expect(cashCommitment(s)).not.toBe('6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b')
    expect(cashCommitment('00'.repeat(32))).toBe('66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925')
  })
  test('a secret is 64 lowercase hex', () => {
    expect(isCashSecret('ab'.repeat(32))).toBe(true)
    for (const bad of ['a'.repeat(63), 'AB'.repeat(32), 'q83v'.repeat(11), `0x${'a'.repeat(62)}`]) expect(isCashSecret(bad)).toBe(false)
    expect(() => cashCommitment('AB'.repeat(32))).toThrow(CoreError)
  })
})

describe('T-103 claim-proof tags (K-CLAIM-1..3)', () => {
  test('K-CLAIM-1: the NIP redeem proof id', () => {
    const tags = claimProofTags({ method: 'cash_redeem', walletPubkey: W1, bolt11Hash: '4'.repeat(64) })
    expect(tags).toEqual([['d', W1], ['m', 'cash_redeem'], ['bolt11_hash', '4'.repeat(64)]])
    expect(idOf(tags)).toBe('ad995b77237f369c79c5df82729d465eb9b5b4ddafb815995dee99db8d6b07c8')
  })
  test('K-CLAIM-2: the NIP transfer proof id', () => {
    const tags = claimProofTags({ method: 'cash_transfer', walletPubkey: W1, newIdentityHash: newIdentityHash(pubkeyTarget(PK1)), amountMillis: 5000n })
    expect(idOf(tags)).toBe('c466018a22842f8b79c7447cebf3a023add78ff7d053d8b715205343ae4ad8df')
  })
  test('K-CLAIM-3: s for [1×64, 2×64], order-sensitive', () => {
    expect(sourcesHash([W1, W2])).toBe('ca9034371c79ec26ec0496b53420a1117d4f765800dfdce138138b139d591f13')
    expect(sourcesHash([W2, W1])).not.toBe(sourcesHash([W1, W2]))
  })
  test.each<[string, ProofBinding]>([
    ['redeem without bolt11_hash', { method: 'cash_redeem', walletPubkey: W1 }],
    ['redeem with amount_millis', { method: 'cash_redeem', walletPubkey: W1, bolt11Hash: W2, amountMillis: 1n }],
    ['transfer without amount', { method: 'cash_transfer', walletPubkey: W1, newIdentityHash: W2 }],
    ['transfer with s', { method: 'cash_transfer', walletPubkey: W1, newIdentityHash: W2, amountMillis: 1n, sourcesHash: W2 }],
    ['consolidate without s', { method: 'cash_consolidate', walletPubkey: W1, newIdentityHash: W2, amountMillis: 1n }],
    ['q on a transfer', { method: 'cash_transfer', walletPubkey: W1, newIdentityHash: W2, amountMillis: 1n, quoteId: W2 }],
    ['withdraw without q', { method: 'cash_withdraw', walletPubkey: W1 }],
    ['an uppercase d', { method: 'cash_redeem', walletPubkey: W1.toUpperCase().replace(/1/g, 'A'), bolt11Hash: W2 }],
    ['a 63-char hash', { method: 'cash_redeem', walletPubkey: W1, bolt11Hash: '4'.repeat(63) }],
    ['connection_key without e', { method: 'cash_redeem', walletPubkey: W1, bolt11Hash: W2, connectionKey: W2 }],
    ['an unknown method', { method: 'mint_cash' as never, walletPubkey: W1 }],
  ])('refuses %s', (_, b) => {
    expect(() => claimProofTags(b)).toThrow(CoreError)
  })
  test('every proof is kind 23198, signed now, with m; a CK proof adds connection_key and e', async () => {
    const req = await cashRedeemRequest({ walletPubkey: W1, invoice: invoice(fill(0xaa, 32)), credential: bySigning(signer), now: NOW })
    const ev = JSON.parse(req.identity_event!) as { kind: number; created_at: number }
    expect([ev.kind, ev.created_at]).toEqual([23198, NOW])
    const iaKey = fill(3, 32)
    const att = finalizeEvent(
      {
        kind: 35522,
        created_at: NOW,
        tags: [['d', newConnectionKey('github', '1')], ['p', signer.pubkey], ['platform', 'github'], ['evidence', '{}'], ['expiration', String(NOW + 100)]],
        content: '',
      },
      iaKey,
    )
    const { parseAttestation } = await import('../src/core/index.js')
    const ck = bySigningConnectionKey(signer, 'github', '1', parseAttestation(att))
    const r = await cashRedeemRequest({ walletPubkey: W1, invoice: invoice(fill(0xaa, 32)), credential: ck, now: NOW })
    expect(tagsOf(r.identity_event).map((t) => t[0])).toEqual(['d', 'm', 'bolt11_hash', 'connection_key', 'e'])
  })
})

describe('T-104 new_identity_hash (K-CLAIM-4)', () => {
  test('type:value:ia with the trailing colon', () => {
    expect(newIdentityHash(pubkeyTarget(PK1))).toBe('90aad9efdfc1980322c6248a266df6bca9d766bb360654f5e2bfecccc941bed0')
    expect(newIdentityHash(pubkeyTarget(PK1))).not.toBe('7d09e57d9def2934d5cbedff5bad3a5c871ea3bf55a674df919e5eb92fc83df4')
  })
})

describe('T-105 checkAttestationForClaim', () => {
  const iaKey = fill(3, 32)
  const ia = getPublicKey(iaKey)
  const ck = newConnectionKey('github', '1')
  const att = (tags: string[][], key = iaKey, kind = 35522) => finalizeEvent({ kind, created_at: NOW, tags, content: '' }, key)
  const good = [['d', ck], ['p', signer.pubkey], ['platform', 'github'], ['evidence', '{}'], ['expiration', String(NOW + 10)]]
  const ctx = { identityValue: ck, iaPubkey: ia, signer: signer.pubkey, now: NOW }
  test('a valid attestation passes', () => {
    expect(checkAttestationForClaim(att(good), ctx).connectionKey).toBe(ck)
  })
  test.each<[string, () => unknown]>([
    ['another kind', () => checkAttestationForClaim(att(good, iaKey, 1), ctx)],
    ['a bad signature', () => checkAttestationForClaim({ ...att(good), sig: '00'.repeat(64) }, ctx)],
    ['another author', () => checkAttestationForClaim(att(good, fill(4, 32)), ctx)],
    ['another d', () => checkAttestationForClaim(att(good.map((t) => (t[0] === 'd' ? ['d', W1] : t))), ctx)],
    ['another p', () => checkAttestationForClaim(att(good.map((t) => (t[0] === 'p' ? ['p', W1] : t))), ctx)],
    ['no platform', () => checkAttestationForClaim(att(good.filter((t) => t[0] !== 'platform')), ctx)],
    ['no evidence', () => checkAttestationForClaim(att(good.filter((t) => t[0] !== 'evidence')), ctx)],
    ['no expiration', () => checkAttestationForClaim(att(good.filter((t) => t[0] !== 'expiration')), ctx)],
    ['a passed expiration', () => checkAttestationForClaim(att(good), { ...ctx, now: NOW + 11 })],
  ])('refuses %s', (_, f) => {
    expect(f).toThrow(CoreError)
  })
})

describe('T-106 / T-107 mint_cash', () => {
  const cash = newCashTarget(() => fill(7, 32))
  test('a request always carries request_id; expiry 0 or absent sends none', () => {
    const r = mintCashRequest({ recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 21000n }], requestId: RID })
    expect(r).toEqual({ recipients: [{ identity_type: 'pubkey', identity_value: W1, amount_millis: 21000n }], request_id: RID })
    expect(mintCashRequest({ recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 1n }], expirySeconds: 0, requestId: RID })).not.toHaveProperty('expiry')
    expect(mintCashRequest({ recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 1n }], expirySeconds: 86400, requestId: RID }).expiry).toBe(86400)
    expect(Object.keys(r)).not.toContain('idempotency_key')
    expect(Object.keys(r)).not.toContain('min_transfer_millis')
  })
  test('100 recipients pass', () => {
    const recipients = Array.from({ length: 100 }, (_, i) => ({ identityType: 'pubkey' as const, identityValue: toHex(Uint8Array.of(...fill(0, 31), i)), amountMillis: 1n }))
    expect(mintCashRequest({ recipients, requestId: RID }).recipients).toHaveLength(100)
  })
  test.each<[string, Parameters<typeof mintCashRequest>[0]]>([
    ['no recipient', { recipients: [], requestId: RID }],
    ['no request_id', { recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 1n }], requestId: '' }],
    ['amount 0', { recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 0n }], requestId: RID }],
    ['a negative amount', { recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: -1n }], requestId: RID }],
    ['a uint64 overflow', { recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 9223372036854775808n }, { identityType: 'pubkey', identityValue: W2, amountMillis: 9223372036854775808n }], requestId: RID }],
    ['a bearer type', { recipients: [{ identityType: 'bearer' as never, identityValue: W1, amountMillis: 1n }], requestId: RID }],
    ['an npub', { recipients: [{ identityType: 'pubkey', identityValue: 'npub1xyz', amountMillis: 1n }], requestId: RID }],
    ['a CK without IA', { recipients: [{ identityType: 'connection_key', identityValue: W1, amountMillis: 1n }], requestId: RID }],
    ['cash mixed', { recipients: [{ identityType: 'cash', identityValue: cash.identityValue, amountMillis: 1n }, { identityType: 'pubkey', identityValue: W1, amountMillis: 1n }], requestId: RID }],
    ['cash with ia', { recipients: [{ identityType: 'cash', identityValue: cash.identityValue, iaPubkey: W1, amountMillis: 1n }], requestId: RID }],
    ['cash with a secret', { recipients: [{ identityType: 'cash', identityValue: cash.identityValue, amountMillis: 1n, cashSecret: cash.secret } as never], requestId: RID }],
    ['a 63-char commitment', { recipients: [{ identityType: 'cash', identityValue: 'a'.repeat(63), amountMillis: 1n }], requestId: RID }],
    ['an uppercase commitment', { recipients: [{ identityType: 'cash', identityValue: 'A'.repeat(64), amountMillis: 1n }], requestId: RID }],
    ['a 0x commitment', { recipients: [{ identityType: 'cash', identityValue: `0x${'a'.repeat(62)}`, amountMillis: 1n }], requestId: RID }],
    ['a duplicate', { recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 1n }, { identityType: 'pubkey', identityValue: W1, amountMillis: 2n }], requestId: RID }],
    ['a fractional expiry', { recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 1n }], expirySeconds: 1.5, requestId: RID }],
    ['a negative expiry', { recipients: [{ identityType: 'pubkey', identityValue: W1, amountMillis: 1n }], expirySeconds: -1, requestId: RID }],
  ])('refuses %s', (_, p) => {
    expect(() => mintCashRequest(p)).toThrow(CoreError)
  })
  const sent = mintCashRequest({ recipients: [{ identityType: 'cash', identityValue: cash.identityValue, amountMillis: 3000n }], requestId: RID })
  const result = { wallet_pubkey: W1, cash_token: 'satscash1xyz', expires_at: 1720000000, recipients: [{ identity_type: 'cash', identity_value: cash.identityValue, amount_millis: 3000 }] }
  test('the token alone is the credential; a pairing_uri is ignored', () => {
    const a = parseMintCashResult(result, sent)
    const b = parseMintCashResult({ ...result, pairing_uri: 'nostr+walletconnect://x' }, sent)
    expect(a).toEqual(b)
    expect(a.cashToken).toBe('satscash1xyz')
    expect(parseMintCashResult({ ...result, expires_at: 0 }, sent).expiresAt).toBeUndefined()
    expect(parseMintCashResult({ ...result, expires_at: null }, sent).expiresAt).toBeUndefined()
  })
  test.each<[string, unknown]>([
    ['an empty token', { ...result, cash_token: '' }],
    ['a changed echo', { ...result, recipients: [{ ...result.recipients[0], amount_millis: 3001 }] }],
    ['a cash_secret on a recipient', { ...result, recipients: [{ ...result.recipients[0], cash_secret: cash.secret }] }],
    ['a negative expiry', { ...result, expires_at: -1 }],
  ])('refuses a result with %s', (_, r) => {
    expect(() => parseMintCashResult(r, sent)).toThrow(CoreError)
  })
})

describe('T-108 redeem builder', () => {
  const hash = fill(0xaa, 32)
  test('bolt11_hash is the invoice payment hash; amount only with an amountless invoice', async () => {
    const r = await cashRedeemRequest({ walletPubkey: W1, invoice: invoice(hash), credential: bySigning(signer), now: NOW })
    expect(tagsOf(r.identity_event).find((t) => t[0] === 'bolt11_hash')![1]).toBe(toHex(hash))
    expect(typeof r.identity_event).toBe('string')
    await expect(cashRedeemRequest({ walletPubkey: W1, invoice: invoice(hash), credential: bySigning(signer), amount: 1n })).rejects.toThrow(/amountless/)
    const amountless = await cashRedeemRequest({ walletPubkey: W1, invoice: invoice(hash, false), credential: bySecret('ab'.repeat(32)), amount: 5000n })
    expect(amountless).toEqual({ invoice: invoice(hash, false), amount: 5000n, cash_secret: 'ab'.repeat(32) })
    await expect(cashRedeemRequest({ walletPubkey: W1, invoice: invoice(hash, false), credential: bySigning(signer), amount: 0n })).rejects.toThrow(CoreError)
  })
})

describe('T-109 / T-1401 transfer builder and outcome', () => {
  const src = cashTargetFromSecret('5e'.repeat(32))
  const rc = newCashTarget(() => fill(9, 32)).identityValue
  test('a split of a cash source needs a fresh remainder_commitment', async () => {
    const base = { walletPubkey: W1, credential: bySecret(src.secret), to: pubkeyTarget(W2), currentAmount: 20000n, splitAmount: 5000n, requestId: RID }
    await expect(cashTransferRequest(base)).rejects.toThrow(/remainder_commitment/)
    await expect(cashTransferRequest({ ...base, remainderCommitment: src.identityValue })).rejects.toThrow(/fresh/)
    await expect(cashTransferRequest({ ...base, remainderCommitment: 'A'.repeat(64) })).rejects.toThrow(CoreError)
    expect((await cashTransferRequest({ ...base, remainderCommitment: rc })).remainder_commitment).toBe(rc)
  })
  test('remainder_commitment is refused on a full transfer and on a non-cash source', async () => {
    await expect(cashTransferRequest({ walletPubkey: W1, credential: bySecret(src.secret), to: pubkeyTarget(W2), currentAmount: 20000n, remainderCommitment: rc, requestId: RID })).rejects.toThrow(CoreError)
    await expect(cashTransferRequest({ walletPubkey: W1, credential: bySigning(signer), to: pubkeyTarget(W2), currentAmount: 20000n, splitAmount: 1n, remainderCommitment: rc, requestId: RID })).rejects.toThrow(CoreError)
  })
  test('zap_target rules', async () => {
    const base = { walletPubkey: W1, credential: bySigning(signer), to: pubkeyTarget(W2), currentAmount: 20000n, requestId: RID }
    expect((await cashTransferRequest({ ...base, zapTarget: 'note1' })).zap_target).toBe('note1')
    await expect(cashTransferRequest({ ...base, zapTarget: '' })).rejects.toThrow(/empty/)
    await expect(cashTransferRequest({ ...base, credential: bySecret(src.secret), zapTarget: 'x' })).rejects.toThrow(/pubkey-bound/)
    await expect(cashTransferRequest({ ...base, to: newCashTarget(), zapTarget: 'x' })).rejects.toThrow(/goes to a pubkey/)
  })
  test('amount 0, over the current amount and a missing id are refused; request_id is sent', async () => {
    const base = { walletPubkey: W1, credential: bySigning(signer), to: pubkeyTarget(W2), currentAmount: 20000n, requestId: RID }
    await expect(cashTransferRequest({ ...base, splitAmount: 0n })).rejects.toThrow(CoreError)
    await expect(cashTransferRequest({ ...base, splitAmount: 20001n })).rejects.toThrow(CoreError)
    await expect(cashTransferRequest({ ...base, requestId: RID.toUpperCase() })).rejects.toThrow(/request_id/)
    expect((await cashTransferRequest(base)).request_id).toBe(RID)
  })
  test.each<[string, Parameters<typeof expectedTransferOutcome>, string]>([
    ['zap full', [{ currentAmount: 10n }, { to: pubkeyTarget(W2), zapTarget: 'x' }], 'spin_off_1'],
    ['zap partial', [{ currentAmount: 10n }, { to: pubkeyTarget(W2), zapTarget: 'x', splitAmount: 3n }], 'spin_off_2'],
    ['split', [{ currentAmount: 10n }, { to: newCashTarget(), splitAmount: 3n }], 'spin_off_2'],
    ['split amount equal to the current', [{ currentAmount: 10n }, { to: pubkeyTarget(W2), splitAmount: 10n }], 'in_place_or_spin_off_1'],
    ['full to a pubkey', [{ currentAmount: 10n }, { to: pubkeyTarget(W2) }], 'in_place_or_spin_off_1'],
    ['full to a connection key', [{ currentAmount: 10n }, { to: { identityType: 'connection_key' } }], 'in_place_or_spin_off_1'],
    ['full to cash, one-recipient history', [{ currentAmount: 10n, singleRecipientHistory: true }, { to: newCashTarget() }], 'in_place'],
    ['full to cash, history unknown', [{ currentAmount: 10n }, { to: newCashTarget() }], 'in_place_or_spin_off_1'],
  ])('%s ⇒ %s', (_, args, want) => {
    expect(expectedTransferOutcome(...args)).toBe(want)
  })
})

describe('T-110 transfer results', () => {
  test('a zap result carries issued_at and expires_at 0; other results carry neither', async () => {
    const z = await parseCashTransferResult({ amount_millis: 5, identity_type: 'pubkey', identity_value: W2, issued_at: 1720000000, expires_at: 0 }, bySecret('ab'.repeat(32)))
    expect([z.issuedAt, z.zapExpiresAt]).toEqual([1720000000, 0])
    const plain = await parseCashTransferResult({ amount_millis: 5, identity_type: 'pubkey', identity_value: W2 }, bySecret('ab'.repeat(32)))
    expect(plain).not.toHaveProperty('issuedAt')
  })
})

const src = (w: string) => ({ walletPubkey: w, amount: 1n, credential: bySigning(signer) })

describe('T-111 consolidate builder', () => {
  test('each source proof carries m, s and its own amount; request_id is sent', async () => {
    const r = await cashConsolidateRequest({ sources: [src(W1), src(W2)], to: pubkeyTarget(signer.pubkey), requestId: RID, now: NOW })
    for (const s of r.sources) expect(tagsOf(s.identity_event).map((t) => t[0])).toEqual(['d', 'm', 'new_identity_hash', 'amount_millis', 's'])
    expect(r.request_id).toBe(RID)
  })
  test.each<[string, object]>([
    ['a cash source', { sources: [src(W1), { walletPubkey: W2, amount: 1n, credential: bySecret('ab'.repeat(32)) }] }],
    ['one source', { sources: [src(W1)] }],
    ['a raw secret as cash identity', { to: { identityType: 'cash', identityValue: 'not hex', iaPubkey: '' } }],
    ['an unknown identity type', { to: { identityType: 'bearer', identityValue: W1, iaPubkey: '' } }],
    ['a connection key without IA', { to: { identityType: 'connection_key', identityValue: W1, iaPubkey: '' } }],
  ])('refuses %s', async (_, over) => {
    await expect(cashConsolidateRequest({ sources: [src(W1), src(W2)], to: pubkeyTarget(signer.pubkey), requestId: RID, ...over } as never)).rejects.toThrow(CoreError)
  })
})

describe('T-113 / T-119 cash_status', () => {
  test('the params carry a scope at most, never a secret', () => {
    expect(cashStatusRequest()).toEqual({})
    expect(cashStatusRequest({ scope: 'all' })).toEqual({ scope: 'all' })
    expect(() => cashStatusRequest({ cashSecret: 'ab'.repeat(32) } as never)).toThrow(/never carries a cash secret/)
    expect(() => cashStatusRequest({ scope: 'everyone' as never })).toThrow(CoreError)
  })
  test('row fields: ia_pubkey, claimed_at, withdraw_request_id; expires_at 0 or null is never', () => {
    const r = parseCashStatusResult({
      recipients: [
        { identity_type: 'connection_key', identity_value: W1, ia_pubkey: W2, amount_millis: 5, claimed: true, claimed_at: 3, redeem_fee_millis: 0, net_redeemable_millis: 5, min_transfer_millis: 0, expires_at: 0, withdraw_request_id: RID },
        { identity_type: 'pubkey', identity_value: W1, amount_millis: 5, claimed: false, redeem_fee_millis: 0, net_redeemable_millis: 5, min_transfer_millis: 0, expires_at: null },
      ],
    })
    expect(r.recipients[0]).toMatchObject({ ia_pubkey: W2, claimed_at: 3, withdraw_request_id: RID })
    expect(r.recipients[0]).not.toHaveProperty('expires_at')
    expect(r.recipients[1]).not.toHaveProperty('expires_at')
  })
})

describe('T-114 tombstones', () => {
  test.each(['redeemed', 'transferred', 'consolidated', 'expired', 'reclaimed'])('reason %s', (reason) => {
    expect(parseTombstone({ status: 'spent', reason, retained_until: 9 })).toEqual({ status: 'spent', reason, retainedUntil: 9 })
  })
  test.each<[string, object]>([
    ['no reason key (written-off)', { status: 'spent' }],
    ['an empty reason', { status: 'spent', reason: '' }],
    ['written-off', { status: 'spent', reason: 'written-off' }],
    ['an unknown reason', { status: 'spent', reason: 'burnt' }],
  ])('%s reads as spent with no reason', (_, v) => {
    expect(parseTombstone(v)).toEqual({ status: 'spent' })
  })
  test('the answer for every bill method; a roster is not a tombstone', async () => {
    const t = { status: 'spent', reason: 'transferred' }
    expect(await parseBillResult(t, parseCashRedeemResult)).toEqual({ kind: 'tombstone', tombstone: { status: 'spent', reason: 'transferred' } })
    expect((await parseBillResult({ preimage: 'ab'.repeat(32), fees_paid: 0 }, parseCashRedeemResult)).kind).toBe('result')
    expect(parseCashStatusResult(t).tombstone?.reason).toBe('transferred')
    expect(parseTombstone({ recipients: [] })).toBeUndefined()
    expect(parseTombstone({ status: 'done' })).toBeUndefined()
  })
  test('withdraw_request_id is read on a tombstone', () => {
    expect(parseTombstone({ status: 'spent', reason: 'redeemed', withdraw_request_id: RID })?.withdrawRequestId).toBe(RID)
    expect(parseTombstone({ status: 'spent', withdraw_request_id: 'xyz' })).not.toHaveProperty('withdrawRequestId')
  })
})

describe('T-115 lookups (K-DL-1, K-LK-1..7, K-JLK-1)', () => {
  test('params: by id or by connection_pubkey, exactly one; bearer with or without secret', () => {
    expect(cashLookupParams({ requestId: RID }, 1720000060)).toEqual({ request_id: RID, deadline: 1720000060 })
    expect(cashLookupParams({ connectionPubkey: W1 }, 5)).toEqual({ connection_pubkey: W1, deadline: 5 })
    expect(cashLookupParams({ requestId: RID }, 5, 'ab'.repeat(32)).cash_secret).toBe('ab'.repeat(32))
    expect(() => cashLookupParams({ requestId: RID, connectionPubkey: W1 } as never, 5)).toThrow(CoreError)
    expect(() => cashLookupParams({} as never, 5)).toThrow(CoreError)
    expect(() => cashLookupParams({ requestId: RID }, 1.5)).toThrow(CoreError)
  })
  test('statuses', () => {
    expect(parseCashLookupResult({ status: 'done', result: { amount_millis: 1 } })).toEqual({ status: 'done', result: { amount_millis: 1 } })
    expect(parseCashLookupResult({ status: 'pending', retry_after: 7 })).toEqual({ status: 'pending', retryAfter: 7 })
    expect(parseCashLookupResult({ status: 'pending', retry_after: 7n })).toEqual({ status: 'pending', retryAfter: 7 })
    expect(parseCashLookupResult({ status: 'unknown' })).toEqual({ status: 'unknown' })
    expect(parseCashLookupResult({ status: 'expired' })).toEqual({ status: 'expired' })
    for (const bad of [{ status: 'done' }, { status: 'pending' }, { status: 'gone' }, []]) expect(() => parseCashLookupResult(bad)).toThrow(CoreError)
  })
  test('done: a destroyed bill appears as its tombstone in a token field; no pairing_uri is read', () => {
    const d = decodeLookupDone({ amount_millis: 5, new_wallet_pubkey: W1, new_wallet_token: { status: 'spent', reason: 'redeemed' }, remainder_wallet_token: 'enc', pairing_uri: 'x' })
    expect(d.tombstones).toEqual({ new_wallet_token: { status: 'spent', reason: 'redeemed' } })
    expect(d.result['new_wallet_token']).toBe('')
    expect(d.result['remainder_wallet_token']).toBe('enc')
    expect(decodeLookupDone({ cash_token: { status: 'spent' } }).tombstones.cash_token).toEqual({ status: 'spent' })
    expect(() => decodeLookupDone({ cash_token: { status: 'other' } })).toThrow(CoreError)
  })
  const D = 1720000000
  test.each<[string, Parameters<typeof decideLookup>[0], unknown]>([
    ['at D: pending, retry D+1', { now: D, deadline: D, horizon: 300, hasRecord: false }, { status: 'pending', retryAfter: D + 1 }],
    ['D+1: unknown', { now: D + 1, deadline: D, horizon: 300, hasRecord: false }, 'unknown'],
    ['D+300: unknown', { now: D + 300, deadline: D, horizon: 300, hasRecord: false }, 'unknown'],
    ['D+301: expired', { now: D + 301, deadline: D, horizon: 300, hasRecord: false }, 'expired'],
    ['a record: done', { now: D + 9999, deadline: D, horizon: 300, hasRecord: true }, 'done'],
    ['deadline now+10000 is clamped: retry now+301', { now: D, deadline: D + 10000, horizon: 300, hasRecord: false }, { status: 'pending', retryAfter: D + 301 }],
    ['H 600 at D+450: unknown', { now: D + 450, deadline: D, horizon: 600, hasRecord: false }, 'unknown'],
    ['join: pending at 1720000300', { now: D + 300, deadline: D + 300, horizon: 360, hasRecord: false }, { status: 'pending', retryAfter: D + 301 }],
    ['join: unknown at 1720000301', { now: D + 301, deadline: D + 300, horizon: 360, hasRecord: false }, 'unknown'],
    ['join: unknown at 1720000660', { now: D + 660, deadline: D + 300, horizon: 360, hasRecord: false }, 'unknown'],
    ['join: expired at 1720000661', { now: D + 661, deadline: D + 300, horizon: 360, hasRecord: false }, 'expired'],
    ['join: deadline now+1000 → retry now+361', { now: D, deadline: D + 1000, horizon: 360, hasRecord: false }, { status: 'pending', retryAfter: D + 361 }],
  ])('%s', (_, p, want) => {
    expect(decideLookup(p)).toEqual(want)
  })
})

describe('T-116 NWC request with expiration', () => {
  test('the expiration tag rides beside p and encryption', () => {
    const e = nwcRequestEvent({ connectionSecret: KEY1, walletPubkey: PK1, method: 'mint_cash', params: {}, createdAt: 1720000000, expiration: 1720000060 })
    expect(e.tags).toEqual([['p', PK1], ['encryption', 'nip44_v2'], ['expiration', '1720000060']])
    expect(nwcRequestEvent({ connectionSecret: KEY1, walletPubkey: PK1, method: 'get_info', createdAt: 1 }).tags).toHaveLength(2)
    expect(() => nwcRequestEvent({ connectionSecret: KEY1, walletPubkey: PK1, method: 'x', createdAt: 1, expiration: -1 })).toThrow(CoreError)
  })
})

describe('T-117 fee quote (K-FEE-1..6)', () => {
  test.each<[bigint, bigint, bigint, bigint, bigint]>([
    [5000n, 100n, 10000n, 150n, 4850n],
    [1000n, 0n, 3333n, 3n, 997n],
    [1000n, 0n, 1000000n, 1000n, 0n],
    [100n, 100n, 0n, 100n, 0n],
    [99n, 100n, 0n, 99n, 0n],
    [21000n, 0n, 10000n, 210n, 20790n],
  ])('(%s, %s, %s) ⇒ fee %s, net %s', (amount, base, ppm, fee, net) => {
    expect(redeemFeeQuote(amount, base, ppm)).toBe(fee)
    expect(amount - redeemFeeQuote(amount, base, ppm)).toBe(net)
  })
  test('ppm above 1,000,000 is refused', () => {
    expect(() => redeemFeeQuote(1000n, 0n, 1000001n)).toThrow(CoreError)
  })
})

describe('T-1402 redeem result', () => {
  test('preimage is 64 lowercase hex and fees_paid an unsigned integer', () => {
    expect(parseCashRedeemResult({ preimage: 'ab'.repeat(32), fees_paid: 0 })).toEqual({ preimage: 'ab'.repeat(32), feesPaid: 0n })
    for (const bad of [{ preimage: 'AB'.repeat(32), fees_paid: 0 }, { preimage: 'a'.repeat(63), fees_paid: 0 }, { fees_paid: 0 }, { preimage: 'ab'.repeat(32) }, { preimage: 'ab'.repeat(32), fees_paid: -1 }, { preimage: 'ab'.repeat(32), fees_paid: 0.5 }]) {
      expect(() => parseCashRedeemResult(bad)).toThrow(CoreError)
    }
  })
})

describe('T-120 withdraw fields', () => {
  test('q only on cash_withdraw, and required there', () => {
    expect(claimProofTags({ method: 'cash_withdraw', walletPubkey: W1, quoteId: W2 })).toEqual([['d', W1], ['m', 'cash_withdraw'], ['q', W2]])
    expect(() => claimProofTags({ method: 'cash_redeem', walletPubkey: W1, bolt11Hash: W2, quoteId: W2 })).toThrow(CoreError)
  })
  test('the withdraw status object is parsed; an invalid one is dropped, never thrown', () => {
    const terms = { withdraw_fee_base: 2000, withdraw_fee_ppm: 500000, min_millis: 1000, script_types: [[0, 20], [0, 32], [1, 32]], final_depth: 3 }
    const ok = parseCashStatusResult({ recipients: [], withdraw: terms })
    expect(ok.withdraw).toEqual({ withdrawFeeBase: 2000n, withdrawFeePpm: 500000n, minMillis: 1000n, scriptTypes: [[0, 20], [0, 32], [1, 32]], finalDepth: 3 })
    for (const bad of [{ ...terms, withdraw_fee_ppm: 1000001 }, { ...terms, script_types: [] }, { ...terms, final_depth: 0 }, { ...terms, min_millis: 5, max_millis: 4 }, 'x']) {
      expect(parseCashStatusResult({ recipients: [], withdraw: bad }).withdraw).toBeUndefined()
    }
  })
})

describe('T-1207 network and chain', () => {
  test.each(['mainnet', 'testnet', 'signet', 'regtest'])('%s', (network) => {
    const r = readNetworkChain({ network, chain: 'bitcoin' })
    expect(r).toMatchObject({ network, chain: 'bitcoin', networkUnknown: false, testNetwork: network !== 'mainnet' })
  })
  test('absent, unknown and non-string are kept and flagged, never thrown', () => {
    expect(readNetworkChain({})).toEqual({ networkUnknown: false, testNetwork: false })
    expect(readNetworkChain({ network: 'main' })).toEqual({ networkRaw: 'main', networkUnknown: true, testNetwork: false })
    expect(readNetworkChain({ network: 1 })).toMatchObject({ networkRaw: 1, networkUnknown: true })
    expect(readNetworkChain(null)).toEqual({ networkUnknown: false, testNetwork: false })
  })
})
