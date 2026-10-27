// Unit tests for targets, credentials, attestations, claim proofs, the cash
// method requests and their results. Ported from nmilat nipcash/{identity,
// proof,proof_binding,claim,cash_redeem,cash_transfer,cash_consolidate}_test.go
// and nipIC/attestation_test.go.
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import {
  bySecret,
  bySigning,
  bySigningConnectionKey,
  cashConsolidateRequest,
  cashRedeemRequest,
  cashTargetFromSecret,
  cashTransferRequest,
  connectionKeyTarget,
  CoreError,
  decryptDelivery,
  finalizeEvent,
  fromHex,
  getPublicKey,
  isSpent,
  KIND_CLAIM_PROOF,
  localSigner,
  matchClaim,
  matchClaimAuto,
  newCashTarget,
  newConnectionKey,
  newIdentityHash,
  nip44,
  parseAttestation,
  parseCashConsolidateResult,
  parseCashRedeemResult,
  parseCashStatusResult,
  parseCashTransferResult,
  pubkeyTarget,
  recipientToken,
  sourcesHash,
  resolvedConnectionKeyTarget,
  toHex,
  verifyEvent,
  type Attestation,
  type NostrEvent,
} from '../src/core/index.js'
import { bech32Encode, toWords } from '../src/core/bech32.js'
import { fill } from './helpers.js'

const claimantKey = fill(2, 32)
const signer = localSigner(claimantKey)
const iaKey = fill(3, 32)
const iaPub = getPublicKey(iaKey)
const WALLET = 'ab'.repeat(32)
const WALLET2 = 'cd'.repeat(32)
const NOW = 1_760_000_000
const RID = '00112233445566778899aabbccddeeff'

function invoiceWithHash(hash: Uint8Array): string {
  const w = [...Array(7).fill(0), 1, 1, 20, ...toWords(hash), ...Array(104).fill(0)]
  return bech32Encode('lnfc10u', Uint8Array.from(w))
}
const INVOICE = invoiceWithHash(fill(0xaa, 32))

function attestation(over: { tags?: readonly (readonly string[])[]; kind?: number } = {}): NostrEvent {
  const tags = over.tags ?? [
    ['d', newConnectionKey('github', '12345')],
    ['p', signer.pubkey],
    ['platform', 'github'],
    ['evidence', '{"version":1,"platform":"github","auth_type":"public_post","user_id":"12345","username":"alice","verified_at":1759999000,"evidence_url":"https://gist.github.com/alice/1","challenge":"npv1x","pre_auth_code":"abcd"}'],
    ['expiration', String(NOW + 86400)],
  ]
  return finalizeEvent({ kind: over.kind ?? 35522, created_at: NOW, tags, content: '' }, iaKey)
}
const ATT: Attestation = parseAttestation(attestation())
const ckCred = bySigningConnectionKey(signer, 'github', '12345', ATT)
const proofOf = (json: string | undefined): NostrEvent => JSON.parse(json!)
const tag = (e: NostrEvent, name: string) => e.tags.find((t) => t[0] === name)?.[1]

const src = (w: string, amount: bigint, cred = bySigning(signer)) => ({ walletPubkey: w, amount, credential: cred })
const row = (identity_type: string, identity_value: string, amount: bigint, claimed = false): Parameters<typeof matchClaim>[0][number] => ({
  identity_type,
  identity_value,
  amount_millis: amount,
  claimed,
})

describe('targets (identity_test.go)', () => {
  test('identity types', () => {
    expect(pubkeyTarget(signer.pubkey).identityType).toBe('pubkey')
    expect(connectionKeyTarget('x', '12345', iaPub)).toEqual({ identityType: 'connection_key', identityValue: newConnectionKey('x', '12345'), iaPubkey: iaPub })
    expect(newCashTarget().identityType).toBe('cash')
  })
  test('a resolved connection key matches the hashed one (TestResolvedConnectionKey_MatchesConnectionKeyWithoutRehashing)', () => {
    expect(resolvedConnectionKeyTarget(newConnectionKey('x', '12345'), 'x', iaPub)).toEqual(connectionKeyTarget('x', '12345', iaPub))
  })
  test('typed input is hashed only for a canonical platform, in its canonical form', () => {
    expect(() => connectionKeyTarget('', '12345', iaPub)).toThrow(CoreError)
    expect(() => connectionKeyTarget('github', '12345', iaPub)).toThrow(/no canonical form/)
    expect(() => connectionKeyTarget('x', '012345', iaPub)).toThrow(/not in canonical form/)
    expect(connectionKeyTarget('dns', 'Example.COM', iaPub).identityValue).toBe(newConnectionKey('dns', 'example.com'))
  })
  test('a cash target commits to sha256 of the secret bytes, and they differ (TestNewCashTarget_*)', () => {
    const t = newCashTarget()
    expect(t.identityValue).not.toBe(t.secret)
    expect(t.identityValue).toBe(toHex(sha256(fromHex(t.secret))))
    expect(cashTargetFromSecret(t.secret)).toEqual(t)
  })
  test('new cash targets are random; an injected source is used', () => {
    expect(newCashTarget().secret).not.toBe(newCashTarget().secret)
    expect(newCashTarget(() => fill(7, 32)).secret).toBe('07'.repeat(32))
  })
  test('cashTargetFromSecret refuses a non-32-byte secret', () => {
    expect(() => cashTargetFromSecret('ab')).toThrow(CoreError)
  })
  test('new_identity_hash is deterministic and sha256(type:value:ia) (TestNewIdentityHash_*)', () => {
    const t = connectionKeyTarget('x', '12345', iaPub)
    expect(newIdentityHash(t)).toBe(newIdentityHash(t))
    expect(newIdentityHash(t)).toBe(toHex(sha256(new TextEncoder().encode(`connection_key:${t.identityValue}:${iaPub}`))))
    const c = newCashTarget()
    expect(newIdentityHash(c)).toBe(toHex(sha256(new TextEncoder().encode(`cash:${c.identityValue}:`))))
  })
})

describe('signer and delivery', () => {
  test('localSigner refuses an invalid key and keeps a copy of the key', () => {
    expect(() => localSigner(new Uint8Array(32))).toThrow(CoreError)
    const key = fill(5, 32)
    const s = localSigner(key)
    key.fill(0)
    expect(s.pubkey).toBe(getPublicKey(fill(5, 32)))
  })
  test('decryptDelivery opens NIP-44 from the new wallet; cash mode passes through', async () => {
    const walletKey = fill(9, 32)
    const ct = nip44.encrypt('lokicash1token', nip44.getConversationKey(walletKey, signer.pubkey))
    expect(await decryptDelivery(bySigning(signer), getPublicKey(walletKey), ct)).toBe('lokicash1token')
    expect(await decryptDelivery(bySecret('s'), getPublicKey(walletKey), 'plain')).toBe('plain')
  })
})

describe('attestation (nipIC attestation_test.go)', () => {
  test('parses a valid attestation', () => {
    expect(ATT).toMatchObject({ connectionKey: newConnectionKey('github', '12345'), userPubkey: signer.pubkey, platform: 'github', expiresAt: NOW + 86400 })
    expect(ATT.evidence).toMatchObject({ userId: '12345', username: 'alice', verifiedAt: 1759999000 })
  })
  test.each<[string, () => NostrEvent]>([
    ['wrong kind', () => attestation({ kind: 1 })],
    ['missing d', () => attestation({ tags: [['p', 'x'], ['platform', 'g'], ['evidence', '{}']] })],
    ['platform-prefixed d', () => attestation({ tags: [['d', 'github:x'], ['p', 'x'], ['platform', 'g'], ['evidence', '{}']] })],
    ['missing evidence', () => attestation({ tags: [['d', 'x'], ['p', 'x'], ['platform', 'g']] })],
    ['evidence not JSON', () => attestation({ tags: [['d', 'x'], ['p', 'x'], ['platform', 'g'], ['evidence', '{']] })],
    ['evidence with a string verified_at', () => attestation({ tags: [['d', 'x'], ['p', 'x'], ['platform', 'g'], ['evidence', '{"verified_at":"1"}']] })],
    ['evidence with a fractional version', () => attestation({ tags: [['d', 'x'], ['p', 'x'], ['platform', 'g'], ['evidence', '{"version":1.0}']] })],
    ['a bad signature', () => ({ ...attestation(), sig: '00'.repeat(64) })],
  ])('refuses %s', (_, make) => {
    expect(() => parseAttestation(make())).toThrow(CoreError)
  })
  const D = newConnectionKey('github', '12345')
  test('evidence keys match case-insensitively and unknown keys are ignored', () => {
    const a = parseAttestation(attestation({ tags: [['d', D], ['p', signer.pubkey], ['platform', 'g'], ['evidence', '{"VERSION":1,"auth_type":"oauth","USER_ID":"u","extra":[1.5]}']] }))
    expect(a.evidence.userId).toBe('u')
  })
  test.each<[string, string[][]]>([
    ['null evidence', [['evidence', 'null']]],
    ['evidence without version 1', [['evidence', '{"auth_type":"oauth"}']]],
    ['evidence without auth_type', [['evidence', '{"version":1}']]],
    ['public_post evidence without its proof fields', [['evidence', '{"version":1,"auth_type":"public_post"}']]],
    ['an unparseable expiration', [['evidence', '{"version":1,"auth_type":"oauth"}'], ['expiration', 'soon']]],
    ['a repeated tag', [['evidence', '{"version":1,"auth_type":"oauth"}'], ['platform', 'x']]],
    ['an uppercase d', [['evidence', '{"version":1,"auth_type":"oauth"}'], ['d', D.toUpperCase()]]],
  ])('refuses %s', (_, extra) => {
    const tags = [['p', signer.pubkey], ['platform', 'g'], ...extra]
    if (!extra.some((t) => t[0] === 'd')) tags.unshift(['d', D])
    expect(() => parseAttestation(attestation({ tags }))).toThrow(CoreError)
  })
})

describe('claim proofs (proof_binding_test.go)', () => {
  test('redeem binds the wallet and the invoice payment hash', async () => {
    const req = await cashRedeemRequest({ walletPubkey: WALLET, invoice: INVOICE, credential: bySigning(signer), now: NOW })
    const proof = proofOf(req.identity_event)
    expect(verifyEvent(proof)).toBe(true)
    expect(proof.kind).toBe(KIND_CLAIM_PROOF)
    expect(proof.created_at).toBe(NOW)
    expect(proof.tags).toEqual([['d', WALLET], ['m', 'cash_redeem'], ['bolt11_hash', 'aa'.repeat(32)]])
    expect(req).toMatchObject({ invoice: INVOICE, identity_type: 'pubkey', identity_value: signer.pubkey })
    expect(req).not.toHaveProperty('cash_secret')
  })
  test('a connection-key proof carries the attestation and its id', async () => {
    const req = await cashRedeemRequest({ walletPubkey: WALLET, invoice: INVOICE, credential: ckCred, now: NOW })
    const proof = proofOf(req.identity_event)
    expect(tag(proof, 'connection_key')).toBe(newConnectionKey('github', '12345'))
    expect(tag(proof, 'e')).toBe(ATT.event.id)
    expect(JSON.parse(req.attestation_event!)).toEqual(ATT.event)
    expect(req.identity_type).toBe('connection_key')
  })
  test('an attestation is mandatory and must not have expired (TestBySigningConnectionKey_MandatoryExpiration)', async () => {
    const noExpiry = parseAttestation(attestation({ tags: ATT.event.tags.filter((t) => t[0] !== 'expiration') }))
    for (const att of [undefined, noExpiry]) {
      await expect(cashRedeemRequest({ walletPubkey: WALLET, invoice: INVOICE, credential: bySigningConnectionKey(signer, 'github', '12345', att), now: NOW })).rejects.toThrow(CoreError)
    }
    await expect(cashRedeemRequest({ walletPubkey: WALLET, invoice: INVOICE, credential: ckCred, now: NOW + 86401 })).rejects.toThrow(/expired/)
    await expect(cashRedeemRequest({ walletPubkey: WALLET, invoice: INVOICE, credential: ckCred, now: NOW + 86400 })).resolves.toBeDefined()
  })
  test('a split binds the new identity and the split amount', async () => {
    const to = newCashTarget()
    const req = await cashTransferRequest({ walletPubkey: WALLET, credential: bySigning(signer), to, currentAmount: 21000n, splitAmount: 5000n, requestId: RID, now: NOW })
    const proof = proofOf(req.identity_event)
    expect(tag(proof, 'new_identity_hash')).toBe(newIdentityHash(to))
    expect(tag(proof, 'amount_millis')).toBe('5000')
    expect(req.amount_millis).toBe(5000n)
    expect(req.new_identity).toEqual({ identity_type: 'cash', identity_value: to.identityValue })
  })
  test('a full transfer binds the current amount and sends no amount_millis (TestCashTransferParams_Request_FullTransfer)', async () => {
    const req = await cashTransferRequest({ walletPubkey: WALLET, credential: bySigning(signer), to: pubkeyTarget(WALLET2), currentAmount: 21000n, requestId: RID, now: NOW })
    expect(tag(proofOf(req.identity_event), 'amount_millis')).toBe('21000')
    expect(req).not.toHaveProperty('amount_millis')
  })
  test('a cash slice presents its secret and no proof (TestCashTransferParams_Request_CashSlicePresentsSecret)', async () => {
    const req = await cashTransferRequest({ walletPubkey: WALLET, credential: bySecret('5e'.repeat(32)), to: pubkeyTarget(WALLET2), currentAmount: 1n, requestId: RID })
    expect(req).toEqual({ cash_secret: '5e'.repeat(32), new_identity: { identity_type: 'pubkey', identity_value: WALLET2 }, request_id: RID })
  })
  test('a connection-key target needs an IA pubkey', async () => {
    await expect(cashTransferRequest({ walletPubkey: WALLET, credential: bySigning(signer), to: connectionKeyTarget('x', '1', ''), currentAmount: 1n, requestId: RID })).rejects.toThrow(/ia_pubkey/)
  })
  test('redeem refuses an invalid invoice (TestCashRedeemParams_Request_InvalidInvoice)', async () => {
    await expect(cashRedeemRequest({ walletPubkey: WALLET, invoice: 'lnfc1nope', credential: bySigning(signer) })).rejects.toThrow(CoreError)
  })
  test('redeem by cash secret and with an amount (TestCashRedeemParams_Request_Cash)', async () => {
    expect(await cashRedeemRequest({ walletPubkey: WALLET, invoice: INVOICE, credential: bySecret('s') })).toEqual({ invoice: INVOICE, cash_secret: 's' })
    await expect(cashRedeemRequest({ walletPubkey: WALLET, invoice: INVOICE, credential: bySecret('s'), amount: 7n })).rejects.toThrow(/amountless/)
  })
})

describe('cash_consolidate (cash_consolidate_test.go)', () => {
  test('happy path: one proof per source, each bound to its own wallet and amount', async () => {
    const to = pubkeyTarget(signer.pubkey)
    const req = await cashConsolidateRequest({ sources: [src(WALLET, 1000n), src(WALLET2, 2000n)], to, requestId: RID, now: NOW })
    expect(req.sources.map((s) => s.wallet_pubkey)).toEqual([WALLET, WALLET2])
    const proofs = req.sources.map((s) => proofOf(s.identity_event))
    expect(proofs.map((p) => tag(p, 'd'))).toEqual([WALLET, WALLET2])
    expect(proofs.map((p) => tag(p, 'amount_millis'))).toEqual(['1000', '2000'])
    expect(proofs.every((p) => tag(p, 'new_identity_hash') === newIdentityHash(to) && verifyEvent(p))).toBe(true)
    expect(proofs.every((p) => tag(p, 'm') === 'cash_consolidate' && tag(p, 's') === sourcesHash([WALLET, WALLET2]))).toBe(true)
    expect(req.request_id).toBe(RID)
  })
  test('cash and connection-key targets are accepted', async () => {
    await expect(cashConsolidateRequest({ sources: [src(WALLET, 1n), src(WALLET2, 1n)], to: newCashTarget(), requestId: RID })).resolves.toBeDefined()
    await expect(cashConsolidateRequest({ sources: [src(WALLET, 1n), src(WALLET2, 1n, ckCred)], to: connectionKeyTarget('x', '1', iaPub), requestId: RID, now: NOW })).resolves.toBeDefined()
  })
  test.each<[string, Parameters<typeof cashConsolidateRequest>[0]]>([
    ['too few sources', { sources: [src(WALLET, 1n)], to: pubkeyTarget(WALLET), requestId: RID }],
    ['a cash-mode source', { sources: [src(WALLET, 1n), src(WALLET2, 1n, bySecret('s'))], to: pubkeyTarget(WALLET), requestId: RID }],
    ['the same source twice', { sources: [src(WALLET, 1n), src(WALLET, 1n)], to: pubkeyTarget(WALLET), requestId: RID }],
    ['a connection-key target without IA', { sources: [src(WALLET, 1n), src(WALLET2, 1n)], to: connectionKeyTarget('x', '1', ''), requestId: RID }],
    ['no request_id', { sources: [src(WALLET, 1n), src(WALLET2, 1n)], to: pubkeyTarget(WALLET), requestId: '' }],
  ])('refuses %s', async (_, p) => {
    await expect(cashConsolidateRequest(p)).rejects.toThrow(CoreError)
  })
})

describe('results', () => {
  const walletKey = fill(9, 32)
  const walletPub = getPublicKey(walletKey)
  const sealTo = (text: string, to: string) => nip44.encrypt(text, nip44.getConversationKey(walletKey, to))

  test('transfer in place: no new token, the recipient keeps the original (RecipientToken)', async () => {
    const r = await parseCashTransferResult({ amount_millis: 21000, identity_type: 'pubkey', identity_value: WALLET2 }, bySigning(signer))
    expect(r.amountMillis).toBe(21000n)
    expect(recipientToken(r, 'lokicash1orig')).toBe('lokicash1orig')
  })
  test('transfer spin-off: the delivered tokens are decrypted', async () => {
    const r = await parseCashTransferResult(
      {
        amount_millis: 5000,
        remaining_amount_millis: 16000,
        new_wallet_pubkey: walletPub,
        new_wallet_token: sealTo('lokicash1new', signer.pubkey),
        remainder_wallet_pubkey: walletPub,
        remainder_wallet_token: sealTo('lokicash1rest', signer.pubkey),
      },
      bySigning(signer),
    )
    expect([r.newWalletToken, r.remainderWalletToken, r.remainingAmountMillis]).toEqual(['lokicash1new', 'lokicash1rest', 16000n])
    expect(recipientToken(r, 'lokicash1orig')).toBe('lokicash1new')
  })
  test('consolidate: decrypted for a pubkey target (self or third party) with the first source', async () => {
    const sources = [{ walletPubkey: WALLET, amount: 1n, credential: bySigning(signer) }]
    const result = { amount_millis: 3000, new_wallet_pubkey: walletPub, new_wallet_token: sealTo('lokicash1merged', signer.pubkey), expires_at: 1800000000 }
    for (const to of [pubkeyTarget(signer.pubkey), pubkeyTarget(WALLET2)]) {
      expect(await parseCashConsolidateResult(result, { sources, to })).toEqual({ amountMillis: 3000n, newWalletPubkey: walletPub, newWalletToken: 'lokicash1merged', expiresAt: 1800000000 })
    }
  })
  test('consolidate: passed through for cash and connection-key targets; undecryptable is an error', async () => {
    const sources = [{ walletPubkey: WALLET, amount: 1n, credential: bySigning(signer) }]
    const plain = { amount_millis: 1, new_wallet_pubkey: walletPub, new_wallet_token: 'lokicash1plain' }
    expect((await parseCashConsolidateResult(plain, { sources, to: newCashTarget() })).newWalletToken).toBe('lokicash1plain')
    expect((await parseCashConsolidateResult(plain, { sources, to: connectionKeyTarget('x', '1', iaPub) })).newWalletToken).toBe('lokicash1plain')
    await expect(parseCashConsolidateResult(plain, { sources, to: pubkeyTarget(WALLET2) })).rejects.toThrow(CoreError)
  })
  test('redeem and status results', () => {
    expect(parseCashRedeemResult({ preimage: 'ff'.repeat(32), fees_paid: 12 })).toEqual({ preimage: 'ff'.repeat(32), feesPaid: 12n })
    const s = parseCashStatusResult({ recipients: [{ identity_type: 'cash', amount_millis: 9007199254740993n, claimed: false, redeem_fee_millis: 0, net_redeemable_millis: 1, min_transfer_millis: 2 }] })
    expect(s.recipients[0]!.amount_millis).toBe(9007199254740993n)
    expect(isSpent(parseCashStatusResult({ status: 'spent', reason: 'redeemed', retained_until: 5 }))).toBe(true)
    expect(parseCashStatusResult({ status: 'spent', retained_until: 5 }).tombstone).toEqual({ status: 'spent', retainedUntil: 5 })
    expect(isSpent(s)).toBe(false)
  })
  test.each<[string, () => unknown]>([
    ['a negative amount', () => parseCashRedeemResult({ preimage: 'ff'.repeat(32), fees_paid: -1 })],
    ['a fractional amount', () => parseCashRedeemResult({ preimage: 'ff'.repeat(32), fees_paid: 1.5 })],
    ['a string amount', () => parseCashRedeemResult({ preimage: 'ff'.repeat(32), fees_paid: '1' })],
    ['a non-object result', () => parseCashStatusResult([])],
    ['non-array recipients', () => parseCashStatusResult({ recipients: {} })],
    ['a non-boolean claimed', () => parseCashStatusResult({ recipients: [{ claimed: 'no' }] })],
  ])('results refuse %s', (_, f) => {
    expect(f).toThrow(CoreError)
  })
})

describe('matchClaim (claim_test.go)', () => {
  test.each<[string, Parameters<typeof matchClaim>[0][number][], boolean, string, bigint | undefined]>([
    ['cash, unclaimed', [row('cash', '', 1000n)], true, '', 1000n],
    ['cash, already claimed', [row('cash', '', 1000n, true)], true, '', undefined],
    ['pubkey, exact match', [row('pubkey', WALLET, 2000n)], false, WALLET, 2000n],
    ['pubkey, already claimed', [row('pubkey', WALLET, 2000n, true)], false, WALLET, undefined],
    ['no local identity never matches a pubkey row', [row('pubkey', '', 2000n)], false, '', undefined],
    ['wrong pubkey', [row('pubkey', WALLET, 2000n)], false, WALLET2, undefined],
    ['no recipients', [], true, '', undefined],
    ['bearer is not cash (TestMatchClaimAuto_BearerIsNotCash)', [row('bearer', '', 1n)], true, '', undefined],
  ])('%s', (_, rows, isCash, as, want) => {
    expect(matchClaim(rows, isCash, as)).toBe(want)
  })
  test('auto: a cash row matches whatever pubkey is supplied, and the full row comes back', () => {
    const rows = [row('pubkey', WALLET2, 1n), row('cash', '', 5n)]
    expect(matchClaimAuto(rows, WALLET)).toBe(rows[1])
  })
  test('auto: a pubkey row matches without a cash hint; no local identity still finds cash', () => {
    expect(matchClaimAuto([row('pubkey', WALLET, 3n)], WALLET)?.amount_millis).toBe(3n)
    expect(matchClaimAuto([row('pubkey', '', 3n), row('cash', '', 4n)], '')?.amount_millis).toBe(4n)
    expect(matchClaimAuto([row('pubkey', WALLET2, 3n)], WALLET)).toBeUndefined()
    expect(matchClaimAuto([row('cash', '', 3n, true)], WALLET)).toBeUndefined()
  })
})
