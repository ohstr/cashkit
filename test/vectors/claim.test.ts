// claim.json: claim proofs (kind 23198), NIP-IC attestations, cash targets,
// the cash_redeem / cash_transfer / cash_consolidate requests and results,
// tombstones, and the caller's own row. The verifyClaimProof refusals,
// tombstoneReason and ordered are Hub-side or wallet-storage rules with no
// pure cashkit counterpart; verifyClaimProof's accepted proofs are checked
// against cashkit's claim-proof builder.
import { describe, expect, test } from 'vitest'
import {
  bySecret,
  bySigning,
  bySigningConnectionKey,
  cashConsolidateRequest,
  cashRedeemRequest,
  cashTargetFromSecret,
  cashTransferRequest,
  claimProofTags,
  connectionKeyTarget,
  decodeLookupDone,
  fromHex,
  getEventHash,
  localSigner,
  matchClaim,
  newConnectionKey,
  newIdentityHash,
  parseAttestation,
  parseCashConsolidateResult,
  parseCashRedeemResult,
  parseCashTransferResult,
  parseTombstone,
  pubkeyTarget,
  resolvedConnectionKeyTarget,
  sourcesHash,
  verifyEvent,
  type ClaimMethod,
  type Credential,
  type ProofBinding,
  type Target,
  type Tombstone,
} from '../../src/core/index.js'
import { parseJSONValue } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('claim.json')
const RID = '00112233445566778899aabbccddeeff'
const NOW = 1760000000
// The claimant: 4d4b6cd1… is the pubkey of 0x02 repeated.
const signer = localSigner(fromHex('02'.repeat(32)))
const attestation = parseAttestation(v.attestation[0].event)
const IA = attestation.event.pubkey

const MISMATCH = new Set([
  // attestation
  'unparseable expiration is ignored', // nmilat refuses expiration "soon"; cashkit ignores it
  'a repeated tag: the last one wins', // nmilat refuses a repeated platform tag; cashkit takes the last
  'evidence null', // nmilat refuses evidence without version 1; cashkit accepts null evidence
  'evidence with unknown fields', // nmilat refuses evidence without version 1; cashkit accepts it
  // requests
  'redeem with an amount', // nmilat sends amount with an invoice that has one (10u); cashkit refuses amount unless the invoice is amountless
  'transfer to pubkey uppercase', // nmilat sends the uppercase pubkey as given; cashkit refuses a pubkey identity that is not lowercase hex
  'transfer to connection_key typed github', // nmilat refuses github (no canonical form); cashkit hashes "github:12345" and builds the request
  // results
  'a Hub returned a secret', // nmilat refuses a reply with a `secret` field; cashkit ignores the field
  // ownRow (cashkit: matchClaim)
  "connection_key, the credential's IA", // nmilat finds the connection_key row of the credential's IA; matchClaim matches only pubkey and cash rows
  'cash, uppercase commitment', // nmilat refuses a scope-mine row that is not the caller's commitment; matchClaim takes any unclaimed cash row
  'widened mine: two rows', // nmilat refuses a scope-mine answer of more than one row; matchClaim takes the caller's row
  // claimable (cashkit: matchClaim)
  'ended by a cash_withdraw', // nmilat: a row with withdraw_request_id is not claimable; matchClaim reads only `claimed`
  'expired one second later', // nmilat: a row past expires_at is not claimable; matchClaim reads only `claimed`
])

const credentials: Record<string, Credential> = {
  secret: bySecret('5e'.repeat(32)),
  signing: bySigning(signer),
  connection_key: bySigningConnectionKey(signer, 'github', '12345', attestation),
  connection_key_no_att: bySigningConnectionKey(signer, 'github', '12345', undefined),
  connection_key_expired: bySigningConnectionKey(signer, 'github', '12345', { ...attestation, expiresAt: 0 }),
}
const targets: Record<string, () => Target> = {
  pubkey: () => pubkeyTarget(signer.pubkey),
  'pubkey uppercase': () => pubkeyTarget(signer.pubkey.toUpperCase()),
  connection_key: () => resolvedConnectionKeyTarget(attestation.connectionKey, 'github', IA),
  'connection_key no ia': () => resolvedConnectionKeyTarget(attestation.connectionKey, 'github', ''),
  'connection_key no platform': () => connectionKeyTarget('', '12345', IA),
  'connection_key typed github': () => connectionKeyTarget('github', '12345', IA),
  'connection_key typed x': () => connectionKeyTarget('x', '12345', IA),
  cash: () => cashTargetFromSecret(v.cashTarget[0].secret),
}

/** A request as the vector writes it: numbers for bigints, identity_event as {kind, pubkey, tags, content, valid}. */
function flatten(x: Json): Json {
  if (typeof x === 'bigint') return Number(x)
  if (Array.isArray(x)) return x.map(flatten)
  if (x === null || typeof x !== 'object') return x
  const out: Json = {}
  for (const [k, val] of Object.entries(x)) {
    if (k === 'identity_event') {
      const e = JSON.parse(val as string)
      out[k] = { content: e.content, kind: e.kind, pubkey: e.pubkey, tags: e.tags, valid: verifyEvent(e) }
    } else if (k === 'attestation_event') out[k] = JSON.parse(val as string)
    else out[k] = flatten(val)
  }
  return out
}
const parsedAttestations = (x: Json): Json =>
  Array.isArray(x) ? x.map(parsedAttestations) : x !== null && typeof x === 'object' ? Object.fromEntries(Object.entries(x).map(([k, y]) => [k, k === 'attestation_event' ? JSON.parse(y as string) : parsedAttestations(y)])) : x

async function request(c: Json): Promise<unknown> {
  const i = c.inputs
  switch (c.method) {
    case 'cash_redeem':
      return cashRedeemRequest({ walletPubkey: i.wallet, invoice: i.invoice, credential: credentials[i.credential]!, ...(i.amount !== undefined && { amount: BigInt(i.amount) }), now: NOW })
    case 'cash_transfer':
      return cashTransferRequest({
        walletPubkey: i.wallet,
        credential: credentials[i.credential]!,
        to: targets[i.to]!(),
        currentAmount: BigInt(i.currentAmount),
        ...(i.splitAmount !== undefined && { splitAmount: BigInt(i.splitAmount) }),
        requestId: RID,
        now: NOW,
      })
    default:
      return cashConsolidateRequest({ to: targets[i.to]!(), requestId: RID, sources: i.sources.map((s: Json) => ({ walletPubkey: s.wallet, amount: BigInt(s.amount), credential: credentials[s.credential]! })), now: NOW })
  }
}

/** A tombstone in wire form. */
const wire = (t: Tombstone | undefined): Json =>
  t === undefined
    ? null
    : { status: t.status, ...(t.reason !== undefined && { reason: t.reason }), ...(t.retainedUntil !== undefined && { retained_until: t.retainedUntil }), ...(t.withdrawRequestId !== undefined && { withdraw_request_id: t.withdrawRequestId }) }
const num = (b: bigint | undefined) => (b === undefined ? null : Number(b))

async function result(c: Json): Promise<Json> {
  let raw = parseJSONValue(c.result) as Record<string, unknown>
  let tombs: Partial<Record<string, Tombstone>> = {}
  if (c.lookup) ({ result: raw, tombstones: tombs } = decodeLookupDone(raw))
  const i = c.inputs
  switch (c.method) {
    case 'cash_redeem': {
      const r = parseCashRedeemResult(raw)
      return { fees_paid: Number(r.feesPaid), preimage: r.preimage }
    }
    case 'cash_transfer': {
      const r = await parseCashTransferResult(raw, credentials[i.credential]!)
      return {
        AmountMillis: Number(r.amountMillis),
        ExpiresAt: r.zapExpiresAt ?? null,
        IdentityType: r.identityType,
        IdentityValue: r.identityValue,
        IssuedAt: r.issuedAt ?? null,
        NewWalletPubkey: r.newWalletPubkey,
        NewWalletToken: r.newWalletToken,
        NewWalletTombstone: wire(tombs['new_wallet_token']),
        RemainderWalletPubkey: r.remainderWalletPubkey,
        RemainderWalletToken: r.remainderWalletToken,
        RemainderWalletTombstone: wire(tombs['remainder_wallet_token']),
        RemainingAmountMillis: num(r.remainingAmountMillis),
      }
    }
    default: {
      const sources = i.sources.map((s: Json) => ({ walletPubkey: s.wallet, amount: BigInt(s.amount), credential: credentials[s.credential]! }))
      const r = await parseCashConsolidateResult(raw, { sources, to: targets[i.to]!() })
      return { AmountMillis: Number(r.amountMillis), ExpiresAt: r.expiresAt ?? null, NewWalletPubkey: r.newWalletPubkey, NewWalletToken: r.newWalletToken, NewWalletTombstone: wire(tombs['new_wallet_token']) }
    }
  }
}

/** The claim-proof binding a kind-23198 event's tags name. */
function bindingOf(tags: string[][]): ProofBinding {
  const t = Object.fromEntries(tags.map((x) => [x[0], x[1]]))
  return {
    method: t['m'] as ClaimMethod,
    walletPubkey: t['d']!,
    ...(t['bolt11_hash'] !== undefined && { bolt11Hash: t['bolt11_hash'] }),
    ...(t['q'] !== undefined && { quoteId: t['q'] }),
    ...(t['new_identity_hash'] !== undefined && { newIdentityHash: t['new_identity_hash'] }),
    ...(t['amount_millis'] !== undefined && { amountMillis: BigInt(t['amount_millis']) }),
    ...(t['s'] !== undefined && { sourcesHash: t['s'] }),
  }
}

/** The index of the caller's own row: an unclaimed row matchClaim accepts, or -1. */
function ownRow(credential: string, rows: Json[]): number {
  const typed = rows.map((r) => ({ ...r, amount_millis: BigInt(r.amount_millis) }))
  return typed.findIndex((r) => matchClaim([r], credential === 'cash', credential === 'signing' ? signer.pubkey : '') !== undefined)
}

describe('claim.json', () => {
  test.each(named(v.attestation))('attestation: %s', (_: string, c: Json) => {
    if (MISMATCH.has(c.name)) return
    if (c.error) {
      expect(() => parseAttestation(c.event)).toThrow()
      return
    }
    const a = parseAttestation(c.event)
    expect({ connectionKey: a.connectionKey, userPubkey: a.userPubkey, platform: a.platform, evidence: a.evidence, expiresAt: a.expiresAt ?? null }).toEqual(c.want)
  })

  test.each(named(v.cashTarget, (c) => c.secret))('cash target %s', (_: string, c: Json) => {
    expect(cashTargetFromSecret(c.secret).identityValue).toBe(c.commit)
  })

  test.each(named(v.kats))('%s', (_: string, c: Json) => {
    if (c.kind !== undefined) {
      expect(claimProofTags(bindingOf(c.tags))).toEqual(c.tags)
      expect(getEventHash({ kind: c.kind, pubkey: c.pubkey, created_at: c.createdAt, tags: c.tags, content: '' })).toBe(c.want)
    } else if (Array.isArray(c.input)) expect(sourcesHash(c.input)).toBe(c.want)
    else {
      // "type:value:ia"; the form without the trailing ":" is the refused one.
      const [, value] = c.input.split(':')
      const got = newIdentityHash(pubkeyTarget(value))
      if (c.id.includes('neg')) expect(got).not.toBe(c.want)
      else expect(got).toBe(c.want)
    }
  })

  test.each(named(v.verifyClaimProof.filter((c: Json) => !c.error)))('verifyClaimProof (accepted): %s', (_: string, c: Json) => {
    const ev = JSON.parse(c.proof)
    const e = c.expect
    expect([ev.pubkey, verifyEvent(ev), getEventHash(ev)]).toEqual([c.signer, true, c.recomputedId])
    const b: ProofBinding = { method: e.method, walletPubkey: e.wallet, ...(e.bolt11Hash !== '' && { bolt11Hash: e.bolt11Hash }), ...(e.quoteId !== '' && { quoteId: e.quoteId }) }
    expect(claimProofTags(b)).toEqual(ev.tags)
  })

  test.each(named(v.requests))('request: %s', async (_: string, c: Json) => {
    if (MISMATCH.has(c.name)) return
    if (c.error) {
      await expect(request(c)).rejects.toThrow()
      return
    }
    expect(flatten(await request(c))).toEqual(parsedAttestations(c.request))
  })

  test.each(named(v.results, (c) => `${c.name}${c.lookup ? ' (lookup)' : ''}`))('result: %s', async (_: string, c: Json) => {
    if (MISMATCH.has(c.name)) return
    if (c.gone) {
      // A destroyed source answers with its tombstone, never a result.
      expect(wire(parseTombstone(parseJSONValue(c.result)))).toEqual(c.gone)
      return
    }
    if (c.error) {
      await expect(result(c)).rejects.toThrow()
      return
    }
    expect(await result(c)).toEqual(c.want)
  })

  test.each(named(v.tombstones))('tombstone: %s', (_: string, c: Json) => {
    let parsed: unknown
    try {
      parsed = parseJSONValue(c.input)
    } catch {
      expect(c.tombstone).toBeNull()
      return
    }
    expect(wire(parseTombstone(parsed))).toEqual(c.tombstone)
  })

  test.each(named(v.ownRow))('ownRow: %s', (_: string, c: Json) => {
    if (MISMATCH.has(c.name)) return
    expect(ownRow(c.credential, c.rows)).toBe(c.index)
  })

  test.each(named(v.claimable))('claimable: %s', (_: string, c: Json) => {
    if (MISMATCH.has(c.name)) return
    expect(ownRow('signing', [c.row]) === 0).toBe(c.ok)
  })
})

test('connection keys the targets use', () => {
  expect(newConnectionKey('github', '12345')).toBe(attestation.connectionKey)
})
