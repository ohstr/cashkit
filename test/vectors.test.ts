// Runs src/core against every vectors/*.json file nmilat produced (§11.1).
import { readFileSync } from 'node:fs'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'
import { describe, expect, test } from 'vitest'
import {
  connectionKeyFromSecret,
  decodeCashHubConnection,
  decodeCircleHubConnection,
  decodeNConnection,
  decodeToken,
  encodeNConnection,
  fromHex,
  hubGroupFor,
  newConnectionKey,
  nip04,
  nip44,
  CoreError,
  getPublicKey,
  sameHubGroup,
  signedMessagePrefix,
  splitCashString,
  toHex,
  buildPairingURI,
  createCircleWalletRequest,
  decodeNaddr,
  decodeNevent,
  decodeNote,
  decodeNprofile,
  decodeNpub,
  decodeNsec,
  encodeNaddr,
  encodeNevent,
  encodeNote,
  encodeNprofile,
  encodeNpub,
  encodeNsec,
  nwcRequestEvent,
  parseCreateCircleWalletResult,
  parseInfoEvent,
  parsePairingURI,
  parseResponseEvent,
  bySecret,
  bySigning,
  bySigningConnectionKey,
  cashConsolidateRequest,
  cashRedeemRequest,
  cashTargetFromSecret,
  cashTransferRequest,
  connectionKeyTarget,
  localSigner,
  matchClaim,
  matchClaimAuto,
  parseAttestation,
  pubkeyTarget,
  resolvedConnectionKeyTarget,
  type Credential,
  type Target,
  decodeBolt11,
  serializeEvent,
  getEventHash,
  verifyEvent,
  type HubConnection,
  type NConnection,
  type Token,
} from '../src/core/index.js'
import { billFromParts, createCircleWalletItem } from '../src/client/index.js'
import { paramsHash, verifyBillProof, verifyItemProof } from '../src/transport/index.js'

type Json = any

/** test.each rows of [title, case]. */
const named = (cases: Json[], title: (c: Json, i: number) => string): [string, Json][] =>
  cases.map((c, i) => [title(c, i), c])

const stripProof = (j: string): unknown => (JSON.parse(j) as { tags: string[][] }).tags.filter((t) => t[0] !== 'm' && t[0] !== 's')
const comparable = (r: Record<string, unknown>): Record<string, unknown> => {
  const { identity_event: ie, request_id: _rid, sources, ...rest } = r
  return {
    ...rest,
    ...(typeof ie === 'string' && { identity_event: stripProof(ie) }),
    ...(Array.isArray(sources) && { sources: sources.map((x: Record<string, unknown>): Record<string, unknown> => comparable(x)) }),
  }
}
const VECTOR_RID = '00112233445566778899aabbccddeeff'

const hexOrUndefined = (h: string | null) => (h === null ? undefined : fromHex(h))

const load = (name: string): Json => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), 'utf8'))

/** A Token in vector form: hex bytes, decimal amount, null for absent. */
function tokenToJSON(t: Token) {
  return {
    hrp: t.hrp,
    walletPubkey: t.walletPubkey,
    secret: t.secret,
    relays: [...t.relays],
    identityRequired: t.identityRequired ?? null,
    mintSignature: t.mintSignature ? toHex(t.mintSignature) : null,
    attestedAmountMillis: t.attestedAmountMillis?.toString() ?? null,
    hubGroup: t.hubGroup ? toHex(t.hubGroup) : null,
  }
}

const hubToJSON = (c: HubConnection) => ({ ...c, relays: [...c.relays] })

const ncToJSON = (c: NConnection) => ({ ...c, relays: [...c.relays] })

const decoders: Record<string, (s: string) => unknown> = {
  token: (s) => tokenToJSON(decodeToken(s)),
  cashhub: (s) => hubToJSON(decodeCashHubConnection(s)),
  circlehub: (s) => hubToJSON(decodeCircleHubConnection(s)),
  nconnection: (s) => ncToJSON(decodeNConnection(s)),
}

const encoders: Record<string, (f: Json) => string> = {
  nconnection: (f) => encodeNConnection({ ...f, relays: f.relays ?? [] }),
}

// The pinned tlv.json and provenance.json predate the signature scheme (TLV 8),
// the `cash-mint:v1` payload and usable-only relay hints. Until they are
// regenerated, a token case checks only what those rules leave unchanged
// (decodes or not, and its other fields); test/token.test.ts and
// test/provenance.test.ts cover the rest from the NIP's own vectors.
// The pinned cashhub1/circlehub1 strings carry no connection signature
// (TLV 4–6), so every one is refused now; test/connection.test.ts covers the
// signed strings from the NIP's examples.
const UNSIGNED_KINDS = new Set(['cashhub', 'circlehub'])
// A token whose only hint is not ASCII has no usable relay: refused now.
const NOW_REFUSED = new Set(['relay of U+FEFF only is not blank'])
const stableTokenFields = ({ relays: _r, mintSignature: _m, attestedAmountMillis: _a, ...rest }: Record<string, unknown>) => rest

describe('tlv.json', () => {
  const v = load('tlv.json')
  test.each(named(v.decode, (c) => `decode ${c.kind}: ${c.name}`))('%s', (_: string, c: Json) => {
    const decode = decoders[c.kind]!
    if (c.error || UNSIGNED_KINDS.has(c.kind) || (c.kind === 'token' && NOW_REFUSED.has(c.name))) expect(() => decode(c.input)).toThrow()
    else if (c.kind === 'token') expect(stableTokenFields(decode(c.input) as Record<string, unknown>)).toEqual(stableTokenFields(c.want))
    else expect(decode(c.input)).toEqual(c.want)
  })
  test.each(named(v.encode.filter((c: Json) => c.kind !== 'token' && !UNSIGNED_KINDS.has(c.kind)), (c) => `encode ${c.kind}: ${c.name}`))('%s', (_: string, c: Json) => {
    const encode = encoders[c.kind]!
    if (c.error) expect(() => encode(c.fields)).toThrow()
    else expect(encode(c.fields)).toBe(c.output)
  })
})

describe('hub-group.json', () => {
  const v = load('hub-group.json')
  test.each(named(v.hubGroupFor, (c) => JSON.stringify(c.hub)))('hubGroupFor(%s)', (_: string, c: Json) => {
    const got = toHex(hubGroupFor(c.hub))
    expect(got).toBe(c.group)
    if (c.notRawBytes) expect(got).not.toBe(c.notRawBytes)
  })
  test.each(named(v.sameHubGroup, (c) => c.name))('sameHubGroup: %s', (_: string, c: Json) => {
    expect(sameHubGroup(hexOrUndefined(c.a), hexOrUndefined(c.b))).toBe(c.same)
  })
})

describe('cash-string.json', () => {
  const v = load('cash-string.json')
  test.each(named(v.split, (c) => JSON.stringify(c.input)))('split %s', (_: string, c: Json) => {
    expect(splitCashString(c.input)).toEqual({ token: c.token, cashSecret: c.cashSecret })
  })
})

describe('provenance.json', () => {
  const v = load('provenance.json')
  test.each(named(v.signedMessagePrefix, (c) => JSON.stringify(c.hrp)))('prefix %s', (_: string, c: Json) => {
    expect(signedMessagePrefix(c.hrp) ?? null).toBe(c.prefix)
  })
})

describe('connection-key.json', () => {
  const v = load('connection-key.json')
  test.each(named(v.newConnectionKey, (c) => `${c.platform}:${c.externalId}`))('newConnectionKey %s', (_: string, c: Json) => {
    expect(newConnectionKey(c.platform, c.externalId)).toBe(c.key)
  })
  test.each(named(v.fromSecret, (c) => c.secret))('connectionKeyFromSecret %s', (_: string, c: Json) => {
    if (c.error) expect(() => connectionKeyFromSecret(c.secret)).toThrow()
    else expect(connectionKeyFromSecret(c.secret).pubkey).toBe(c.pubkey)
  })
  test.each([
    ['zero', '00'.repeat(32)],
    ['curve order n', 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'],
    ['all ones', 'ff'.repeat(32)],
  ])('connectionKeyFromSecret refuses an out-of-range secret (%s)', (_, s) => {
    expect(() => connectionKeyFromSecret(s)).toThrow()
  })
})

describe('nip04.json', () => {
  const v = load('nip04.json')
  test.each(named(v.valid, (c) => c.name))('decrypts, and re-encrypts byte for byte: %s', (_: string, c: Json) => {
    expect(nip04.decrypt(c.payload, fromHex(c.receiverSecret), c.senderPubkey)).toBe(c.plaintext)
    const iv = base64.decode(c.payload.split('?iv=')[1])
    expect(nip04.encrypt(c.plaintext, fromHex(c.senderSecret), c.receiverPubkey, iv)).toBe(c.payload)
  })
  test.each(named(v.invalid, (c) => c.name))('refuses with an error: %s', (_: string, c: Json) => {
    expect(c.nmilat).toBe('refused')
    expect(() => nip04.decrypt(c.payload, fromHex('00'.repeat(31) + '02'), getPublicKey(fromHex('00'.repeat(31) + '01')))).toThrow(CoreError)
  })
})

describe('nip44.json', () => {
  const v = load('nip44.json').v2

  test.each(named(v.valid.get_conversation_key, (_c, i) => String(i)))('conversation key %s', (_: string, c: Json) => {
    expect(toHex(nip44.getConversationKey(fromHex(c.sec1), c.pub2))).toBe(c.conversation_key)
  })
  test.each(v.valid.calc_padded_len as [number, number][])('calcPaddedLen(%i) = %i', (len: number, padded: number) => {
    expect(nip44.calcPaddedLen(len)).toBe(padded)
  })
  test.each(named(v.valid.encrypt_decrypt, (_c, i) => String(i)))('encrypt/decrypt %s', (_: string, c: Json) => {
    const pub2 = toHex(secp256k1.getPublicKey(fromHex(c.sec2), true).subarray(1))
    expect(toHex(nip44.getConversationKey(fromHex(c.sec1), pub2))).toBe(c.conversation_key)
    expect(nip44.encrypt(c.plaintext, fromHex(c.conversation_key), fromHex(c.nonce))).toBe(c.payload)
    expect(nip44.decrypt(c.payload, fromHex(c.conversation_key))).toBe(c.plaintext)
  })
  test.each(named(v.valid.encrypt_decrypt_long_msg, (_c, i) => String(i)))('long message %s', (_: string, c: Json) => {
    const plaintext = c.pattern.repeat(c.repeat)
    expect(toHex(sha256(new TextEncoder().encode(plaintext)))).toBe(c.plaintext_sha256)
    const payload = nip44.encrypt(plaintext, fromHex(c.conversation_key), fromHex(c.nonce))
    expect(toHex(sha256(new TextEncoder().encode(payload)))).toBe(c.payload_sha256)
    expect(nip44.decrypt(payload, fromHex(c.conversation_key))).toBe(plaintext)
  })
  // The upstream file predates NIP-44's extended prefix: of its invalid
  // lengths, only 0 is still invalid. The rest now encrypt (see crypto.test.ts).
  test.each(v.invalid.encrypt_msg_lengths as number[])('encrypt %i bytes: only 0 is refused under the current NIP', (len: number) => {
    const ck = new Uint8Array(32).fill(1)
    if (len === 0) expect(() => nip44.encrypt('', ck)).toThrow()
    else expect(nip44.decrypt(nip44.encrypt('a'.repeat(len), ck), ck)).toHaveLength(len)
  })
  test.each(named(v.invalid.decrypt, (c) => c.note))('refuses to decrypt: %s', (_: string, c: Json) => {
    expect(() => nip44.decrypt(c.payload, fromHex(c.conversation_key))).toThrow()
  })
  test.each(named(v.invalid.get_conversation_key, (c) => c.note))('refuses a conversation key: %s', (_: string, c: Json) => {
    expect(() => nip44.getConversationKey(fromHex(c.sec1), c.pub2)).toThrow()
  })
})

describe('bolt11.json', () => {
  const v = load('bolt11.json')
  test.each(named(v.decode, (c) => c.name))('decode: %s', (_: string, c: Json) => {
    // An amount nmilat computes by wrapping int64 is refused here instead.
    if (c.error || c.overflow) {
      expect(() => decodeBolt11(c.invoice)).toThrow()
      return
    }
    expect(decodeBolt11(c.invoice)).toEqual({ ...c.want, amountMillis: BigInt(c.want.amountMillis) })
  })
})

/** The request as the vector records it: proofs parsed, bigints as numbers. */
function flatten(x: Json): Json {
  if (typeof x === 'bigint') return Number(x)
  if (Array.isArray(x)) return x.map(flatten)
  if (x === null || typeof x !== 'object') return x
  const out: Json = {}
  for (const [k, val] of Object.entries(x)) {
    if (k === 'identity_event') {
      const e = JSON.parse(val as string)
      out[k] = { kind: e.kind, pubkey: e.pubkey, tags: e.tags, content: e.content, valid: verifyEvent(e) }
    } else out[k] = flatten(val)
  }
  return out
}

describe('claim.json', () => {
  const v = load('claim.json')
  const claimant = fromHex('02'.repeat(32))
  const signer = localSigner(claimant)
  const iaPub = toHex(secp256k1.getPublicKey(fromHex('03'.repeat(32)), true).subarray(1))
  const ck = newConnectionKey('github', '12345')

  test.each(named(v.attestation, (c) => c.name))('attestation: %s', (_: string, c: Json) => {
    const ev = { ...c.event, tags: c.event.tags ?? [] }
    if (c.error) {
      expect(() => parseAttestation(ev)).toThrow()
      return
    }
    const a = parseAttestation(ev)
    expect({ connectionKey: a.connectionKey, userPubkey: a.userPubkey, platform: a.platform, evidence: a.evidence, expiresAt: a.expiresAt ?? null }).toEqual(c.want)
  })

  test.each(named(v.cashTarget, (c) => c.secret))('cash target %s', (_: string, c: Json) => {
    expect(cashTargetFromSecret(c.secret).identityValue).toBe(c.commit)
  })

  const attestation = parseAttestation({ ...v.attestation[0].event })
  const credentials: Record<string, Credential> = {
    secret: bySecret('5e'.repeat(32)),
    signing: bySigning(signer),
    connection_key: bySigningConnectionKey(signer, 'github', '12345', attestation),
    connection_key_no_att: bySigningConnectionKey(signer, 'github', '12345', undefined),
    connection_key_expired: bySigningConnectionKey(signer, 'github', '12345', { ...attestation, expiresAt: 0 }),
  }
  const targets: Record<string, Target> = {
    pubkey: pubkeyTarget(signer.pubkey),
    'pubkey uppercase': pubkeyTarget(signer.pubkey.toUpperCase()),
    connection_key: connectionKeyTarget('github', '12345', iaPub),
    'connection_key no ia': connectionKeyTarget('github', '12345', ''),
    'connection_key no platform': connectionKeyTarget('', '12345', iaPub),
    'resolved connection_key': resolvedConnectionKeyTarget(ck, 'github', iaPub),
    cash: cashTargetFromSecret(v.cashTarget[0].secret),
  }

  function build(c: Json): Promise<unknown> {
    const i = c.inputs
    switch (c.method) {
      case 'cash_redeem':
        return cashRedeemRequest({
          walletPubkey: i.wallet,
          invoice: i.invoice,
          credential: credentials[i.credential]!,
          ...(i.amount !== undefined && { amount: BigInt(i.amount) }),
        })
      case 'cash_transfer':
        return cashTransferRequest({
          walletPubkey: i.wallet,
          credential: credentials[i.credential]!,
          to: targets[i.to]!,
          currentAmount: BigInt(i.currentAmount),
          ...(i.splitAmount !== undefined && { splitAmount: BigInt(i.splitAmount) }),
          requestId: VECTOR_RID,
        })
      default:
        return cashConsolidateRequest({
          to: targets[i.to]!,
          requestId: VECTOR_RID,
          sources: i.sources.map((s: Json) => ({ walletPubkey: s.wallet, amount: BigInt(s.amount), credential: credentials[s.credential]! })),
        })
    }
  }

  // The pinned claim.json predates the `m` and `s` tags and request_id: a case
  // is compared without them, and a target the stricter builder refuses
  // (an uppercase pubkey, a pubkey-typed key carrying an IA) is expected to fail.
  const REFUSED_REQUESTS = new Set(['transfer to pubkey uppercase', 'transfer to connection_key no platform', 'redeem with an amount'])
  test.each(named(v.requests, (c) => c.name))('request: %s', async (_: string, c: Json) => {
    if (c.error || REFUSED_REQUESTS.has(c.name)) {
      await expect(build(c)).rejects.toThrow()
      return
    }
    const got = comparable(flatten(await build(c)))
    c = { ...c, request: comparable(c.request) }
    // attestation_event is the same event; compare it parsed, as the Hub reads it.
    if (c.request.attestation_event) {
      expect(JSON.parse(got['attestation_event'] as string)).toEqual(JSON.parse(c.request.attestation_event))
      got['attestation_event'] = c.request.attestation_event
    }
    expect(got).toEqual(c.request)
  })

  test.each(named(v.matchClaim, (c) => c.name))('match: %s', (_: string, c: Json) => {
    const rows = c.recipients.map((r: Json) => ({ ...r, amount_millis: BigInt(r.amount_millis) }))
    const amount = matchClaim(rows, c.isCash, c.asPubkey)
    expect(amount !== undefined).toBe(c.matchClaimOk)
    if (c.matchClaimOk) expect(amount).toBe(BigInt(c.matchClaimAmount))
    const auto = matchClaimAuto(rows, c.asPubkey)
    expect(auto === undefined ? -1 : rows.indexOf(auto)).toBe(c.matchClaimAutoIndex)
  })
})

describe('nip19.json', () => {
  const v = load('nip19.json')
  const nip19Decoders: Record<string, (s: string) => unknown> = {
    npub: decodeNpub,
    nsec: decodeNsec,
    note: decodeNote,
    nprofile: (s) => ({ ...decodeNprofile(s) }),
    nevent: (s) => ({ ...decodeNevent(s) }),
    naddr: (s) => ({ ...decodeNaddr(s) }),
  }
  const nip19Encoders: Record<string, (f: Json) => string> = {
    npub: encodeNpub,
    nsec: encodeNsec,
    note: encodeNote,
    nprofile: (f) => encodeNprofile({ pubkey: f.pubkey, relays: f.relays ?? [] }),
    nevent: (f) => encodeNevent({ id: f.id, relays: f.relays ?? [], author: f.author ?? '', kind: f.kind ?? 0 }),
    naddr: (f) => encodeNaddr({ identifier: f.identifier, pubkey: f.pubkey, kind: f.kind, relays: f.relays ?? [] }),
  }
  test.each(named(v.decode, (c) => `${c.kind}: ${c.name}`))('decode %s', (_: string, c: Json) => {
    if (c.error) expect(() => nip19Decoders[c.kind]!(c.input)).toThrow()
    else expect(nip19Decoders[c.kind]!(c.input)).toEqual(c.want)
  })
  test.each(named(v.encode, (c) => `${c.kind}: ${c.name}`))('encode %s', (_: string, c: Json) => {
    if (c.error) expect(() => nip19Encoders[c.kind]!(c.fields)).toThrow()
    else expect(nip19Encoders[c.kind]!(c.fields)).toBe(c.want)
  })
})

describe('nip47.json', () => {
  const v = load('nip47.json')
  const appSecret = fromHex('04'.repeat(32))
  const walletSecret = fromHex('05'.repeat(32))
  test.each(named(v.pairingBuild, (c) => c.uri))('build %s', (_: string, c: Json) => {
    expect(buildPairingURI(c.walletPubkey, c.relays, c.secret, c.extra)).toBe(c.uri)
  })
  test.each(named(v.pairingParse, (c) => c.name))('parse: %s', (_: string, c: Json) => {
    if (c.error) expect(() => parsePairingURI(c.uri)).toThrow()
    else expect({ ...parsePairingURI(c.uri) }).toEqual(c.want)
  })
  test.each(named(v.info, (c) => c.name))('info: %s', (_: string, c: Json) => {
    const e = { ...c.event, tags: c.event.tags ?? [] }
    if (c.error) expect(() => parseInfoEvent(e)).toThrow()
    else expect({ ...parseInfoEvent(e) }).toEqual(c.want)
  })
  test.each(named(v.requests, (c) => c.name))('request: %s', (_: string, c: Json) => {
    const e = c.event
    expect(verifyEvent(e)).toBe(true)
    const ck = nip44.getConversationKey(walletSecret, e.pubkey)
    expect(JSON.parse(nip44.decrypt(e.content, ck))).toEqual(JSON.parse(c.plaintext))
    // Re-encrypting cashkit's plaintext with nmilat's nonce must give nmilat's bytes.
    const nonce = Uint8Array.from(atob(e.content), (ch) => ch.charCodeAt(0)).subarray(1, 33)
    const ours = nwcRequestEvent({ connectionSecret: appSecret, walletPubkey: e.tags[0][1], method: c.method, params: c.params, createdAt: e.created_at, nonce })
    expect(ours).toEqual({ pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content })
  })
  test.each(named(v.responses, (c) => c.name))('response: %s', (_: string, c: Json) => {
    const e = { ...c.event, tags: c.event.tags ?? [] }
    if (c.error) {
      expect(() => parseResponseEvent(e, appSecret, c.fallback)).toThrow()
      return
    }
    const r = parseResponseEvent(e, appSecret, c.fallback)
    const { request_event_id, sub_payment_id, result_type, error, result } = c.want
    expect(r).toEqual({
      resultType: result_type,
      ...(error && { error }),
      ...(result !== undefined && { result }),
      requestEventId: request_event_id,
      subPaymentId: sub_payment_id,
    })
  })
})

describe('nipcw.json', () => {
  const v = load('nipcw.json')
  const signer = localSigner(fromHex('02'.repeat(32)))
  const hub = toHex(secp256k1.getPublicKey(fromHex('06'.repeat(32)), true).subarray(1))
  const conn = connectionKeyFromSecret('11'.repeat(32))
  test.each(named(v.requests, (c) => c.name))('request: %s', async (_: string, c: Json) => {
    const i = c.inputs
    const run = () =>
      createCircleWalletRequest({
        signer,
        connection: i.connectionSecret === '' ? undefined : connectionKeyFromSecret(i.connectionSecret),
        hubPubkey: i.hub,
        maxAmountMillis: BigInt(i.maxAmountMillis),
        expirySeconds: i.expirySeconds,
        ...(i.budgetRenewal !== '' && { budgetRenewal: i.budgetRenewal }),
      })
    if (c.error) {
      await expect(run()).rejects.toThrow()
      return
    }
    expect(flatten(await run())).toEqual(c.request)
  })
  test.each(named(v.results, (c) => c.name))('result: %s', async (_: string, c: Json) => {
    let parsed: unknown
    try {
      parsed = JSON.parse(c.result)
    } catch {
      expect(c.error).toBeTruthy()
      return
    }
    const run = () => parseCreateCircleWalletResult(parsed, { signer, connection: conn, hubPubkey: hub })
    if (c.error) {
      await expect(run()).rejects.toThrow()
      return
    }
    const w = await run()
    expect({
      PairingURI: w.pairingUri,
      WalletPubkey: w.walletPubkey,
      Relays: w.relays,
      MaxAmountMillis: w.maxAmountMillis === undefined ? null : Number(w.maxAmountMillis),
      ExpiresAt: w.expiresAt,
      FeesPpm: w.feesPpm,
      BudgetRenewal: w.budgetRenewal,
    }).toEqual(c.want)
  })
})

/** A proof as private-join.json records it: no time-dependent fields, ph checked then replaced. */
function proofShape(proof: string, ph: string) {
  const e = JSON.parse(proof)
  expect(e.tags.find((t: string[]) => t[0] === 'ph')?.[1]).toBe(ph)
  return { kind: e.kind, pubkey: e.pubkey, tags: e.tags.map((t: string[]) => (t[0] === 'ph' ? ['ph', '<params hash>'] : t)) }
}

/** A verifier's signer, or that it refused. */
function signerOrError(f: () => string): { signer: string } | { error: true } {
  try {
    return { signer: f() }
  } catch {
    return { error: true }
  }
}

// nmilat nipcw/private_join_test.go, nipcash/client/batch_circle_join_test.go.
describe('private-join.json', () => {
  const v = load('private-join.json')
  const signer = localSigner(fromHex('02'.repeat(32)))
  const binding = { hub: v.node, nonce: v.nonce, notAfter: v.notAfter }
  test.each(named(v.build, (c) => c.name))('build: %s', async (_: string, c: Json) => {
    const i = c.inputs
    const run = async () =>
      createCircleWalletItem(
        'join',
        billFromParts(v.hub, i.hubConnectionSecret),
        {
          signer,
          ...(i.connectionSecret !== '' && { connection: connectionKeyFromSecret(i.connectionSecret) }),
          maxAmountMillis: BigInt(i.maxAmountMillis),
          expirySeconds: i.expirySeconds,
          ...(i.budgetRenewal !== '' && { budgetRenewal: i.budgetRenewal }),
        },
        binding,
        Math.floor(Date.now() / 1000),
      )
    if (c.error) {
      await expect(run()).rejects.toThrow()
      return
    }
    const item = await run()
    const ph = paramsHash(item.params!)
    expect({
      id: item.id,
      target: item.target,
      method: item.method,
      params: flatten(JSON.parse(item.params!)),
      proof: proofShape(item.proof!, ph),
      billProof: proofShape(item.billProof!, ph),
    }).toEqual(c.item)
  })
  test.each(named(v.verify, (c) => c.name))('verify: %s', (_: string, c: Json) => {
    const want = { target: c.target, hub: v.node, method: 'create_circle_wallet', paramsHash: paramsHash(c.params), nonce: v.nonce, notAfter: v.notAfter }
    const item = signerOrError(() => verifyItemProof(c.proof, want, v.now))
    const bill = signerOrError(() => verifyBillProof(c.billProof, want, v.now))
    expect(item).toEqual(c.itemError ? { error: true } : { signer: c.itemSigner })
    expect(bill).toEqual(c.billError ? { error: true } : { signer: c.billSigner })
    const hubConnection = getPublicKey(fromHex(v.hubConnectionSecret))
    const admitted = c.target === v.hub && 'signer' in item && 'signer' in bill && item.signer === JSON.parse(c.params).pubkey && bill.signer === hubConnection
    expect(admitted).toBe(c.admitted)
  })
})

describe('nip01.json', () => {
  const v = load('nip01.json')
  test.each(named(v.serialize, (c) => c.name))('serialize: %s', (_: string, c: Json) => {
    const e = { pubkey: c.pubkey, created_at: c.created_at, kind: c.kind, tags: c.tags ?? [], content: c.content }
    expect(serializeEvent(e)).toBe(c.serialized)
    expect(getEventHash(e)).toBe(c.id)
  })
  test.each(named(v.verify, (c) => c.name))('verify: %s', (_: string, c: Json) => {
    expect(verifyEvent({ ...c.event, tags: c.event.tags ?? [] })).toBe(c.valid)
  })
})
