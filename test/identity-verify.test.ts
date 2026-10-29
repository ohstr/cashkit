// NIP-IC: ConnectionKey refs (T-205, T-206, T-208) and the Verification
// Model over a MemoryRelayPool (T-209, T-1601, T-1602).
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import { resolveConnection } from '../src/client/index.js'
import {
  connectionKeyFromAttestation,
  connectionKeyFromAttested,
  connectionKeyFromNConnection,
  connectionKeyRefFromTyped,
  connectionTarget,
  evaluateConnection,
  finalizeEvent,
  getPublicKey,
  newIdentityHash,
  parseAttestation,
  parseIdentityConnection,
  type AttestationSource,
  type NostrEvent,
  toHex,
} from '../src/core/index.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'

const NOW = 1_800_000_000
const RELAY = 'wss://ia.example'
const CLAIMS = 'wss://claims.example'
const iaKey = fill(1, 32)
const ia2Key = fill(2, 32)
const userKey = fill(3, 32)
const otherKey = fill(4, 32)
const strangerKey = fill(5, 32)
const IA = getPublicKey(iaKey)
const IA2 = getPublicKey(ia2Key)
const USER = getPublicKey(userKey)
const OTHER = getPublicKey(otherKey)
const UID = '80351110224678912'
const CK = connectionKeyFromAttested('discord', UID)
const OTHER_CK = connectionKeyFromAttested('discord', '42')

interface AttOpts {
  key?: Uint8Array
  d?: string
  p?: string
  platform?: string
  userId?: string
  username?: string
  createdAt?: number
  expiration?: number | undefined
}
function att(o: AttOpts = {}): NostrEvent {
  const evidence = JSON.stringify({ version: 1, platform: o.platform ?? 'discord', auth_type: 'oauth', user_id: o.userId ?? UID, username: o.username ?? 'alice', verified_at: NOW - 100 })
  const tags = [['d', o.d ?? CK], ['p', o.p ?? USER], ['platform', o.platform ?? 'discord'], ['evidence', evidence]]
  const exp = 'expiration' in o ? o.expiration : NOW + 86400
  if (exp !== undefined) tags.push(['expiration', String(exp)])
  return finalizeEvent({ kind: 35522, created_at: o.createdAt ?? NOW - 60, tags, content: '' }, o.key ?? iaKey)
}
function claim(refs: readonly NostrEvent[], o: { key?: Uint8Array; d?: string; platform?: string; content?: string; relay?: string } = {}): NostrEvent {
  const tags = [['d', o.d ?? CK], ...refs.map((a) => ['e', a.id, o.relay ?? RELAY]), ['platform', o.platform ?? 'discord']]
  return finalizeEvent({ kind: 35521, created_at: NOW - 30, tags, content: o.content ?? '' }, o.key ?? userKey)
}

function pool(events: { relay: string; event: NostrEvent }[]): MemoryRelayPool {
  const p = new MemoryRelayPool()
  for (const { relay, event } of events) p.relay(relay).stored.push(event)
  return p
}
/** An IA's NIP-65 relay list, `[url, marker?]` per relay. */
const relayList = (key: Uint8Array, relays: readonly (readonly [string, string?])[], createdAt = NOW - 1000) =>
  finalizeEvent({ kind: 10002, created_at: createdAt, tags: relays.map(([u, m]) => (m === undefined ? ['r', u] : ['r', u, m])), content: '' }, key)
/** The usual layout: claims and the IAs' relay lists on CLAIMS, attestations (and deletions) on the IA relay. */
function world(claims: NostrEvent[], ias: NostrEvent[], extra: NostrEvent[] = []) {
  const lists = [relayList(iaKey, [[RELAY]]), relayList(ia2Key, [[RELAY, 'write']])]
  return pool([...[...claims, ...lists].map((event) => ({ relay: CLAIMS, event })), ...[...ias, ...extra].map((event) => ({ relay: RELAY, event }))])
}
const resolve = (p: MemoryRelayPool, trusted = [IA, IA2], key = CK) => resolveConnection(p, key, { trustedIas: trusted, relays: [CLAIMS], now: NOW, timeoutMs: 200 })

describe('ConnectionKey refs (T-205, T-206, T-208)', () => {
  test('an attestation gives its d with its author as the IA, when d is the hash of platform:user_id', () => {
    const a = parseAttestation(att())
    expect(connectionKeyFromAttestation(a)).toEqual({ key: CK, platform: 'discord', ia: IA })
    const gh = parseAttestation(att({ platform: 'github', userId: 'Alice_01', d: connectionKeyFromAttested('github', 'Alice_01') }))
    // An IA-defined user id is hashed byte for byte, never normalized.
    expect(connectionKeyFromAttestation(gh).key).toBe(connectionKeyFromAttested('github', 'Alice_01'))
    expect(connectionKeyFromAttestation(gh).key).not.toBe(connectionKeyFromAttested('github', 'alice_01'))
  })
  test('an attestation whose d is another key, or whose user id is not canonical on a canonical platform, is refused', () => {
    expect(() => connectionKeyFromAttestation(parseAttestation(att({ d: OTHER_CK })))).toThrow(/d is not the ConnectionKey/)
    const padded = parseAttestation(att({ userId: `0${UID}`, d: toHex(sha256(new TextEncoder().encode(`discord:0${UID}`))) }))
    expect(() => connectionKeyFromAttestation(padded)).toThrow(/not in canonical form/)
  })
  test('an nconnection key is taken as it is, with the IA the sender names; no IA or no platform is refused', () => {
    const key = 'ab'.repeat(32)
    expect(connectionKeyFromNConnection({ connectionKey: key, relays: [], platform: 'github' }, IA)).toEqual({ key, platform: 'github', ia: IA })
    expect(() => connectionKeyFromNConnection({ connectionKey: key, relays: [], platform: 'github' }, '')).toThrow(/ia_pubkey/)
    expect(() => connectionKeyFromNConnection({ connectionKey: key, relays: [], platform: '' }, IA)).toThrow(/platform name/)
  })
  test('a key always travels with its IA: two IAs make two targets', () => {
    const a = connectionTarget(connectionKeyFromNConnection({ connectionKey: CK, relays: [], platform: 'discord' }, IA))
    const b = connectionTarget(connectionKeyFromNConnection({ connectionKey: CK, relays: [], platform: 'discord' }, IA2))
    expect(newIdentityHash(a)).not.toBe(newIdentityHash(b))
  })
  test('typed input is hashed only on x, discord, email and dns; nostr and platform names outside [a-z0-9._-]+ are refused', () => {
    expect(connectionKeyRefFromTyped('discord', UID, IA).key).toBe('22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d')
    expect(() => connectionKeyRefFromTyped('nostr', USER, IA)).toThrow(/no canonical form/)
    expect(() => connectionKeyRefFromTyped('github', '12345', IA)).toThrow(/no canonical form/)
    for (const p of ['Discord', 'git:hub', 'git hub', '']) expect(() => connectionKeyRefFromTyped(p, '1', IA)).toThrow(/platform name/)
  })
})

describe('Kind 35521 parse', () => {
  test('d once as 64 lowercase hex, platform once and valid, at least one e', () => {
    const a = att()
    expect(parseIdentityConnection(claim([a]))).toMatchObject({ connectionKey: CK, platform: 'discord', attestations: [{ eventId: a.id, relay: RELAY }] })
    expect(() => parseIdentityConnection(claim([]))).toThrow(/at least one attestation/)
    expect(() => parseIdentityConnection(claim([a], { d: `discord:${CK}` }))).toThrow(/platform-prefixed/)
    expect(() => parseIdentityConnection(claim([a], { platform: 'Discord' }))).toThrow(/platform name/)
    const twice = finalizeEvent({ kind: 35521, created_at: NOW, tags: [['d', CK], ['d', CK], ['e', a.id], ['platform', 'discord']], content: '' }, userKey)
    expect(() => parseIdentityConnection(twice)).toThrow(/repeated/)
  })
})

describe('resolveConnection (T-209)', () => {
  test('no 35521: unverified', async () => {
    expect((await resolve(world([], [att()]))).state).toBe('unverified')
  })
  test("a claim pointing to the trusted IA's current attestation for its own pubkey: verified", async () => {
    const a = att()
    const r = await resolve(world([claim([a])], [a]))
    expect(r.state).toBe('verified')
    expect(r.pubkey).toBe(USER)
    expect(r.attestation?.evidence).toMatchObject({ userId: UID, username: 'alice' })
  })
  test('an attestation without an expiration counts; one at its expiration does not', async () => {
    const a = att({ expiration: undefined })
    expect((await resolve(world([claim([a])], [a]))).state).toBe('verified')
    const b = att({ expiration: NOW })
    expect((await resolve(world([claim([b])], [b]))).state).toBe('spoofed')
  })
  test('a hint-less e tag is fetched from the query relays', async () => {
    const a = att()
    const p = world([claim([a], { relay: '' }), a], [a])
    expect((await resolve(p)).state).toBe('verified')
  })
  test('an unreachable IA relay: the reference does not count', async () => {
    const a = att()
    const p = world([claim([a])], [a])
    p.relay(RELAY).down = true
    const r = await resolve(p)
    expect(r.state).toBe('spoofed')
    expect(r.verdicts[0]!.reasons[0]).toMatch(/not fetched/)
  })
  test('a malformed 35521 for this key is spoofed; one for another key is ignored', async () => {
    const a = att()
    const bad = finalizeEvent({ kind: 35521, created_at: NOW, tags: [['d', CK], ['platform', 'discord']], content: '' }, otherKey)
    expect((await resolve(world([bad], [a]))).state).toBe('spoofed')
    const src: AttestationSource = { fetch: async () => a, current: async () => a.id, deletedByAuthor: async () => false }
    const verdicts = await evaluateConnection(CK, [claim([a], { d: OTHER_CK })], src, () => true, NOW)
    expect(verdicts).toEqual([{ state: 'unverified', pubkey: '', reasons: [] }])
  })
})

describe("the IA's own relays decide what is current and what is deleted (step 3)", () => {
  const EVIL = 'wss://mallory.example'
  const OTHER_IA_RELAY = 'wss://ia-two.example'
  test('an attestation its IA revoked does not verify through a hint relay that lacks the deletion', async () => {
    const old = att({ p: OTHER, createdAt: NOW - 600 })
    const deletion = finalizeEvent({ kind: 5, created_at: NOW - 300, content: 'revoked', tags: [['e', old.id]] }, iaKey)
    const p = world([claim([old], { key: otherKey, relay: EVIL })], [old], [deletion])
    p.relay(EVIL).stored.push(old)
    expect((await resolve(p)).state).toBe('spoofed')
  })
  test('an attestation its IA replaced (the account moved) does not verify through a hint relay that lacks the new one', async () => {
    const old = att({ p: OTHER, createdAt: NOW - 600 })
    const moved = att({ p: USER, createdAt: NOW - 300 })
    const p = world([claim([old], { key: otherKey, relay: EVIL })], [moved])
    p.relay(EVIL).stored.push(old)
    const r = await resolve(p)
    expect(r.state).toBe('spoofed')
    expect(r.verdicts[0]!.reasons.join()).toMatch(/not the IA's current attestation/)
  })
  test('the attestation may be fetched from any hint; the IA relays still confirm it', async () => {
    const a = att()
    const p = world([claim([a], { relay: EVIL })], [a])
    p.relay(EVIL).stored.push(a)
    expect((await resolve(p)).state).toBe('verified')
  })
  test('an IA with no relay list: the attestation does not count', async () => {
    const a = att()
    const p = pool([{ relay: CLAIMS, event: claim([a]) }, { relay: RELAY, event: a }])
    const r = await resolve(p)
    expect(r.state).toBe('spoofed')
    expect(r.verdicts[0]!.reasons.join()).toMatch(/deletion check failed/)
  })
  test('a relay the IA lists as read-only is not one of its relays', async () => {
    const a = att()
    const p = pool([{ relay: CLAIMS, event: claim([a]) }, { relay: CLAIMS, event: relayList(iaKey, [[RELAY, 'read']]) }, { relay: RELAY, event: a }])
    expect((await resolve(p)).state).toBe('spoofed')
  })
  test("none of the IA's relays answering: the attestation does not count; one of two answering is enough", async () => {
    const a = att()
    const lists = [relayList(iaKey, [[OTHER_IA_RELAY], [RELAY]])]
    const p = pool([...[claim([a], { relay: EVIL }), ...lists].map((event) => ({ relay: CLAIMS, event })), { relay: EVIL, event: a }, { relay: RELAY, event: a }])
    p.relay(OTHER_IA_RELAY).down = true
    expect((await resolve(p)).state).toBe('verified')
    p.relay(RELAY).down = true
    expect((await resolve(p)).state).toBe('spoofed')
  })
  test("the IA's newest relay list counts; an older one naming the claimant's relay does not", async () => {
    const old = att({ p: OTHER, createdAt: NOW - 600 })
    const moved = att({ p: USER, createdAt: NOW - 300 })
    const p = pool([
      { relay: CLAIMS, event: claim([old], { key: otherKey, relay: EVIL }) },
      { relay: CLAIMS, event: relayList(iaKey, [[EVIL]], NOW - 5000) },
      { relay: CLAIMS, event: relayList(iaKey, [[RELAY]], NOW - 1000) },
      { relay: EVIL, event: old },
      { relay: RELAY, event: moved },
    ])
    expect((await resolve(p)).state).toBe('spoofed')
  })
  test('relays the trust configuration names for an IA are used in place of its list', async () => {
    const a = att()
    const p = pool([{ relay: CLAIMS, event: claim([a]) }, { relay: OTHER_IA_RELAY, event: a }, { relay: RELAY, event: a }])
    const r = await resolveConnection(p, CK, { trustedIas: [IA], relays: [CLAIMS], iaRelays: { [IA]: [OTHER_IA_RELAY] }, now: NOW, timeoutMs: 200 })
    expect(r.state).toBe('verified')
    p.relay(OTHER_IA_RELAY).down = true
    expect((await resolveConnection(p, CK, { trustedIas: [IA], relays: [CLAIMS], iaRelays: { [IA]: [OTHER_IA_RELAY] }, now: NOW, timeoutMs: 200 })).state).toBe('spoofed')
  })
})

const failsWith = async (p: MemoryRelayPool, reason: RegExp, trusted = [IA, IA2]) => {
  const r = await resolve(p, trusted)
  expect(r.state).toBe('spoofed')
  expect(r.verdicts.flatMap((v) => v.reasons).join('\n')).toMatch(reason)
}

describe('step-3 checks one at a time (T-1602)', () => {
  test('an untrusted IA', async () => {
    const a = att()
    await failsWith(world([claim([a])], [a]), /not a trusted IA/, [IA2])
  })
  test('the IA is the claim author (self-attestation)', async () => {
    const a = att({ key: userKey })
    await failsWith(world([claim([a])], [a]), /self-attested/, [IA, USER])
  })
  test("d differs from the claim's", async () => {
    const a = att({ d: OTHER_CK, userId: '42' })
    await failsWith(world([claim([a])], [a]), /d or platform differs/)
  })
  test("platform differs from the claim's", async () => {
    const a = att({ platform: 'x' })
    await failsWith(world([claim([a])], [a]), /d or platform differs/)
  })
  test("p is not the claim's author", async () => {
    const a = att({ p: OTHER })
    await failsWith(world([claim([a])], [a]), /p names another pubkey/)
  })
  test('expired', async () => {
    const a = att({ expiration: NOW - 1 })
    await failsWith(world([claim([a])], [a]), /expired/)
  })
  test('deleted by its IA; a deletion by another key is ignored', async () => {
    const a = att()
    const del = (key: Uint8Array) => finalizeEvent({ kind: 5, created_at: NOW - 10, tags: [['e', a.id]], content: 'revoked' }, key)
    await failsWith(world([claim([a])], [a], [del(iaKey)]), /deleted by its IA/)
    expect((await resolve(world([claim([a])], [a], [del(strangerKey)]))).state).toBe('verified')
  })
  test('created_at now + 901 does not count; now + 900 does', async () => {
    const late = att({ createdAt: NOW + 901 })
    await failsWith(world([claim([late])], [late]), /15 minutes ahead/)
    const edge = att({ createdAt: NOW + 900 })
    expect((await resolve(world([claim([edge])], [edge]))).state).toBe('verified')
  })
  test("not the IA's current attestation", async () => {
    const old = att({ createdAt: NOW - 600 })
    const reissued = att({ createdAt: NOW - 60, p: OTHER })
    await failsWith(world([claim([old])], [old, reissued]), /not the IA's current attestation/)
  })
  test('a relay answering a reference with another (even current) attestation does not verify the claim', async () => {
    const stale = att({ createdAt: NOW - 120 })
    const current = att({ createdAt: NOW - 60 })
    const src: AttestationSource = { fetch: async () => current, current: async () => current.id, deletedByAuthor: async () => false }
    const v = await evaluateConnection(CK, [claim([stale])], src, (x) => x === IA, NOW)
    expect(v[0]).toMatchObject({ state: 'spoofed', reasons: [expect.stringMatching(/returned another event/)] })
    const honest: AttestationSource = { ...src, fetch: async () => stale }
    expect((await evaluateConnection(CK, [claim([current])], { ...honest, fetch: async () => current }, (x) => x === IA, NOW))[0]!.state).toBe('verified')
  })
  test('two e tags, one counting: verified', async () => {
    const good = att()
    const stranger = att({ key: strangerKey })
    const r = await resolve(world([claim([stranger, good])], [stranger, good]))
    expect(r.state).toBe('verified')
    expect(r.verdicts[0]!.reasons).toHaveLength(1)
  })
  test('step 5: the latest trusted attestation wins; the other pubkey is spoofed, and a 901 s future-dated rival is ignored', async () => {
    const mine = att({ createdAt: NOW - 600 })
    const theirs = att({ key: ia2Key, p: OTHER, createdAt: NOW - 60 })
    const r = await resolve(world([claim([mine]), claim([theirs], { key: otherKey })], [mine, theirs]))
    expect(r).toMatchObject({ state: 'verified', pubkey: OTHER })
    expect(r.verdicts.find((v) => v.pubkey === USER)).toMatchObject({ state: 'spoofed', reasons: ['a newer trusted attestation names another pubkey'] })
    const future = att({ key: ia2Key, p: OTHER, createdAt: NOW + 901 })
    const r2 = await resolve(world([claim([mine]), claim([future], { key: otherKey })], [mine, future]))
    expect(r2).toMatchObject({ state: 'verified', pubkey: USER })
  })
})

describe('content cross-check (T-1601)', () => {
  const a = att()
  const withContent = (content: string) => resolve(world([claim([a], { content })], [a]))
  test('a user_id or username other than the evidence makes the claim spoofed', async () => {
    expect((await withContent(JSON.stringify({ user_id: '42' }))).state).toBe('spoofed')
    expect((await withContent(JSON.stringify({ username: 'mallory' }))).state).toBe('spoofed')
  })
  test('equal or absent fields verify, and the handle shown is the evidence, never the content', async () => {
    const r = await withContent(JSON.stringify({ display_name: 'Not Alice', user_id: UID, username: 'alice' }))
    expect(r.state).toBe('verified')
    expect(r.attestation?.evidence.username).toBe('alice')
    expect((await withContent(JSON.stringify({ display_name: 'A' }))).state).toBe('verified')
    expect((await withContent('not json')).state).toBe('verified')
  })
})
