// Targets and NIP-05. Ported from cashctl internal/credential/
// credential_test.go and nip05_test.go (names in comments).
import { describe, expect, test } from 'vitest'
import { encodeNConnection, encodeNpub, connectionKeyFromAttested } from '../src/core/index.js'
import { looksLikeTarget, parseTarget, resolveNip05 } from '../src/wallet/index.js'
import type { Fetch } from '../src/wallet/index.js'
import { looksLikeNip05, MAX_NIP05_BODY } from '../src/wallet/target.js'

const PK = 'ab'.repeat(32)
const IA = 'cd'.repeat(32)

function fakeFetch(o: { status?: number; body?: string; url?: string; redirected?: boolean; throws?: Error } = {}) {
  const calls: { url: string; init: Parameters<Fetch>[1] }[] = []
  const f: Fetch = async (url, init) => {
    calls.push({ url, init })
    if (o.throws) throw o.throws
    return { ok: (o.status ?? 200) === 200, status: o.status ?? 200, url: o.url ?? url, ...(o.redirected !== undefined && { redirected: o.redirected }), text: async () => o.body ?? JSON.stringify({ names: { alice: PK } }) }
  }
  return { f, calls }
}

const code = (p: Promise<unknown>) => p.then(() => 'ok', (e: { code?: string }) => e.code)

describe('parseTarget', () => {
  test('bare hex and npub become a pubkey target; hex is lowercased (TestParseTarget_BareHexPubkey, _UppercaseHex, _Npub)', async () => {
    const a = await parseTarget(PK.toUpperCase())
    expect(a).toMatchObject({ kind: 'pubkey', target: { identityType: 'pubkey', identityValue: PK }, display: encodeNpub(PK), resolved: '' })
    expect((await parseTarget(encodeNpub(PK))).target.identityValue).toBe(PK)
    expect(await code(parseTarget('npub1qqqq'))).toBe('invalid_input')
  })
  test('pubkey: keeps the value as given (TestParseTarget_Pubkey)', async () => {
    expect((await parseTarget(`pubkey:${PK}`)).target.identityValue).toBe(PK)
    expect(await code(parseTarget('pubkey:'))).toBe('invalid_input')
  })
  test('connection:<platform>:<id>:<ia> (TestParseTarget_Connection)', async () => {
    const t = await parseTarget(`connection:discord:80351110224678912:${IA}`)
    expect(t.target).toEqual({ identityType: 'connection_key', identityValue: '22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d', iaPubkey: IA })
    expect(t.display).toBe('discord connection')
    expect(await code(parseTarget('connection:discord:alice'))).toBe('invalid_input')
  })
  test('T-1808 a typed connection is hashed only in its canonical form, on a canonical platform', async () => {
    const dns = await parseTarget(`connection:dns:BüCHER.example:${IA}`)
    expect(dns.target.identityValue).toBe(connectionKeyFromAttested('dns', 'xn--bcher-kva.example'))
    const email = await parseTarget(`connection:email: Alice@Example.COM :${IA}`)
    expect(email.target.identityValue).toBe(connectionKeyFromAttested('email', 'alice@example.com'))
    // Not canonical: refused, never repaired.
    expect(await code(parseTarget(`connection:discord:080351110224678912:${IA}`))).toBe('invalid_input')
    expect(await code(parseTarget(`connection:discord:alice:${IA}`))).toBe('invalid_input')
    expect(await code(parseTarget(`connection:dns:BÜCHER.example:${IA}`))).toBe('invalid_input')
    // Any other platform: the key comes from the recipient's nconnection.
    const gh = await parseTarget(`connection:github:12345:${IA}`).catch((x: { code: string; message: string; hint?: string }) => x)
    expect(gh).toMatchObject({ code: 'invalid_input', hint: 'nconnection1…' })
    expect((gh as { message: string }).message).toContain('nconnection1')
    expect(await code(parseTarget(`connection:Discord:80351110224678912:${IA}`))).toBe('invalid_input')
    expect(await code(parseTarget(`connection:nostr:${IA}:${IA}`))).toBe('invalid_input')
    // The IA may be an npub too.
    expect((await parseTarget(`connection:x:12:${encodeNpub(IA)}`)).target.iaPubkey).toBe(IA)
  })
  test('cash makes a fresh secret each time, and never shows it (TestParseTarget_CashTarget_GeneratesFreshSecretEachTime)', async () => {
    const a = await parseTarget('cash')
    const b = await parseTarget('cash')
    expect(a.kind).toBe('cash')
    expect(a.target.identityValue).not.toBe(b.target.identityValue)
    // cashctl's Resolved surfaces the secret (TestParseTarget_CashTarget_ResolvedSurfacesSecret);
    // cashkit keeps targets public (§4.2) and returns the note as SendResult.cashNote.
    expect(a.resolved).toBe('')
    expect(a.display).toBe('cash')
  })
  test('NIP-05 resolves over HTTPS without redirects (TestParseTarget_NIP05_Resolves)', async () => {
    const { f, calls } = fakeFetch()
    const t = await parseTarget('alice@example.com', { fetch: f })
    expect(t).toMatchObject({ kind: 'pubkey', display: 'alice@example.com', resolved: `pubkey ${PK}`, target: { identityValue: PK } })
    expect(calls[0]!.url).toBe('https://example.com/.well-known/nostr.json?name=alice')
    expect(calls[0]!.init?.redirect).toBe('error')
  })
  test('NIP-05 failures (TestParseTarget_NIP05_MalformedPubkeyRejected, _NoMatchingName, _UnreachableDomain)', async () => {
    expect(await code(parseTarget('alice@example.com', { fetch: fakeFetch({ body: JSON.stringify({ names: { alice: 'zz' } }) }).f }))).toBe('invalid_input')
    expect(await code(parseTarget('bob@example.com', { fetch: fakeFetch().f }))).toBe('not_found')
    expect(await code(parseTarget('alice@example.com', { fetch: fakeFetch({ throws: new Error('ENOTFOUND') }).f }))).toBe('network')
  })
  test('an nconnection needs an IA, and names it (TestParseTarget_NConnection_NeedsIA, _NoPlatform)', async () => {
    const key = 'ef'.repeat(32)
    const nc = encodeNConnection({ connectionKey: key, relays: ['wss://r'], platform: 'discord' })
    const e = await parseTarget(nc).catch((x: { code: string; message: string }) => x)
    expect(e).toMatchObject({ code: 'usage' })
    expect((e as { message: string }).message).toContain('discord')
    const t = await parseTarget(nc, { ia: IA })
    expect(t.target).toEqual({ identityType: 'connection_key', identityValue: key, iaPubkey: IA })
    expect(t.resolved).toBe(`discord connection; Identity Authority: ${IA}`)
    expect(t.display).not.toContain('nconnection')
    // Taken byte for byte, never re-derived; one without a platform is refused for a send.
    expect(await code(parseTarget(encodeNConnection({ connectionKey: key, relays: ['wss://r'], platform: '' }), { ia: IA }))).toBe('invalid_input')
    const other = await parseTarget(encodeNConnection({ connectionKey: key, relays: [], platform: 'github' }), { ia: IA })
    expect(other.target).toEqual({ identityType: 'connection_key', identityValue: key, iaPubkey: IA })
  })
  test('the IA may be a NIP-05 name (TestResolveConnectionTarget)', async () => {
    const nc = encodeNConnection({ connectionKey: 'ef'.repeat(32), relays: ['wss://r'], platform: 'discord' })
    const t = await parseTarget(nc, { ia: 'alice@example.com', fetch: fakeFetch().f })
    expect(t.resolved).toBe(`discord connection; Identity Authority: alice@example.com (${PK})`)
  })
  test('anything else is invalid_input (TestParseTarget_Errors)', async () => {
    for (const s of ['', 'nonsense', 'foo:bar']) expect(await code(parseTarget(s))).toBe('invalid_input')
  })
})

describe('resolveNip05 (credential/nip05_test.go)', () => {
  test('refuses a redirect, however the fetch reports it (TestResolveNIP05_RefusesARedirect)', async () => {
    expect(await code(resolveNip05('alice@example.com', fakeFetch({ redirected: true }).f))).toBe('invalid_input')
    expect(await code(resolveNip05('alice@example.com', fakeFetch({ url: 'http://169.254.169.254/latest' }).f))).toBe('invalid_input')
  })
  test('an oversized body is reported as too large; a large one still resolves (TestResolveNIP05_OversizedBodyIsReportedAsTooLarge, _AnOrdinarilyLargeBodyStillResolves)', async () => {
    const pad = (n: number) => JSON.stringify({ names: { alice: PK }, pad: 'x'.repeat(n) })
    expect(await code(resolveNip05('alice@example.com', fakeFetch({ body: pad(MAX_NIP05_BODY) }).f))).toBe('invalid_input')
    expect(await resolveNip05('alice@example.com', fakeFetch({ body: pad(MAX_NIP05_BODY - 100) }).f)).toBe(PK)
  })
  test('a status error names only the code (TestResolveNIP05_StatusErrorOmitsTheRemoteReasonPhrase)', async () => {
    const e = await resolveNip05('alice@example.com', fakeFetch({ status: 404 }).f).catch((x: Error) => x)
    expect((e as Error).message).toBe('example.com returned HTTP 404 for nostr.json')
  })
})

test('looksLikeNip05 and looksLikeTarget (TestLooksLikeNIP05, TestLooksLikeTarget)', () => {
  expect(looksLikeNip05('alice@example.com')).toBe(true)
  expect(looksLikeNip05('@example.com')).toBe(false)
  expect(looksLikeNip05('alice@localhost')).toBe(false)
  for (const s of ['cash', PK, encodeNpub(PK), 'a@b.co', 'pubkey:x', 'connection:a:b:c']) expect(looksLikeTarget(s)).toBe(true)
  for (const s of ['5', '0.5', 'foo:bar', 'hello']) expect(looksLikeTarget(s)).toBe(false)
})
