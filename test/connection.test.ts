// Signed connection strings (NIP-CASH §The Cash Hub Connection, §Connection
// Signatures; NIP-CO §Wire Format; NIP-CW §The Circle Wallet Hub
// Connection). The literals are the NIPs' own examples. Cases follow nmilat
// nipcash/connection_sig_test.go, nipCO/order_connection_test.go and
// nipcw/circlehub_connection_test.go.
import { describe, expect, test } from 'vitest'
import { utf8 } from '../src/core/bytes.js'
import {
  chainSignedMessagePrefix,
  connectionDigest,
  connectionSignedText,
  connFieldsOf,
  CoreError,
  decodeAnyConnection,
  decodeCashHubConnection,
  decodeCircleHubConnection,
  decodeOrderConnection,
  encodeCashHubConnection,
  encodeCircleHubConnection,
  encodeOrderConnection,
  fromHex,
  getPublicKey,
  hubIdentityEqual,
  LOOKALIKE_MARKS,
  onlineCheck,
  qrForm,
  relayHashOf,
  sanitizeText,
  signCircleHubConnection,
  signConnection,
  sniff,
  toHex,
  validChainName,
  verifyCashHubConnection,
  verifyCircleHubConnection,
  verifyConnection,
  verifyOrderConnection,
  type HubConnection,
} from '../src/core/index.js'
import { fill, HUB_KEY, rawBech32, type RawTLV } from './helpers.js'

const PUBKEY = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
const IDENTITY = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const RELAY = 'wss://relay.example.com'
const range = (from: number) => toHex(Uint8Array.from({ length: 32 }, (_, i) => from + i))
const KEY2 = Uint8Array.of(...fill(0, 31), 2)

const K_CH_1 =
  'cashhub1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzyqszzg3rysjjvfeg9y4zktpd9chnqvfjxv6r2d3h8qun5weu85lr7qcsg9kxjcm9yaejqsmpwd5zqjr4vgzzq7d7vel0nh9m4326qc54e6rskpczn07dktww9rv4nu5ptvt0s9ucq4q377sfr0m7hp53amvskrznsqm50ld4vpkxdm3ddl852cszj7hrs4yg2lfx9693az8l4qhk3mex6v67va8sae5q2epsph453eyy9d45zvqsvpmzd96xxmmfdcvlu0w2'
const K_CO_1 =
  'cashorder1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzypqyzsjrg3z5v36gf99yknzdfe84q52j2d2924jhtpv45k6ut4097qc5g9kxjcm9yaejqcmpwd5zqcm0w4h8getjqss8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xq9gy079m5vml5lhete5l55tj2xs3dc0utwlzmp05fuars7sgx9k9q94qrcvyt93he0x9rzhu2gtr76ry3z3fuznp0skm4cfl29quz073phg5rqwcnfw33k76twqxha8f'
const K_CWH_1 =
  'circlehub1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzyqszzg3rysjjvfeg9y4zktpd9chnqvfjxv6r2d3h8qun5weu85lr7qcng9jxzfmnyprxzmtfd3ujqsmfwf3kcegyypumuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqtesp2pruz886khdq7pmdm0v9uyc5pmnlsp34xme8djme07vp9elacp0edw2nx04n8ldyhuufvsr90xyevlpynnq7v0tfsn6mts8ypjs7c9agzmqcrky6t5vdhkjms0uy6sx'

interface Kat {
  readonly hrp: 'cashhub' | 'cashorder' | 'circlehub'
  readonly s: string
  readonly length: number
  readonly secret: string
  readonly label?: string
  readonly relayHash: string
  readonly labelHash: string
  readonly digest: string
  readonly sig: string
}
const KATS: Kat[] = [
  {
    hrp: 'cashhub',
    s: K_CH_1,
    length: 368,
    secret: range(0x20),
    label: "Alice's Cash Hub",
    relayHash: '16c4c4164c27d448128dabf8052dddd5b30c61904b7b7c1b85e1486c37b7a500',
    labelHash: 'b5d2b9a2a7f9519d7367521d3a125f882cc34bbcc6f2844aed18533f5f724294',
    digest: 'c4976825128c4be05a7c553d29852f9611667832eb6d2c096417cd7a6c8817dd',
    sig: '1f7a091bf7eb8691eed90b0c53803747fdb5606c66ee2d6fcf45620297ae38548857d262e8b1e88ffa82f68ef26d335e674f0ee680564300deb48e4842b6b41301',
  },
  {
    hrp: 'cashorder',
    s: K_CO_1,
    length: 376,
    secret: range(0x40),
    label: "Alice's cash counter",
    relayHash: '1681e7f0cca2d68c5a2a57e369f815529f0127b2a118adfeafa2f0edadb4d3d5',
    labelHash: '4415045cc4156b398d107e30b03adc967e5cafa1008863146c4467e79f6ed76f',
    digest: '0d819a660d269d960d5d898ca15a21fe79eab05c37c2949a973f4377d1180c28',
    sig: '1fe2ee8cdfe9fbe579a7e945c946845b87f16ef8b617d13ce8e1e820c5b1405a8078611658df2f31462bf14858fda192228a782985f0b6eb84fd450704ff443745',
  },
  {
    hrp: 'circlehub',
    s: K_CWH_1,
    length: 375,
    secret: range(0x20),
    label: "Ada's Family Circle",
    relayHash: '16c4c4164c27d448128dabf8052dddd5b30c61904b7b7c1b85e1486c37b7a500',
    labelHash: 'c7c2b59bc693ccb3290c0a51e5c3114e49d382ba14d374ad9b1a17ffdb1750c1',
    digest: '7c945cb9b96fd8a62c973c42661e572ed186026a012cd7d4882c2eccc1cf1356',
    sig: '1f0473ead7683c1db76f61784c503b9fe018d4dbc9db2de5fe604b9ff7017e5ae54ccfaccff692fce2590195e62659f092730798f5a613d6d703903287b05ea05b',
  },
]
const LABELS = { cashhub: 'cash-hub:v1', cashorder: 'cash-order:v1', circlehub: 'circle-hub:v1' } as const
const codec = {
  cashhub: { decode: decodeCashHubConnection, encode: encodeCashHubConnection, verify: verifyCashHubConnection },
  cashorder: { decode: decodeOrderConnection, encode: encodeOrderConnection, verify: verifyOrderConnection },
  circlehub: { decode: decodeCircleHubConnection, encode: encodeCircleHubConnection, verify: verifyCircleHubConnection },
} as const

/** The KAT's TLV entries, for hand-built variants. */
const entries = (k: Kat, over: Partial<Record<number, RawTLV[1] | null>> = {}, extra: RawTLV[] = []): RawTLV[] => {
  const base: [number, RawTLV[1]][] = [
    [0, fromHex(PUBKEY)],
    [1, RELAY],
    [2, fromHex(k.secret)],
    [3, k.label!],
    [4, fromHex(IDENTITY)],
    [5, fromHex(k.sig)],
    [6, 'bitcoin'],
  ]
  const out: RawTLV[] = []
  for (const [t, v] of base) {
    const o = over[t]
    if (o === null) continue
    out.push([t, o ?? v])
  }
  return [...out, ...extra]
}

describe('T-1201 / T-1203 the NIP examples (K-CH-1, K-CO-1, K-CWH-1)', () => {
  test.each(KATS)('$hrp decodes, verifies and re-encodes byte for byte', (k) => {
    const c = codec[k.hrp].decode(k.s)
    expect(k.s).toHaveLength(k.length)
    expect(c).toMatchObject({ walletPubkey: PUBKEY, secret: k.secret, relays: [RELAY], label: k.label, hubIdentity: IDENTITY, chain: 'bitcoin' })
    expect(toHex(c.signature)).toBe(k.sig)
    expect(codec[k.hrp].verify(c)).toEqual({ verified: true })
    expect(codec[k.hrp].encode(c)).toBe(k.s)
    expect(sniff(k.s)).toBe(k.hrp)
  })
  test.each(KATS)('$hrp signed text, digest and TLV 5 (private key 1, header 31)', (k) => {
    const c = codec[k.hrp].decode(k.s)
    expect(relayHashOf([utf8(RELAY)], k.secret)).toBe(k.relayHash)
    expect(connectionSignedText(k.hrp, c)).toBe(`${LABELS[k.hrp]}:bitcoin:${PUBKEY}:${IDENTITY}:${k.relayHash}:${k.labelHash}`)
    expect(toHex(connectionDigest(connFieldsOf(k.hrp, c))!)).toBe(k.digest)
    const sig = signConnection(connFieldsOf(k.hrp, c), HUB_KEY)
    expect(toHex(sig)).toBe(k.sig)
    expect(sig[0]).toBe(31)
  })
  test('K-CH-2: without TLV 3, the text ends with ":" and the string has 339 characters', () => {
    const c = { ...decodeCashHubConnection(K_CH_1), label: '' }
    const { labelBytes: _l, ...noLabel } = c
    const text = connectionSignedText('cashhub', noLabel)
    expect(text.endsWith(':16c4c4164c27d448128dabf8052dddd5b30c61904b7b7c1b85e1486c37b7a500:')).toBe(true)
    expect(toHex(connectionDigest(connFieldsOf('cashhub', noLabel))!)).toBe('bd39cc19f477bb273774acdef3ed94f8b8a7f9954bb6363a913d6200c48d5c73')
    const sig = signConnection(connFieldsOf('cashhub', noLabel), HUB_KEY)
    expect(toHex(sig)).toBe('1fde47e84298e41bec6555ebe870bd44ec3467ea474386b0a4775b0416a26c55642a57810577e59f31ac0e74164749dbe942ea83f5b8a60cdd62ca16c945ca964c')
    const s = encodeCashHubConnection({ ...noLabel, signature: sig })
    expect(s).toHaveLength(339)
    expect(verifyCashHubConnection(decodeCashHubConnection(s))).toEqual({ verified: true })
  })
  test('a present empty TLV 3 hashes as sha256(""), and the encoder refuses to emit it', () => {
    const k = KATS[0]!
    const c = decodeCashHubConnection(rawBech32('cashhub', entries(k, { 3: '' })))
    expect(c.labelBytes).toEqual(new Uint8Array())
    expect(connectionSignedText('cashhub', c).endsWith(':e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe(true)
    expect(() => encodeCashHubConnection(c)).toThrow(CoreError)
  })
  test('every encoder refuses an unsigned connection', () => {
    const { signature: _s, ...unsigned } = decodeCashHubConnection(K_CH_1)
    for (const h of Object.values(codec)) expect(() => h.encode(unsigned)).toThrow(CoreError)
  })
  test('chainSignedMessagePrefix', () => {
    expect(chainSignedMessagePrefix('bitcoin')).toBe('Lightning Signed Message:')
    expect(chainSignedMessagePrefix('bitcoin-x')).toBeUndefined()
  })
  test('a non-UTF-8 relay hint is hashed as encoded and listed as decoded', () => {
    const k = KATS[0]!
    const odd = Uint8Array.of(0xff, 0x01)
    const fields = { ...decodeCashHubConnection(K_CH_1), relays: [RELAY], relayBytes: [utf8(RELAY), odd] }
    const sig = signConnection(connFieldsOf('cashhub', fields), HUB_KEY)
    const c = decodeCashHubConnection(rawBech32('cashhub', [...entries(k, { 5: sig }), [1, odd]]))
    expect(c.relays).toEqual([RELAY, '\uFFFD\u0001'])
    expect(verifyCashHubConnection(c)).toEqual({ verified: true })
  })
})

describe('T-1202 refusals (K-CO-2, K-CWH-2)', () => {
  const co = KATS[1]!
  const cwh = KATS[2]!
  test.each<[string, Partial<Record<number, RawTLV[1] | null>>, RawTLV[]]>([
    ['no TLV 0', { 0: null }, []],
    ['no TLV 2', { 2: null }, []],
    ['no TLV 4', { 4: null }, []],
    ['no TLV 5', { 5: null }, []],
    ['no TLV 6', { 6: null }, []],
    ['a 31-byte TLV 0', { 0: fill(1, 31) }, []],
    ['a 64-byte TLV 5', { 5: fill(1, 64) }, []],
    ['TLV 6 empty', { 6: '' }, []],
    ['TLV 6 Bitcoin', { 6: 'Bitcoin' }, []],
    ['TLV 6 of 33 bytes', { 6: 'a'.repeat(33) }, []],
    ['TLV 3 twice', {}, [[3, 'x']]],
    ['TLV 5 twice', {}, [[5, fill(1, 65)]]],
    ['TLV 6 twice', {}, [[6, 'bitcoin']]],
  ])('K-CO-2 refuses %s; the same for cashhub1', (_, over, extra) => {
    expect(() => decodeOrderConnection(rawBech32('cashorder', entries(co, over, extra)))).toThrow(CoreError)
    expect(() => decodeCashHubConnection(rawBech32('cashhub', entries({ ...KATS[0]! }, over, extra)))).toThrow(CoreError)
  })
  test.each<[string, Partial<Record<number, RawTLV[1] | null>>, RawTLV[]]>([
    ['no TLV 4', { 4: null }, []],
    ['no TLV 5', { 5: null }, []],
    ['no TLV 6', { 6: null }, []],
    ['a 31-byte TLV 4', { 4: fill(1, 31) }, []],
    ['TLV 6 bit_coin', { 6: 'bit_coin' }, []],
    ['TLV 4 twice', {}, [[4, fromHex(IDENTITY)]]],
  ])('K-CWH-2 refuses %s', (_, over, extra) => {
    const err = (() => {
      try {
        decodeCircleHubConnection(rawBech32('circlehub', entries(cwh, over, extra)))
      } catch (e) {
        return e
      }
      return undefined
    })()
    expect(err).toBeInstanceOf(CoreError)
    expect((err as CoreError).code).toBe('invalid_tlv')
  })
  test('an extra TLV 9 decodes, is ignored and stays outside the signature (K-CO-2, K-CSIG-1)', () => {
    const c = decodeOrderConnection(rawBech32('cashorder', entries(co, {}, [[9, 'future']])))
    expect(verifyOrderConnection(c)).toEqual({ verified: true })
    expect(encodeOrderConnection(c)).toBe(K_CO_1)
    const h = decodeCashHubConnection(rawBech32('cashhub', entries(KATS[0]!, {}, [[9, 'x']])))
    expect(verifyCashHubConnection(h)).toEqual({ verified: true })
  })
})

describe('T-1204 unverified strings (K-CSIG-1, K-CHAIN-1)', () => {
  test('TLV 6 bitcoin-x with the signature kept: decodes, unverified (chain_no_prefix)', () => {
    const c = decodeOrderConnection(rawBech32('cashorder', entries(KATS[1]!, { 6: 'bitcoin-x' })))
    expect(c.chain).toBe('bitcoin-x')
    expect(verifyOrderConnection(c)).toEqual({ verified: false, reason: 'chain_no_prefix' })
  })
  test('TLV 3 changed with the signature kept: unverified (signer_mismatch)', () => {
    const c = decodeOrderConnection(rawBech32('cashorder', entries(KATS[1]!, { 3: "Bob's cash counter" })))
    expect(verifyOrderConnection(c)).toEqual({ verified: false, reason: 'signer_mismatch' })
  })
  test('signed by private key 2 with TLV 4 still private key 1: unverified (signer_mismatch)', () => {
    const c = decodeCircleHubConnection(K_CWH_1)
    expect(() => signCircleHubConnection(c, KEY2)).toThrow(CoreError)
    const forged = signConnection({ ...connFieldsOf('circlehub', c), hubIdentity: getPublicKey(KEY2) }, KEY2)
    expect(verifyConnection(connFieldsOf('circlehub', c), forged)).toEqual({ verified: false, reason: 'signer_mismatch' })
    const s = rawBech32('circlehub', entries(KATS[2]!, { 5: forged }))
    expect(verifyCircleHubConnection(decodeCircleHubConnection(s))).toEqual({ verified: false, reason: 'signer_mismatch' })
  })
  test.each([
    ['bitcoin', true],
    ['a'.repeat(32), true],
    ['bitcoin-x', true],
    ['', false],
    ['Bitcoin', false],
    ['bit coin', false],
    ['bit_coin', false],
    ['a'.repeat(33), false],
  ])('K-CHAIN-1 %j valid=%s, and the decoder agrees', (chain, ok) => {
    expect(validChainName(chain)).toBe(ok)
    const decode = () => decodeCashHubConnection(rawBech32('cashhub', entries(KATS[0]!, { 6: chain })))
    if (ok) expect(decode().chain).toBe(chain)
    else expect(decode).toThrow(CoreError)
  })
})

describe('T-1205 online check (K-ONL-1)', () => {
  const conn = { hubIdentity: IDENTITY, chain: 'bitcoin' }
  test.each([IDENTITY, `02${IDENTITY}`, `03${IDENTITY}`, IDENTITY.toUpperCase()])('identity %s passes', (identity) => {
    expect(hubIdentityEqual(IDENTITY, identity)).toBe(true)
    expect(() => onlineCheck(conn, { identity, chain: 'bitcoin' })).not.toThrow()
  })
  test.each([`04${IDENTITY}`, `${IDENTITY.slice(0, 63)}9`])('identity %s fails hub_identity_mismatch', (identity) => {
    expect(hubIdentityEqual(IDENTITY, identity)).toBe(false)
    expect(() => onlineCheck(conn, { identity, chain: 'bitcoin' })).toThrow(expect.objectContaining({ code: 'hub_identity_mismatch' }))
  })
  test('a missing identity fails', () => {
    expect(() => onlineCheck(conn, { chain: 'bitcoin' })).toThrow(expect.objectContaining({ code: 'hub_identity_mismatch' }))
  })
  test.each<[string, unknown]>([
    ['Bitcoin', 'Bitcoin'],
    ['absent', undefined],
    ['a number', 1],
  ])('chain %s fails chain_mismatch', (_, chain) => {
    expect(() => onlineCheck(conn, { identity: IDENTITY, chain })).toThrow(expect.objectContaining({ code: 'chain_mismatch' }))
  })
})

describe('T-1208 uppercase QR form', () => {
  test.each(KATS)('$hrp: qrForm decodes to the same connection; mixed case is refused', (k) => {
    expect(qrForm(k.s)).toBe(k.s.toUpperCase())
    expect(codec[k.hrp].decode(qrForm(k.s))).toEqual(codec[k.hrp].decode(k.s))
    const mixed = k.s.slice(0, 12) + k.s.slice(12).toUpperCase()
    expect(() => codec[k.hrp].decode(mixed)).toThrow(expect.objectContaining({ code: 'mixed_case' }))
  })
})

describe('T-1210 paste routing', () => {
  test.each(KATS)('decodeAnyConnection($hrp) gives kind, connection and verdict', (k) => {
    const r = decodeAnyConnection(`  ${k.s}\n`)
    expect(r.kind).toBe(k.hrp)
    expect(r.connection.walletPubkey).toBe(PUBKEY)
    expect(r.verdict).toEqual({ verified: true })
    expect(decodeAnyConnection(qrForm(k.s)).kind).toBe(k.hrp)
  })
  test('an unverified string decodes with its reason', () => {
    const s = rawBech32('cashorder', entries(KATS[1]!, { 6: 'bitcoin-x' }))
    expect(decodeAnyConnection(s).verdict).toEqual({ verified: false, reason: 'chain_no_prefix' })
  })
  test('a token, a URI or an nconnection is not a connection string', () => {
    expect(() => decodeAnyConnection('nostr+walletconnect://abc')).toThrow()
    expect(() => decodeAnyConnection(rawBech32('satscash', [[0, fill(1, 32)], [1, RELAY], [2, fill(2, 32)]]))).toThrow(CoreError)
    expect(sniff('nostr+walletconnect://abc?relay=wss://r&secret=x')).toBe('nwc_uri')
  })
  test('a connection decoded once keeps its raw bytes for the signature', () => {
    const c: HubConnection = decodeCircleHubConnection(K_CWH_1)
    expect(c.relayBytes).toEqual([utf8(RELAY)])
    expect(c.labelBytes).toEqual(utf8("Ada's Family Circle"))
  })
})

describe('K-TXT-1 sanitizeText', () => {
  test.each<[string, string, number, string]>([
    ['zero-width and bidi controls', 'Alice​\'s‮ cash counter', 40, "Alice's cash counter"],
    ['a check-mark look-alike', '✔ Alice', 40, ' Alice'],
    ['a line break', 'A\nB', 40, 'A B'],
    ['41 ASCII letters, title cap', 'a'.repeat(41), 40, 'a'.repeat(40)],
    ['é ×41, title cap', 'é'.repeat(41), 40, 'é'.repeat(40)],
    ['281 ASCII letters, content cap', 'a'.repeat(281), 280, 'a'.repeat(280)],
  ])('%s', (_, input, cap, want) => {
    expect(sanitizeText(input, cap)).toBe(want)
  })
  test('every look-alike mark is removed; a cluster is one character; links stay plain text', () => {
    expect(sanitizeText(LOOKALIKE_MARKS.join('x'), 40)).toBe('x'.repeat(LOOKALIKE_MARKS.length - 1))
    expect(sanitizeText('é'.repeat(3), 2)).toBe('éé')
    expect(sanitizeText('see https://example.com\tnow', 40)).toBe('see https://example.com now')
  })
})
