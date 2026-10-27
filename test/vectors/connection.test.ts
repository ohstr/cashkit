// vectors/connection.json: the signed Hub connection strings (cashhub1,
// cashorder1, circlehub1): signing KATs, decode, encode, verify, chain names
// and the online check.
import { describe, expect, test } from 'vitest'
import {
  chainSignedMessagePrefix,
  connectionDigest,
  connFieldsOf,
  connSignedText,
  decodeCashHubConnection,
  decodeCircleHubConnection,
  decodeOrderConnection,
  encodeCashHubConnection,
  encodeCircleHubConnection,
  encodeOrderConnection,
  fromHex,
  fromUtf8,
  onlineCheck,
  relayHashOf,
  signConnection,
  toHex,
  validChainName,
  verifyCashHubConnection,
  verifyCircleHubConnection,
  verifyOrderConnection,
  type HubConnection,
  type HubConnectionFields,
} from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('connection.json')
const KEY1 = Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0))

const decoders: Record<string, (s: string) => HubConnection> = { cashhub: decodeCashHubConnection, cashorder: decodeOrderConnection, circlehub: decodeCircleHubConnection }
const encoders: Record<string, (c: HubConnectionFields) => string> = { cashhub: encodeCashHubConnection, cashorder: encodeOrderConnection, circlehub: encodeCircleHubConnection }
const verifiers: Record<string, (c: HubConnection) => { verified: boolean }> = { cashhub: verifyCashHubConnection, cashorder: verifyOrderConnection, circlehub: verifyCircleHubConnection }

/** Vector fields as cashkit's: `pubkey` is the wallet pubkey; a null label is none, an empty one is an empty TLV 3. */
function fieldsOf(f: Json): HubConnectionFields {
  return {
    walletPubkey: f.pubkey,
    secret: f.secret,
    relays: f.relays ?? [],
    label: f.label ?? '',
    ...(f.label === '' && { labelBytes: new Uint8Array(0) }),
    hubIdentity: f.hubIdentity,
    chain: f.chain,
    ...(f.signature !== null && f.signature !== undefined && { signature: fromHex(f.signature) }),
  }
}

/** A decoded string in vector form: every TLV 1 as encoded, the label null when absent. */
function asVector(c: HubConnection, verified: boolean) {
  return {
    pubkey: c.walletPubkey,
    relays: c.relayBytes.map((b) => fromUtf8(b)),
    secret: c.secret,
    label: c.labelBytes !== undefined ? c.label : null,
    hubIdentity: c.hubIdentity,
    signature: toHex(c.signature),
    chain: c.chain,
    verified,
  }
}

describe('kats: the signing steps', () => {
  test.each(named(v.kats, (c) => c.id))('%s', (_, c: Json) => {
    const f = connFieldsOf(c.kind, fieldsOf(c.inputs))
    expect(relayHashOf(f.relayBytes, f.secret)).toBe(c.relayHash)
    expect(connSignedText(f)).toBe(c.text)
    expect(c.text.split(':').at(-1)).toBe(c.labelHash ?? '')
    expect(chainSignedMessagePrefix(c.inputs.chain)).toBe(c.prefix)
    expect(toHex(connectionDigest(f)!)).toBe(c.digest)
    const sig = signConnection(f, KEY1)
    expect(toHex(sig)).toBe(c.signature)
    expect(sig[0]).toBe(c.header)
    const s = encoders[c.kind]!({ ...fieldsOf(c.inputs), signature: sig })
    expect(s).toBe(c.string)
    if (c.length !== undefined) expect(s.length).toBe(c.length)
  })
})

describe('decode', () => {
  test.each(named(v.decode, (c) => `${c.kind}: ${c.name}`))('%s', (_, c: Json) => {
    if (c.error) {
      expect(() => decoders[c.kind]!(c.input)).toThrow()
      return
    }
    const d = decoders[c.kind]!(c.input)
    const { verifyError: _e, ...want } = c.want
    expect(asVector(d, verifiers[c.kind]!(d).verified)).toEqual(want)
  })
})

describe('encode', () => {
  test.each(named(v.encode, (c) => `${c.kind}: ${c.name}`))('%s', (_, c: Json) => {
    if (c.error) expect(() => encoders[c.kind]!(fieldsOf(c.fields))).toThrow()
    else expect(encoders[c.kind]!(fieldsOf(c.fields))).toBe(c.output)
  })
})

describe('verify', () => {
  test.each(named(v.verify, (c) => `${c.kind}: ${c.name}`))('%s', (_, c: Json) => {
    const d = decoders[c.kind]!(c.input)
    expect(verifiers[c.kind]!(d).verified).toBe(c.verify === '')
  })
})

describe('chain names and the online check', () => {
  test.each(named(v.chainName, (c) => JSON.stringify(c.value)))('validChainName %s', (_, c: Json) => {
    expect(validChainName(c.value)).toBe(c.valid)
  })
  test.each(named(v.onlineCheck, (c, i) => `${c.id} #${i} ${c.infoIdentity} ${c.infoChain}`))('%s', (_, c: Json) => {
    const run = () => onlineCheck({ hubIdentity: c.hubIdentity, chain: c.chain }, { ...(c.infoIdentity !== null && { identity: c.infoIdentity }), ...(c.infoChain !== null && { chain: c.infoChain }) })
    if (c.error) expect(run).toThrow()
    else expect(run).not.toThrow()
  })
})

