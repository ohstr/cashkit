// vectors/nip19.json: npub, nsec, note, nprofile, nevent, naddr.
import { describe, expect, test } from 'vitest'
import { decodeNaddr, decodeNevent, decodeNote, decodeNprofile, decodeNpub, decodeNsec, encodeNaddr, encodeNevent, encodeNote, encodeNprofile, encodeNpub, encodeNsec } from '../../src/core/index.js'
import { load, named, plain, type Json } from './helpers.js'

const v = load('nip19.json')
const decoders: Record<string, (s: string) => unknown> = {
  npub: decodeNpub,
  nsec: decodeNsec,
  note: decodeNote,
  nprofile: (s) => plain(decodeNprofile(s)),
  nevent: (s) => plain(decodeNevent(s)),
  naddr: (s) => plain(decodeNaddr(s)),
}
const encoders: Record<string, (f: Json) => string> = {
  npub: encodeNpub,
  nsec: encodeNsec,
  note: encodeNote,
  nprofile: (f) => encodeNprofile({ pubkey: f.pubkey, relays: f.relays ?? [] }),
  nevent: (f) => encodeNevent({ id: f.id, relays: f.relays ?? [], author: f.author ?? '', kind: f.kind ?? 0 }),
  naddr: (f) => encodeNaddr({ identifier: f.identifier, pubkey: f.pubkey, kind: f.kind, relays: f.relays ?? [] }),
}

describe('nip19.json', () => {
  test.each(named(v.decode, (c) => `${c.kind}: ${c.name}`))('decode %s', (_, c: Json) => {
    if (c.error) expect(() => decoders[c.kind]!(c.input)).toThrow()
    else expect(decoders[c.kind]!(c.input)).toEqual(c.want)
  })
  test.each(named(v.encode, (c) => `${c.kind}: ${c.name}`))('encode %s', (_, c: Json) => {
    if (c.error) expect(() => encoders[c.kind]!(c.fields)).toThrow()
    else expect(encoders[c.kind]!(c.fields)).toBe(c.want)
  })
})
