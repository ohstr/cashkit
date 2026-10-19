// NIP-19 bech32 entities as nmilat encodes and decodes them. Port of nmilat
// nip19/nip19.go, quirks included: npub/nsec/note accept more than 32 bytes
// and keep the first 32, their encoders take any length, and a truncated
// TLV tail is ignored.
import { bech32Decode, bech32Encode, fromWords, toWords } from './bech32.js'
import { concatBytes, fromHex, fromUtf8, toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'

const fail = (msg: string) => new CoreError('invalid_tlv', `nip19: ${msg}`)

function decodeBytes(s: string, want?: string): { hrp: string; data: Uint8Array } {
  const { hrp, words } = bech32Decode(s)
  if (want !== undefined && hrp !== want) throw fail(`expected ${want}, got ${hrp}`)
  return { hrp, data: fromWords(words) }
}

function decodeSimple(s: string, want: 'npub' | 'nsec' | 'note'): string {
  const { data } = decodeBytes(s, want)
  if (data.length < 32) throw fail(`data is less than 32 bytes (${data.length})`)
  return toHex(data.subarray(0, 32))
}

const encodeSimple = (hrp: string, hex: string, field: string) => bech32Encode(hrp, toWords(fromHex(hex, field)))

export const decodeNpub = (s: string): string => decodeSimple(s, 'npub')
export const decodeNsec = (s: string): string => decodeSimple(s, 'nsec')
export const decodeNote = (s: string): string => decodeSimple(s, 'note')
export const encodeNpub = (pubkeyHex: string): string => encodeSimple('npub', pubkeyHex, 'public key')
export const encodeNsec = (secretHex: string): string => encodeSimple('nsec', secretHex, 'private key')
export const encodeNote = (idHex: string): string => encodeSimple('note', idHex, 'event id')

/** All values per TLV type, stopping quietly at a truncated entry. */
function readTLVMap(data: Uint8Array): Map<number, Uint8Array[]> {
  const out = new Map<number, Uint8Array[]>()
  let pos = 0
  while (pos + 2 <= data.length) {
    const type = data[pos]!
    const len = data[pos + 1]!
    pos += 2
    if (pos + len > data.length) break
    out.set(type, [...(out.get(type) ?? []), data.subarray(pos, pos + len)])
    pos += len
  }
  return out
}

function writeTLV(entries: [number, Uint8Array][]): Uint8Array {
  const parts: Uint8Array[] = []
  for (const [type, value] of entries) {
    if (value.length > 255) throw fail(`tlv value for type ${type} exceeds 255 bytes (${value.length})`)
    parts.push(Uint8Array.of(type, value.length), value)
  }
  return concatBytes(...parts)
}

function key32(hex: string, field: string): Uint8Array {
  const b = fromHex(hex, field)
  if (b.length !== 32) throw fail(`${field} must be 32 bytes, got ${b.length}`)
  return b
}

const u32 = (n: number) => {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n >>> 0)
  return b
}
const readU32 = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, 4).getUint32(0)

export interface ProfilePointer {
  readonly pubkey: string
  readonly relays: readonly string[]
}

export function encodeNprofile(p: ProfilePointer): string {
  const entries: [number, Uint8Array][] = [[0, key32(p.pubkey, 'public key')], ...p.relays.map((r): [number, Uint8Array] => [1, utf8(r)])]
  return bech32Encode('nprofile', toWords(writeTLV(entries)))
}

export function decodeNprofile(s: string): ProfilePointer {
  const tlv = readTLVMap(decodeBytes(s, 'nprofile').data)
  const pks = tlv.get(0) ?? []
  if (pks.length !== 1 || pks[0]!.length !== 32) throw fail('nprofile public key missing or not 32 bytes')
  return { pubkey: toHex(pks[0]!), relays: (tlv.get(1) ?? []).map(fromUtf8) }
}

export interface EventPointer {
  readonly id: string
  readonly relays: readonly string[]
  /** "" when absent. */
  readonly author: string
  /** 0 when absent. */
  readonly kind: number
}

export function encodeNevent(p: EventPointer): string {
  const entries: [number, Uint8Array][] = [[0, key32(p.id, 'event id')], ...p.relays.map((r): [number, Uint8Array] => [1, utf8(r)])]
  if (p.author !== '') entries.push([2, key32(p.author, 'author pubkey')])
  if (p.kind !== 0) entries.push([3, u32(p.kind)])
  return bech32Encode('nevent', toWords(writeTLV(entries)))
}

export function decodeNevent(s: string): EventPointer {
  const tlv = readTLVMap(decodeBytes(s, 'nevent').data)
  const ids = tlv.get(0) ?? []
  if (ids.length !== 1 || ids[0]!.length !== 32) throw fail('nevent event id missing or not 32 bytes')
  const authors = tlv.get(2) ?? []
  const kinds = tlv.get(3) ?? []
  return {
    id: toHex(ids[0]!),
    relays: (tlv.get(1) ?? []).map(fromUtf8),
    author: authors.length === 1 && authors[0]!.length === 32 ? toHex(authors[0]!) : '',
    kind: kinds.length === 1 && kinds[0]!.length === 4 ? readU32(kinds[0]!) : 0,
  }
}

export interface AddressPointer {
  readonly identifier: string
  readonly pubkey: string
  readonly kind: number
  readonly relays: readonly string[]
}

export function encodeNaddr(p: AddressPointer): string {
  const pk = key32(p.pubkey, 'public key')
  const entries: [number, Uint8Array][] = [
    [0, utf8(p.identifier)],
    ...p.relays.map((r): [number, Uint8Array] => [1, utf8(r)]),
    [2, pk],
    [3, u32(p.kind)],
  ]
  return bech32Encode('naddr', toWords(writeTLV(entries)))
}

export function decodeNaddr(s: string): AddressPointer {
  const tlv = readTLVMap(decodeBytes(s, 'naddr').data)
  const idents = tlv.get(0) ?? []
  if (idents.length !== 1) throw fail('naddr identifier missing')
  const authors = tlv.get(2) ?? []
  if (authors.length !== 1 || authors[0]!.length !== 32) throw fail('naddr author pubkey missing or not 32 bytes')
  const kinds = tlv.get(3) ?? []
  if (kinds.length !== 1 || kinds[0]!.length !== 4) throw fail('naddr kind missing or not 4 bytes')
  return {
    identifier: fromUtf8(idents[0]!),
    pubkey: toHex(authors[0]!),
    kind: readU32(kinds[0]!),
    relays: (tlv.get(1) ?? []).map(fromUtf8),
  }
}
