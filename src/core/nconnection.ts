// nconnection1 (NIP-IC): 0 connection key, 1 relay, 2 platform. Port of
// nmilat nipIC/nconnection.go, including its leniency: no duplicate checks
// (the last key or platform wins), and a truncated tail is ignored rather
// than refused.
import { bech32Encode, toWords } from './bech32.js'
import { concatBytes, fromUtf8, toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'
import { decodeBech32TLV, keyFromHex } from './tlv.js'

export const NCONNECTION_HRP = 'nconnection'

export interface NConnection {
  /** Hex, 32 bytes. */
  readonly connectionKey: string
  readonly relays: readonly string[]
  /** "" when not set. */
  readonly platform: string
}

export function decodeNConnection(s: string): NConnection {
  const { hrp, data } = decodeBech32TLV(s)
  if (hrp !== NCONNECTION_HRP) throw new CoreError('invalid_tlv', `nconnection: unexpected hrp, want ${NCONNECTION_HRP}`)

  let connectionKey = ''
  let platform = ''
  const relays: string[] = []
  let pos = 0
  while (pos + 2 <= data.length) {
    const type = data[pos]!
    const len = data[pos + 1]!
    pos += 2
    if (pos + len > data.length) break
    const value = data.subarray(pos, pos + len)
    pos += len
    switch (type) {
      case 0:
        if (len !== 32) throw new CoreError('invalid_tlv', `nconnection: connection key must be 32 bytes, got ${len}`)
        connectionKey = toHex(value)
        break
      case 1:
        relays.push(fromUtf8(value))
        break
      case 2:
        platform = fromUtf8(value)
        break
      default:
    }
  }
  if (connectionKey === '') throw new CoreError('invalid_tlv', 'nconnection: missing connection key')
  return { connectionKey, relays, platform }
}

/**
 * Encodes an nconnection1 string. Like nmilat it writes every relay, blank
 * ones included; unlike nmilat it refuses a value too long for its length
 * byte instead of silently truncating the length.
 */
export function encodeNConnection(c: NConnection): string {
  const parts: Uint8Array[] = []
  const put = (type: number, value: Uint8Array) => {
    if (value.length > 255) throw new CoreError('invalid_field', `nconnection: TLV ${type} value exceeds 255 bytes`)
    parts.push(Uint8Array.of(type, value.length), value)
  }
  put(0, keyFromHex(c.connectionKey, 'connection key'))
  for (const r of c.relays) put(1, utf8(r))
  if (c.platform !== '') put(2, utf8(c.platform))
  return bech32Encode(NCONNECTION_HRP, toWords(concatBytes(...parts)))
}
