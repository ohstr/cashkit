// nconnection1 (NIP-IC): 0 connection key (exactly one, 32 bytes), 1 relay
// (ASCII, repeatable), 2 platform (at most one, [a-z0-9._-]+). Port of nmilat
// nipIC/nconnection.go: a duplicate key or platform, a bad platform name and
// a truncated or overrunning TLV are refused; unknown types are ignored.
import { bech32Encode, toWords } from './bech32.js'
import { concatBytes, fromUtf8, toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'
import { validPlatformName } from './idna.js'
import { decodeBech32TLV, keyFromHex } from './tlv.js'

const PLATFORM_NAME = 'nipIC: platform name must match [a-z0-9._-]+'
const HEX64 = /^[0-9a-f]{64}$/

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
  let havePlatform = false
  for (let pos = 0; pos < data.length; ) {
    if (pos + 2 > data.length) throw new CoreError('invalid_tlv', `nipIC: truncated TLV at offset ${pos}`)
    const type = data[pos]!
    const len = data[pos + 1]!
    pos += 2
    if (pos + len > data.length) throw new CoreError('invalid_tlv', `nipIC: TLV at offset ${pos - 2} runs past the end`)
    const value = data.subarray(pos, pos + len)
    pos += len
    switch (type) {
      case 0:
        if (connectionKey !== '') throw new CoreError('invalid_tlv', 'nipIC: more than one ConnectionKey')
        if (len !== 32) throw new CoreError('invalid_tlv', `nipIC: ConnectionKey must be 32 bytes, got ${len}`)
        connectionKey = toHex(value)
        break
      case 1:
        relays.push(fromUtf8(value))
        break
      case 2:
        if (havePlatform) throw new CoreError('invalid_tlv', 'nipIC: more than one platform')
        havePlatform = true
        platform = fromUtf8(value)
        if (!validPlatformName(platform)) throw new CoreError('invalid_tlv', PLATFORM_NAME)
        break
      default:
    }
  }
  if (connectionKey === '') throw new CoreError('invalid_tlv', 'nipIC: nconnection missing ConnectionKey')
  return { connectionKey, relays, platform }
}

/**
 * Encodes an nconnection1 string. Refuses a key that is not 64 lowercase hex,
 * a relay that is not ASCII or exceeds 255 bytes (blank relays are written as
 * given), and a platform outside [a-z0-9._-]+.
 */
export function encodeNConnection(c: NConnection): string {
  if (!HEX64.test(c.connectionKey)) throw new CoreError('invalid_field', 'nipIC: a ConnectionKey is 64 lowercase hex characters')
  const parts: Uint8Array[] = [Uint8Array.of(0, 32), keyFromHex(c.connectionKey, 'connection key')]
  for (const r of c.relays) {
    // oxlint-disable-next-line no-control-regex
    if (r.length > 255 || !/^[\x00-\x7f]*$/.test(r)) throw new CoreError('invalid_field', `nipIC: relay ${JSON.stringify(r)} is not an ASCII URL of at most 255 bytes`)
    parts.push(Uint8Array.of(1, r.length), utf8(r))
  }
  if (c.platform !== '') {
    if (!validPlatformName(c.platform) || c.platform.length > 255) throw new CoreError('invalid_field', PLATFORM_NAME)
    parts.push(Uint8Array.of(2, c.platform.length), utf8(c.platform))
  }
  return bech32Encode(NCONNECTION_HRP, toWords(concatBytes(...parts)))
}
