// cashhub1 (NIP-CASH) and circlehub1 (NIP-CW) connection strings. They share
// one layout: 0 pubkey, 1 relay, 2 secret, 3 optional label. Port of nmilat
// nipcash/cashhub_connection.go and nipcw/circlehub_connection.go.
import { fromUtf8, toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'
import {
  KEY_LEN,
  MAX_TLV_VALUE_LEN,
  countUsableRelays,
  decodeBech32TLV,
  encodeBech32TLV,
  keyFromHex,
  readTLVs,
  relayEntries,
  type TLVEntry,
} from './tlv.js'

export const CASH_HUB_HRP = 'cashhub'
export const CIRCLE_HUB_HRP = 'circlehub'

/** A Hub connection. Secret-bearing (design §10). */
export interface HubConnection {
  /** Hex, 32 bytes: the Hub's own pubkey. */
  readonly walletPubkey: string
  /** Hex, 32 bytes: the NWC connection secret. */
  readonly secret: string
  readonly relays: readonly string[]
  /** "" when not set. */
  readonly label: string
}

const T_LABEL = 3

function decodeHub(s: string, wantHrp: string): HubConnection {
  const invalid = (msg: string) => new CoreError('invalid_tlv', `${wantHrp}: ${msg}`)
  const { hrp, data } = decodeBech32TLV(s)
  if (hrp !== wantHrp) throw invalid(`unexpected hrp, want ${wantHrp}`)

  let walletPubkey: string | undefined
  let secret: string | undefined
  let label: string | undefined
  const relays: string[] = []
  for (const { type, value } of readTLVs(data)) {
    switch (type) {
      case 0:
        if (value.length !== KEY_LEN) throw invalid(`wallet pubkey must be ${KEY_LEN} bytes, got ${value.length}`)
        if (walletPubkey !== undefined) throw invalid('duplicate wallet pubkey entry')
        walletPubkey = toHex(value)
        break
      case 1:
        relays.push(fromUtf8(value))
        break
      case 2:
        if (value.length !== KEY_LEN) throw invalid(`secret must be ${KEY_LEN} bytes, got ${value.length}`)
        if (secret !== undefined) throw invalid('duplicate secret entry')
        secret = toHex(value)
        break
      case T_LABEL:
        if (label !== undefined) throw invalid('duplicate label entry')
        label = fromUtf8(value)
        break
      default:
    }
  }
  if (walletPubkey === undefined) throw invalid('missing wallet pubkey')
  if (secret === undefined) throw invalid('missing secret')
  if (countUsableRelays(relays) === 0) throw invalid('no usable relay url, so the hub is unreachable')
  return { walletPubkey, secret, relays, label: label ?? '' }
}

function encodeHub(c: HubConnection, hrp: string): string {
  const entries: TLVEntry[] = [{ type: 0, value: keyFromHex(c.walletPubkey, 'wallet pubkey') }]
  const secret = keyFromHex(c.secret, 'secret')
  entries.push(...relayEntries(c.relays, `a ${hrp} connection`))
  entries.push({ type: 2, value: secret })
  const label = utf8(c.label)
  if (label.length > MAX_TLV_VALUE_LEN) throw new CoreError('invalid_field', `label exceeds ${MAX_TLV_VALUE_LEN} bytes`)
  if (label.length > 0) entries.push({ type: T_LABEL, value: label })
  return encodeBech32TLV(hrp, entries)
}

export const decodeCashHubConnection = (s: string): HubConnection => decodeHub(s, CASH_HUB_HRP)
export const encodeCashHubConnection = (c: HubConnection): string => encodeHub(c, CASH_HUB_HRP)
export const decodeCircleHubConnection = (s: string): HubConnection => decodeHub(s, CIRCLE_HUB_HRP)
export const encodeCircleHubConnection = (c: HubConnection): string => encodeHub(c, CIRCLE_HUB_HRP)
