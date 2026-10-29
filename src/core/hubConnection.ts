// Signed Hub connection strings: `cashhub1` (NIP-CASH), `cashorder1`
// (NIP-CO) and `circlehub1` (NIP-CW). They share one layout: 0 connection
// pubkey, 1 relay, 2 secret, 3 optional label, 4 Hub identity, 5 connection
// signature, 6 chain. Port of nmilat nipcash/cashhub_connection.go,
// nipCO/order_connection.go and nipcw/circlehub_connection.go.
import { fromUtf8, isBlank, isUtf8, toHex } from './bytes.js'
import { connSignedText, signConnection, validChainName, verifyConnection, type ConnFields, type ConnVerdict } from './connection.js'
import { CoreError } from './errors.js'
import { MINT_SIGNATURE_LEN } from './token.js'
import { KEY_LEN, MAX_TLV_VALUE_LEN, decodeBech32TLV, encodeBech32TLV, keyFromHex, readTLVs, usableHint, type TLVEntry } from './tlv.js'

export const CASH_HUB_HRP = 'cashhub'
export const ORDER_CONNECTION_HRP = 'cashorder'
export const CIRCLE_HUB_HRP = 'circlehub'

/** A signed Hub connection. Secret-bearing (design §10). */
export interface HubConnection {
  /** Hex, 32 bytes: the connection pubkey (TLV 0). */
  readonly walletPubkey: string
  /** Hex, 32 bytes: the connection secret (TLV 2). */
  readonly secret: string
  /** The hints a client dials: non-blank printable ASCII, in encoded order. */
  readonly relays: readonly string[]
  /** Every TLV 1 exactly as encoded; the signature covers these. */
  readonly relayBytes: readonly Uint8Array[]
  /** TLV 3 read as UTF-8; "" when not set. A claim until the string verifies. */
  readonly label: string
  /** TLV 3 as encoded; undefined when the string has none. */
  readonly labelBytes?: Uint8Array
  /** TLV 4: the x-only node identity, 64 lowercase hex. */
  readonly hubIdentity: string
  /** TLV 5: the connection signature, 65 bytes. */
  readonly signature: Uint8Array
  /** TLV 6: the chain name, e.g. `bitcoin`. */
  readonly chain: string
}

/** What an encoder or signer needs: the decoded fields, with `relayBytes` taken from `relays` when absent. */
export type HubConnectionFields = Omit<HubConnection, 'relayBytes' | 'signature'> & {
  readonly relayBytes?: readonly Uint8Array[]
  readonly signature?: Uint8Array
}

const T_LABEL = 3
const T_HUB_IDENTITY = 4
const T_SIGNATURE = 5
const T_CHAIN = 6

function decodeHub(s: string, wantHrp: string): HubConnection {
  const invalid = (msg: string) => new CoreError('invalid_tlv', `${wantHrp}: ${msg}`)
  const { hrp, data } = decodeBech32TLV(s)
  if (hrp !== wantHrp) throw invalid(`unexpected hrp, want ${wantHrp}`)

  let walletPubkey: string | undefined
  let secret: string | undefined
  let labelBytes: Uint8Array | undefined
  let hubIdentity: string | undefined
  let signature: Uint8Array | undefined
  let chain: string | undefined
  const relays: string[] = []
  const relayBytes: Uint8Array[] = []
  const once = <T>(cur: T | undefined, name: string) => {
    if (cur !== undefined) throw invalid(`duplicate ${name} entry`)
  }
  for (const { type, value } of readTLVs(data)) {
    switch (type) {
      case 0:
        if (value.length !== KEY_LEN) throw invalid(`wallet pubkey must be ${KEY_LEN} bytes, got ${value.length}`)
        once(walletPubkey, 'wallet pubkey')
        walletPubkey = toHex(value)
        break
      case 1: {
        relayBytes.push(value.slice())
        const r = usableHint(value)
        if (r !== undefined) relays.push(r)
        break
      }
      case 2:
        if (value.length !== KEY_LEN) throw invalid(`secret must be ${KEY_LEN} bytes, got ${value.length}`)
        once(secret, 'secret')
        secret = toHex(value)
        break
      case T_LABEL:
        once(labelBytes, 'label')
        if (!isUtf8(value)) throw invalid('label is not valid UTF-8')
        labelBytes = value.slice()
        break
      case T_HUB_IDENTITY:
        if (value.length !== KEY_LEN) throw invalid(`hub identity must be ${KEY_LEN} bytes, got ${value.length}`)
        once(hubIdentity, 'hub identity')
        hubIdentity = toHex(value)
        break
      case T_SIGNATURE:
        if (value.length !== MINT_SIGNATURE_LEN) throw invalid(`connection signature must be ${MINT_SIGNATURE_LEN} bytes, got ${value.length}`)
        once(signature, 'connection signature')
        signature = value.slice()
        break
      case T_CHAIN: {
        once(chain, 'chain')
        const c = String.fromCharCode(...value)
        if (!validChainName(c)) throw invalid('chain must be 1 to 32 bytes of a-z, 0-9 and -')
        chain = c
        break
      }
      default:
      // A type above 6 is ignored: it is outside the signature.
    }
  }
  if (walletPubkey === undefined) throw invalid('missing wallet pubkey')
  if (secret === undefined) throw invalid('missing secret')
  if (hubIdentity === undefined) throw invalid('missing hub identity')
  if (signature === undefined) throw invalid('missing connection signature')
  if (chain === undefined) throw invalid('missing chain')
  if (relays.length === 0) throw invalid('no usable relay url, so the hub is unreachable')
  return {
    walletPubkey,
    secret,
    relays,
    relayBytes,
    label: labelBytes !== undefined ? fromUtf8(labelBytes) : '',
    ...(labelBytes !== undefined && { labelBytes }),
    hubIdentity,
    signature,
    chain,
  }
}

const labelOf = (c: HubConnectionFields): Uint8Array | undefined => c.labelBytes ?? (c.label !== '' ? new TextEncoder().encode(c.label) : undefined)

function checkRelays(relays: readonly string[]): Uint8Array[] {
  if (relays.length === 0) throw new CoreError('invalid_field', 'a connection needs at least one relay url')
  return relays.map((r) => {
    if (!/^[\x20-\x7e]+$/.test(r) || isBlank(r)) throw new CoreError('invalid_field', 'a relay hint must be non-empty printable ASCII')
    if (r.length > MAX_TLV_VALUE_LEN) throw new CoreError('invalid_field', `relay url exceeds ${MAX_TLV_VALUE_LEN} bytes`)
    return Uint8Array.from(r, (ch) => ch.charCodeAt(0))
  })
}

/** The signed fields of a connection, as its encoder writes them. */
export function connFieldsOf(hrp: string, c: HubConnectionFields): ConnFields {
  const labelBytes = labelOf(c)
  return {
    hrp,
    chain: c.chain,
    pubkey: c.walletPubkey,
    hubIdentity: c.hubIdentity,
    relayBytes: c.relayBytes ?? checkRelays(c.relays),
    secret: c.secret,
    ...(labelBytes !== undefined && { labelBytes }),
  }
}

function encodeHub(c: HubConnectionFields, hrp: string): string {
  if (c.signature === undefined) throw new CoreError('invalid_field', `a ${hrp} connection must be signed by its Hub`)
  if (c.signature.length !== MINT_SIGNATURE_LEN) throw new CoreError('invalid_field', `connection signature must be ${MINT_SIGNATURE_LEN} bytes`)
  if (!validChainName(c.chain)) throw new CoreError('invalid_field', 'chain must be 1 to 32 bytes of a-z, 0-9 and -')
  const label = labelOf(c)
  if (label !== undefined && label.length === 0) throw new CoreError('invalid_field', 'an empty label is never encoded')
  if (label !== undefined && label.length > MAX_TLV_VALUE_LEN) throw new CoreError('invalid_field', `label exceeds ${MAX_TLV_VALUE_LEN} bytes`)
  const entries: TLVEntry[] = [{ type: 0, value: keyFromHex(c.walletPubkey, 'wallet pubkey') }]
  for (const value of checkRelays(c.relays)) entries.push({ type: 1, value })
  entries.push({ type: 2, value: keyFromHex(c.secret, 'secret') })
  if (label !== undefined) entries.push({ type: T_LABEL, value: label })
  entries.push({ type: T_HUB_IDENTITY, value: keyFromHex(c.hubIdentity, 'hub identity') })
  entries.push({ type: T_SIGNATURE, value: c.signature })
  entries.push({ type: T_CHAIN, value: Uint8Array.from(c.chain, (ch) => ch.charCodeAt(0)) })
  return encodeBech32TLV(hrp, entries)
}

const verifyHub = (hrp: string, c: HubConnection): ConnVerdict => verifyConnection(connFieldsOf(hrp, c), c.signature)
const signHub = (hrp: string, c: HubConnectionFields, key: Uint8Array): HubConnection => {
  const relayBytes = c.relayBytes ?? checkRelays(c.relays)
  return { ...c, relayBytes, signature: signConnection(connFieldsOf(hrp, { ...c, relayBytes }), key) }
}

export const decodeCashHubConnection = (s: string): HubConnection => decodeHub(s, CASH_HUB_HRP)
export const encodeCashHubConnection = (c: HubConnectionFields): string => encodeHub(c, CASH_HUB_HRP)
export const verifyCashHubConnection = (c: HubConnection): ConnVerdict => verifyHub(CASH_HUB_HRP, c)
/** Signs a `cashhub1` connection with its Hub's key (fake Hub and tests only). */
export const signCashHubConnection = (c: HubConnectionFields, key: Uint8Array): HubConnection => signHub(CASH_HUB_HRP, c, key)

export const decodeOrderConnection = (s: string): HubConnection => decodeHub(s, ORDER_CONNECTION_HRP)
export const encodeOrderConnection = (c: HubConnectionFields): string => encodeHub(c, ORDER_CONNECTION_HRP)
export const verifyOrderConnection = (c: HubConnection): ConnVerdict => verifyHub(ORDER_CONNECTION_HRP, c)
/** Signs a `cashorder1` connection with its Hub's key (fake Hub and tests only). */
export const signOrderConnection = (c: HubConnectionFields, key: Uint8Array): HubConnection => signHub(ORDER_CONNECTION_HRP, c, key)

export const decodeCircleHubConnection = (s: string): HubConnection => decodeHub(s, CIRCLE_HUB_HRP)
export const encodeCircleHubConnection = (c: HubConnectionFields): string => encodeHub(c, CIRCLE_HUB_HRP)
export const verifyCircleHubConnection = (c: HubConnection): ConnVerdict => verifyHub(CIRCLE_HUB_HRP, c)
/** Signs a `circlehub1` connection with its Hub's key (fake Hub and tests only). */
export const signCircleHubConnection = (c: HubConnectionFields, key: Uint8Array): HubConnection => signHub(CIRCLE_HUB_HRP, c, key)

export type HubConnectionKind = 'cashhub' | 'cashorder' | 'circlehub'

/**
 * Decodes any signed connection string for a paste box: its kind, the
 * connection and the signature verdict. Throws for anything else, or for a
 * malformed string; an unverified one decodes.
 */
export function decodeAnyConnection(s: string): { readonly kind: HubConnectionKind; readonly connection: HubConnection; readonly verdict: ConnVerdict } {
  const { hrp } = decodeBech32TLV(s.trim())
  if (hrp !== CASH_HUB_HRP && hrp !== ORDER_CONNECTION_HRP && hrp !== CIRCLE_HUB_HRP) throw new CoreError('invalid_tlv', 'not a cashhub1, cashorder1 or circlehub1 connection')
  const connection = decodeHub(s.trim(), hrp)
  return { kind: hrp, connection, verdict: verifyHub(hrp, connection) }
}

/** The text a connection's signature covers. */
export const connectionSignedText = (hrp: HubConnectionKind, c: HubConnectionFields): string => connSignedText(connFieldsOf(hrp, c))
