// The cash token: `satscash1…` or any other HRP (NIP-CASH
// §The Cash Token). Port of nmilat nipcash/token.go.
import { isBlank, toHex } from './bytes.js'
import { CoreError } from './errors.js'
import { HUB_GROUP_LEN } from './hubGroup.js'
import { KEY_LEN, MAX_TLV_VALUE_LEN, decodeBech32TLV, encodeBech32TLV, keyFromHex, readTLVs, usableHint, type TLVEntry } from './tlv.js'

const T_WALLET_PUBKEY = 0
const T_RELAY = 1
const T_SECRET = 2
const T_IDENTITY_REQUIRED = 3
// Type 4 is reserved and ignored like any unknown type.
const T_MINT_SIGNATURE = 5
const T_ATTESTED_AMOUNT = 6
const T_HUB_GROUP = 7
/** TLV 8: which payload the mint signature signs. */
export const T_SIGNATURE_SCHEME = 8

/** Byte length of the recoverable compact mint signature. */
export const MINT_SIGNATURE_LEN = 65
const AMOUNT_LEN = 8
const MAX_U64 = (1n << 64n) - 1n

/**
 * What a token's mint signature signs (TLV 8): `mint_v1` (`cash-mint:v1`)
 * or `zap_v1` (`cash-zap:v1`). `malformed` means the provenance fields are
 * there but unusable (TLV 8 missing, wrong-length, repeated or unknown, or
 * TLV 5/6 unpaired or malformed); `none` means no TLV 5 or 6 at all. Only
 * `mint_v1` and `zap_v1` can verify.
 */
export type TokenScheme = 'mint_v1' | 'zap_v1' | 'malformed' | 'none'

const SCHEME_BYTE: Readonly<Record<'mint_v1' | 'zap_v1', number>> = { mint_v1: 1, zap_v1: 2 }

/**
 * A decoded cash token. `secret` is the NWC connection secret, so a Token is
 * secret-bearing: keep it out of logs and activity (design §10).
 */
export interface Token {
  /** Lowercase, e.g. `satscash`. */
  readonly hrp: string
  /** Hex, 32 bytes. */
  readonly walletPubkey: string
  /** Hex, 32 bytes. */
  readonly secret: string
  /**
   * The relay hints a client dials, in encoded order: every hint that is not
   * blank (empty once ASCII whitespace is trimmed).
   */
  readonly relays: readonly string[]
  /**
   * Every TLV 1 exactly as encoded, skipped ones included; the relay hash
   * of the mint signature is computed over these. Ignored by the encoder.
   */
  readonly relayBytes?: readonly Uint8Array[]
  /**
   * Best-effort hint from mint time, never a live guarantee: the Hub still
   * checks every call. Absent when the token does not carry it.
   */
  readonly identityRequired?: boolean
  /** Which payload the mint signature signs; see `TokenScheme`. */
  readonly scheme: TokenScheme
  /**
   * Mint provenance, present only when `scheme` is `mint_v1` or `zap_v1`.
   * Verify it with `verifyProvenance`; a signature proves origin, never
   * spendability.
   */
  readonly mintSignature?: Uint8Array
  readonly attestedAmountMillis?: bigint
  /**
   * Issuing Hub fingerprint, a grouping hint only (see `sameHubGroup`).
   * Unauthenticated; never an authorization input.
   */
  readonly hubGroup?: Uint8Array
}

const invalid = (msg: string) => new CoreError('invalid_tlv', `token: ${msg}`)

/**
 * Decodes a cash token under any HRP.
 *
 * A missing, wrong-length or repeated pubkey, secret or identity_required is
 * fatal, and so is a token with no usable relay. Faulty provenance (TLV 5, 6
 * or 8) leaves the token decodable with no valid provenance, and a faulty
 * hub group (TLV 7) is dropped: those fields never make a bill unspendable.
 * An all-uppercase string decodes as its lowercase form; a mixed-case one is
 * refused.
 */
export function decodeToken(s: string): Token {
  const { hrp, data } = decodeBech32TLV(s)

  let walletPubkey: string | undefined
  let secret: string | undefined
  let identityRequired: boolean | undefined
  const relays: string[] = []
  const relayBytes: Uint8Array[] = []
  let mintSignature: Uint8Array | undefined
  let amount: bigint | undefined
  let sigSeen = false
  let amountSeen = false
  let provenancePoisoned = false
  let schemeByte: number | undefined
  let schemePoisoned = false
  let hubGroup: Uint8Array | undefined
  let hubGroupPoisoned = false

  for (const { type, value } of readTLVs(data)) {
    switch (type) {
      case T_WALLET_PUBKEY:
        if (value.length !== KEY_LEN) throw invalid(`wallet pubkey must be ${KEY_LEN} bytes, got ${value.length}`)
        if (walletPubkey !== undefined) throw invalid('duplicate wallet pubkey entry')
        walletPubkey = toHex(value)
        break
      case T_RELAY: {
        relayBytes.push(value.slice())
        const r = usableHint(value)
        if (r !== undefined) relays.push(r)
        break
      }
      case T_SECRET:
        if (value.length !== KEY_LEN) throw invalid(`secret must be ${KEY_LEN} bytes, got ${value.length}`)
        if (secret !== undefined) throw invalid('duplicate secret entry')
        secret = toHex(value)
        break
      case T_IDENTITY_REQUIRED:
        if (value.length !== 1) throw invalid(`identity_required must be 1 byte, got ${value.length}`)
        if (value[0]! > 1) throw invalid('identity_required must be 0 or 1')
        if (identityRequired !== undefined) throw invalid('duplicate identity_required entry')
        identityRequired = value[0] === 1
        break
      case T_MINT_SIGNATURE:
        if (sigSeen || value.length !== MINT_SIGNATURE_LEN) provenancePoisoned = true
        else mintSignature = value.slice()
        sigSeen = true
        break
      case T_ATTESTED_AMOUNT:
        if (amountSeen || value.length !== AMOUNT_LEN) provenancePoisoned = true
        else amount = new DataView(value.buffer, value.byteOffset, AMOUNT_LEN).getBigUint64(0)
        amountSeen = true
        break
      case T_HUB_GROUP:
        if (hubGroup !== undefined || value.length !== HUB_GROUP_LEN) hubGroupPoisoned = true
        else hubGroup = value.slice()
        break
      case T_SIGNATURE_SCHEME:
        if (schemeByte !== undefined || value.length !== 1) schemePoisoned = true
        else schemeByte = value[0]
        break
      default:
      // Unknown types (4 included) are ignored so new fields don't break old decoders.
    }
  }

  if (walletPubkey === undefined) throw invalid('missing wallet pubkey')
  if (secret === undefined) throw invalid('missing secret')
  if (relays.length === 0) throw invalid('no usable relay url, so the wallet is unreachable')

  let scheme: TokenScheme
  if (!sigSeen && !amountSeen) scheme = 'none'
  else if (provenancePoisoned || mintSignature === undefined || amount === undefined || schemePoisoned) scheme = 'malformed'
  else if (schemeByte === 1) scheme = 'mint_v1'
  else if (schemeByte === 2) scheme = 'zap_v1'
  else scheme = 'malformed'
  const provenance = scheme === 'mint_v1' || scheme === 'zap_v1'

  return {
    hrp,
    walletPubkey,
    secret,
    relays,
    relayBytes,
    ...(identityRequired !== undefined && { identityRequired }),
    scheme,
    ...(provenance && { mintSignature: mintSignature!, attestedAmountMillis: amount! }),
    ...(!hubGroupPoisoned && hubGroup !== undefined && { hubGroup }),
  }
}

/** What `encodeToken` needs: a token with its provenance (`relayBytes` is ignored). */
export type TokenFields = Omit<Token, 'relayBytes'> & { readonly relayBytes?: readonly Uint8Array[] }

/**
 * Encodes a token, entries in ascending type order. Refuses a token without
 * provenance (TLV 5, 6 and a `mint_v1` or `zap_v1` scheme), an empty or
 * non-ASCII relay hint, and a wrong-length hub group.
 */
export function encodeToken(t: TokenFields): string {
  if (t.hrp !== t.hrp.toLowerCase()) throw new CoreError('invalid_field', `a token's hrp must be lowercase: ${JSON.stringify(t.hrp)}`)
  if (t.relays.length === 0) throw new CoreError('invalid_field', 'a cash token needs at least one relay url')
  const relayValues = t.relays.map((r) => {
    if (!/^[\x20-\x7e]+$/.test(r) || isBlank(r)) throw new CoreError('invalid_field', 'a relay hint must be non-empty printable ASCII')
    if (r.length > MAX_TLV_VALUE_LEN) throw new CoreError('invalid_field', `relay url exceeds ${MAX_TLV_VALUE_LEN} bytes`)
    return Uint8Array.from(r, (c) => c.charCodeAt(0))
  })
  if (t.mintSignature === undefined || t.attestedAmountMillis === undefined) {
    throw new CoreError('invalid_field', 'a cash token needs its mint signature and attested amount')
  }
  if (t.scheme !== 'mint_v1' && t.scheme !== 'zap_v1') throw new CoreError('invalid_field', 'a cash token needs a signature scheme (mint_v1 or zap_v1)')
  if (t.mintSignature.length !== MINT_SIGNATURE_LEN) {
    throw new CoreError('invalid_field', `mint signature must be ${MINT_SIGNATURE_LEN} bytes, got ${t.mintSignature.length}`)
  }
  const amount = t.attestedAmountMillis
  if (amount < 0n || amount > MAX_U64) throw new CoreError('invalid_field', 'attested amount out of uint64 range')
  if (t.hubGroup !== undefined && t.hubGroup.length !== HUB_GROUP_LEN) {
    throw new CoreError('invalid_field', `hub group must be ${HUB_GROUP_LEN} bytes, got ${t.hubGroup.length}`)
  }

  const entries: TLVEntry[] = [{ type: T_WALLET_PUBKEY, value: keyFromHex(t.walletPubkey, 'wallet pubkey') }]
  for (const value of relayValues) entries.push({ type: T_RELAY, value })
  entries.push({ type: T_SECRET, value: keyFromHex(t.secret, 'secret') })
  if (t.identityRequired !== undefined) entries.push({ type: T_IDENTITY_REQUIRED, value: Uint8Array.of(t.identityRequired ? 1 : 0) })
  const amountBytes = new Uint8Array(AMOUNT_LEN)
  new DataView(amountBytes.buffer).setBigUint64(0, amount)
  entries.push({ type: T_MINT_SIGNATURE, value: t.mintSignature }, { type: T_ATTESTED_AMOUNT, value: amountBytes })
  if (t.hubGroup !== undefined) entries.push({ type: T_HUB_GROUP, value: t.hubGroup })
  entries.push({ type: T_SIGNATURE_SCHEME, value: Uint8Array.of(SCHEME_BYTE[t.scheme]) })
  return encodeBech32TLV(t.hrp, entries)
}

/** Whether `t` carries usable provenance: a TLV 5/6 pair under a known scheme. */
export function hasProvenance(t: Pick<Token, 'mintSignature' | 'attestedAmountMillis'> & { readonly scheme?: TokenScheme }): boolean {
  return t.mintSignature !== undefined && t.attestedAmountMillis !== undefined && (t.scheme === 'mint_v1' || t.scheme === 'zap_v1')
}
