// The cash token: `lokicash1…`, `satscash1…` or any other HRP (NIP-CASH
// §The Cash Token). Port of nmilat nipcash/token.go.
import { fromUtf8, toHex } from './bytes.js'
import { CoreError } from './errors.js'
import { HUB_GROUP_LEN } from './hubGroup.js'
import {
  KEY_LEN,
  countUsableRelays,
  decodeBech32TLV,
  encodeBech32TLV,
  keyFromHex,
  readTLVs,
  relayEntries,
  type TLVEntry,
} from './tlv.js'

const T_WALLET_PUBKEY = 0
const T_RELAY = 1
const T_SECRET = 2
const T_IDENTITY_REQUIRED = 3
// Type 4 is reserved and ignored like any unknown type.
const T_MINT_SIGNATURE = 5
const T_ATTESTED_AMOUNT = 6
const T_HUB_GROUP = 7

/** Byte length of the recoverable compact mint signature. */
export const MINT_SIGNATURE_LEN = 65
const AMOUNT_LEN = 8
const MAX_U64 = (1n << 64n) - 1n

/**
 * A decoded cash token. `secret` is the NWC connection secret, so a Token is
 * secret-bearing: keep it out of logs and activity (design §10).
 */
export interface Token {
  /** Lowercase, e.g. `lokicash`. */
  readonly hrp: string
  /** Hex, 32 bytes. */
  readonly walletPubkey: string
  /** Hex, 32 bytes. */
  readonly secret: string
  /** In encoded order. A decoded token may carry blank entries. */
  readonly relays: readonly string[]
  /**
   * Best-effort hint from mint time, never a live guarantee: the Hub still
   * checks every call. Absent when the token does not carry it.
   */
  readonly identityRequired?: boolean
  /**
   * Mint provenance, present only as a pair. Verify it with
   * `verifyProvenance`; a signature alone proves origin, never spendability.
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
 * fatal, and so is a token with no usable relay. An anomalous provenance
 * pair or hub group is dropped instead, because those fields are optional
 * and a bill carrying a bad one is still spendable.
 */
export function decodeToken(s: string): Token {
  const { hrp, data } = decodeBech32TLV(s)

  let walletPubkey: string | undefined
  let secret: string | undefined
  let identityRequired: boolean | undefined
  const relays: string[] = []
  let mintSignature: Uint8Array | undefined
  let amount: bigint | undefined
  let provenancePoisoned = false
  let hubGroup: Uint8Array | undefined
  let hubGroupPoisoned = false

  for (const { type, value } of readTLVs(data)) {
    switch (type) {
      case T_WALLET_PUBKEY:
        if (value.length !== KEY_LEN) throw invalid(`wallet pubkey must be ${KEY_LEN} bytes, got ${value.length}`)
        if (walletPubkey !== undefined) throw invalid('duplicate wallet pubkey entry')
        walletPubkey = toHex(value)
        break
      case T_RELAY:
        relays.push(fromUtf8(value))
        break
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
        if (mintSignature !== undefined || value.length !== MINT_SIGNATURE_LEN) provenancePoisoned = true
        else mintSignature = value.slice()
        break
      case T_ATTESTED_AMOUNT:
        if (amount !== undefined || value.length !== AMOUNT_LEN) provenancePoisoned = true
        else amount = new DataView(value.buffer, value.byteOffset, AMOUNT_LEN).getBigUint64(0)
        break
      case T_HUB_GROUP:
        if (hubGroup !== undefined || value.length !== HUB_GROUP_LEN) hubGroupPoisoned = true
        else hubGroup = value.slice()
        break
      default:
      // Unknown types are ignored so new fields don't break old decoders.
    }
  }

  if (walletPubkey === undefined) throw invalid('missing wallet pubkey')
  if (secret === undefined) throw invalid('missing secret')
  if (countUsableRelays(relays) === 0) throw invalid('no usable relay url, so the wallet is unreachable')

  return {
    hrp,
    walletPubkey,
    secret,
    relays,
    ...(identityRequired !== undefined && { identityRequired }),
    ...(!provenancePoisoned &&
      mintSignature !== undefined &&
      amount !== undefined && { mintSignature, attestedAmountMillis: amount }),
    ...(!hubGroupPoisoned && hubGroup !== undefined && { hubGroup }),
  }
}

/** Encodes a token. Blank relays are skipped; at least one must remain. */
export function encodeToken(t: Token): string {
  const entries: TLVEntry[] = [{ type: T_WALLET_PUBKEY, value: keyFromHex(t.walletPubkey, 'wallet pubkey') }]
  const secret = keyFromHex(t.secret, 'secret')
  entries.push(...relayEntries(t.relays, 'a cash token'))
  entries.push({ type: T_SECRET, value: secret })

  if ((t.mintSignature === undefined) !== (t.attestedAmountMillis === undefined)) {
    throw new CoreError('invalid_field', 'mint signature and attested amount must be set together')
  }
  if (t.mintSignature !== undefined && t.mintSignature.length !== MINT_SIGNATURE_LEN) {
    throw new CoreError('invalid_field', `mint signature must be ${MINT_SIGNATURE_LEN} bytes, got ${t.mintSignature.length}`)
  }
  if (t.hubGroup !== undefined && t.hubGroup.length !== HUB_GROUP_LEN) {
    throw new CoreError('invalid_field', `hub group must be ${HUB_GROUP_LEN} bytes, got ${t.hubGroup.length}`)
  }

  if (t.identityRequired !== undefined) {
    entries.push({ type: T_IDENTITY_REQUIRED, value: Uint8Array.of(t.identityRequired ? 1 : 0) })
  }
  if (t.mintSignature !== undefined && t.attestedAmountMillis !== undefined) {
    const amount = t.attestedAmountMillis
    if (amount < 0n || amount > MAX_U64) throw new CoreError('invalid_field', 'attested amount out of uint64 range')
    const value = new Uint8Array(AMOUNT_LEN)
    new DataView(value.buffer).setBigUint64(0, amount)
    entries.push({ type: T_MINT_SIGNATURE, value: t.mintSignature }, { type: T_ATTESTED_AMOUNT, value })
  }
  if (t.hubGroup !== undefined) entries.push({ type: T_HUB_GROUP, value: t.hubGroup })
  return encodeBech32TLV(t.hrp, entries)
}

/** Whether `t` carries a complete mint-provenance pair. */
export function hasProvenance(t: Pick<Token, 'mintSignature' | 'attestedAmountMillis'>): boolean {
  return t.mintSignature !== undefined && t.attestedAmountMillis !== undefined
}
