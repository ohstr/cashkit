// The bolt11 fields a wallet needs: currency and amount from the HRP, the
// payment hash a redeem claim proof binds, the creation time and expiry,
// and the payee. Port of nmilat nip57/bolt11.go, plus the payee and expiry.
// The node signature is not checked; the payee is the `n` field when the
// invoice carries one, else the key its signature recovers to.
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bech32Decode, convertBits } from './bech32.js'
import { concatBytes, fromUtf8, toHex, utf8 } from './bytes.js'
import { CoreError } from './errors.js'

export interface Bolt11Invoice {
  /** The HRP between "ln" and the amount, e.g. "bc", "fc". */
  readonly currency: string
  /** 0n when the invoice names no amount. */
  readonly amountMillis: bigint
  /** The `d` field, "" if absent. */
  readonly description: string
  /** The `h` field (hex), "" if absent. */
  readonly descriptionHash: string
  /** The `p` field (hex). Always present. */
  readonly paymentHash: string
  /** Creation time, unix seconds. */
  readonly timestamp: number
  /** The `x` field, seconds; 3600 when absent (BOLT 11). */
  readonly expirySeconds: number
  /** The payee node's compressed key (66 hex): the `n` field, else recovered from the signature; undefined when neither works. */
  readonly payee?: string
}

/** When the invoice expires, unix seconds. */
export const invoiceExpiresAt = (i: Pick<Bolt11Invoice, 'timestamp' | 'expirySeconds'>): number => i.timestamp + i.expirySeconds

const TIMESTAMP_WORDS = 7
const DEFAULT_EXPIRY = 3600
const PAYEE_FIELD_WORDS = 53
const SIGNATURE_WORDS = 104
const HASH_FIELD_WORDS = 52
const MAX_INT64 = (1n << 63n) - 1n

const MULTIPLIER: Readonly<Record<string, bigint>> = {
  m: 100_000_000n,
  u: 100_000n,
  n: 100n,
  p: 1n, // then divided by 10
}

const fail = (msg: string) => new CoreError('invalid_payload', `bolt11: ${msg}`)

function amountFromHrp(amountPart: string): bigint {
  if (amountPart === '') return 0n
  const last = amountPart[amountPart.length - 1]!
  const hasMultiplier = last < '0' || last > '9'
  const digits = hasMultiplier ? amountPart.slice(0, -1) : amountPart
  if (hasMultiplier && !Object.hasOwn(MULTIPLIER, last)) throw fail('unknown amount multiplier')
  if (!/^[0-9]+$/.test(digits)) throw fail('invalid amount')
  const value = BigInt(digits)
  if (value > MAX_INT64) throw fail('invalid amount')
  let millis = value * (hasMultiplier ? MULTIPLIER[last]! : 100_000_000_000n)
  if (last === 'p') {
    if (value % 10n !== 0n) throw fail('pico amount must be a multiple of 10')
    millis /= 10n
  }
  // nmilat multiplies in int64 and wraps; cashkit refuses instead.
  if (millis > MAX_INT64) throw fail('amount too large')
  return millis
}

/** A big-endian number of 5-bit words. */
function wordsInt(words: Uint8Array): number {
  let n = 0
  for (const w of words) n = n * 32 + w
  return n
}

function payeeField(words: Uint8Array): string | undefined {
  if (words.length !== PAYEE_FIELD_WORDS) return undefined
  try {
    const b = convertBits(words, 5, 8, false)
    return b.length === 33 && (b[0] === 2 || b[0] === 3) ? toHex(b) : undefined
  } catch {
    return undefined
  }
}

/** The key the signature recovers to over sha256(hrp ‖ data), else undefined. */
function recoverPayee(hrp: string, data: Uint8Array, sigWords: Uint8Array): string | undefined {
  try {
    const sig = convertBits(sigWords, 5, 8, false)
    if (sig.length !== 65 || sig[64]! > 3) return undefined
    const digest = sha256(concatBytes(utf8(hrp), convertBits(data, 5, 8, true)))
    return toHex(secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(sig[64]!), sig.subarray(0, 64)), digest, { prehash: false }))
  } catch {
    return undefined
  }
}

function hashHex(words: Uint8Array): string | undefined {
  if (words.length !== HASH_FIELD_WORDS) return undefined
  try {
    const b = convertBits(words, 5, 8, false)
    return b.length === 32 ? toHex(b) : undefined
  } catch {
    return undefined
  }
}

/** Reads a bolt11 invoice; throws if it is not one or has no payment hash. */
export function decodeBolt11(invoice: string): Bolt11Invoice {
  let hrp: string
  let words: Uint8Array
  try {
    ;({ hrp, words } = bech32Decode(invoice))
  } catch {
    throw fail('invalid encoding')
  }
  if (!hrp.startsWith('ln')) throw fail('not a lightning invoice')
  const rest = hrp.slice(2)
  const firstDigit = rest.search(/[0-9]/)
  const currency = firstDigit < 0 ? rest : rest.slice(0, firstDigit)
  const amountMillis = amountFromHrp(firstDigit < 0 ? '' : rest.slice(firstDigit))

  if (words.length < TIMESTAMP_WORDS + SIGNATURE_WORDS) throw fail('data part too short')
  const fields = words.subarray(TIMESTAMP_WORDS, words.length - SIGNATURE_WORDS)

  let paymentHash = ''
  let seenPaymentHash = false
  let description = ''
  let descriptionHash = ''
  let expirySeconds = DEFAULT_EXPIRY
  let payee: string | undefined
  for (let i = 0; i + 3 <= fields.length; ) {
    const type = fields[i]!
    const len = fields[i + 1]! * 32 + fields[i + 2]!
    i += 3
    if (i + len > fields.length) throw fail(`tagged field ${type} truncated`)
    const data = fields.subarray(i, i + len)
    i += len
    switch (type) {
      case 1:
        // A p field of another length is skipped; a second 32-byte one is refused, since readers disagree on which counts.
        if (data.length !== HASH_FIELD_WORDS) break
        if (seenPaymentHash) throw fail('more than one payment hash')
        seenPaymentHash = true
        paymentHash = hashHex(data) ?? paymentHash
        break
      case 13:
        try {
          description = fromUtf8(convertBits(data, 5, 8, false))
        } catch {
          // A malformed description is dropped, as in nmilat.
        }
        break
      case 23:
        descriptionHash = hashHex(data) ?? descriptionHash
        break
      case 6:
        expirySeconds = wordsInt(data)
        break
      case 19:
        payee = payeeField(data) ?? payee
        break
      default:
    }
  }
  if (paymentHash === '') throw fail('no payment hash')
  const timestamp = wordsInt(words.subarray(0, TIMESTAMP_WORDS))
  payee ??= recoverPayee(hrp, words.subarray(0, words.length - SIGNATURE_WORDS), words.subarray(words.length - SIGNATURE_WORDS))
  return { currency, amountMillis, description, descriptionHash, paymentHash, timestamp, expirySeconds, ...(payee !== undefined && { payee }) }
}
