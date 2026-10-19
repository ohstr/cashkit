// The bolt11 fields a wallet needs: currency and amount from the HRP, plus
// the payment hash a redeem claim proof binds. Port of nmilat
// nip57/bolt11.go. The node signature is not checked, as in nmilat; the
// Hub pays the invoice and is the one that has to trust it.
import { bech32Decode, convertBits } from './bech32.js'
import { fromUtf8, toHex } from './bytes.js'
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
}

const TIMESTAMP_WORDS = 7
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
  let description = ''
  let descriptionHash = ''
  for (let i = 0; i + 3 <= fields.length; ) {
    const type = fields[i]!
    const len = fields[i + 1]! * 32 + fields[i + 2]!
    i += 3
    if (i + len > fields.length) throw fail(`tagged field ${type} truncated`)
    const data = fields.subarray(i, i + len)
    i += len
    switch (type) {
      case 1:
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
      default:
    }
  }
  if (paymentHash === '') throw fail('no payment hash')
  return { currency, amountMillis, description, descriptionHash, paymentHash }
}
