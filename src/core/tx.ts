// A payout's raw transaction, checked before the app is offered to
// broadcast it itself (NIP-CASH §Response: its id is `txid`, and output
// `vout` pays exactly `payout_millis` to `address`). Port of nmilat
// nipcash/withdraw_tx.go.
import { sha256 } from '@noble/hashes/sha2.js'
import { decodeWitnessAddress, witnessScript } from './address.js'
import { fromHex, toHex } from './bytes.js'
import { CoreError } from './errors.js'

export interface Tx {
  readonly version: number
  readonly inputs: readonly { readonly prevout: string; readonly script: Uint8Array; readonly sequence: number }[]
  readonly outputs: readonly { readonly value: bigint; readonly script: Uint8Array }[]
  readonly locktime: number
  /** The serialization without witnesses, which the txid hashes. */
  readonly stripped: Uint8Array
}

const bad = (m: string) => new CoreError('invalid_payload', `transaction: ${m}`)

/** Parses a raw transaction strictly: no trailing bytes, counts within what remains, canonical compact sizes. */
export function parseTx(hex: string): Tx {
  const b = fromHex(hex, 'tx')
  let i = 0
  const need = (n: number) => {
    if (i + n > b.length) throw bad('truncated')
  }
  const u32 = () => {
    need(4)
    const v = b[i]! | (b[i + 1]! << 8) | (b[i + 2]! << 16) | (b[i + 3]! << 24)
    i += 4
    return v >>> 0
  }
  const u64 = () => {
    need(8)
    let v = 0n
    for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(b[i + k]!)
    i += 8
    return v
  }
  const varint = (): number => {
    need(1)
    const f = b[i++]!
    if (f < 0xfd) return f
    if (f === 0xfd) {
      need(2)
      const v = b[i]! | (b[i + 1]! << 8)
      i += 2
      if (v < 0xfd) throw bad('non-canonical compact size')
      return v
    }
    if (f === 0xfe) {
      const v = u32()
      if (v <= 0xffff) throw bad('non-canonical compact size')
      return v
    }
    throw bad('compact size too large')
  }
  const bytes = (n: number) => {
    need(n)
    const out = b.slice(i, i + n)
    i += n
    return out
  }
  const version = u32()
  let segwit = false
  if (b[i] === 0 && b[i + 1] === 1) {
    segwit = true
    i += 2
  }
  const startIns = segwit ? 6 : 4
  const nIn = varint()
  if (nIn * 41 > b.length - i) throw bad('more inputs than bytes')
  const inputs: { prevout: string; script: Uint8Array; sequence: number }[] = []
  for (let k = 0; k < nIn; k++) {
    const prev = bytes(36)
    const script = bytes(varint())
    inputs.push({ prevout: toHex(prev), script, sequence: u32() })
  }
  const nOut = varint()
  if (nOut * 9 > b.length - i) throw bad('more outputs than bytes')
  const outputs: { value: bigint; script: Uint8Array }[] = []
  for (let k = 0; k < nOut; k++) outputs.push({ value: u64(), script: bytes(varint()) })
  const endOuts = i
  if (segwit) {
    for (let k = 0; k < nIn; k++) {
      const items = varint()
      for (let j = 0; j < items; j++) bytes(varint())
    }
  }
  const locktime = u32()
  if (i !== b.length) throw bad('trailing bytes')
  const stripped = new Uint8Array(4 + (endOuts - startIns) + 4)
  stripped.set(b.subarray(0, 4), 0)
  stripped.set(b.subarray(startIns, endOuts), 4)
  stripped.set(b.subarray(b.length - 4), 4 + (endOuts - startIns))
  return { version, inputs, outputs, locktime, stripped }
}

/** The txid: the reversed double-SHA-256 of the serialization without witnesses. */
export function txid(tx: Tx): string {
  const h = sha256(sha256(tx.stripped))
  // oxlint-disable-next-line unicorn/no-array-reverse -- reverses a fresh hash
  h.reverse()
  return toHex(h)
}

const mismatch = (m: string) => new CoreError('tx_mismatch', `the payout transaction ${m}`)

/**
 * Checks a payout's transaction: its id is `txid`, output `vout` exists, its
 * script is the address's witness script and its value is exactly
 * `payoutMillis / 1000`. `hrp` `''` takes the address's own HRP (the quote
 * already signed it). Throws `tx_mismatch` otherwise.
 */
export function verifyPayoutTx(txHex: string, id: string, vout: number, address: string, hrp: string, payoutMillis: bigint): void {
  if (payoutMillis % 1000n !== 0n) throw mismatch('cannot pay a fraction of a base unit')
  let tx: Tx
  try {
    tx = parseTx(txHex)
  } catch {
    throw mismatch('does not parse')
  }
  if (txid(tx) !== id) throw mismatch('has another id')
  const out = tx.outputs[vout]
  if (out === undefined) throw mismatch('has no such output')
  const h = hrp !== '' ? hrp : address.slice(0, address.lastIndexOf('1'))
  const w = decodeWitnessAddress(address, h)
  const want = witnessScript(w.version, w.program)
  if (toHex(out.script) !== toHex(want)) throw mismatch('pays another script')
  if (out.value !== payoutMillis / 1000n) throw mismatch('pays another amount')
}
