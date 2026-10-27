// Witness addresses for on-chain withdrawals (NIP-CASH §Quoting a
// Withdrawal): BIP-173 bech32 for version 0, BIP-350 bech32m for versions
// 1–16, the script type a Hub pays, and the output script an address pays.
// Port of nmilat nipcash/withdraw_address.go.
import { sha256 } from '@noble/hashes/sha2.js'
import { bech32, bech32m, createBase58check } from '@scure/base'
import { CoreError } from './errors.js'

/** A script type: the exact pair of witness version and program length. */
export type ScriptType = readonly [version: number, programLength: number]

const base58check = createBase58check(sha256)
const isBase58check = (s: string): boolean => {
  try {
    base58check.decode(s)
    return true
  } catch {
    return false
  }
}

/** Every witness HRP of a coin's networks; undefined for a chain this SDK has no table for (the Hub checks then). */
export function withdrawHrps(chain: string | undefined): readonly string[] | undefined {
  switch (chain) {
    case 'bitcoin':
      return ['bc', 'tb', 'bcrt']
    case 'flokicoin':
      return ['fc', 'tf', 'fcrt']
    default:
      return undefined
  }
}

/** ASCII-trims; a single-case address comes back lowercased; mixed case is refused. */
export function normalizeAddressText(s: string): string {
  const a = s.trim()
  if (a.toLowerCase() !== a && a.toUpperCase() !== a) {
    if (isBase58check(a)) throw new CoreError('address_no_witness', 'a legacy address has no witness program')
    throw new CoreError('address_malformed', 'the address mixes upper and lower case')
  }
  return a.toLowerCase()
}

function decodeAny(addr: string): { hrp: string; version: number; program: Uint8Array } {
  if (isBase58check(addr)) throw new CoreError('address_no_witness', 'a legacy address has no witness program')
  if (addr.length > 90 || addr !== addr.toLowerCase()) throw new CoreError('address_malformed', 'not a lowercase witness address of at most 90 characters')
  let dec: { prefix: string; words: number[] } | undefined
  let m = false
  try {
    dec = bech32.decode(addr as `${string}1${string}`, 90)
  } catch {
    try {
      dec = bech32m.decode(addr as `${string}1${string}`, 90)
      m = true
    } catch {
      throw new CoreError('address_malformed', 'not a witness address')
    }
  }
  if (dec.words.length < 1) throw new CoreError('address_malformed', 'no witness version')
  const version = dec.words[0]!
  let program: Uint8Array
  try {
    program = Uint8Array.from(bech32.fromWords(dec.words.slice(1)))
  } catch {
    throw new CoreError('address_malformed', 'malformed witness program')
  }
  if (version > 16 || program.length < 2 || program.length > 40) throw new CoreError('address_malformed', 'malformed witness program')
  if (version === 0 && (m || (program.length !== 20 && program.length !== 32))) throw new CoreError('address_malformed', 'malformed version 0 address')
  if (version > 0 && !m) throw new CoreError('address_malformed', `a version ${version} address uses bech32m`)
  return { hrp: dec.prefix, version, program }
}

/** Decodes a witness address under exactly `hrp`; a valid one of another HRP is `address_network`. */
export function decodeWitnessAddress(addr: string, hrp: string): { version: number; program: Uint8Array } {
  const d = decodeAny(addr)
  if (d.hrp !== hrp) throw new CoreError('address_network', `the address is for ${d.hrp}, not ${hrp}`)
  return { version: d.version, program: d.program }
}

export function classifyAddress(addr: string, hrp: string): ScriptType {
  const d = decodeWitnessAddress(addr, hrp)
  return [d.version, d.program.length]
}

/** The script type under whichever of `hrps` the address carries; none of them is `address_network`. */
export function classifyAddressAmong(addr: string, hrps: readonly string[]): { scriptType: ScriptType; hrp: string } {
  const d = decodeAny(addr)
  if (!hrps.includes(d.hrp)) throw new CoreError('address_network', `the address is for ${d.hrp}, not this coin's networks`)
  return { scriptType: [d.version, d.program.length], hrp: d.hrp }
}

/** Whether the Hub pays this script type; refused as `script_type_not_paid` otherwise. */
export function paysScriptType(pays: readonly ScriptType[], st: ScriptType): void {
  if (!pays.some(([v, l]) => v === st[0] && l === st[1])) throw new CoreError('script_type_not_paid', `this Hub does not pay version ${st[0]} addresses of ${st[1]} bytes`)
}

/** The output script: `OP_0` or `OP_1`..`OP_16`, then the program pushed. */
export function witnessScript(version: number, program: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + program.length)
  out[0] = version === 0 ? 0 : 0x50 + version
  out[1] = program.length
  out.set(program, 2)
  return out
}

/** The address in groups of four characters, for display and screen readers. */
export const addressGroups = (addr: string): string[] => addr.match(/.{1,4}/g) ?? []

/** Same HRP, same first and last six characters of the data part, not equal: the address-poisoning look-alike. */
export function nearMatch(a: string, b: string): boolean {
  if (a === b) return false
  const ia = a.lastIndexOf('1')
  const ib = b.lastIndexOf('1')
  if (ia < 1 || ib < 1 || a.slice(0, ia) !== b.slice(0, ib)) return false
  const da = a.slice(ia + 1)
  const db = b.slice(ib + 1)
  return da.length >= 12 && db.length >= 12 && da.slice(0, 6) === db.slice(0, 6) && da.slice(-6) === db.slice(-6)
}
