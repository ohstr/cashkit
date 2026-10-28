// The `withdraw` terms a Hub reports in `cash_status` when it offers
// on-chain withdrawals (NIP-CASH §Redeeming On-chain). For display only: a
// quote alone fixes a payout.
import { MAX_FEE_PPM } from './fees.js'

export interface WithdrawTerms {
  readonly withdrawFeeBase: bigint
  readonly withdrawFeePpm: bigint
  /** Bounds on the slice's amount; absent when the Hub sets none. */
  readonly minMillis?: bigint
  readonly maxMillis?: bigint
  /** `[witness_version, program_length]` pairs, e.g. `[[0, 20], [0, 32], [1, 32]]`. */
  readonly scriptTypes: readonly (readonly [number, number])[]
  /** Confirmations the Hub waits for. */
  readonly finalDepth: number
}

const u64 = (v: unknown): bigint | undefined => {
  if (typeof v === 'bigint' && v >= 0n && v < 1n << 64n) return v
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v)
  return undefined
}

const smallInt = (v: unknown, max: number): number | undefined => (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max ? v : typeof v === 'bigint' && v >= 0n && v <= BigInt(max) ? Number(v) : undefined)

/** The terms, or undefined for an object that is not a valid `withdraw` block. Never throws. */
export function validateWithdrawTerms(v: unknown): WithdrawTerms | undefined {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return undefined
  const o = v as Record<string, unknown>
  const base = u64(o['withdraw_fee_base'])
  const ppm = u64(o['withdraw_fee_ppm'])
  const depth = smallInt(o['final_depth'], 1_000_000)
  if (base === undefined || ppm === undefined || ppm > MAX_FEE_PPM || depth === undefined || depth < 1) return undefined
  const min = o['min_millis'] === undefined ? undefined : u64(o['min_millis'])
  const max = o['max_millis'] === undefined ? undefined : u64(o['max_millis'])
  if ((o['min_millis'] !== undefined && min === undefined) || (o['max_millis'] !== undefined && max === undefined)) return undefined
  if (min !== undefined && max !== undefined && min > max) return undefined
  const raw = o['script_types']
  if (!Array.isArray(raw) || raw.length === 0) return undefined
  const scriptTypes: [number, number][] = []
  for (const p of raw) {
    if (!Array.isArray(p) || p.length !== 2) return undefined
    const ver = smallInt(p[0], 16)
    const len = smallInt(p[1], 40)
    if (ver === undefined || len === undefined || len < 2 || (ver === 0 && len !== 20 && len !== 32)) return undefined
    scriptTypes.push([ver, len])
  }
  return { withdrawFeeBase: base, withdrawFeePpm: ppm, ...(min !== undefined && { minMillis: min }), ...(max !== undefined && { maxMillis: max }), scriptTypes, finalDepth: depth }
}
