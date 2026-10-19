// Public, secret-free shapes of stored rows, and `toJSON` (design §8): the
// shape cashctl prints under --json, with snake_case keys and bigint
// amounts as exact JSON integers.
import { toJSONText } from '../core/index.js'
import type { Holding, HoldingMode, HoldingStatus, Protection } from './model.js'

export interface HoldingView {
  readonly id: string
  readonly status: HoldingStatus
  readonly mode: HoldingMode
  readonly protection: Protection
  readonly amount?: bigint
  readonly verified: boolean
  readonly expiresAt?: number
  /** Whether `expiresAt` has passed. */
  readonly expired: boolean
  readonly walletPubkey: string
  readonly minterPubkey?: string
  readonly hubGroup: string
  readonly relayUrls: readonly string[]
  readonly addedAt: number
  /** Mid-merge: moved onto a throwaway key for a merge that has not finished. */
  readonly midMerge: boolean
  /** A write-ahead slot is still open (§5.1); `settle()` resolves it. */
  readonly unsettled: boolean
}

export function holdingView(h: Holding, nowSeconds: number): HoldingView {
  return {
    id: h.id,
    status: h.status,
    mode: h.mode,
    protection: h.protection,
    ...(h.amount !== undefined && { amount: h.amount }),
    verified: h.verified,
    ...(h.expiresAt !== undefined && { expiresAt: h.expiresAt }),
    expired: h.expiresAt !== undefined && h.expiresAt <= nowSeconds,
    walletPubkey: h.walletPubkey,
    ...(h.minterPubkey !== undefined && { minterPubkey: h.minterPubkey }),
    hubGroup: h.hubGroup,
    relayUrls: [...h.relayUrls],
    addedAt: h.addedAt,
    midMerge: h.throwawayKey !== undefined || h.pendingThrowawayKey !== undefined,
    unsettled: h.pendingCashSecret !== undefined || h.pendingDestinationCashSecret !== undefined || h.pendingThrowawayKey !== undefined,
  }
}

const snake = (k: string) => k.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)

function snakeKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(snakeKeys)
  if (v instanceof Error) return 'toJSON' in v && typeof v.toJSON === 'function' ? snakeKeys(v.toJSON()) : { error: v.message }
  if (v !== null && typeof v === 'object' && !(v instanceof Uint8Array)) {
    const out: Record<string, unknown> = {}
    for (const [k, x] of Object.entries(v)) if (x !== undefined) out[snake(k)] = snakeKeys(x)
    return out
  }
  return v
}

/**
 * JSON text for any wallet result: snake_case keys, exact integers for
 * bigint amounts, and errors in cashctl's error shape. Results only carry a
 * secret when the caller asked for one (a cash note to hand over, or
 * `includeSecrets`), so nothing is stripped here.
 */
export function toJSON(value: unknown): string {
  return toJSONText(snakeKeys(value))
}
