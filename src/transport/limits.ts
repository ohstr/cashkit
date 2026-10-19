// Envelope size policy. Port of nmilat nipcash/transport/limits.go. A client
// builds to the Hub's announced limits so a batch the Hub would refuse fails
// locally instead of as silence.
import { TransportError } from './errors.js'

/** NIP-44's plaintext ceiling. */
export const MAX_NIP44_PLAINTEXT = 65535
export const MAX_ITEM_ID_BYTES = 256
/** The smallest padding bucket an announced policy may set. */
export const MIN_PAD_BUCKET_BYTES = 2 * 1024
const CONSOLIDATE_ITEM_BASE_BYTES = 1010
const CONSOLIDATE_ITEM_PER_SOURCE_BYTES = 952
const MIN_CONSOLIDATE_SOURCES = 2

export interface Limits {
  /** Ceiling on the padded plaintext. */
  readonly maxEnvelopeBytes: number
  readonly maxItems: number
  readonly padBucketBytes: number
  /** Signature verifications one envelope may demand. */
  readonly maxVerifyBudget: number
  readonly maxConsolidateSources: number
}

export const DEFAULT_LIMITS: Limits = Object.freeze({
  maxEnvelopeBytes: 56 * 1024,
  maxItems: 32,
  padBucketBytes: 8 * 1024,
  maxVerifyBudget: 200,
  maxConsolidateSources: 48,
})

/** Roughly how large a cash_consolidate item with `n` sources encodes to. */
export function estimatedConsolidateItemBytes(n: number): number {
  return CONSOLIDATE_ITEM_BASE_BYTES + Math.max(n, 0) * CONSOLIDATE_ITEM_PER_SOURCE_BYTES
}

/** The largest source count whose item fits, never below two. */
export function maxSourcesForEnvelope(maxEnvelopeBytes: number): number {
  const fits = Math.trunc((maxEnvelopeBytes - CONSOLIDATE_ITEM_BASE_BYTES) / CONSOLIDATE_ITEM_PER_SOURCE_BYTES)
  return fits < MIN_CONSOLIDATE_SOURCES ? MIN_CONSOLIDATE_SOURCES : fits
}

/** Refuses a policy that cannot be honoured. */
export function validateLimits(l: Limits): void {
  if (!(l.maxEnvelopeBytes > 0 && l.maxItems > 0 && l.padBucketBytes > 0 && l.maxVerifyBudget > 0)) {
    throw new TransportError('limits_invalid', 'every envelope limit must be positive')
  }
  if (l.maxConsolidateSources < MIN_CONSOLIDATE_SOURCES) {
    throw new TransportError('limits_invalid', 'max consolidate sources is below the two-source minimum')
  }
  if (estimatedConsolidateItemBytes(l.maxConsolidateSources) > l.maxEnvelopeBytes) {
    throw new TransportError('limits_invalid', 'max consolidate sources allows an item too large to encrypt')
  }
  if (l.maxEnvelopeBytes > MAX_NIP44_PLAINTEXT) {
    throw new TransportError('limits_invalid', "max envelope bytes exceeds NIP-44's plaintext ceiling")
  }
  if (l.padBucketBytes > l.maxEnvelopeBytes) {
    throw new TransportError('limits_invalid', 'pad bucket exceeds max envelope bytes')
  }
}

/** validateLimits plus what matters for a policy adopted from a Hub. */
export function validateAnnouncedLimits(l: Limits): void {
  validateLimits(l)
  if (l.padBucketBytes < MIN_PAD_BUCKET_BYTES) {
    throw new TransportError('limits_invalid', `announced pad bucket below the ${MIN_PAD_BUCKET_BYTES}-byte floor would defeat padding`)
  }
}

/** The smallest bucket multiple that holds `n` bytes; too large throws. */
export function paddedSize(l: Limits, n: number): number {
  if (n < 0) throw new TransportError('envelope_malformed', 'negative size')
  const buckets = Math.max(Math.ceil(n / l.padBucketBytes), 1)
  const padded = buckets * l.padBucketBytes
  if (padded > l.maxEnvelopeBytes) {
    throw new TransportError('envelope_too_large', `${n} bytes pads to ${padded}, limit ${l.maxEnvelopeBytes}`)
  }
  return padded
}

/** Roughly how large a full envelope is as base64 in an event's content. */
export function estimatedWireBytes(l: Limits): number {
  const raw = l.maxEnvelopeBytes + 1 + 32 + 32
  return Math.trunc((raw + 2) / 3) * 4
}
