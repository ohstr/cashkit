// The private-transport envelope: many bill operations in one NIP-44
// plaintext. Port of nmilat nipcash/transport/envelope.go. Encoding matches
// Go's json.Marshal byte for byte; decoding drops a structurally bad item
// rather than failing its co-items.
import { paramsHash } from './canonical.js'
import { TransportError } from './errors.js'
import { compactGo, decodeGo, goString, parseGo, unmarshalGo, type GoType } from './gojson.js'
import { MAX_ITEM_ID_BYTES, paddedSize, validateLimits, type Limits } from './limits.js'

export const KIND_PRIVATE_REQUEST = 23190
export const KIND_PRIVATE_RESPONSE = 23191
export const KIND_ITEM_PROOF = 23192
export const KIND_BILL_PROOF = 23193
export const ENVELOPE_VERSION = 1
/** How far ahead an envelope may claim validity, in seconds. */
export const MAX_NOT_AFTER_WINDOW = 120

/**
 * One bill operation. `params`, `proof` and `billProof` are JSON text, kept
 * as written: the proofs sign a hash of exactly this params text, and the
 * Hub hands it to the method untouched.
 */
export interface Item {
  readonly id: string
  /** The bill's wallet pubkey, lowercase hex. */
  readonly target: string
  readonly method: string
  readonly params?: string
  /** The kind 23192 slice proof; absent for a cash-mode (bearer) item. */
  readonly proof?: string
  /** The kind 23193 bill proof; required on every item. */
  readonly billProof?: string
}

export interface Envelope {
  readonly v: number
  /** Unix seconds. */
  readonly notAfter: number
  readonly nonce: string
  readonly replyTo: string
  readonly items: readonly Item[]
}

export interface ItemRejection {
  readonly index: number
  readonly error: TransportError
}

const utf8Len = (s: string) => new TextEncoder().encode(s).length
const isLowerHex64 = (s: string) => /^[0-9a-f]{64}$/.test(s)

/** Whether raw JSON text is a value other than null. */
function hasRawValue(raw: string | undefined): boolean {
  if (raw === undefined) return false
  const t = raw.trim()
  return t !== '' && t !== 'null'
}

export const hasProof = (i: Item): boolean => hasRawValue(i.proof)
export const hasBillProof = (i: Item): boolean => hasRawValue(i.billProof)

/** Decodes params into a Go struct as nmilat does; any failure reads as no fields. */
function paramsAs(i: Item, t: GoType): Record<string, unknown> {
  try {
    const { value, typeError } = unmarshalGo(i.params ?? '', t)
    return typeError ? {} : ((value as Record<string, unknown> | undefined) ?? {})
  } catch {
    return {}
  }
}

/** A cash-mode item: its params carry a non-empty cash_secret. */
export function isBearer(i: Item): boolean {
  const p = paramsAs(i, { object: { cash_secret: 'string' } })
  return typeof p['cash_secret'] === 'string' && p['cash_secret'] !== ''
}

/** How many consolidate sources the params declare; 0 for other methods. */
export function sourceCount(i: Item): number {
  const p = paramsAs(i, { object: { sources: { array: 'raw' } } })
  return Array.isArray(p['sources']) ? p['sources'].length : 0
}

/** Signature verifications the Hub will spend on this item, counted from its shape. */
export function verificationCost(i: Item): number {
  let cost = 1 // the bill proof
  if (!isBearer(i)) cost++ // the slice proof
  const p = paramsAs(i, { object: { sources: { array: { object: { identity_event: 'string', attestation_event: 'string' } } } } })
  for (const s of (p['sources'] as Record<string, unknown>[] | undefined) ?? []) {
    if (s['identity_event']) cost++
    if (s['attestation_event']) cost++
  }
  return cost
}

const bad = (code: TransportError['code'], msg: string) => ({ error: new TransportError(code, msg) })

function itemError(i: number, item: Item, limits: Limits): { hash?: string; error?: TransportError } {
  if (item.id === '') return bad('envelope_malformed', `item ${i} has no id`)
  if (utf8Len(item.id) > MAX_ITEM_ID_BYTES) return bad('envelope_malformed', `item ${i} has an id over ${MAX_ITEM_ID_BYTES} bytes`)
  let hash: string
  try {
    hash = paramsHash(item.params ?? '')
  } catch {
    return bad('envelope_malformed', `item ${i} params are not valid JSON`)
  }
  if (!isLowerHex64(item.target)) return bad('envelope_malformed', `item ${i} target must be 64 lowercase hex characters`)
  if (item.method === '') return bad('envelope_malformed', `item ${i} has no method`)
  if (!hasProof(item) && !isBearer(item)) return bad('envelope_malformed', `item ${i} has no proof and carries no cash secret`)
  if (!hasBillProof(item)) return bad('envelope_malformed', `item ${i} has no bill proof`)
  if (sourceCount(item) > limits.maxConsolidateSources) {
    return bad('too_many_items', `item ${i} declares ${sourceCount(item)} sources, limit ${limits.maxConsolidateSources}`)
  }
  return { hash }
}

function checkHeader(e: Envelope, limits: Limits): void {
  if (e.v !== ENVELOPE_VERSION) throw new TransportError('envelope_version', `unsupported envelope version ${e.v}`)
  if (!isLowerHex64(e.nonce)) throw new TransportError('envelope_malformed', 'nonce must be 64 lowercase hex characters')
  if (!isLowerHex64(e.replyTo)) throw new TransportError('envelope_malformed', 'reply_to must be 64 lowercase hex characters')
  if (e.items.length === 0) throw new TransportError('envelope_no_items', 'envelope carries no items')
  if (e.items.length > limits.maxItems) {
    throw new TransportError('too_many_items', `${e.items.length} items, limit ${limits.maxItems}`)
  }
}

/** Items that pass, and those rejected: every item sharing an id, and repeats of an identical item. */
function checkItems(e: Envelope, limits: Limits): { kept: Item[]; rejected: ItemRejection[] } {
  const idCount = new Map<string, number>()
  for (const it of e.items) idCount.set(it.id, (idCount.get(it.id) ?? 0) + 1)
  const seen = new Map<string, string>()
  const kept: Item[] = []
  const rejected: ItemRejection[] = []
  e.items.forEach((item, index) => {
    let { hash, error } = itemError(index, item, limits)
    if (error === undefined && idCount.get(item.id)! > 1) {
      error = new TransportError('duplicate_item_id', `envelope reuses item id at index ${index}`)
    }
    if (error === undefined) {
      const fingerprint = `${item.target}\0${item.method}\0${hash}`
      if (seen.has(fingerprint)) error = new TransportError('duplicate_item', `item ${index} repeats an identical item`)
      else seen.set(fingerprint, item.id)
    }
    if (error !== undefined) rejected.push({ index, error })
    else kept.push(item)
  })
  return { kept, rejected }
}

function checkBudget(items: readonly Item[], limits: Limits): void {
  const budget = items.reduce((n, it) => n + verificationCost(it), 0)
  if (budget > limits.maxVerifyBudget) {
    throw new TransportError('verify_budget_exceeded', `${budget} verifications, limit ${limits.maxVerifyBudget}`)
  }
}

function marshalItem(i: Item): string {
  let s = `{"id":${goString(i.id)},"target":${goString(i.target)},"method":${goString(i.method)}`
  if (i.params !== undefined && i.params !== '') s += `,"params":${compactGo(i.params)}`
  if (i.proof !== undefined && i.proof !== '') s += `,"proof":${compactGo(i.proof)}`
  if (i.billProof !== undefined && i.billProof !== '') s += `,"bill_proof":${compactGo(i.billProof)}`
  return s + '}'
}

function marshalEnvelope(e: Envelope, pad: string): string {
  return (
    `{"v":${e.v},"not_after":${e.notAfter},"nonce":${goString(e.nonce)},"reply_to":${goString(e.replyTo)},` +
    `"items":[${e.items.map(marshalItem).join(',')}]` +
    (pad === '' ? '' : `,"pad":${goString(pad)}`) +
    '}'
  )
}

const PAD_FIELD_OVERHEAD = ',"pad":""'.length

/**
 * The padded plaintext for NIP-44, byte for byte as nmilat writes it. Every
 * receive-side rule is applied here too, strictly: any bad item fails it.
 */
export function encodeEnvelope(e: Envelope, limits: Limits): string {
  validateLimits(limits)
  checkHeader(e, limits)
  const { kept, rejected } = checkItems(e, limits)
  if (rejected.length > 0) throw rejected[0]!.error
  checkBudget(kept, limits)
  const body = marshalEnvelope(e, '')
  const target = paddedSize(limits, utf8Len(body) + PAD_FIELD_OVERHEAD)
  const fill = Math.max(target - utf8Len(body) - PAD_FIELD_OVERHEAD, 0)
  const padded = marshalEnvelope(e, '0'.repeat(fill))
  if (utf8Len(padded) > limits.maxEnvelopeBytes) {
    throw new TransportError('envelope_too_large', `${utf8Len(padded)} bytes after padding, limit ${limits.maxEnvelopeBytes}`)
  }
  return padded
}

const ITEM_TYPE: GoType = { object: { id: 'string', target: 'string', method: 'string', params: 'raw', proof: 'raw', bill_proof: 'raw' } }
const ENVELOPE_TYPE: GoType = {
  object: { v: 'int', not_after: 'int', nonce: 'string', reply_to: 'string', items: { array: ITEM_TYPE }, pad: 'string' },
}

/**
 * Parses and checks an envelope plaintext, as the Hub does. Structurally bad
 * items land in `rejected`; it throws only for an envelope-level fault, or
 * when no item survives (with that item's own error).
 */
export function decodeEnvelope(plaintext: string, limits: Limits): { envelope: Envelope; rejected: ItemRejection[] } {
  validateLimits(limits)
  if (utf8Len(plaintext) > limits.maxEnvelopeBytes) {
    throw new TransportError('envelope_too_large', `${utf8Len(plaintext)} bytes, limit ${limits.maxEnvelopeBytes}`)
  }
  let decoded: { value: unknown; typeError: boolean }
  try {
    decoded = decodeGo(parseGo(plaintext), ENVELOPE_TYPE)
  } catch {
    throw new TransportError('envelope_malformed', 'envelope is not valid JSON')
  }
  if (decoded.typeError) throw new TransportError('envelope_malformed', 'envelope field has the wrong type')
  const o = (decoded.value ?? {}) as Record<string, unknown>
  const items = ((o['items'] as Record<string, unknown>[] | undefined) ?? []).map(
    (it): Item => ({
      id: (it['id'] as string | undefined) ?? '',
      target: (it['target'] as string | undefined) ?? '',
      method: (it['method'] as string | undefined) ?? '',
      ...(it['params'] !== undefined && { params: it['params'] as string }),
      ...(it['proof'] !== undefined && { proof: it['proof'] as string }),
      ...(it['bill_proof'] !== undefined && { billProof: it['bill_proof'] as string }),
    }),
  )
  const e: Envelope = {
    v: Number((o['v'] as bigint | undefined) ?? 0n),
    notAfter: Number((o['not_after'] as bigint | undefined) ?? 0n),
    nonce: (o['nonce'] as string | undefined) ?? '',
    replyTo: (o['reply_to'] as string | undefined) ?? '',
    items,
  }
  checkHeader(e, limits)
  const { kept, rejected } = checkItems(e, limits)
  if (kept.length === 0) throw rejected[0]!.error
  checkBudget(kept, limits)
  return { envelope: { ...e, items: kept }, rejected }
}

/** Refuses an envelope already expired at `now`, or valid more than 120 s ahead. */
export function checkFreshness(e: Pick<Envelope, 'notAfter'>, now: number): void {
  if (now > e.notAfter) throw new TransportError('envelope_expired', 'envelope not_after has passed')
  if (e.notAfter - now > MAX_NOT_AFTER_WINDOW) {
    throw new TransportError('envelope_too_fresh', `envelope valid for ${e.notAfter - now}s, maximum ${MAX_NOT_AFTER_WINDOW}s`)
  }
}

/** A fresh random 32-byte hex value, for a nonce or reply_to. */
export function newNonce(random: (n: number) => Uint8Array = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n))): string {
  return [...random(32)].map((b) => b.toString(16).padStart(2, '0')).join('')
}
