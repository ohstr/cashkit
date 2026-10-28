// The private-transport envelope: many bill operations in one NIP-44
// plaintext. Port of nmilat nipcash/transport/envelope.go. Encoding matches
// Go's json.Marshal byte for byte; decoding is structural and drops only an
// item that is not well formed, never failing its co-items.
import { isRequestId } from '../core/index.js'
import { paramsHash } from './canonical.js'
import { TransportError } from './errors.js'
import { compactGo, decodeGo, goString, parseGo, unmarshalGo, type GoType, type JNode } from './gojson.js'
import { MAX_ITEM_ID_BYTES, paddedSize, validateLimits, type Limits } from './limits.js'

export const KIND_PRIVATE_REQUEST = 23190
export const KIND_PRIVATE_RESPONSE = 23191
export const KIND_ITEM_PROOF = 23192
export const KIND_BILL_PROOF = 23193

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

/** Whether the item's params carry a non-empty cash_secret. */
export function hasCashSecret(i: Item): boolean {
  const p = paramsAs(i, { object: { cash_secret: 'string' } })
  return typeof p['cash_secret'] === 'string' && p['cash_secret'] !== ''
}

/** A `cash_withdraw` cancel request: its params carry `cancel`. */
export function isCancelRequest(i: Pick<Item, 'method' | 'params'>): boolean {
  if (i.method !== 'cash_withdraw') return false
  const p = paramsAs(i as Item, { object: { cancel: 'raw' } })
  return p['cancel'] !== undefined && p['cancel'] !== 'null'
}

/**
 * The method a Hub serves an item under (NIP-CASH §Cancelling a Payout): a
 * `cash_withdraw` whose params carry `cancel` is a cancel request, served as
 * the `cash_lookup` of that call; anything else is served as its own method.
 * A malformed cancel (`cancel` not `true`, a field other than `cancel`,
 * `request_id` and `cash_secret`, or no well-formed `request_id`) throws
 * `bad_cancel`, which a Hub answers `BAD_REQUEST`.
 */
export function servingMethod(method: string, params: string | undefined): string {
  if (method !== 'cash_withdraw') return method
  let n: JNode
  try {
    n = parseGo(params ?? '')
  } catch {
    return method // not JSON: the withdraw's own parser refuses it
  }
  if (n.kind !== 'object') return method
  const cancel = member(n, 'cancel')
  if (cancel === undefined) return method
  if (cancel.kind !== 'bool' || !cancel.value) throw new TransportError('bad_cancel', 'malformed cash_withdraw cancel request: cancel must be true')
  for (const [k] of n.members) {
    if (k !== 'cancel' && k !== 'request_id' && k !== 'cash_secret') {
      throw new TransportError('bad_cancel', `malformed cash_withdraw cancel request: ${JSON.stringify(k)} is not allowed`)
    }
  }
  const rid = member(n, 'request_id')
  if (rid?.kind !== 'string' || !isRequestId(rid.value)) throw new TransportError('bad_cancel', 'malformed cash_withdraw cancel request: request_id')
  return 'cash_lookup'
}

/**
 * Whether an item's authorization has a shape the method it is served under
 * allows (NIP-CASH §Bearer Items, §Serving an Envelope I8): never both
 * `proof` and a `cash_secret`; a value method needs one of them; `cash_order`
 * needs `proof`; a `cash_status` or `cash_withdraw_quote` carries no secret
 * (a cash-mode one passes on its bill proof alone); any other method,
 * `cash_lookup` and a cancel request included, may go either way. A
 * malformed cancel request is never well shaped.
 */
export function bearerShapeOK(method: string, params: string | undefined, hasProofField: boolean, hasSecret: boolean): boolean {
  if (hasProofField && hasSecret) return false
  let serving: string
  try {
    serving = servingMethod(method, params)
  } catch {
    return false
  }
  switch (serving) {
    case 'cash_redeem':
    case 'cash_withdraw':
    case 'cash_transfer':
    case 'cash_consolidate':
      return hasProofField || hasSecret
    case 'cash_order':
      return hasProofField
    case 'cash_status':
    case 'cash_withdraw_quote':
      return !hasSecret
    default:
      return true
  }
}

/** How many consolidate sources the params declare; 0 for other methods. */
export function sourceCount(i: Item): number {
  const p = paramsAs(i, { object: { sources: { array: 'raw' } } })
  return Array.isArray(p['sources']) ? p['sources'].length : 0
}

const SIGNED_PARAMS: GoType = {
  object: {
    identity_event: 'raw',
    attestation_event: 'raw',
    quote: 'raw',
    sources: { array: { object: { identity_event: 'raw', attestation_event: 'raw' } } },
  },
}

/**
 * Signature verifications the Hub will spend on this item (NIP-CASH §Bearer
 * Items): its bill proof, its item proof when present, and every signed
 * event in its params (kind 23198, 35522 or 23187), one per source for a
 * consolidate. A cash secret costs nothing.
 */
export function verificationCost(i: Item): number {
  let cost = 1 // the bill proof
  if (hasProof(i)) cost++
  const p = paramsAs(i, SIGNED_PARAMS)
  for (const k of ['identity_event', 'attestation_event', 'quote']) if (hasRawValue(p[k] as string | undefined) && p[k] !== '""') cost++
  for (const s of (p['sources'] as Record<string, unknown>[] | undefined) ?? []) {
    for (const k of ['identity_event', 'attestation_event']) if (hasRawValue(s[k] as string | undefined) && s[k] !== '""') cost++
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
  if (!bearerShapeOK(item.method, item.params, hasProof(item), hasCashSecret(item))) return bad('envelope_malformed', `item ${i} carries an authorization its method does not allow`)
  if (!hasBillProof(item)) return bad('envelope_malformed', `item ${i} has no bill proof`)
  if (sourceCount(item) > limits.maxConsolidateSources) {
    return bad('too_many_items', `item ${i} declares ${sourceCount(item)} sources, limit ${limits.maxConsolidateSources}`)
  }
  return { hash }
}

function checkHeader(e: Envelope, limits: Limits): void {
  if (!isLowerHex64(e.nonce)) throw new TransportError('envelope_malformed', 'nonce must be 64 lowercase hex characters')
  if (!isLowerHex64(e.replyTo)) throw new TransportError('envelope_malformed', 'reply_to must be 64 lowercase hex characters')
  if (e.items.length === 0) throw new TransportError('envelope_no_items', 'envelope carries no items')
  if (e.items.length > limits.maxItems) {
    throw new TransportError('too_many_items', `${e.items.length} items, limit ${limits.maxItems}`)
  }
}

/**
 * The Hub's per-item checks after a structural decode: an item with no id, a
 * bad target, no method, params that are not JSON, an authorization its
 * method does not allow or no bill proof is omitted, and so is every repeat
 * of an identical item (the first is kept); `encodeEnvelope` also refuses
 * items sharing an id. For a Hub (and the fake Hub).
 */
export function servableItems(e: Envelope, limits: Limits): { kept: Item[]; rejected: ItemRejection[] } {
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

/** A request_id names one call: two items of one envelope never carry the same one (lookups aside). */
function checkRequestIds(items: readonly Item[]): void {
  const seen = new Set<string>()
  for (const it of items) {
    if (it.method === 'cash_lookup' || isCancelRequest(it)) continue
    const id = paramsAs(it, { object: { request_id: 'string' } })['request_id']
    if (typeof id !== 'string' || id === '') continue
    if (seen.has(id)) throw new TransportError('duplicate_item', 'two items carry the same request_id')
    seen.add(id)
  }
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
    `{"not_after":${e.notAfter},"nonce":${goString(e.nonce)},"reply_to":${goString(e.replyTo)},` +
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
  const { kept, rejected } = servableItems(e, limits)
  if (rejected.length > 0) throw rejected[0]!.error
  checkRequestIds(kept)
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
const ENVELOPE_TYPE: GoType = { object: { not_after: 'int', nonce: 'string', reply_to: 'string', items: { array: 'raw' } } }

/** An object member by exact name, the last occurrence winning (Go's map decoding). */
function member(n: JNode & { kind: 'object' }, name: string): JNode | undefined {
  let found: JNode | undefined
  for (const [k, v] of n.members) if (k === name) found = v
  return found
}

/**
 * An item's I1 shape: a JSON object with string `id`, `target` and `method`,
 * and `params` absent, null or an object.
 */
function itemShapeOK(raw: string): boolean {
  let n: JNode
  try {
    n = parseGo(raw)
  } catch {
    return false
  }
  if (n.kind !== 'object') return false
  const field = (name: string) => member(n, name)
  for (const name of ['id', 'target', 'method']) if (field(name)?.kind !== 'string') return false
  const params = field('params')
  return params === undefined || params.kind === 'null' || params.kind === 'object'
}

/** The string `id` of each raw item that carries one, for the uniqueness rule. */
function rawItemId(raw: string): string | undefined {
  try {
    const n = parseGo(raw)
    if (n.kind !== 'object') return undefined
    const id = member(n, 'id')
    return id?.kind === 'string' ? id.value : undefined
  } catch {
    return undefined
  }
}

/**
 * Parses an envelope plaintext structurally, as nmilat's `Decode` does: the
 * size limit, the header, at least one and at most `maxItems` items, unique
 * item ids (an envelope with two items sharing one is refused whole), and the
 * verification budget over the items kept. An item that is not well formed,
 * or that declares more consolidate sources than allowed, lands in
 * `rejected`; every other item is kept, whatever its target, proofs or
 * duplicates, for the Hub's per-item serving rules (`servableItems`) to
 * judge.
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
  const raws = (o['items'] as string[] | undefined) ?? []
  const header: Envelope = {
    notAfter: Number((o['not_after'] as bigint | undefined) ?? 0n),
    nonce: (o['nonce'] as string | undefined) ?? '',
    replyTo: (o['reply_to'] as string | undefined) ?? '',
    items: [],
  }
  if (!isLowerHex64(header.nonce)) throw new TransportError('envelope_malformed', 'nonce must be 64 lowercase hex characters')
  if (!isLowerHex64(header.replyTo)) throw new TransportError('envelope_malformed', 'reply_to must be 64 lowercase hex characters')
  if (raws.length === 0) throw new TransportError('envelope_no_items', 'envelope carries no items')
  if (raws.length > limits.maxItems) throw new TransportError('too_many_items', `${raws.length} items, limit ${limits.maxItems}`)
  const ids = new Set<string>()
  for (const raw of raws) {
    const id = rawItemId(raw)
    if (id === undefined) continue
    if (ids.has(id)) throw new TransportError('duplicate_item_id', 'two items share an id')
    ids.add(id)
  }
  const items: Item[] = []
  const rejected: ItemRejection[] = []
  raws.forEach((raw, index) => {
    if (!itemShapeOK(raw)) {
      rejected.push({ index, error: new TransportError('envelope_malformed', `item ${index} is not well formed`) })
      return
    }
    const { value, typeError } = unmarshalGo(raw, ITEM_TYPE)
    if (typeError) {
      rejected.push({ index, error: new TransportError('envelope_malformed', `item ${index} field has the wrong type`) })
      return
    }
    const it = value as Record<string, string | undefined>
    const item: Item = {
      id: it['id'] ?? '',
      target: it['target'] ?? '',
      method: it['method'] ?? '',
      ...(it['params'] !== undefined && { params: it['params'] }),
      ...(it['proof'] !== undefined && { proof: it['proof'] }),
      ...(it['bill_proof'] !== undefined && { billProof: it['bill_proof'] }),
    }
    const sources = sourceCount(item)
    if (sources > limits.maxConsolidateSources) {
      rejected.push({ index, error: new TransportError('too_many_items', `item ${index} declares ${sources} sources, limit ${limits.maxConsolidateSources}`) })
      return
    }
    items.push(item)
  })
  checkBudget(items, limits)
  return { envelope: { ...header, items }, rejected }
}


/**
 * The Hub's freshness rule (NIP-CASH §Envelopes): an envelope past its
 * `not_after` is dropped (`envelope_expired`); one more than the Hub's
 * current `max_request_age` ahead is refused with an envelope-level
 * `BAD_REQUEST` (`envelope_too_far_ahead`). For a Hub (and the fake Hub);
 * a client sets its deadline from H instead.
 */
export function checkFreshness(e: Pick<Envelope, 'notAfter'>, now: number, maxRequestAge: number): void {
  if (now > e.notAfter) throw new TransportError('envelope_expired', 'envelope not_after has passed')
  if (e.notAfter - now > maxRequestAge) {
    throw new TransportError('envelope_too_far_ahead', `envelope valid for ${e.notAfter - now}s, the hub accepts at most ${maxRequestAge}s`)
  }
}

/** A fresh random 32-byte hex value, for a nonce or reply_to. */
export function newNonce(random: (n: number) => Uint8Array = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n))): string {
  return [...random(32)].map((b) => b.toString(16).padStart(2, '0')).join('')
}
