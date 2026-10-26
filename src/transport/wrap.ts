// Request wrapping and the response that answers it. Port of nmilat
// nipcash/transport/{request,response}.go.
//
// A request is ONE NIP-44 layer, not a gift wrap: kind 23190 from a fresh
// ephemeral key, p-tagged to the Hub's inbox, created_at randomised up to
// two days into the past. The response is NIP-44 under a key derived from
// that request's conversation key and its reply_to tag.
import { expand } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { finalizeEvent, nip44, type NostrEvent } from '../core/index.js'
import { utf8 } from '../core/bytes.js'
import { KIND_PRIVATE_REQUEST } from './envelope.js'
import { TransportError } from './errors.js'
import { compactGo, goString, unmarshalGo, type GoType } from './gojson.js'
import { paddedSize, validateLimits, type Limits } from './limits.js'

const REPLY_KEY_INFO = 'nipcash-reply-v1'
/** NIP-59's backdating range. */
export const MAX_CREATED_AT_BACKDATE = 2 * 24 * 60 * 60

const isLowerHex64 = (s: string) => /^[0-9a-f]{64}$/.test(s)

type Random = (n: number) => Uint8Array
const defaultRandom: Random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n))

/** A created_at up to two days before `now`, as NIP-59 randomises it. */
export function randomizedCreatedAt(now: number, random: Random = defaultRandom): number {
  const b = random(8)
  const n = new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0)
  return now - Number(n % BigInt(MAX_CREATED_AT_BACKDATE))
}

export interface WrappedRequest {
  readonly event: NostrEvent
  /** Keep it: it is the only way to read the reply. */
  readonly conversationKey: Uint8Array
}

/** Wraps an encoded envelope plaintext for the Hub's inbox. */
export function wrapRequest(plaintext: string, inbox: string, opts: { now: number; random?: Random }): WrappedRequest {
  if (plaintext === '') throw new TransportError('envelope_malformed', 'refusing to wrap an empty payload')
  if (!isLowerHex64(inbox)) throw new TransportError('announcement_malformed', 'inbox pubkey must be 64 lowercase hex characters')
  if (!isValidPoint(inbox)) throw new TransportError('announcement_malformed', 'inbox pubkey is not a valid point')
  const random = opts.random ?? defaultRandom
  let ephemeral: Uint8Array
  let conversationKey: Uint8Array
  for (;;) {
    // Retried only for 32 random bytes outside the curve order, which is
    // astronomically rare.
    ephemeral = random(32)
    try {
      conversationKey = nip44.getConversationKey(ephemeral, inbox)
      break
    } catch {
      continue
    }
  }
  const content = nip44.encrypt(plaintext, conversationKey, random(32))
  const event = finalizeEvent(
    { kind: KIND_PRIVATE_REQUEST, created_at: randomizedCreatedAt(opts.now, random), tags: [['p', inbox]], content },
    ephemeral,
  )
  ephemeral.fill(0)
  return { event, conversationKey }
}

function isValidPoint(xOnly: string): boolean {
  try {
    nip44.getConversationKey(new Uint8Array(32).fill(1), xOnly)
    return true
  } catch {
    return false
  }
}

/** The conversation key between a request's author and an inbox secret (the Hub's side). */
export function conversationKeyFor(eventPubkey: string, counterpartySecret: Uint8Array): Uint8Array {
  if (!isLowerHex64(eventPubkey)) throw new TransportError('envelope_malformed', 'event pubkey must be 64 lowercase hex characters')
  try {
    return nip44.getConversationKey(counterpartySecret, eventPubkey)
  } catch {
    throw new TransportError('envelope_malformed', 'event pubkey is not a valid point')
  }
}

/** HKDF-Expand(SHA-256, conversation key, "nipcash-reply-v1" || reply_to, 32). */
export function deriveReplyKey(conversationKey: Uint8Array, replyTo: string): Uint8Array {
  if (!isLowerHex64(replyTo)) throw new TransportError('envelope_malformed', 'reply_to must be 64 lowercase hex characters')
  return expand(sha256, conversationKey, utf8(REPLY_KEY_INFO + replyTo), 32)
}

// ---- response envelope

export interface ResultError {
  readonly code: string
  readonly message?: string
  /** A machine-readable refinement some refusals carry (e.g. a withdraw quote's), kept as sent. */
  readonly detail?: string
}

/** One item's outcome: a result, or an error. */
export interface ItemResult {
  readonly id: string
  readonly resultType?: string
  /** JSON text of the result. */
  readonly result?: string
  readonly error?: ResultError
}

export interface ResponseEnvelope {
  readonly reqNonce: string
  /** Set only when the whole envelope was refused. */
  readonly error?: ResultError
  readonly results: readonly ItemResult[]
  /** 1-based chunk position and count. */
  readonly seq: number
  readonly total: number
  /** Decoded only: ids this chunk answered twice, or with both a result and an error. They have no decided outcome. */
  readonly conflictedIds?: readonly string[]
  /** Decoded only: ids answered that the request never sent; dropped. */
  readonly unknownIds?: readonly string[]
  /** Decoded only: `seq` outside 1 to `total`, which makes the reply incomplete. */
  readonly malformedSeq?: boolean
}

const RESULT_ERROR: GoType = { object: { code: 'string', message: 'string', detail: 'string' } }
const RESPONSE_TYPE: GoType = {
  object: {
    req_nonce: 'string',
    error: RESULT_ERROR,
    results: { array: { object: { id: 'string', result_type: 'string', result: 'raw', error: RESULT_ERROR } } },
    seq: 'int',
    total: 'int',
    pad: 'string',
  },
}

function marshalError(e: ResultError): string {
  return `{"code":${goString(e.code)}${e.message ? `,"message":${goString(e.message)}` : ''}${e.detail !== undefined ? `,"detail":${goString(e.detail)}` : ''}}`
}

function readError(err: Record<string, unknown>): ResultError {
  return {
    code: (err['code'] as string | undefined) ?? '',
    ...(err['message'] ? { message: err['message'] as string } : {}),
    ...(typeof err['detail'] === 'string' && { detail: err['detail'] }),
  }
}

function marshalResponse(r: ResponseEnvelope, pad: string): string {
  let s = `{"req_nonce":${goString(r.reqNonce)}`
  if (r.error) s += `,"error":${marshalError(r.error)}`
  if (r.results.length > 0) {
    s +=
      ',"results":[' +
      r.results
        .map(
          (x) =>
            `{"id":${goString(x.id)}` +
            (x.resultType ? `,"result_type":${goString(x.resultType)}` : '') +
            (x.result !== undefined && x.result !== '' ? `,"result":${compactGo(x.result)}` : '') +
            (x.error ? `,"error":${marshalError(x.error)}` : '') +
            '}',
        )
        .join(',') +
      ']'
  }
  s += `,"seq":${r.seq},"total":${r.total}`
  if (pad !== '') s += `,"pad":${goString(pad)}`
  return s + '}'
}

const utf8Len = (s: string) => utf8(s).length

/** Serialises and pads a response, as a Hub does (used by tests and FakeHub). */
export function encodeResponse(r: ResponseEnvelope, limits: Limits): string {
  validateLimits(limits)
  if (!isLowerHex64(r.reqNonce)) throw new TransportError('response_malformed', 'req_nonce must be 64 lowercase hex characters')
  const seq = r.seq === 0 && r.total === 0 ? 1 : r.seq
  const total = r.seq === 0 && r.total === 0 ? 1 : r.total
  if (total < 1 || seq < 1 || seq > total) throw new TransportError('response_malformed', `seq ${seq} of ${total} is not a position in a reply`)
  const norm = { ...r, seq, total }
  const body = marshalResponse(norm, '')
  const overhead = ',"pad":""'.length
  const target = paddedSize(limits, utf8Len(body) + overhead)
  const padded = marshalResponse(norm, '0'.repeat(Math.max(target - utf8Len(body) - overhead, 0)))
  if (utf8Len(padded) > limits.maxEnvelopeBytes) {
    throw new TransportError('envelope_too_large', `${utf8Len(padded)} bytes after padding, limit ${limits.maxEnvelopeBytes}`)
  }
  return padded
}

/**
 * Parses a response chunk and checks it answers the request with
 * `reqNonce` (a mismatch rejects the chunk). It never throws for a bad item:
 * an unknown id is dropped (`unknownIds`), an id answered twice or with both
 * a result and an error has no outcome (`conflictedIds`), and a `seq`
 * outside 1 to `total` is flagged (`malformedSeq`) with its results kept.
 */
export function decodeResponse(plaintext: string, reqNonce: string, requestedIds: readonly string[], limits: Limits): ResponseEnvelope {
  validateLimits(limits)
  if (utf8Len(plaintext) > limits.maxEnvelopeBytes) {
    throw new TransportError('envelope_too_large', `${utf8Len(plaintext)} bytes, limit ${limits.maxEnvelopeBytes}`)
  }
  let decoded: { value: unknown; typeError: boolean }
  try {
    decoded = unmarshalGo(plaintext, RESPONSE_TYPE)
  } catch {
    throw new TransportError('response_malformed', 'response is not valid JSON')
  }
  if (decoded.typeError) throw new TransportError('response_malformed', 'response field has the wrong type')
  const o = (decoded.value ?? {}) as Record<string, unknown>
  const nonce = (o['req_nonce'] as string | undefined) ?? ''
  if (nonce !== reqNonce) throw new TransportError('response_mismatch', 'response answers a different request')
  let seq = Number((o['seq'] as bigint | undefined) ?? 0n)
  let total = Number((o['total'] as bigint | undefined) ?? 0n)
  if (seq === 0 && total === 0) seq = total = 1
  const malformedSeq = total < 1 || seq < 1 || seq > total

  const known = new Set(requestedIds)
  const count = new Map<string, number>()
  const raws = (o['results'] as Record<string, unknown>[] | undefined) ?? []
  for (const raw of raws) {
    const id = (raw['id'] as string | undefined) ?? ''
    count.set(id, (count.get(id) ?? 0) + 1)
  }
  const unknownIds = new Set<string>()
  const conflicted = new Set<string>()
  const results: ItemResult[] = []
  for (const raw of raws) {
    const id = (raw['id'] as string | undefined) ?? ''
    if (!known.has(id)) {
      unknownIds.add(id)
      continue
    }
    const err = raw['error'] as Record<string, unknown> | undefined
    if (count.get(id)! > 1 || (raw['result'] !== undefined && err !== undefined)) {
      conflicted.add(id)
      continue
    }
    results.push({
      id,
      ...(raw['result_type'] !== undefined && raw['result_type'] !== '' && { resultType: raw['result_type'] as string }),
      ...(raw['result'] !== undefined && { result: raw['result'] as string }),
      ...(err !== undefined && { error: readError(err) }),
    })
  }
  const envErr = o['error'] as Record<string, unknown> | undefined
  return {
    reqNonce: nonce,
    ...(envErr !== undefined && { error: readError(envErr) }),
    results,
    seq,
    total,
    ...(conflicted.size > 0 && { conflictedIds: [...conflicted] }),
    ...(unknownIds.size > 0 && { unknownIds: [...unknownIds] }),
    ...(malformedSeq && { malformedSeq: true }),
  }
}

/** Ids requested but not answered: "not served", never "spent". */
export function omittedIds(r: Pick<ResponseEnvelope, 'results'>, requestedIds: readonly string[]): string[] {
  const answered = new Set(r.results.map((x) => x.id))
  return requestedIds.filter((id) => !answered.has(id))
}

/** Decrypts a kind 23191 reply's content with the derived reply key. */
export function openReply(content: string, conversationKey: Uint8Array, replyTo: string): string {
  return nip44.decrypt(content, deriveReplyKey(conversationKey, replyTo))
}

/** Encrypts a reply's content (the Hub's side; used by FakeHub). */
export function sealReply(plaintext: string, conversationKey: Uint8Array, replyTo: string): string {
  return nip44.encrypt(plaintext, deriveReplyKey(conversationKey, replyTo))
}
