// NIP-47 (Nostr Wallet Connect) messages: pairing URIs, the info event, and
// nip44_v2 request and response events. Port of nmilat nip47/{pairing,
// events,methods}.go. Only nip44_v2 content is handled; a nip04-only wallet
// is reported as such rather than spoken to.
import { fromUtf8, goFields, utf8 } from './bytes.js'
import { CoreError } from './errors.js'
import { decodeGoStruct } from './gojson.js'
import { toJSONText } from './json.js'
import { getPublicKey, type NostrEvent, type UnsignedEvent } from './nip01.js'
import { decrypt, encrypt, getConversationKey } from './nip44.js'
import * as nip04 from './nip04.js'

export const PAIRING_URI_SCHEME = 'nostr+walletconnect'
export const KIND_NWC_INFO = 13194
export const KIND_NWC_REQUEST = 23194
export const KIND_NWC_RESPONSE = 23195
export const ENCRYPTION_NIP04 = 'nip04'
export const ENCRYPTION_NIP44_V2 = 'nip44_v2'

const fail = (msg: string) => new CoreError('invalid_payload', `nip47: ${msg}`)

// ---- pairing URI

const UNRESERVED = /[A-Za-z0-9\-_.~]/

/** Go's url.QueryEscape. */
function queryEscape(s: string): string {
  let out = ''
  for (const b of utf8(s)) {
    const c = String.fromCharCode(b)
    if (UNRESERVED.test(c)) out += c
    else if (c === ' ') out += '+'
    else out += '%' + b.toString(16).toUpperCase().padStart(2, '0')
  }
  return out
}

/** Go's url.QueryUnescape, or undefined for a malformed escape. */
function queryUnescape(s: string): string | undefined {
  const bytes: number[] = []
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!
    if (c === '+') bytes.push(0x20)
    else if (c === '%') {
      const hex = s.slice(i + 1, i + 3)
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) return undefined
      bytes.push(parseInt(hex, 16))
      i += 2
    } else bytes.push(...utf8(c))
  }
  return fromUtf8(Uint8Array.from(bytes))
}

export interface PairingInfo {
  readonly walletPubkey: string
  readonly relays: readonly string[]
  /** The connection secret. Secret-bearing (design §10). */
  readonly secret: string
  /** Every other query parameter, in order of appearance per key. */
  readonly extra: Readonly<Record<string, readonly string[]>>
}

/**
 * `nostr+walletconnect://<pubkey>?relay=…&secret=…`, with parameters sorted by
 * key and escaped as Go's url.Values.Encode does.
 */
export function buildPairingURI(
  walletPubkey: string,
  relays: readonly string[],
  secret: string,
  extra: Readonly<Record<string, readonly string[]>> = {},
): string {
  const q = new Map<string, string[]>()
  const add = (k: string, v: string) => q.set(k, [...(q.get(k) ?? []), v])
  for (const r of relays) add('relay', r)
  q.set('secret', [secret])
  for (const [k, vs] of Object.entries(extra)) for (const v of vs) add(k, v)
  const parts: string[] = []
  // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
  for (const k of [...q.keys()].sort()) for (const v of q.get(k)!) parts.push(`${queryEscape(k)}=${queryEscape(v)}`)
  return `${PAIRING_URI_SCHEME}://${walletPubkey}?${parts.join('&')}`
}

/**
 * Parses a pairing URI as nmilat does (Go's url.Parse and Query()): the
 * scheme is case-insensitive, a fragment is dropped, userinfo before the
 * pubkey is ignored, a query pair with a ';' or a bad escape is dropped, and
 * the first `secret` wins.
 */
export function parsePairingURI(uri: string): PairingInfo {
  for (let i = 0; i < uri.length; i++) {
    const c = uri.charCodeAt(i)
    if (c < 0x20 || c === 0x7f) throw fail('invalid pairing uri: control character')
  }
  const colon = uri.indexOf(':')
  const scheme = colon > 0 ? uri.slice(0, colon) : ''
  if (!/^[A-Za-z][A-Za-z0-9+.-]*$/.test(scheme)) throw fail('invalid pairing uri: missing scheme')
  if (scheme.toLowerCase() !== PAIRING_URI_SCHEME) throw fail(`invalid pairing uri scheme, expected ${PAIRING_URI_SCHEME}`)

  let rest = uri.slice(colon + 1)
  const hash = rest.indexOf('#')
  if (hash >= 0) rest = rest.slice(0, hash)
  const qmark = rest.indexOf('?')
  const rawQuery = qmark >= 0 ? rest.slice(qmark + 1) : ''
  const beforeQuery = qmark >= 0 ? rest.slice(0, qmark) : rest

  let pubkey: string
  if (beforeQuery.startsWith('//')) {
    const authority = beforeQuery.slice(2).split('/')[0]!
    const at = authority.lastIndexOf('@')
    pubkey = at >= 0 ? authority.slice(at + 1) : authority
  } else {
    pubkey = beforeQuery
  }
  if (!/^[0-9a-fA-F]{64}$/.test(pubkey)) throw fail('invalid wallet pubkey in pairing uri')

  const params = new Map<string, string[]>()
  for (const pair of rawQuery.split('&')) {
    if (pair === '' || pair.includes(';')) continue
    const eq = pair.indexOf('=')
    const k = queryUnescape(eq >= 0 ? pair.slice(0, eq) : pair)
    const v = queryUnescape(eq >= 0 ? pair.slice(eq + 1) : '')
    if (k === undefined || v === undefined) continue
    params.set(k, [...(params.get(k) ?? []), v])
  }
  const relays = params.get('relay') ?? []
  if (relays.length === 0) throw fail('pairing uri missing relay parameter')
  const secret = params.get('secret')?.[0] ?? ''
  if (secret === '') throw fail('pairing uri missing secret parameter')
  params.delete('relay')
  params.delete('secret')
  return { walletPubkey: pubkey, relays, secret, extra: Object.fromEntries(params) }
}

// ---- info event

export interface WalletInfo {
  readonly methods: readonly string[]
  readonly notificationTypes: readonly string[]
  /** Defaults to ["nip04"] when the wallet does not say. */
  readonly supportedEncryptions: readonly string[]
}

type TagLookup = { readonly found: 'absent' | 'repeated' | 'novalue' } | { readonly found: 'one'; readonly value: string }

/** nmilat's FindUniqueEventTagValue: exactly one tag named `name`, with a value. */
function uniqueTag(e: { tags: readonly (readonly string[])[] }, name: string): TagLookup {
  const found = e.tags.filter((t) => t.length > 0 && t[0] === name)
  if (found.length === 0) return { found: 'absent' }
  if (found.length > 1) return { found: 'repeated' }
  if (found[0]!.length < 2) return { found: 'novalue' }
  return { found: 'one', value: found[0]![1]! }
}

const nonEmpty = (t: TagLookup): string | undefined => (t.found === 'one' && t.value !== '' ? t.value : undefined)

export function parseInfoEvent(e: NostrEvent): WalletInfo {
  if (e.kind !== KIND_NWC_INFO) throw fail(`invalid kind ${e.kind}, expected ${KIND_NWC_INFO}`)
  const enc = nonEmpty(uniqueTag(e, 'encryption'))
  const notif = nonEmpty(uniqueTag(e, 'notifications'))
  return {
    methods: e.content === '' ? [] : goFields(e.content),
    notificationTypes: notif !== undefined ? goFields(notif) : [],
    supportedEncryptions: enc !== undefined ? goFields(enc) : [ENCRYPTION_NIP04],
  }
}

// ---- request and response

export interface NWCError {
  readonly code: string
  readonly message: string
}

export type NWCEncryption = typeof ENCRYPTION_NIP44_V2 | typeof ENCRYPTION_NIP04

/**
 * The scheme to talk to a wallet in (NIP-47 §Encryption): nip44_v2 whenever
 * the wallet lists it, nip04 when it lists only that or says nothing (an
 * absent tag means nip04-only). Undefined when it lists neither.
 */
export function chooseEncryption(info: Pick<WalletInfo, 'supportedEncryptions'>): NWCEncryption | undefined {
  if (info.supportedEncryptions.includes(ENCRYPTION_NIP44_V2)) return ENCRYPTION_NIP44_V2
  if (info.supportedEncryptions.includes(ENCRYPTION_NIP04)) return ENCRYPTION_NIP04
  return undefined
}

/**
 * Builds the unsigned kind 23194 request: `{"method","params"}` encrypted to
 * the wallet from the connection's own key, with nip44_v2 unless the wallet
 * speaks only nip04. Sign it with the same key (`finalizeEvent`).
 */
export function nwcRequestEvent(p: {
  connectionSecret: Uint8Array
  walletPubkey: string
  method: string
  params?: unknown
  createdAt: number
  /** nip44_v2: the 32-byte nonce; nip04: the 16-byte IV. For vectors only. */
  nonce?: Uint8Array
  encryption?: NWCEncryption
}): UnsignedEvent {
  const plaintext = toJSONText(p.params === undefined || p.params === null ? { method: p.method } : { method: p.method, params: p.params })
  const encryption = p.encryption ?? ENCRYPTION_NIP44_V2
  let content: string
  if (encryption === ENCRYPTION_NIP04) {
    content = p.nonce === undefined ? nip04.encrypt(plaintext, p.connectionSecret, p.walletPubkey) : nip04.encrypt(plaintext, p.connectionSecret, p.walletPubkey, p.nonce)
  } else {
    const ck = getConversationKey(p.connectionSecret, p.walletPubkey)
    content = p.nonce === undefined ? encrypt(plaintext, ck) : encrypt(plaintext, ck, p.nonce)
  }
  return {
    pubkey: getPublicKey(p.connectionSecret),
    created_at: p.createdAt,
    kind: KIND_NWC_REQUEST,
    tags: [
      ['p', p.walletPubkey],
      ['encryption', encryption],
    ],
    content,
  }
}

export interface NWCResponse {
  readonly resultType: string
  readonly error?: NWCError
  /** The parsed `result`, if any. */
  readonly result?: unknown
  /** From the `e` tag. */
  readonly requestEventId: string
  /** From the `d` tag; "" for single-payment methods. */
  readonly subPaymentId: string
}

/**
 * Decrypts and parses a kind 23195 response with the connection secret. The
 * response's own `encryption` tag wins; `fallbackEncryption` covers wallets
 * that do not re-tag (pass the scheme the request used). Exactly one `e`
 * tag is required, and at most one `d` tag.
 */
export function parseResponseEvent(e: NostrEvent, connectionSecret: Uint8Array, fallbackEncryption = ENCRYPTION_NIP44_V2): NWCResponse {
  if (e.kind !== KIND_NWC_RESPONSE) throw fail(`invalid kind ${e.kind}, expected ${KIND_NWC_RESPONSE}`)
  const eTag = uniqueTag(e, 'e')
  if (eTag.found !== 'one') throw fail('response needs exactly one e tag')
  const requestEventId = eTag.value
  const dTag = uniqueTag(e, 'd')
  if (dTag.found !== 'one' && dTag.found !== 'absent') throw fail('response d tag repeated or empty')
  const encryption = nonEmpty(uniqueTag(e, 'encryption')) ?? fallbackEncryption
  if (encryption !== ENCRYPTION_NIP44_V2 && encryption !== ENCRYPTION_NIP04) throw fail(`unsupported encryption ${JSON.stringify(encryption)}`)

  let plaintext: string
  try {
    plaintext = encryption === ENCRYPTION_NIP04 ? nip04.decrypt(e.content, connectionSecret, e.pubkey) : decrypt(e.content, getConversationKey(connectionSecret, e.pubkey))
  } catch {
    throw fail('decrypt response failed')
  }
  let body: unknown
  try {
    body = JSON.parse(plaintext)
  } catch {
    throw fail('response is not JSON')
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) throw fail('response is not an object')
  const o = body as Record<string, unknown>
  const top = decodeGoStruct(body, { result_type: 'string' }, 'nip47 response')
  const resultType = (top['result_type'] as string | undefined) ?? ''
  let error: NWCError | undefined
  if (o['error'] !== undefined && o['error'] !== null) {
    const eo = decodeGoStruct(o['error'], { code: 'string', message: 'string' }, 'nip47 response error')
    error = { code: (eo['code'] as string | undefined) ?? '', message: (eo['message'] as string | undefined) ?? '' }
  }
  return {
    resultType,
    ...(error !== undefined && { error }),
    ...(o['result'] !== undefined && o['result'] !== null && { result: o['result'] }),
    requestEventId,
    subPaymentId: dTag.found === 'one' ? dTag.value : '',
  }
}
