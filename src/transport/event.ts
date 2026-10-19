// Events inside the transport (proofs, announcements) as nmilat reads and
// writes them: decoded with encoding/json's struct rules, written with
// json.Marshal's field order and escaping.
import type { NostrEvent } from '../core/index.js'
import { TransportError } from './errors.js'
import { goString, unmarshalGo, type GoType } from './gojson.js'

const EVENT_TYPE: GoType = {
  object: {
    id: 'string',
    pubkey: 'string',
    created_at: 'uint',
    kind: 'int',
    tags: { array: { array: 'string' } },
    content: 'string',
    sig: 'string',
  },
}

/** Decodes event JSON as nmilat's nip01.Event; a wrong type or bad JSON throws. */
export function parseGoEvent(text: string, code: TransportError['code'], what: string): NostrEvent {
  let decoded: { value: unknown; typeError: boolean }
  try {
    decoded = unmarshalGo(text, EVENT_TYPE)
  } catch {
    throw new TransportError(code, `${what} is not valid JSON`)
  }
  if (decoded.typeError) throw new TransportError(code, `${what} has a field of the wrong type`)
  const o = (decoded.value ?? {}) as Record<string, unknown>
  const createdAt = (o['created_at'] as bigint | undefined) ?? 0n
  const kind = (o['kind'] as bigint | undefined) ?? 0n
  if (createdAt > BigInt(Number.MAX_SAFE_INTEGER) || kind > BigInt(Number.MAX_SAFE_INTEGER) || kind < BigInt(Number.MIN_SAFE_INTEGER)) {
    throw new TransportError(code, `${what} has an out-of-range number`)
  }
  return {
    id: (o['id'] as string | undefined) ?? '',
    pubkey: (o['pubkey'] as string | undefined) ?? '',
    created_at: Number(createdAt),
    kind: Number(kind),
    tags: (o['tags'] as string[][] | undefined) ?? [],
    content: (o['content'] as string | undefined) ?? '',
    sig: (o['sig'] as string | undefined) ?? '',
  }
}

/** Event JSON in nip01.Event's field order, escaped as json.Marshal does. */
export function goEventJSON(e: NostrEvent): string {
  return (
    `{"id":${goString(e.id)},"pubkey":${goString(e.pubkey)},"created_at":${e.created_at},"kind":${e.kind},` +
    `"tags":[${e.tags.map((t) => '[' + t.map(goString).join(',') + ']').join(',')}],` +
    `"content":${goString(e.content)},"sig":${goString(e.sig)}}`
  )
}
