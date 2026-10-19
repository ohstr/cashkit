// Kind 11190 Hub announcements: how a client learns a Hub's inbox and
// limits. Port of nmilat nipcash/transport/{announcement,identity}.go.
//
// The trust chain is bill -> node key (from the bill's mint signature) ->
// announcement -> inbox. parseAnnouncement is the link that refuses to be
// skipped: it requires the expected node key.
import { nip44, verifyEvent, type NostrEvent } from '../core/index.js'
import { TransportError } from './errors.js'
import { unmarshalGo, type GoType } from './gojson.js'
import { validateAnnouncedLimits, type Limits } from './limits.js'

export const KIND_HUB_ANNOUNCEMENT = 11190
export const ANNOUNCEMENT_VERSION = 1

export interface Announcement {
  /** x-only pubkey clients encrypt envelopes to and p-tag. */
  readonly inbox: string
  readonly limits: Limits
  readonly relays: readonly string[]
  /** The event's created_at: newer replaces older (rollback guard). */
  readonly createdAt: number
}

const isLowerHex64 = (s: string) => /^[0-9a-f]{64}$/.test(s)

const CONTENT: GoType = {
  object: {
    v: 'int',
    inbox: 'string',
    limits: {
      object: { max_bytes: 'int', max_items: 'int', max_consolidate_sources: 'int', pad_bucket_bytes: 'int', max_verify_budget: 'int' },
    },
    relays: { array: 'string' },
  },
}

function validPoint(xOnly: string): boolean {
  try {
    nip44.getConversationKey(new Uint8Array(32).fill(1), xOnly)
    return true
  } catch {
    return false
  }
}

/** Verifies an announcement against the node key it must come from. */
export function parseAnnouncement(ev: NostrEvent, expectedNode: string): Announcement {
  if (ev.kind !== KIND_HUB_ANNOUNCEMENT) throw new TransportError('announcement_malformed', `kind ${ev.kind}, want ${KIND_HUB_ANNOUNCEMENT}`)
  if (!isLowerHex64(expectedNode)) throw new TransportError('announcement_malformed', 'expected node pubkey must be 64 lowercase hex characters')
  if (ev.pubkey !== expectedNode) throw new TransportError('announcement_author', 'announcement was not signed by the expected node identity')
  if (!verifyEvent(ev, { checkPow: false })) throw new TransportError('announcement_signature', 'announcement signature is invalid')

  let decoded: { value: unknown; typeError: boolean }
  try {
    decoded = unmarshalGo(ev.content, CONTENT)
  } catch {
    throw new TransportError('announcement_malformed', 'announcement content is not valid JSON')
  }
  if (decoded.typeError) throw new TransportError('announcement_malformed', 'announcement field has the wrong type')
  const o = (decoded.value ?? {}) as Record<string, unknown>
  const v = Number((o['v'] as bigint | undefined) ?? 0n)
  if (v !== ANNOUNCEMENT_VERSION) throw new TransportError('announcement_version', `unsupported announcement version ${v}`)
  const inbox = (o['inbox'] as string | undefined) ?? ''
  if (!isLowerHex64(inbox)) throw new TransportError('announcement_malformed', 'inbox pubkey must be 64 lowercase hex characters')
  if (!validPoint(inbox)) throw new TransportError('announcement_malformed', 'inbox is not a valid x-only pubkey')
  if (inbox === expectedNode) throw new TransportError('announcement_malformed', 'inbox must not be the node identity key')
  const l = (o['limits'] as Record<string, bigint> | undefined) ?? {}
  const n = (k: string) => Number(l[k] ?? 0n)
  const limits: Limits = {
    maxEnvelopeBytes: n('max_bytes'),
    maxItems: n('max_items'),
    maxConsolidateSources: n('max_consolidate_sources'),
    padBucketBytes: n('pad_bucket_bytes'),
    maxVerifyBudget: n('max_verify_budget'),
  }
  try {
    validateAnnouncedLimits(limits)
  } catch (err) {
    throw new TransportError('announcement_malformed', `announced limits are unusable: ${(err as Error).message}`)
  }
  return { inbox, limits, relays: (o['relays'] as string[] | undefined) ?? [], createdAt: ev.created_at }
}

/**
 * The x-only form of a Hub's node identity: a compressed key from a mint
 * signature (66 hex) loses its 02/03 prefix; an x-only key (64 hex) is kept.
 */
export function normalizeNodeIdentity(pubkeyHex: string): string {
  const s = pubkeyHex.trim().toLowerCase()
  if (!/^(?:[0-9a-f]{2})*$/.test(s)) throw new TransportError('announcement_malformed', 'hub identity is not hex')
  if (s.length === 64) return s
  if (s.length === 66) {
    if (!s.startsWith('02') && !s.startsWith('03')) {
      throw new TransportError('announcement_malformed', 'hub identity is 33 bytes but not a compressed pubkey')
    }
    return s.slice(2)
  }
  throw new TransportError('announcement_malformed', `hub identity must be 64 or 66 hex characters, got ${s.length}`)
}
