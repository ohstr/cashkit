// Kind 11190 Hub announcements (NIP-CASH §The Hub Announcement): how a
// client learns a Hub's inbox, limits and relays. Port of nmilat
// nipcash/transport/{announcement,identity}.go, tag form.
//
// The trust chain is bill -> node key (from the bill's mint signature) ->
// announcement -> inbox. parseAnnouncement is the link that refuses to be
// skipped: it requires the expected node key.
import { nip44, verifyEvent, type NostrEvent } from '../core/index.js'
import { TransportError } from './errors.js'
import { MAX_NIP44_PLAINTEXT, validateAnnouncedLimits, type Limits } from './limits.js'

export const KIND_HUB_ANNOUNCEMENT = 11190
/** The smallest `max_request_age` a Hub may announce for bill-creating calls. */
export const MIN_REQUEST_AGE = 60

export interface Announcement {
  /** x-only pubkey clients encrypt envelopes to and p-tag; may equal the author. */
  readonly inbox: string
  readonly limits: Limits
  /** `max_request_age` (H), in seconds; absent when the Hub announces none. */
  readonly maxRequestAge?: number
  /** `r` tags, in the Hub's order. */
  readonly relays: readonly string[]
  /** `addr` tags (`host:port`), for display only; malformed ones are dropped. */
  readonly addrs: readonly string[]
  /** The event's created_at: newer replaces older (rollback guard). */
  readonly createdAt: number
}

const isLowerHex64 = (s: string) => /^[0-9a-f]{64}$/.test(s)
const DECIMAL = /^(?:0|[1-9][0-9]{0,15})$/

const LIMIT_NAMES = ['max_bytes', 'max_items', 'max_consolidate_sources', 'pad_bucket_bytes', 'max_verify_budget', 'max_request_age'] as const
type LimitName = (typeof LIMIT_NAMES)[number]

function validPoint(xOnly: string): boolean {
  try {
    nip44.getConversationKey(new Uint8Array(32).fill(1), xOnly)
    return true
  } catch {
    return false
  }
}

function validRelay(s: string): boolean {
  return /^wss?:\/\/[\x21-\x7e]+$/.test(s)
}

/** `host:port` with an IPv4 address, a bracketed IPv6 address or an onion host. */
export function validAddr(s: string): boolean {
  const m = /^(.+):([0-9]{1,5})$/.exec(s)
  if (m === null || Number(m[2]) < 1 || Number(m[2]) > 65535) return false
  const host = m[1]!
  if (/^\[[0-9a-fA-F:.]+\]$/.test(host)) return host.includes(':')
  if (/^[a-z2-7]{56}\.onion$/.test(host)) return true
  const parts = host.split('.')
  return parts.length === 4 && parts.every((p) => /^(?:0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255)
}

const malformed = (msg: string) => new TransportError('announcement_malformed', msg)

/**
 * Verifies an announcement against the node key it must come from and reads
 * its tags. Rejects no or two `inbox`, two `limit` tags of one name, and a
 * malformed `inbox`, `limit` or `r`; ignores unknown tags, unknown limits and
 * a malformed `addr`; never reads `content`. A `max_bytes` above 65535 reads
 * as 65535. Every envelope limit must be present (there are no defaults);
 * `max_request_age` may be missing or below 60, which leaves the Hub usable
 * for reads and redeems only (`hubUsableForBills`).
 */
export function parseAnnouncement(ev: NostrEvent, expectedNode: string): Announcement {
  if (ev.kind !== KIND_HUB_ANNOUNCEMENT) throw malformed(`kind ${ev.kind}, want ${KIND_HUB_ANNOUNCEMENT}`)
  if (!isLowerHex64(expectedNode)) throw malformed('expected node pubkey must be 64 lowercase hex characters')
  if (ev.pubkey !== expectedNode) throw new TransportError('announcement_author', 'announcement was not signed by the expected node identity')
  if (!verifyEvent(ev, { checkPow: false })) throw new TransportError('announcement_signature', 'announcement signature is invalid')

  let inbox: string | undefined
  const limits = new Map<LimitName, number>()
  const relays: string[] = []
  const addrs: string[] = []
  for (const t of ev.tags) {
    switch (t[0]) {
      case 'inbox': {
        if (inbox !== undefined) throw malformed('more than one inbox')
        const v = t[1] ?? ''
        if (!isLowerHex64(v) || !validPoint(v)) throw malformed('inbox is not a 64-hex x-only pubkey')
        inbox = v
        break
      }
      case 'limit': {
        const name = t[1] ?? ''
        if (!(LIMIT_NAMES as readonly string[]).includes(name)) break
        if (limits.has(name as LimitName)) throw malformed(`two limit tags for ${name}`)
        const v = t[2] ?? ''
        if (!DECIMAL.test(v)) throw malformed(`limit ${name} is not an unsigned decimal`)
        limits.set(name as LimitName, Number(v))
        break
      }
      case 'r': {
        const v = t[1] ?? ''
        if (!validRelay(v)) throw malformed('an r tag is not a relay url')
        relays.push(v)
        break
      }
      case 'addr':
        if (validAddr(t[1] ?? '')) addrs.push(t[1]!)
        break
      default:
    }
  }
  if (inbox === undefined) throw malformed('no inbox')
  const need = (k: LimitName) => {
    const v = limits.get(k)
    if (v === undefined || v <= 0) throw malformed(`announced limits are unusable: ${k} is missing or not positive`)
    return v
  }
  const l: Limits = {
    maxEnvelopeBytes: Math.min(need('max_bytes'), MAX_NIP44_PLAINTEXT),
    maxItems: need('max_items'),
    maxConsolidateSources: need('max_consolidate_sources'),
    padBucketBytes: need('pad_bucket_bytes'),
    maxVerifyBudget: need('max_verify_budget'),
  }
  try {
    validateAnnouncedLimits(l)
  } catch (err) {
    throw malformed(`announced limits are unusable: ${(err as Error).message}`)
  }
  const h = limits.get('max_request_age')
  return { inbox, limits: l, ...(h !== undefined && { maxRequestAge: h }), relays, addrs, createdAt: ev.created_at }
}

/** Whether a client may send bill-creating calls: the Hub announces `max_request_age` of at least 60. */
export function hubUsableForBills(a: Pick<Announcement, 'maxRequestAge'>): boolean {
  return a.maxRequestAge !== undefined && a.maxRequestAge >= MIN_REQUEST_AGE
}

/** The announcement's tags, as a Hub publishes them (used by the fake Hub and tests). */
export function announcementTags(p: { readonly inbox: string; readonly limits: Limits; readonly maxRequestAge?: number; readonly relays?: readonly string[]; readonly addrs?: readonly string[] }): string[][] {
  const l = p.limits
  return [
    ['inbox', p.inbox],
    ['limit', 'max_bytes', String(l.maxEnvelopeBytes)],
    ['limit', 'max_items', String(l.maxItems)],
    ['limit', 'max_consolidate_sources', String(l.maxConsolidateSources)],
    ['limit', 'pad_bucket_bytes', String(l.padBucketBytes)],
    ['limit', 'max_verify_budget', String(l.maxVerifyBudget)],
    ...(p.maxRequestAge !== undefined ? [['limit', 'max_request_age', String(p.maxRequestAge)]] : []),
    ...(p.relays ?? []).map((r) => ['r', r]),
    ...(p.addrs ?? []).map((a) => ['addr', a]),
  ]
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
