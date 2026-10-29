// NIP-LSP, the Lightning Service Provider Announcement (kind 10735): built
// from an LSP's own live LSPS answers, signed by its node key, and checked by
// a client in the NIP's order. The announcement only advertises: the live
// LSPS answers always decide. Port of nmilat niplsp.
import { CoreError, getEventHash, sanitizeText, validChainName, verifyEvent, type NostrEvent, type UnsignedEvent } from '../core/index.js'
import { validAddr } from '../transport/index.js'

export const KIND_LSP_ANNOUNCEMENT = 10735
export const LSP_MAX_EXPIRY_SECS = 30 * 24 * 60 * 60
/** How far ahead of the client's clock an announcement's `created_at` may be (§Client Behavior step 4). */
export const LSP_MAX_FUTURE_SECS = 15 * 60

/** Step 4's bound on `created_at`. */
function checkNotFuture(createdAt: number, now: number): void {
  if (createdAt > now + LSP_MAX_FUTURE_SECS) throw new AnnouncementError(4, `created_at ${createdAt} is more than 15 minutes ahead of now ${now}`)
}
export const LSP_MAX_TITLE = 40
export const LSP_MAX_CONTENT = 280
const LANGUAGE_NAMESPACE = 'ISO-639-1'
const ALT_PREFIX = 'Lightning service provider'

export type LspStatus = 'open' | 'paused' | 'closed'
const NETWORKS = ['mainnet', 'testnet', 'signet', 'regtest']

/** An `lsps1` option or `lsps5` field: its name without a unit suffix, and its value as the tag carries it. */
export interface LspOption {
  readonly name: string
  readonly value: string
}

/** One row of LSPS2's `opening_fee_params_menu`, without `valid_until` and `promise`. Amounts in millis. */
export interface FeeRow {
  readonly minFeeMillis: bigint
  readonly proportional: bigint
  readonly minLifetime: bigint
  readonly maxClientToSelfDelay: bigint
  readonly minPaymentSizeMillis: bigint
  readonly maxPaymentSizeMillis: bigint
}

export interface LspFields {
  /** 64 hex x-only, or a 66-character node id (`02`/`03`), kept in x-only form. */
  readonly nodeKey: string
  readonly addrs: readonly string[]
  readonly chain: string
  readonly network: string
  /** Default `open`. */
  readonly status?: LspStatus
  /** Unix seconds; 0 or absent means `created_at` + 30 days. */
  readonly expiration?: number
  readonly title?: string
  readonly content?: string
  readonly website?: string
  readonly image?: string
  readonly operator?: { readonly pubkey: string; readonly relay?: string }
  readonly languages?: readonly string[]
  readonly relays?: readonly string[]
  readonly protocols: readonly number[]
  readonly lsps1?: readonly LspOption[]
  readonly lsps2?: readonly FeeRow[]
  readonly lsps5?: readonly LspOption[]
}

type Kind = 'number' | 'bool'
type Better = 'lower' | 'higher' | 'true'
type Unit = 'none' | 'base' | 'millis'
interface Known {
  readonly name: string
  readonly unit: Unit
  readonly kind: Kind
  readonly better: Better
}

/** The LSPS1 `get_info` options, in bLIP-51 order. */
const LSPS1: readonly Known[] = [
  { name: 'min_required_channel_confirmations', unit: 'none', kind: 'number', better: 'lower' },
  { name: 'min_funding_confirms_within_blocks', unit: 'none', kind: 'number', better: 'lower' },
  { name: 'supports_zero_channel_reserve', unit: 'none', kind: 'bool', better: 'true' },
  { name: 'max_channel_expiry_blocks', unit: 'none', kind: 'number', better: 'higher' },
  { name: 'min_initial_client_balance', unit: 'base', kind: 'number', better: 'lower' },
  { name: 'max_initial_client_balance', unit: 'base', kind: 'number', better: 'higher' },
  { name: 'min_initial_lsp_balance', unit: 'base', kind: 'number', better: 'lower' },
  { name: 'max_initial_lsp_balance', unit: 'base', kind: 'number', better: 'higher' },
  { name: 'min_channel_balance', unit: 'base', kind: 'number', better: 'lower' },
  { name: 'max_channel_balance', unit: 'base', kind: 'number', better: 'higher' },
]
const LSPS5: readonly Known[] = [{ name: 'max_webhooks', unit: 'none', kind: 'number', better: 'higher' }]
const FEE_FIELDS: readonly Known[] = [
  { name: 'min_fee', unit: 'millis', kind: 'number', better: 'lower' },
  { name: 'proportional', unit: 'none', kind: 'number', better: 'lower' },
  { name: 'min_lifetime', unit: 'none', kind: 'number', better: 'higher' },
  { name: 'max_client_to_self_delay', unit: 'none', kind: 'number', better: 'higher' },
  { name: 'min_payment_size', unit: 'millis', kind: 'number', better: 'lower' },
  { name: 'max_payment_size', unit: 'millis', kind: 'number', better: 'higher' },
]

export const lsps1OptionNames = (): string[] => LSPS1.map((o) => o.name)

const rowValues = (r: FeeRow): bigint[] => [r.minFeeMillis, r.proportional, r.minLifetime, r.maxClientToSelfDelay, r.minPaymentSizeMillis, r.maxPaymentSizeMillis]
const rowOf = (v: readonly bigint[]): FeeRow => ({ minFeeMillis: v[0]!, proportional: v[1]!, minLifetime: v[2]!, maxClientToSelfDelay: v[3]!, minPaymentSizeMillis: v[4]!, maxPaymentSizeMillis: v[5]! })

// ---- unit dialects (`_sat`/`_msat`, `_loki`/`_mloki`)

const SUFFIXES: readonly { s: string; u: Unit; d: 'sat' | 'loki' }[] = [
  { s: '_msat', u: 'millis', d: 'sat' },
  { s: '_mloki', u: 'millis', d: 'loki' },
  { s: '_sat', u: 'base', d: 'sat' },
  { s: '_loki', u: 'base', d: 'loki' },
]

/** An LSPS field name in either dialect, as an announcement names it, with its unit. */
export function fromLspsName(lspsName: string): { name: string; unit: Unit } {
  for (const x of SUFFIXES) if (lspsName.endsWith(x.s) && lspsName.length > x.s.length) return { name: lspsName.slice(0, -x.s.length), unit: x.u }
  return { name: lspsName, unit: 'none' }
}

/** The LSPS field name of an announced name with its unit, in a dialect. */
export function toLspsName(name: string, unit: Unit, dialect: 'sat' | 'loki'): string {
  return name + (SUFFIXES.find((x) => x.u === unit && x.d === dialect)?.s ?? '')
}

// ---- forms

const DEC = /^(0|[1-9][0-9]*)$/
const HEX64 = /^[0-9a-f]{64}$/
const canonical = (s: string | undefined): bigint | undefined => (s !== undefined && DEC.test(s) && BigInt(s) < 1n << 64n ? BigInt(s) : undefined)
const validHttps = (s: string) => {
  try {
    const u = new URL(s)
    return u.protocol === 'https:' && u.host !== '' && u.username === '' && u.password === ''
  } catch {
    return false
  }
}
const validRelay = (s: string) => {
  try {
    const u = new URL(s)
    return (u.protocol === 'wss:' || u.protocol === 'ws:') && u.host !== ''
  } catch {
    return false
  }
}
const validLanguage = (s: string) => /^[a-z]{2}$/.test(s)
const validOptionName = (s: string) => /^[a-z0-9_]+$/.test(s) && fromLspsName(s).unit === 'none'
const validValue = (k: Known | undefined, v: string) => (k === undefined ? canonical(v) !== undefined || v === 'true' || v === 'false' : k.kind === 'bool' ? v === 'true' || v === 'false' : canonical(v) !== undefined)
const graphemes = (s: string) => [...new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(s)].length

function xonlyNodeKey(k: string): string | undefined {
  let x = k.toLowerCase()
  if (x.length === 66 && (x.startsWith('02') || x.startsWith('03'))) x = x.slice(2)
  return HEX64.test(x) ? x : undefined
}

/** The two node ids an x-only node key can stand for: `02` and `03` followed by it. */
export const nodeIds = (pubkey: string): [string, string] => [`02${pubkey.toLowerCase()}`, `03${pubkey.toLowerCase()}`]

const bad = (m: string) => new CoreError('invalid_request', `lsp announcement: ${m}`)

function checkOptions(opts: readonly LspOption[], table: readonly Known[], protocol: boolean, tag: string): void {
  if (opts.length > 0 && !protocol) throw bad(`${tag} without its protocol`)
  const seen = new Set<string>()
  for (const o of opts) {
    if (seen.has(o.name)) throw bad(`${tag} ${o.name} appears twice`)
    seen.add(o.name)
    if (!validOptionName(o.name) || !validValue(table.find((k) => k.name === o.name), o.value)) throw bad(`${tag} ${o.name} = ${o.value}`)
  }
}

/**
 * The unsigned kind-10735 event for `f`, with its id and its tags in the
 * NIP's order. Refuses an expiration not after `createdAt` or more than 30
 * days after it, protocol 2 without a fee row, step data without its
 * protocol, an option twice, a non-https website or image, a malformed
 * addr, content over 280 characters and any other malformed value.
 */
export function newAnnouncement(f: LspFields, createdAt: number): UnsignedEvent & { id: string } {
  const key = xonlyNodeKey(f.nodeKey)
  if (key === undefined) throw bad('the node key is 64 hex characters, or a 66-character node id starting 02 or 03')
  if (f.addrs.length === 0 || f.addrs.some((a) => !validAddr(a))) throw bad('addr must be host:port with an IPv4, bracketed IPv6 or onion host')
  if (!validChainName(f.chain)) throw bad(`chain ${f.chain}`)
  if (!NETWORKS.includes(f.network)) throw bad(`network ${f.network}`)
  const status = f.status ?? 'open'
  if (!['open', 'paused', 'closed'].includes(status)) throw bad(`status ${status}`)
  if (f.protocols.length === 0 || new Set(f.protocols).size !== f.protocols.length || f.protocols.some((p) => !Number.isInteger(p) || p < 1)) throw bad('protocols')
  const has = (p: number) => f.protocols.includes(p)
  checkOptions(f.lsps1 ?? [], LSPS1, has(1), 'lsps1')
  checkOptions(f.lsps5 ?? [], LSPS5, has(5), 'lsps5')
  if (has(2) && (f.lsps2 ?? []).length === 0) throw bad('protocol 2 needs at least one lsps2_fee row')
  if (!has(2) && (f.lsps2 ?? []).length > 0) throw bad('lsps2_fee without protocol 2')
  if (graphemes(f.content ?? '') > LSP_MAX_CONTENT) throw bad('content is at most 280 characters')
  if (f.website !== undefined && f.website !== '' && !validHttps(f.website)) throw bad('website must be https')
  if (f.image !== undefined && f.image !== '' && !validHttps(f.image)) throw bad('image must be https')
  if (f.operator !== undefined && (!HEX64.test(f.operator.pubkey) || (f.operator.relay !== undefined && f.operator.relay !== '' && !validRelay(f.operator.relay)))) throw bad('operator')
  const langs = f.languages ?? []
  if (langs.some((l) => !validLanguage(l)) || new Set(langs).size !== langs.length) throw bad('languages')
  if ((f.relays ?? []).some((r) => !validRelay(r))) throw bad('relays')
  const expiration = f.expiration !== undefined && f.expiration !== 0 ? f.expiration : createdAt + LSP_MAX_EXPIRY_SECS
  if (expiration <= createdAt || expiration - createdAt > LSP_MAX_EXPIRY_SECS) throw bad('expiration must be after created_at and at most 30 days after it')
  const tags: string[][] = [
    ...f.addrs.map((a) => ['addr', a]),
    ['n', f.chain],
    ['network', f.network],
    ['status', status],
    ['expiration', String(expiration)],
    ...f.protocols.map((p) => ['protocol', String(p)]),
    ...(f.lsps1 ?? []).map((o) => ['lsps1', o.name, o.value]),
    ...(f.lsps2 ?? []).map((r) => ['lsps2_fee', ...rowValues(r).map(String)]),
    ...(f.lsps5 ?? []).map((o) => ['lsps5', o.name, o.value]),
    ...(f.title !== undefined && f.title !== '' ? [['title', f.title]] : []),
    ...(f.website !== undefined && f.website !== '' ? [['website', f.website]] : []),
    ...(f.image !== undefined && f.image !== '' ? [['image', f.image]] : []),
    ...(f.operator !== undefined ? [f.operator.relay !== undefined && f.operator.relay !== '' ? ['p', f.operator.pubkey, f.operator.relay] : ['p', f.operator.pubkey]] : []),
    ...(langs.length > 0 ? [['L', LANGUAGE_NAMESPACE], ...langs.map((l) => ['l', l, LANGUAGE_NAMESPACE])] : []),
    ['alt', f.title !== undefined && f.title !== '' ? `${ALT_PREFIX}: ${f.title}` : ALT_PREFIX],
    ...(f.relays ?? []).map((r) => ['r', r]),
  ]
  const ev = { kind: KIND_LSP_ANNOUNCEMENT, pubkey: key, created_at: createdAt, tags, content: f.content ?? '' }
  return { ...ev, id: getEventHash(ev) }
}

/**
 * What the node's signer is handed: the event's NIP-01 serialization, whose
 * SHA-256 is the id. Only kind 10735: the node key signs no other Nostr event.
 */
export function signingPayload(ev: UnsignedEvent): string {
  if (ev.kind !== KIND_LSP_ANNOUNCEMENT) throw new CoreError('invalid_request', 'lsp announcement: the node key signs only kind 10735')
  if (!HEX64.test(ev.pubkey)) throw new CoreError('invalid_request', 'lsp announcement: the pubkey is 64 lowercase hex')
  return JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content])
}

// ---- the client side

/** The first check an announcement failed (§Client Behavior, steps 1–5). The client ignores it. */
export class AnnouncementError extends Error {
  override readonly name = 'AnnouncementError'
  constructor(
    readonly step: 1 | 2 | 3 | 4 | 5,
    readonly reason: string,
  ) {
    super(`lsp announcement fails step ${step}: ${reason}`)
  }
}

export interface LspAnnouncement extends Omit<LspFields, 'status' | 'expiration' | 'lsps1' | 'lsps2' | 'lsps5' | 'languages' | 'relays'> {
  readonly event: NostrEvent
  readonly createdAt: number
  readonly status: LspStatus
  readonly expiration: number
  readonly lsps1: readonly LspOption[]
  readonly lsps2: readonly FeeRow[]
  readonly lsps5: readonly LspOption[]
  readonly languages: readonly string[]
  readonly relays: readonly string[]
  /** Not `closed`. */
  readonly shown: boolean
  /** Only `open`: nothing new is offered through a paused one. */
  readonly selling: boolean
  /** The LSP's claims, stripped and capped: never verified facts. */
  readonly displayTitle: string
  readonly displayContent: string
}

const EXACTLY = ['n', 'network', 'status', 'expiration']
const AT_LEAST = ['addr', 'protocol']
const AT_MOST = ['title', 'website', 'image', 'p', 'alt']

/**
 * Checks an announcement as §Client Behavior orders, reporting the first
 * failure: (1) kind and signature; (2) the counts, and a fee row with
 * protocol 2; (3) every value's form, no option twice; (4) `created_at` at
 * most 15 minutes ahead, not expired, at most 30 days after `created_at`; (5) a chain and network the client uses.
 * Unknown tags, unknown options and step data without its protocol are
 * ignored; a closed or paused one parses (see `shown`, `selling`).
 */
export function parseAnnouncement(ev: NostrEvent, o: { chains: readonly string[]; networks: readonly string[]; now: number }): LspAnnouncement {
  if (ev.kind !== KIND_LSP_ANNOUNCEMENT || !HEX64.test(ev.pubkey) || getEventHash(ev) !== ev.id || !verifyEvent(ev)) throw new AnnouncementError(1, 'kind or signature')
  const count = new Map<string, number>()
  for (const t of ev.tags) if (t.length > 0) count.set(t[0]!, (count.get(t[0]!) ?? 0) + 1)
  for (const n of EXACTLY) if (count.get(n) !== 1) throw new AnnouncementError(2, `exactly one ${n}`)
  for (const n of AT_LEAST) if ((count.get(n) ?? 0) === 0) throw new AnnouncementError(2, `no ${n}`)
  for (const n of AT_MOST) if ((count.get(n) ?? 0) > 1) throw new AnnouncementError(2, `at most one ${n}`)
  const protocol2 = ev.tags.some((t) => t[0] === 'protocol' && t[1] === '2')
  if (protocol2 && (count.get('lsps2_fee') ?? 0) === 0) throw new AnnouncementError(2, 'protocol 2 without an lsps2_fee tag')
  const protocols: number[] = []
  for (const t of ev.tags) {
    if (t[0] !== 'protocol') continue
    const v = canonical(t[1])
    if (v === undefined || v > 0xffffffffn) throw new AnnouncementError(3, `protocol ${t[1]}`)
    if (!protocols.includes(Number(v))) protocols.push(Number(v))
  }
  const addrs: string[] = []
  const lsps1: LspOption[] = []
  const lsps5: LspOption[] = []
  const lsps2: FeeRow[] = []
  const languages: string[] = []
  const relays: string[] = []
  const seen1 = new Set<string>()
  const seen5 = new Set<string>()
  let chain = ''
  let network = ''
  let status: LspStatus = 'open'
  let expiration = 0
  let title: string | undefined
  let website: string | undefined
  let image: string | undefined
  let operator: { pubkey: string; relay?: string } | undefined
  const readOption = (t: readonly string[], table: readonly Known[], seen: Set<string>, out: LspOption[]) => {
    if (t.length < 3 || t[1] === '') throw new AnnouncementError(3, `malformed ${t[0]}`)
    if (seen.has(t[1]!)) throw new AnnouncementError(3, `${t[0]} ${t[1]} appears twice`)
    seen.add(t[1]!)
    const k = table.find((x) => x.name === t[1])
    if (k === undefined) return
    if (!validValue(k, t[2]!)) throw new AnnouncementError(3, `malformed ${t[0]} ${t[1]}`)
    out.push({ name: t[1]!, value: t[2]! })
  }
  for (const t of ev.tags) {
    const v = t[1] ?? ''
    const fail = () => new AnnouncementError(3, `malformed ${t[0]} tag`)
    switch (t[0]) {
      case 'addr':
        if (!validAddr(v)) throw fail()
        addrs.push(v)
        break
      case 'n':
        if (!validChainName(v)) throw fail()
        chain = v
        break
      case 'network':
        if (!NETWORKS.includes(v)) throw fail()
        network = v
        break
      case 'status':
        if (v !== 'open' && v !== 'paused' && v !== 'closed') throw fail()
        status = v
        break
      case 'expiration': {
        const x = canonical(v)
        if (x === undefined || x > 1n << 62n) throw fail()
        expiration = Number(x)
        break
      }
      case 'lsps1':
        if (protocols.includes(1)) readOption(t, LSPS1, seen1, lsps1)
        break
      case 'lsps5':
        if (protocols.includes(5)) readOption(t, LSPS5, seen5, lsps5)
        break
      case 'lsps2_fee': {
        if (!protocols.includes(2)) break
        if (t.length < 7) throw fail()
        const vals = t.slice(1, 7).map(canonical)
        if (vals.some((x) => x === undefined)) throw fail()
        lsps2.push(rowOf(vals as bigint[]))
        break
      }
      case 'title':
        if (t.length < 2) throw fail()
        title = v
        break
      case 'website':
        if (!validHttps(v)) throw fail()
        website = v
        break
      case 'image':
        if (!validHttps(v)) throw fail()
        image = v
        break
      case 'p': {
        const relay = t[2]
        if (!HEX64.test(v) || (relay !== undefined && relay !== '' && !validRelay(relay))) throw fail()
        operator = { pubkey: v, ...(relay !== undefined && relay !== '' && { relay }) }
        break
      }
      case 'l':
        if (t[2] !== LANGUAGE_NAMESPACE) break
        if (!validLanguage(v)) throw fail()
        if (!languages.includes(v)) languages.push(v)
        break
      case 'r':
        if (!validRelay(v)) throw fail()
        relays.push(v)
        break
      default:
        break
    }
  }
  checkNotFuture(ev.created_at, o.now)
  if (o.now > expiration) throw new AnnouncementError(4, `expired at ${expiration}`)
  if (expiration - ev.created_at > LSP_MAX_EXPIRY_SECS) throw new AnnouncementError(4, 'expiration is more than 30 days after created_at')
  if (!o.chains.includes(chain)) throw new AnnouncementError(5, `chain ${chain} is not one the client uses`)
  if (!o.networks.includes(network)) throw new AnnouncementError(5, `network ${network} is not one the client uses`)
  return {
    event: ev,
    createdAt: ev.created_at,
    nodeKey: ev.pubkey,
    addrs,
    chain,
    network,
    status,
    expiration,
    ...(title !== undefined && { title }),
    content: ev.content,
    ...(website !== undefined && { website }),
    ...(image !== undefined && { image }),
    ...(operator !== undefined && { operator }),
    languages,
    relays,
    protocols,
    lsps1,
    lsps2,
    lsps5,
    shown: status !== 'closed',
    selling: status === 'open',
    displayTitle: sanitizeText(title ?? '', LSP_MAX_TITLE),
    displayContent: sanitizeText(ev.content, LSP_MAX_CONTENT),
  }
}

/**
 * Keeps the newest announcement of each node (later `created_at`, then the
 * lower id) and remembers it: an older one offered later is refused, and
 * when the newest fails a check the node has none until a newer one passes.
 * There is no fallback to an older one.
 */
export class LspSeen {
  private readonly nodes = new Map<string, { createdAt: number; id: string; ann?: LspAnnouncement; err?: unknown }>()
  constructor(readonly options: { chains: readonly string[]; networks: readonly string[]; now: () => number }) {}

  offer(ev: NostrEvent): LspAnnouncement | undefined {
    if (ev.kind !== KIND_LSP_ANNOUNCEMENT || getEventHash(ev) !== ev.id || !verifyEvent(ev)) return undefined
    const cur = this.nodes.get(ev.pubkey)
    if (cur !== undefined && cur.id === ev.id) return cur.ann
    // Dated more than 15 minutes ahead: fails step 4 and does not count as seen, so it cannot hide later announcements.
    if (ev.created_at > this.options.now() + LSP_MAX_FUTURE_SECS) return undefined
    if (cur !== undefined && !(ev.created_at > cur.createdAt || (ev.created_at === cur.createdAt && ev.id < cur.id))) return undefined
    try {
      const ann = parseAnnouncement(ev, { ...this.options, now: this.options.now() })
      this.nodes.set(ev.pubkey, { createdAt: ev.created_at, id: ev.id, ann })
      return ann
    } catch (err) {
      this.nodes.set(ev.pubkey, { createdAt: ev.created_at, id: ev.id, err })
      return undefined
    }
  }

  /** The node's newest announcement while it passed every check and has not expired. */
  current(nodeKey: string): LspAnnouncement | undefined {
    const e = this.nodes.get(nodeKey)
    if (e?.ann === undefined || this.options.now() > e.ann.expiration) return undefined
    return e.ann
  }

  marks(): Record<string, { createdAt: number; id: string }> {
    return Object.fromEntries([...this.nodes].map(([k, v]) => [k, { createdAt: v.createdAt, id: v.id }]))
  }

  remember(nodeKey: string, m: { createdAt: number; id: string }): void {
    if (m.createdAt > this.options.now() + LSP_MAX_FUTURE_SECS) return
    const cur = this.nodes.get(nodeKey)
    if (cur !== undefined && !(m.createdAt > cur.createdAt || (m.createdAt === cur.createdAt && m.id < cur.id))) return
    this.nodes.set(nodeKey, m)
  }
}

/** Offers every event and returns the usable newest announcement of each node. */
export function newestAnnouncements(seen: LspSeen, evs: readonly NostrEvent[]): Map<string, LspAnnouncement> {
  for (const e of evs) seen.offer(e)
  const out = new Map<string, LspAnnouncement>()
  for (const k of Object.keys(seen.marks())) {
    const a = seen.current(k)
    if (a !== undefined) out.set(k, a)
  }
  return out
}

// ---- LSPS answers (both unit dialects)

const lspsUint = (v: unknown): bigint | undefined => {
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v)
  if (typeof v === 'bigint' && v >= 0n) return v
  if (typeof v === 'string' && /^[0-9]+$/.test(v)) return BigInt(v)
  return undefined
}
const lspsBad = (m: string) => new CoreError('invalid_payload', `LSPS answer: ${m}`)

function readKnown(obj: Record<string, unknown>, table: readonly Known[], what: string): Map<string, string> {
  const out = new Map<string, string>()
  const from = new Map<string, string>()
  for (const [key, raw] of Object.entries(obj)) {
    const { name, unit } = fromLspsName(key)
    const k = table.find((x) => x.name === name)
    if (k === undefined || k.unit !== unit) continue
    if (from.has(name)) throw lspsBad(`${what} gives both ${from.get(name)} and ${key}`)
    from.set(name, key)
    if (k.kind === 'bool') {
      if (typeof raw !== 'boolean') throw lspsBad(`${what} ${key}`)
      out.set(name, String(raw))
    } else {
      const n = lspsUint(raw)
      if (n === undefined) throw lspsBad(`${what} ${key}`)
      out.set(name, n.toString())
    }
  }
  return out
}

const asObject = (v: unknown, what: string): Record<string, unknown> => {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw lspsBad(`${what} is not an object`)
  return v as Record<string, unknown>
}

/** LSPS0 `list_protocols` (`{protocols: [...]}` or the array alone). */
export function parseListProtocols(v: unknown): number[] {
  const arr = Array.isArray(v) ? v : asObject(v, 'list_protocols')['protocols']
  if (!Array.isArray(arr)) throw lspsBad('list_protocols has no protocols')
  return arr.map((x) => {
    if (typeof x !== 'number' || !Number.isInteger(x) || x < 0 || x > 0xffffffff) throw lspsBad(`protocol ${String(x)}`)
    return x
  })
}

/** LSPS1 `get_info`'s known options, in bLIP-51 order (top level, or an `options` object). */
export function parseLsps1Info(v: unknown): LspOption[] {
  let o = asObject(v, 'LSPS1 get_info')
  if (o['options'] !== null && typeof o['options'] === 'object' && !Array.isArray(o['options'])) o = o['options'] as Record<string, unknown>
  const vals = readKnown(o, LSPS1, 'LSPS1 get_info')
  return LSPS1.flatMap((k) => (vals.has(k.name) ? [{ name: k.name, value: vals.get(k.name)! }] : []))
}

/** LSPS2 `get_info`'s `opening_fee_params_menu` (or the array alone); `valid_until` and `promise` dropped. */
export function parseLsps2Menu(v: unknown): FeeRow[] {
  const menu = Array.isArray(v) ? v : asObject(v, 'LSPS2 get_info')['opening_fee_params_menu']
  if (!Array.isArray(menu)) throw lspsBad('LSPS2 get_info has no opening_fee_params_menu')
  return menu.map((r, i) => {
    const vals = readKnown(asObject(r, 'opening_fee_params_menu row'), FEE_FIELDS, 'opening_fee_params_menu row')
    return rowOf(
      FEE_FIELDS.map((k) => {
        const s = vals.get(k.name)
        if (s === undefined) throw lspsBad(`opening_fee_params_menu row ${i} has no ${k.name}`)
        return BigInt(s)
      }),
    )
  })
}

/** The LSPS5 fields an announcement carries (`max_webhooks`). */
export function parseLsps5(v: unknown): LspOption[] {
  const vals = readKnown(asObject(v, 'LSPS5 answer'), LSPS5, 'LSPS5 answer')
  if (!vals.has('max_webhooks')) throw lspsBad('LSPS5 answer has no max_webhooks')
  return [{ name: 'max_webhooks', value: vals.get('max_webhooks')! }]
}

/** An announcement's fields from the LSP's own live answers, so what it announces equals what it answers. */
export function fromLspsInfo(p: { protocols: readonly number[]; lsps1Info?: unknown; lsps2Menu?: unknown; lsps5?: unknown; meta: Omit<LspFields, 'protocols' | 'lsps1' | 'lsps2' | 'lsps5'> }): LspFields {
  const has = (n: number) => p.protocols.includes(n)
  if (has(1) && p.lsps1Info === undefined) throw lspsBad('protocol 1 without LSPS1 get_info')
  if (has(2) && p.lsps2Menu === undefined) throw lspsBad('protocol 2 without LSPS2 get_info')
  return {
    ...p.meta,
    protocols: [...p.protocols],
    ...(has(1) && { lsps1: parseLsps1Info(p.lsps1Info) }),
    ...(has(2) && { lsps2: parseLsps2Menu(p.lsps2Menu) }),
    ...(has(5) && p.lsps5 !== undefined && { lsps5: parseLsps5(p.lsps5) }),
  }
}

// ---- the live check

export type Verdict = 'same' | 'worse' | 'better'
export interface FieldDiff {
  readonly field: string
  readonly announced: string
  readonly live: string
  readonly verdict: Verdict
}
export interface LiveDiff {
  /** Announced protocols `list_protocols` does not list: the client does not use the LSP. */
  readonly missingProtocol: readonly number[]
  readonly fields: readonly FieldDiff[]
  readonly usable: boolean
  /** Any live value worse for the buyer: show both and ask again before buying. */
  readonly worse: boolean
}

function compare(better: Better, announced: string, live: string): Verdict {
  if (announced === live) return 'same'
  if (better === 'true') return live === 'true' && announced === 'false' ? 'better' : 'worse'
  const a = canonical(announced)
  const l = canonical(live)
  if (l === undefined) return 'worse'
  if (a === undefined) return 'better'
  if (a === l) return 'same'
  return l < a === (better === 'lower') ? 'better' : 'worse'
}

/** Compares an announcement with the node's live answers (which decide), value by value, for the buyer. */
export function checkLive(a: LspAnnouncement, live: { protocols?: readonly number[]; lsps1?: readonly LspOption[]; lsps2Menu?: readonly FeeRow[] }): LiveDiff {
  const missingProtocol = live.protocols !== undefined ? a.protocols.filter((p) => !live.protocols!.includes(p)) : []
  const fields: FieldDiff[] = []
  if (live.lsps1 !== undefined) {
    for (const o of a.lsps1) {
      const k = LSPS1.find((x) => x.name === o.name)
      if (k === undefined) continue
      const lv = live.lsps1.find((x) => x.name === o.name)?.value ?? ''
      fields.push({ field: o.name, announced: o.value, live: lv, verdict: compare(k.better, o.value, lv) })
    }
  }
  if (live.lsps2Menu !== undefined) {
    const n = Math.max(a.lsps2.length, live.lsps2Menu.length)
    for (let i = 0; i < n; i++) {
      const ann = a.lsps2[i]
      const lv = live.lsps2Menu[i]
      FEE_FIELDS.forEach((k, j) => {
        const announced = ann !== undefined ? rowValues(ann)[j]!.toString() : ''
        const l = lv !== undefined ? rowValues(lv)[j]!.toString() : ''
        fields.push({ field: `lsps2_fee[${i}].${k.name}`, announced, live: l, verdict: lv === undefined ? 'worse' : ann === undefined ? 'better' : compare(k.better, announced, l) })
      })
    }
  }
  return { missingProtocol, fields, usable: missingProtocol.length === 0, worse: fields.some((f) => f.verdict === 'worse') }
}
