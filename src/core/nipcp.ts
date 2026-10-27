// NIP-CP Cash Pocket entries (kind 9525): a held token, a written-ahead
// bill-creating call or withdrawal (`pending`), or a final state; their
// tags, resolution per `w`, and the balance. Port of nmilat nipCP.
import { CoreError } from './errors.js'
import type { Rumor } from './nip59.js'
import { isRequestId } from './requestId.js'

export const KIND_POCKET_ENTRY = 9525
export const POCKET_STATES = ['live', 'pending', 'spent', 'expired', 'reclaimed', 'done', 'unknown'] as const
export type PocketState = (typeof POCKET_STATES)[number]
export const FINAL_STATES: readonly PocketState[] = ['spent', 'expired', 'reclaimed', 'done']
export const SECRET_ROLE_REMAINDER = 'remainder'
export const SECRET_ROLE_REMINT = 'remint'

export type PocketIdentity = { readonly type: 'pubkey'; readonly value: string } | { readonly type: 'connection_key'; readonly value: string; readonly ia: string } | { readonly type: 'cash' }

export interface PocketEntry {
  /** The token's wallet pubkey, or the call's `request_id` for a pending entry. */
  readonly w: string
  readonly rev: number
  readonly state: PocketState
  readonly checkedAt: number
  readonly wrapKey: string
  readonly amountMillis: bigint
  readonly chain: string
  readonly cash?: string
  readonly identity?: PocketIdentity
  readonly expiresAt?: number
  readonly mint?: string
  readonly source?: string
  /** Each cash secret, with its role (`''` the new bill's, `remainder`, `remint`). */
  readonly secrets?: readonly { readonly secret: string; readonly role: string }[]
  readonly requestId?: string
  readonly deadline?: number
  readonly target?: string
  readonly device?: string
  readonly orderKey?: string
  readonly notify?: string
  readonly address?: string
  readonly quote?: string
  readonly receipt?: string
}

const DEC = /^(0|[1-9][0-9]*)$/
const bad = (m: string) => new CoreError('invalid_payload', `pocket entry: ${m}`)
/** Lowercase hex of `n` characters; of any even length when `n` is 0. */
const lowerHex = (s: string | undefined, n = 0): boolean => s !== undefined && s !== '' && (n > 0 ? s.length === n : s.length % 2 === 0) && /^[0-9a-f]+$/.test(s)
const isFinal = (s: PocketState) => FINAL_STATES.includes(s)

function identityValid(id: PocketIdentity | undefined): boolean {
  if (id === undefined) return false
  switch (id.type) {
    case 'pubkey':
      return lowerHex(id.value, 64)
    case 'connection_key':
      return lowerHex(id.value, 64) && lowerHex(id.ia, 64)
    case 'cash':
      return true
  }
}

/**
 * Checks an entry against §Kind 9525 for writing; throws `invalid_payload`.
 * A pending entry (or the done entry closing one) has `w` = its
 * `request_id`, a deadline, target and device, and no cash, identity or
 * expiry; a withdrawal's has its address and quote together, its notify
 * with them, and its receipt only with its quote. A bill's entry has a
 * 64-hex `w` and its identity, never the call fields, and no cash only in a
 * final state. Secrets are 64 lowercase hex, of role `''`, `remainder`, or
 * `remint` (a pending entry's); `expires_at` is never 0, `mint` 66 hex.
 */
export function validatePocketEntry(e: PocketEntry): void {
  if (!lowerHex(e.w)) throw bad('w must be lowercase hex')
  if (!Number.isSafeInteger(e.rev) || e.rev < 1) throw bad('rev starts at 1')
  if (!(POCKET_STATES as readonly string[]).includes(e.state) || e.state === 'unknown') throw bad(`state ${JSON.stringify(e.state)}`)
  if (!Number.isSafeInteger(e.checkedAt) || e.checkedAt <= 0) throw bad('state needs its check time')
  if (e.amountMillis <= 0n) throw bad('amount')
  if (e.chain === '') throw bad('chain')
  if (e.wrapKey !== '' && !lowerHex(e.wrapKey, 64)) throw bad('wrap_key')
  if (e.expiresAt !== undefined && e.expiresAt <= 0) throw bad('expires_at 0 means never and is not stored')
  if (e.mint !== undefined && !lowerHex(e.mint, 66)) throw bad('mint is a 66-hex compressed pubkey')
  if (e.source !== undefined && !lowerHex(e.source, 64)) throw bad('source')
  const call = e.requestId !== undefined && e.requestId !== ''
  for (const x of e.secrets ?? []) {
    if (!lowerHex(x.secret, 64)) throw bad('secret')
    if (x.role === SECRET_ROLE_REMINT && !call) throw bad("a remint secret is a cash_withdraw pending entry's")
    if (x.role !== '' && x.role !== SECRET_ROLE_REMAINDER && x.role !== SECRET_ROLE_REMINT) throw bad(`secret role ${JSON.stringify(x.role)}`)
  }
  if (call) {
    if (e.w !== e.requestId || !isRequestId(e.requestId)) throw bad("a pending entry's w is its request_id")
    if (e.state !== 'pending' && e.state !== 'done') throw bad(`a pending entry is pending or done, not ${JSON.stringify(e.state)}`)
    if (e.deadline === undefined || e.deadline <= 0) throw bad('deadline')
    if (!lowerHex(e.target, 64)) throw bad('target')
    if (!lowerHex(e.device)) throw bad('device')
    if (e.cash !== undefined || e.identity !== undefined || e.expiresAt !== undefined) throw bad('a pending entry has no cash, identity or expires_at')
    if (e.orderKey !== undefined && !lowerHex(e.orderKey, 64)) throw bad('order_key')
    if (e.notify !== undefined && !lowerHex(e.notify, 64)) throw bad('notify')
    if ((e.address === undefined) !== (e.quote === undefined)) throw bad('a cash_withdraw entry has both address and quote, or neither once rewritten')
    if (e.quote !== undefined && e.notify === undefined) throw bad('a cash_withdraw entry keeps its notify')
    if (e.receipt !== undefined && e.quote === undefined) throw bad('a receipt is kept with its quote')
    return
  }
  for (const k of ['deadline', 'target', 'device', 'orderKey', 'notify', 'address', 'quote', 'receipt'] as const) {
    if (e[k] !== undefined) throw bad('only a pending entry has deadline, target, device, order_key, notify, address, quote or receipt')
  }
  if (e.state === 'pending' || e.state === 'done') throw bad(`a bill entry is never ${e.state}`)
  if (!identityValid(e.identity)) throw bad('identity')
  if (!lowerHex(e.w, 64)) throw bad("a bill's w is its 64-hex wallet pubkey")
  if (e.cash === undefined && !isFinal(e.state)) throw bad('an entry without cash is always in a final state')
}

/**
 * Checks a call's pending entry as it is first written (§Writing): a
 * `cash_order` entry keeps its notify, and its secret or order key; a
 * `cash_withdraw` entry keeps its notify, address and quote, and its only
 * secret is the remint secret. Throws `invalid_payload`.
 */
export function checkPendingEntry(method: string, e: PocketEntry): void {
  if (method === 'cash_order' && (e.notify === undefined || (e.orderKey === undefined && (e.secrets ?? []).length === 0))) {
    throw bad('a cash_order entry keeps its notify, and its secret or order_key')
  }
  if (method === 'cash_withdraw') {
    if (e.notify === undefined || e.address === undefined || e.quote === undefined) throw bad('a cash_withdraw entry keeps its notify, address and quote')
    const xs = e.secrets ?? []
    if (xs.length > 1 || (xs.length === 1 && xs[0]!.role !== SECRET_ROLE_REMINT)) throw bad("a cash_withdraw entry's only secret is its remint secret")
  }
}

/** An entry's tags, encoded as §Encodings requires (decimals without leading zeros, lowercase hex). The entry must validate (`validatePocketEntry`) and carry its wrap key. */
export function pocketEntryTags(e: PocketEntry): string[][] {
  validatePocketEntry(e)
  if (e.wrapKey === '') throw bad('no wrap_key')
  const id = e.identity
  return [
    ['w', e.w],
    ['rev', String(e.rev)],
    ...(e.cash !== undefined ? [['cash', e.cash]] : []),
    ['amount', e.amountMillis.toString()],
    ['chain', e.chain],
    ...(id === undefined ? [] : id.type === 'cash' ? [['identity', 'cash']] : id.type === 'pubkey' ? [['identity', 'pubkey', id.value]] : [['identity', 'connection_key', id.value, id.ia]]),
    ['state', e.state, String(e.checkedAt)],
    ...(e.mint !== undefined ? [['mint', e.mint]] : []),
    ...(e.expiresAt !== undefined ? [['expires_at', String(e.expiresAt)]] : []),
    ...(e.source !== undefined ? [['source', e.source]] : []),
    ...(e.requestId !== undefined ? [['request_id', e.requestId]] : []),
    ...(e.deadline !== undefined ? [['deadline', String(e.deadline)]] : []),
    ...(e.target !== undefined ? [['target', e.target]] : []),
    ...(e.device !== undefined ? [['device', e.device]] : []),
    ...(e.secrets ?? []).map((s) => (s.role === '' ? ['secret', s.secret] : ['secret', s.secret, s.role])),
    ...(e.orderKey !== undefined ? [['order_key', e.orderKey]] : []),
    ...(e.notify !== undefined ? [['notify', e.notify]] : []),
    ...(e.address !== undefined ? [['address', e.address]] : []),
    ...(e.quote !== undefined ? [['quote', e.quote]] : []),
    ...(e.receipt !== undefined ? [['receipt', e.receipt]] : []),
    ['wrap_key', e.wrapKey],
  ]
}

const SINGLE = new Set(['w', 'rev', 'cash', 'amount', 'chain', 'identity', 'state', 'mint', 'expires_at', 'source', 'request_id', 'deadline', 'target', 'device', 'order_key', 'notify', 'address', 'quote', 'receipt', 'wrap_key'])

/**
 * Reads a 9525 rumor strictly (§Encodings): integers unsigned decimal
 * without leading zeros, hex lowercase, each single tag at most once, `w`,
 * `rev` and `state` required. An entry whose state is not recognised is
 * returned with `state` `unknown`, checked only for `w` and `rev`, for the
 * derived-id check; a recognised one needs its check time, `amount`,
 * `chain` and `wrap_key`, and must validate (`validatePocketEntry`).
 */
export function parsePocketEntry(r: Pick<Rumor, 'kind' | 'tags'>): PocketEntry & { readonly recognised: boolean } {
  if (r.kind !== KIND_POCKET_ENTRY) throw bad('not kind 9525')
  const tags = new Map<string, readonly string[]>()
  const secrets: { secret: string; role: string }[] = []
  for (const t of r.tags) {
    const k = t[0]
    if (k === 'secret') {
      if (t[1] === undefined) throw bad('secret tag is short')
      secrets.push({ secret: t[1], role: t[2] ?? '' })
      continue
    }
    if (k === undefined || !SINGLE.has(k)) continue
    if (tags.has(k)) throw bad(`two ${JSON.stringify(k)} tags`)
    if (t[1] === undefined) throw bad(`${JSON.stringify(k)} tag is short`)
    tags.set(k, t)
  }
  const opt = (k: string) => tags.get(k)?.[1]
  const uint = (v: string, k: string): number => {
    if (!DEC.test(v) || BigInt(v) > 1n << 62n) throw bad(`${k}: ${JSON.stringify(v)} is not a canonical unsigned integer`)
    return Number(v)
  }
  const w = opt('w')
  const revRaw = opt('rev')
  const st = tags.get('state')
  if (w === undefined || w === '' || revRaw === undefined || st === undefined) throw bad('w, rev and state are required')
  const rev = uint(revRaw, 'rev')
  if (!lowerHex(w) || rev === 0) throw bad('w or rev')
  const recognised = (POCKET_STATES as readonly string[]).includes(st[1]!) && st[1] !== 'unknown'
  const amountRaw = opt('amount')
  const amount = amountRaw === undefined ? undefined : DEC.test(amountRaw) ? BigInt(amountRaw) : undefined
  if (amountRaw !== undefined && amount === undefined) throw bad(`amount: ${JSON.stringify(amountRaw)} is not a canonical unsigned integer`)
  const idt = tags.get('identity')
  const identity: PocketIdentity | undefined = idt === undefined ? undefined : idt[1] === 'cash' ? { type: 'cash' } : idt[1] === 'connection_key' ? { type: 'connection_key', value: idt[2] ?? '', ia: idt[3] ?? '' } : { type: 'pubkey', value: idt[2] ?? '' }
  if (idt !== undefined && idt[1] !== 'cash' && idt[1] !== 'connection_key' && idt[1] !== 'pubkey' && recognised) throw bad('identity')
  const entry = {
    w,
    rev,
    state: recognised ? (st[1] as PocketState) : ('unknown' as const),
    recognised,
    checkedAt: 0,
    wrapKey: opt('wrap_key') ?? '',
    amountMillis: amount ?? 0n,
    chain: opt('chain') ?? '',
    ...(opt('cash') !== undefined && { cash: opt('cash')! }),
    ...(identity !== undefined && { identity }),
    ...(opt('expires_at') !== undefined && { expiresAt: uint(opt('expires_at')!, 'expires_at') }),
    ...(opt('mint') !== undefined && { mint: opt('mint')! }),
    ...(opt('source') !== undefined && { source: opt('source')! }),
    ...(secrets.length > 0 && { secrets }),
    ...(opt('request_id') !== undefined && { requestId: opt('request_id')! }),
    ...(opt('deadline') !== undefined && { deadline: uint(opt('deadline')!, 'deadline') }),
    ...(opt('target') !== undefined && { target: opt('target')! }),
    ...(opt('device') !== undefined && { device: opt('device')! }),
    ...(opt('order_key') !== undefined && { orderKey: opt('order_key')! }),
    ...(opt('notify') !== undefined && { notify: opt('notify')! }),
    ...(opt('address') !== undefined && { address: opt('address')! }),
    ...(opt('quote') !== undefined && { quote: opt('quote')! }),
    ...(opt('receipt') !== undefined && { receipt: opt('receipt')! }),
  }
  if (!recognised) return entry
  if (st[2] === undefined) throw bad('state needs its check time')
  const checked = { ...entry, checkedAt: uint(st[2], 'state check time') }
  if (amount === undefined || opt('chain') === undefined || checked.wrapKey === '') throw bad('amount, chain and wrap_key are required')
  validatePocketEntry(checked)
  return checked
}

/**
 * Resolves the entries of each `w` (§Reading): the highest `rev` wins; at
 * one `rev`, a final state over any other, then the latest rumor
 * `created_at`, then the lowest rumor id. Unrecognised states are left out.
 * `conflicts` names, sorted, every `w` whose winning `rev` holds more than
 * one distinct rumor: the wallet re-checks that bill.
 */
export function resolveEntries(rumors: readonly { readonly rumor: Pick<Rumor, 'id' | 'created_at'>; readonly entry: PocketEntry & { readonly recognised?: boolean } }[]): { entries: Map<string, PocketEntry>; conflicts: string[] } {
  const best = new Map<string, (typeof rumors)[number]>()
  const rivals = new Map<string, Set<string>>()
  const beats = (x: (typeof rumors)[number], y: (typeof rumors)[number]): boolean => {
    const xf = isFinal(x.entry.state)
    if (xf !== isFinal(y.entry.state)) return xf
    if (x.rumor.created_at !== y.rumor.created_at) return x.rumor.created_at > y.rumor.created_at
    return x.rumor.id < y.rumor.id
  }
  for (const x of rumors) {
    if (x.entry.recognised === false) continue
    const w = x.entry.w
    const cur = best.get(w)
    if (cur === undefined || x.entry.rev > cur.entry.rev) {
      best.set(w, x)
      rivals.set(w, new Set([x.rumor.id]))
    } else if (x.entry.rev === cur.entry.rev) {
      rivals.get(w)!.add(x.rumor.id)
      if (beats(x, cur)) best.set(w, x)
    }
  }
  const entries = new Map<string, PocketEntry>()
  for (const [w, x] of best) entries.set(w, x.entry)
  const conflicts = [...rivals].filter(([, ids]) => ids.size > 1).map(([w]) => w)
  conflicts.sort()
  return { entries, conflicts }
}

/** The balance per chain: the sum of `amount` over `live` entries. */
export function pocketBalance(entries: Iterable<PocketEntry>): Map<string, bigint> {
  const out = new Map<string, bigint>()
  for (const e of entries) if (e.state === 'live') out.set(e.chain, (out.get(e.chain) ?? 0n) + e.amountMillis)
  return out
}

/** The state a tombstone's `reason` maps to (§Balance). */
export const stateForTombstone = (reason: string | undefined): PocketState => (reason === 'expired' ? 'expired' : reason === 'reclaimed' ? 'reclaimed' : 'spent')

/**
 * A wrap's NIP-40 `expiration`, used only when the user turns it on:
 * `expires_at` plus the grace, rounded up to a whole week, plus 0–6 random days.
 */
export function wrapExpiration(expiresAt: number, o: { graceSeconds?: number; random: (n: number) => Uint8Array }): number {
  const WEEK = 604800
  const t = expiresAt + (o.graceSeconds ?? 2_592_000)
  return Math.ceil(t / WEEK) * WEEK + (o.random(1)[0]! % 7) * 86400
}
