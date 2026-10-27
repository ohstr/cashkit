// NIP-CP Cash Pocket entries (kind 9525): a held token, a written-ahead
// bill-creating call or withdrawal (`pending`), or a final state; their
// tags, resolution per `w`, and the balance. Port of nmilat nipCP.
import { CoreError } from './errors.js'
import type { Rumor } from './nip59.js'

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
const HEX = /^[0-9a-f]+$/
const bad = (m: string) => new CoreError('invalid_payload', `pocket entry: ${m}`)

/** An entry's tags, encoded as §Encodings requires (decimals without leading zeros, lowercase hex). */
export function pocketEntryTags(e: PocketEntry): string[][] {
  for (const [k, v] of [
    ['w', e.w],
    ['wrap_key', e.wrapKey],
    ...(e.requestId !== undefined ? [['request_id', e.requestId]] : []),
    ...(e.target !== undefined ? [['target', e.target]] : []),
    ...(e.device !== undefined ? [['device', e.device]] : []),
  ] as const) {
    if (!HEX.test(v)) throw new CoreError('invalid_request', `pocket entry: ${k} is lowercase hex`)
  }
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

/** Reads a 9525 rumor. An entry whose state is not recognised is returned with `state` `unknown` only for the derived-id check. */
export function parsePocketEntry(r: Pick<Rumor, 'kind' | 'tags'>): PocketEntry & { readonly recognised: boolean } {
  if (r.kind !== KIND_POCKET_ENTRY) throw bad('not kind 9525')
  const one = (k: string) => r.tags.find((t) => t[0] === k)
  const req = (k: string) => {
    const t = one(k)
    if (t === undefined || t[1] === undefined) throw bad(`missing ${k}`)
    return t
  }
  const num = (v: string | undefined, k: string) => {
    if (v === undefined || !DEC.test(v)) throw bad(`${k} is an unsigned decimal`)
    return Number(v)
  }
  const st = req('state')
  const recognised = (POCKET_STATES as readonly string[]).includes(st[1]!)
  const idt = one('identity')
  const identity: PocketIdentity | undefined = idt === undefined ? undefined : idt[1] === 'cash' ? { type: 'cash' } : idt[1] === 'connection_key' ? { type: 'connection_key', value: idt[2] ?? '', ia: idt[3] ?? '' } : { type: 'pubkey', value: idt[2] ?? '' }
  const opt = (k: string) => one(k)?.[1]
  const secrets = r.tags.filter((t) => t[0] === 'secret' && typeof t[1] === 'string').map((t) => ({ secret: t[1]!, role: t[2] ?? '' }))
  const amount = req('amount')[1]!
  if (!DEC.test(amount)) throw bad('amount is an unsigned decimal')
  return {
    w: req('w')[1]!,
    rev: num(req('rev')[1], 'rev'),
    state: recognised ? (st[1] as PocketState) : 'unknown',
    recognised,
    checkedAt: num(st[2] ?? '0', 'state check time'),
    wrapKey: req('wrap_key')[1]!,
    amountMillis: BigInt(amount),
    chain: req('chain')[1]!,
    ...(opt('cash') !== undefined && { cash: opt('cash')! }),
    ...(identity !== undefined && { identity }),
    ...(opt('expires_at') !== undefined && { expiresAt: num(opt('expires_at'), 'expires_at') }),
    ...(opt('mint') !== undefined && { mint: opt('mint')! }),
    ...(opt('source') !== undefined && { source: opt('source')! }),
    ...(secrets.length > 0 && { secrets }),
    ...(opt('request_id') !== undefined && { requestId: opt('request_id')! }),
    ...(opt('deadline') !== undefined && { deadline: num(opt('deadline'), 'deadline') }),
    ...(opt('target') !== undefined && { target: opt('target')! }),
    ...(opt('device') !== undefined && { device: opt('device')! }),
    ...(opt('order_key') !== undefined && { orderKey: opt('order_key')! }),
    ...(opt('notify') !== undefined && { notify: opt('notify')! }),
    ...(opt('address') !== undefined && { address: opt('address')! }),
    ...(opt('quote') !== undefined && { quote: opt('quote')! }),
    ...(opt('receipt') !== undefined && { receipt: opt('receipt')! }),
  }
}

/**
 * Resolves the entries of each `w` (§Reading): a final state wins over
 * entries of lower or equal `rev`; otherwise the highest `rev`; then the
 * latest rumor `created_at`; then the lowest rumor id. Unrecognised states
 * are left out. `conflicts` names every `w` with more than one candidate.
 */
export function resolveEntries(rumors: readonly { readonly rumor: Pick<Rumor, 'id' | 'created_at'>; readonly entry: PocketEntry & { readonly recognised?: boolean } }[]): { entries: Map<string, PocketEntry>; conflicts: string[] } {
  const by = new Map<string, typeof rumors[number][]>()
  for (const x of rumors) {
    if (x.entry.recognised === false) continue
    by.set(x.entry.w, [...(by.get(x.entry.w) ?? []), x])
  }
  const entries = new Map<string, PocketEntry>()
  const conflicts: string[] = []
  for (const [w, xs] of by) {
    if (new Set(xs.map((x) => x.rumor.id)).size > 1) conflicts.push(w)
    let best = xs[0]!
    for (const x of xs.slice(1)) {
      const a = x.entry
      const b = best.entry
      const aFinal = FINAL_STATES.includes(a.state)
      const bFinal = FINAL_STATES.includes(b.state)
      let wins: boolean
      if (bFinal && a.rev <= b.rev) wins = aFinal && a.rev === b.rev && (x.rumor.created_at > best.rumor.created_at || (x.rumor.created_at === best.rumor.created_at && x.rumor.id < best.rumor.id))
      else if (aFinal && b.rev <= a.rev) wins = true
      else if (a.rev !== b.rev) wins = a.rev > b.rev
      else if (x.rumor.created_at !== best.rumor.created_at) wins = x.rumor.created_at > best.rumor.created_at
      else wins = x.rumor.id < best.rumor.id
      if (wins) best = x
    }
    entries.set(w, best.entry)
  }
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
