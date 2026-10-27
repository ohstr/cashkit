// NIP-CZ Cash Zaps: kind 9522 (a zap paid with a cash token) and kind
// 10522 (the recipient's accepted chains, minters and relays), the
// verification rules 1–8, and counting. Port of nmilat nipCZ.
import { chainForHrp, verifyProvenance, verifyZapProvenance, type ZapFields } from './provenance.js'
import { CoreError } from './errors.js'
import { verifyEvent, type NostrEvent } from './nip01.js'
import { decodeToken, type Token } from './token.js'

export const KIND_CASH_ZAP = 9522
export const KIND_CASH_ZAP_INFO = 10522

const HEX64 = /^[0-9a-f]{64}$/
const DEC = /^(0|[1-9][0-9]*)$/
const MINTER = /^0[23][0-9a-f]{64}$/

/** An identity tag (`p`, `P`): a Nostr pubkey when `[2]` is missing, empty or `nostr`, else a ConnectionKey on that platform. */
export function parseIdentityTag(tag: readonly string[]): { readonly value: string; readonly kind: 'pubkey' } | { readonly value: string; readonly kind: 'connection_key'; readonly platform: string } {
  const value = tag[1] ?? ''
  const platform = tag[2]
  if (platform === undefined || platform === '' || platform === 'nostr') return { value, kind: 'pubkey' }
  return { value, kind: 'connection_key', platform }
}

/** A 9522's tags, as rule 2 reads them. */
export interface CashZapTags {
  readonly p: ReturnType<typeof parseIdentityTag>
  readonly P?: ReturnType<typeof parseIdentityTag>
  readonly amountMillis: bigint
  readonly chain: string
  readonly cash: string
  readonly w: string
  readonly ia?: string
  readonly e?: string
  readonly a?: string
  readonly k?: string
  readonly issuedAt?: number
  readonly expiresAt?: number
  /** It carries a NIP-40 `expiration` tag, which a Cash Zap must not: shown, never counted. */
  readonly hasExpiration?: true
}

const bad = (m: string) => new CoreError('zap_invalid', `rule 2: ${m}`)
const ONCE = ['p', 'amount', 'chain', 'cash', 'w'] as const
const AT_MOST_ONCE = ['e', 'a', 'k', 'P', 'issued_at', 'expires_at', 'ia'] as const

/**
 * Rule 2: the cardinality of §Kind 9522, decimals without leading zeros,
 * `p`/`P`/`w` 64 lowercase hex (never lowercased), `ia` iff `p` is a
 * ConnectionKey, `P` only a ConnectionKey, and, when
 * the token is given, `w` equal to its TLV 0 and `issued_at`/`expires_at`
 * present on a zap-signed token. Throws `zap_invalid` naming the rule. A
 * NIP-40 `expiration` tag is not a rule 2 failure: it is reported as
 * `hasExpiration`, and the zap is never counted.
 */
export function checkCashZapTags(ev: Pick<NostrEvent, 'tags'>, token?: Token): CashZapTags {
  const by = new Map<string, (readonly string[])[]>()
  for (const t of ev.tags) by.set(t[0] ?? '', [...(by.get(t[0] ?? '') ?? []), t])
  for (const k of ONCE) if ((by.get(k)?.length ?? 0) !== 1) throw bad(`exactly one ${k} tag`)
  for (const k of AT_MOST_ONCE) if ((by.get(k)?.length ?? 0) > 1) throw bad(`at most one ${k} tag`)
  const one = (k: string) => by.get(k)?.[0]
  const p = parseIdentityTag(one('p')!)
  if (!HEX64.test(p.value)) throw bad('p is 64 lowercase hex')
  const Pt = one('P')
  const P = Pt !== undefined ? parseIdentityTag(Pt) : undefined
  if (P !== undefined && (!HEX64.test(P.value) || P.kind !== 'connection_key')) throw bad('P is a ConnectionKey of 64 lowercase hex')
  const w = one('w')![1] ?? ''
  if (!HEX64.test(w)) throw bad('w is 64 lowercase hex')
  const amount = one('amount')![1] ?? ''
  if (!DEC.test(amount) || amount === '0') throw bad('amount is a positive unsigned decimal')
  const ia = one('ia')?.[1]
  if ((p.kind === 'connection_key') !== (ia !== undefined)) throw bad('ia exactly when p is a ConnectionKey')
  if (ia !== undefined && !HEX64.test(ia)) throw bad('ia is 64 lowercase hex')
  const dec = (k: string): number | undefined => {
    const v = one(k)?.[1]
    if (v === undefined) return undefined
    if (!DEC.test(v)) throw bad(`${k} is an unsigned decimal without leading zeros`)
    return Number(v)
  }
  const issuedAt = dec('issued_at')
  const expiresAt = dec('expires_at')
  if (token !== undefined) {
    if (token.walletPubkey !== w) throw bad("w is not the token's wallet pubkey")
    if (token.scheme === 'zap_v1' && (issuedAt === undefined || expiresAt === undefined)) throw bad('a zap-signed token needs issued_at and expires_at')
  }
  return {
    p,
    ...(P !== undefined && { P }),
    amountMillis: BigInt(amount),
    chain: one('chain')![1] ?? '',
    cash: one('cash')![1] ?? '',
    w,
    ...(ia !== undefined && { ia }),
    ...(one('e') !== undefined && { e: one('e')![1]! }),
    ...(one('a') !== undefined && { a: one('a')![1]! }),
    ...(one('k') !== undefined && { k: one('k')![1]! }),
    ...(issuedAt !== undefined && { issuedAt }),
    ...(expiresAt !== undefined && { expiresAt }),
    ...(by.has('expiration') && { hasExpiration: true as const }),
  }
}

/** The zap fields a 9522 gives its token's `cash-zap:v1` payload: `p`, the signer, the target (`a`, else `e`), the times. */
export function zapFieldsFromEvent(ev: Pick<NostrEvent, 'pubkey'>, t: CashZapTags): ZapFields | undefined {
  const target = t.a ?? t.e
  if (target === undefined || t.issuedAt === undefined || t.expiresAt === undefined || t.p.kind !== 'pubkey') return undefined
  return { recipient: t.p.value, sender: ev.pubkey, zapTarget: target, issuedAt: t.issuedAt, expiresAt: t.expiresAt }
}

/** A recipient's 10522: accepted chains (none = any), trusted minters per accepted chain, and relays. */
export interface CashZapInfo {
  readonly chains: readonly string[]
  readonly mints: readonly { readonly minter: string; readonly chain: string }[]
  readonly relays: readonly string[]
}

/** Reads a 10522: a `mint` without a chain, or for a chain not accepted, is ignored. */
export function parseCashZapInfo(ev: Pick<NostrEvent, 'kind' | 'tags'>): CashZapInfo {
  if (ev.kind !== KIND_CASH_ZAP_INFO) throw new CoreError('invalid_payload', 'not a kind 10522 event')
  const chains = ev.tags.filter((t) => t[0] === 'chain' && typeof t[1] === 'string' && t[1] !== '').map((t) => t[1]!)
  const accepts = (c: string) => chains.length === 0 || chains.includes(c)
  const mints = ev.tags.filter((t) => t[0] === 'mint' && MINTER.test(t[1] ?? '') && typeof t[2] === 'string' && t[2] !== '' && accepts(t[2])).map((t) => ({ minter: t[1]!, chain: t[2]! }))
  const relays = ev.tags.filter((t) => t[0] === 'relay' && typeof t[1] === 'string' && t[1] !== '').map((t) => t[1]!)
  return { chains, mints, relays }
}

/** Minters compare by their x-only part. */
const xonly = (k: string) => (k.length === 66 ? k.slice(2) : k)

/** Whether a minter is trusted for a chain, by the reader's list or the recipient's 10522. */
export function isTrustedMinter(minter: string, chain: string, trusted: readonly { minter: string; chain: string }[]): boolean {
  return trusted.some((t) => t.chain === chain && xonly(t.minter) === xonly(minter))
}

export interface CashZapVerdict {
  /** Each rule's result; undefined when it could not be evaluated (an earlier rule failed). */
  readonly rules: Readonly<Partial<Record<1 | 2 | 3 | 4 | 5 | 6 | 7 | 8, boolean>>>
  readonly tags?: CashZapTags
  readonly token?: Token
  /** The Minter (33-byte compressed, hex) rule 6 recovered. */
  readonly minter?: string
  /** Rules 1–6 hold: the event may be shown. */
  readonly valid: boolean
  /** Rules 1–8 hold, the token is zap-signed and no NIP-40 `expiration` tag: it may be totalled (with the life check of §Counting). */
  readonly countable: boolean
  /** The failing rule, when there is one. */
  readonly failed?: number
}

/**
 * Verifies a 9522 (§Verification Algorithm), rule 1 first: its signature,
 * its tags, the token, the chain, the identity hint, the Minter over the
 * token's payload with the amount, the zap signature against its target
 * (`target` is the zapped event: an `e`-only zap must name its `id`, when
 * given, and is not issued before it; its author is `p`; without `target`,
 * an `a` tag's author is read from the coordinate), and a trusted Minter.
 */
export function verifyCashZap(ev: NostrEvent, o: { target?: Pick<NostrEvent, 'pubkey' | 'created_at'> & { readonly id?: string }; zapInfo?: CashZapInfo; trusted?: readonly { minter: string; chain: string }[] } = {}): CashZapVerdict {
  const rules: Partial<Record<1 | 2 | 3 | 4 | 5 | 6 | 7 | 8, boolean>> = {}
  const fail = (n: number, extra: Partial<CashZapVerdict> = {}): CashZapVerdict => ({ rules, valid: false, countable: false, failed: n, ...extra })
  rules[1] = ev.kind === KIND_CASH_ZAP && verifyEvent(ev)
  if (!rules[1]) return fail(1)
  let tags: CashZapTags
  try {
    tags = checkCashZapTags(ev)
  } catch {
    rules[2] = false
    return fail(2)
  }
  let token: Token
  try {
    token = decodeToken(tags.cash)
    rules[3] = true
  } catch {
    rules[2] = true
    rules[3] = false
    return fail(3, { tags })
  }
  try {
    checkCashZapTags(ev, token)
    rules[2] = true
  } catch {
    rules[2] = false
    return fail(2, { tags, token })
  }
  rules[4] = chainForHrp(token.hrp) === tags.chain
  if (!rules[4]) return fail(4, { tags, token })
  rules[5] = token.identityRequired !== false
  if (!rules[5]) return fail(5, { tags, token })
  const zap = zapFieldsFromEvent(ev, tags)
  const m = token.scheme === 'zap_v1' ? (zap !== undefined ? verifyZapProvenance(token, zap) : undefined) : verifyProvenance(token)
  rules[6] = m !== undefined && token.attestedAmountMillis === tags.amountMillis
  if (!rules[6]) return fail(6, { tags, token })
  const minter = m!.minter
  const t = o.target
  const author = t !== undefined ? t.pubkey : tags.a?.split(':')[1]
  const namesTarget = t === undefined || tags.a !== undefined || t.id === undefined || tags.e === t.id
  rules[7] = token.scheme === 'zap_v1' && zap !== undefined && author !== undefined && author === tags.p.value && namesTarget && (tags.a !== undefined || t === undefined || (tags.issuedAt ?? 0) >= t.created_at)
  const trustList = [...(o.trusted ?? []), ...(o.zapInfo?.mints ?? [])]
  rules[8] = isTrustedMinter(minter, tags.chain, trustList)
  return { rules, tags, token, minter, valid: true, countable: rules[7] && rules[8] && tags.hasExpiration !== true, ...(!rules[7] ? { failed: 7 } : !rules[8] ? { failed: 8 } : {}) }
}

/**
 * Totals Cash Zaps (§Counting): only those passing rules 1–8 with a
 * zap-signed token, whose life (`expires_at − issued_at`) is at least
 * `minLife` or never ends, not deleted by their sender; a token counts
 * once, whatever copies share its `w`. `collapse` also counts repeated zaps
 * between one sender and recipient once.
 */
export function countCashZaps(verdicts: readonly { readonly event: NostrEvent; readonly verdict: CashZapVerdict }[], o: { minLife: number; deletions?: ReadonlySet<string>; collapseRepeated?: boolean }): { totalMillis: bigint; counted: readonly string[] } {
  const seenW = new Set<string>()
  const pairs = new Set<string>()
  const counted: string[] = []
  let total = 0n
  for (const { event, verdict } of verdicts) {
    const t = verdict.tags
    if (!verdict.countable || t === undefined || o.deletions?.has(event.id) === true) continue
    const life = t.expiresAt === 0 ? Infinity : (t.expiresAt ?? 0) - (t.issuedAt ?? 0)
    if (life < o.minLife) continue
    if (seenW.has(t.w)) continue
    const pair = `${event.pubkey}:${t.p.value}`
    if (o.collapseRepeated === true && pairs.has(pair)) continue
    seenW.add(t.w)
    pairs.add(pair)
    counted.push(event.id)
    total += t.amountMillis
  }
  return { totalMillis: total, counted }
}

/** The tags of a 9522 (§Kind 9522): `a` only when the bill was signed over it, never NIP-40; `ia` iff a ConnectionKey `p`. */
export function cashZapTags(p: {
  recipient: { value: string; platform?: string }
  amountMillis: bigint
  chain: string
  token: string
  walletPubkey: string
  ia?: string
  e?: string
  a?: string
  k?: string
  issuedAt?: number
  expiresAt?: number
}): string[][] {
  if (!HEX64.test(p.recipient.value) || !HEX64.test(p.walletPubkey)) throw new CoreError('invalid_request', 'a Cash Zap names 64-hex keys')
  const ck = p.recipient.platform !== undefined && p.recipient.platform !== '' && p.recipient.platform !== 'nostr'
  if (ck !== (p.ia !== undefined)) throw new CoreError('invalid_request', 'ia exactly when the recipient is a ConnectionKey')
  return [
    ...(p.e !== undefined ? [['e', p.e]] : []),
    ...(p.a !== undefined ? [['a', p.a]] : []),
    ...(p.k !== undefined ? [['k', p.k]] : []),
    ck ? ['p', p.recipient.value, p.recipient.platform!] : ['p', p.recipient.value],
    ['amount', p.amountMillis.toString()],
    ['chain', p.chain],
    ['cash', p.token],
    ['w', p.walletPubkey],
    ...(p.ia !== undefined ? [['ia', p.ia]] : []),
    ...(p.issuedAt !== undefined ? [['issued_at', String(p.issuedAt)]] : []),
    ...(p.expiresAt !== undefined ? [['expires_at', String(p.expiresAt)]] : []),
  ]
}

/** Incoming zaps for these recipients (pubkey and linked ConnectionKeys). */
export const incomingZapFilter = (recipients: readonly string[]) => ({ kinds: [KIND_CASH_ZAP], '#p': [...recipients] })
/** Zaps this user sent: as author, and through Proxy Agents for linked ConnectionKeys. */
export const sentZapFilters = (author: string, connectionKeys: readonly string[] = []) => [{ kinds: [KIND_CASH_ZAP], authors: [author] }, ...(connectionKeys.length > 0 ? [{ kinds: [KIND_CASH_ZAP], '#P': [...connectionKeys] }] : [])]
