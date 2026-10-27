// Balance, activity and handoffs (design §6.5, §6.6). Port of cashctl
// cmd/wallet_balance.go and cmd/handoffs.go (refreshHandoffs, checkHandoff,
// maskedHandoff, outstandingCashNotes).
import { bySecret, cashCommitment, decodeToken, splitCashString } from '../core/index.js'
import { billFor, WalletError } from '../client/index.js'
import type { Ctx } from './context.js'
import { CashkitError, classifyReadError, codeForNwc, fromWalletError } from './errors.js'
import { isLightning, nwcFor } from './circle.js'
import { heldHoldings } from './ledger.js'
import type { Activity, ConnectionKind, Handoff, HandoffStatus } from './model.js'

export interface WalletBalance {
  readonly name: string
  readonly kind: ConnectionKind
  readonly balance?: bigint
  /** An auth-class decline with a cached figure: shown, still counted, as cashctl does. */
  readonly stranded?: boolean
  readonly unreachable?: CashkitError
}

export interface Balance {
  /** Wallets plus unexpired held cash, as cashctl's total. */
  readonly total: bigint
  /** The part of `total` that is a stranded wallet's cached figure. */
  readonly stranded: bigint
  readonly wallets: readonly WalletBalance[]
  readonly holdings: { readonly held: bigint; readonly count: number; readonly expired: bigint; readonly pendingMerge: number }
  /** Handed out and unclaimed: shown, never counted. */
  readonly outstandingCashNotes: { readonly count: number; readonly amount: bigint }
}

export async function balance(ctx: Ctx, o: { refresh?: boolean } = {}): Promise<Balance> {
  const refresh = o.refresh ?? true
  // Lightning wallets only: a Cash Hub connection holds no balance of its own.
  const conns = (await ctx.read((t) => t.list('connections'))).filter(isLightning)
  const wallets: WalletBalance[] = []
  let total = 0n
  let stranded = 0n
  for (const c of conns) {
    if (!refresh) {
      if (c.lastKnownBalance !== undefined) total += c.lastKnownBalance.millis
      wallets.push({ name: c.id, kind: c.kind, ...(c.lastKnownBalance !== undefined && { balance: c.lastKnownBalance.millis }) })
      continue
    }
    try {
      const r = await (await nwcFor(ctx, c)).getBalance()
      const millis = BigInt(r.balance)
      total += millis
      wallets.push({ name: c.id, kind: c.kind, balance: millis })
      await ctx.commit((t) => t.put('connections', { ...c, lastKnownBalance: { millis, at: ctx.now() }, version: c.version + 1 }, c.version)).catch(() => undefined)
    } catch (err) {
      if (err instanceof WalletError && codeForNwc(err.walletCode) === 'auth' && c.lastKnownBalance !== undefined) {
        total += c.lastKnownBalance.millis
        stranded += c.lastKnownBalance.millis
        wallets.push({ name: c.id, kind: c.kind, balance: c.lastKnownBalance.millis, stranded: true })
        continue
      }
      wallets.push({ name: c.id, kind: c.kind, unreachable: err instanceof WalletError ? fromWalletError(err) : classifyReadError(err) })
    }
  }
  const now = ctx.nowSeconds()
  let held = 0n
  let expired = 0n
  let count = 0
  let pendingMerge = 0
  for (const h of await ctx.read(heldHoldings)) {
    if (h.throwawayKey !== undefined) pendingMerge++
    if (h.amount === undefined) continue
    count++
    if (h.expiresAt !== undefined && h.expiresAt <= now) expired += h.amount
    else held += h.amount
  }
  const handoffs = await ctx.read((t) => t.list('handoffs'))
  const notes = handoffs.filter((h) => h.kind === 'cash_note' && h.status === 'unclaimed')
  return {
    total: total + held,
    stranded,
    wallets,
    holdings: { held, count, expired, pendingMerge },
    outstandingCashNotes: { count: notes.length, amount: notes.reduce((a, h) => a + h.amount, 0n) },
  }
}

export interface HandoffView {
  readonly id: string
  readonly at: number
  readonly kind: Handoff['kind']
  /** The note or gift token; an unclaimed note's secret is hidden unless asked for. */
  readonly handoff: string
  readonly secretHidden: boolean
  readonly amount: bigint
  readonly target: string
  readonly walletPubkey: string
  readonly status: HandoffStatus
  readonly checkedAt?: number
  readonly expiresAt?: number
}

/** `maskedHandoff`. */
export async function handoffView(ctx: Ctx, h: Handoff, includeSecrets: boolean): Promise<HandoffView> {
  const value = await ctx.open(h.handoff)
  const hide = !includeSecrets && h.kind === 'cash_note' && h.status === 'unclaimed'
  return {
    id: h.id,
    at: h.at,
    kind: h.kind,
    handoff: hide ? `${splitCashString(value).token}#<hidden>` : value,
    secretHidden: hide,
    amount: h.amount,
    target: h.target,
    walletPubkey: h.walletPubkey,
    status: h.status,
    ...(h.checkedAt !== undefined && { checkedAt: h.checkedAt }),
    ...(h.expiresAt !== undefined && { expiresAt: h.expiresAt }),
  }
}

/** `checkHandoff`: what the note's Hub says now, or undefined when it can't tell. */
async function checkNote(ctx: Ctx, note: string): Promise<HandoffStatus | undefined> {
  // A cash note is read with its bearer credential, the secret never sent: the row alone says whether it was claimed.
  const { token, cashSecret } = splitCashString(note)
  if (cashSecret === '') return undefined
  try {
    const r = await ctx.client(token).statusMany([{ id: '1', bill: billFor(decodeToken(token)), credential: bySecret(cashSecret), scope: 'mine' }])
    const o = r.outcomes[0]
    if (o?.state === 'tombstone' || (o?.state === 'result' && o.tombstone !== undefined)) return 'claimed'
    if (o?.state === 'result' && o.value !== undefined) {
      if (o.value.tombstone !== undefined) return 'claimed'
      const row = o.value.recipients[0]
      if (row === undefined) return undefined
      // Claimed, or moved to another identity: the note no longer pays its holder.
      if (row.claimed || row.identity_type !== 'cash' || row.identity_value !== cashCommitment(cashSecret)) return 'claimed'
      if (row.expires_at !== undefined && row.expires_at <= ctx.nowSeconds()) return 'expired'
      return 'unclaimed'
    }
    if (o?.state === 'error' && o.error?.code === 'EXPIRED') return 'expired'
    return undefined
  } catch {
    return undefined
  }
}

/** `refreshHandoffs`: re-checks every unclaimed cash note, in parallel. */
export async function refreshHandoffs(ctx: Ctx): Promise<void> {
  const rows = (await ctx.read((t) => t.list('handoffs'))).filter((h) => h.kind === 'cash_note' && h.status === 'unclaimed')
  const checked = await Promise.all(rows.map(async (h) => ({ h, status: await checkNote(ctx, await ctx.open(h.handoff)) })))
  const changed = checked.filter((c) => c.status !== undefined && c.status !== c.h.status)
  if (changed.length === 0) return
  await ctx
    .commit(async (t) => {
      for (const { h, status } of changed) {
        const cur = await t.get('handoffs', h.id)
        if (cur === undefined) continue
        await t.put('handoffs', { ...cur, status: status!, checkedAt: ctx.now(), version: cur.version + 1 }, cur.version)
      }
    })
    .catch(() => undefined)
}

export async function listHandoffs(ctx: Ctx, o: { status?: readonly HandoffStatus[]; includeSecrets?: boolean; refresh?: boolean } = {}): Promise<HandoffView[]> {
  if (o.refresh === true) await refreshHandoffs(ctx)
  const rows = (await ctx.read((t) => t.list('handoffs'))).filter((h) => o.status === undefined || o.status.includes(h.status))
  return Promise.all(rows.map((h) => handoffView(ctx, h, o.includeSecrets === true)))
}

export type ActivityItem = ({ readonly type: 'activity' } & Activity) | ({ readonly type: 'handoff' } & HandoffView)

/** Activity rows and handoffs, newest first. */
export async function activity(ctx: Ctx, o: { refresh?: boolean; includeSecrets?: boolean; limit?: number; before?: number } = {}): Promise<ActivityItem[]> {
  if (o.refresh === true) await refreshHandoffs(ctx)
  const acts = await ctx.read((t) => t.list('activity'))
  const hs = await listHandoffs(ctx, { ...(o.includeSecrets !== undefined && { includeSecrets: o.includeSecrets }) })
  const items: ActivityItem[] = [...acts.map((a) => ({ type: 'activity' as const, ...a })), ...hs.map((h) => ({ type: 'handoff' as const, ...h }))]
  // Newest first; for equal times, later-written rows first.
  const indexed = items.map((it, i) => ({ it, i }))
  indexed.sort((a, b) => b.it.at - a.it.at || b.i - a.i)
  const filtered = indexed.map((x) => x.it).filter((it) => o.before === undefined || it.at < o.before)
  return o.limit !== undefined ? filtered.slice(0, o.limit) : filtered
}
