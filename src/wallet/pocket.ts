// The Cash Pocket engine (NIP-CP §Writing, §Reading, §Balance), used when
// `WalletDeps.pocket` is set. Before a bill-creating call or a withdrawal
// goes out, its pending entry is stored and read back (failing that, the
// call is not sent). Once the outcome is saved, an entry is written for
// each bill this wallet keeps, then the pending entry is closed `done` with
// its sources `spent`; an order or a withdrawal stays pending until it is
// finished. A sync imports live entries this device does not hold and
// republishes what the relays no longer return.
import {
  chainForHrp,
  createRumor,
  createSeal,
  createWrap,
  decodeToken,
  checkPendingEntry,
  fromHex,
  getPublicKey,
  KIND_POCKET_ENTRY,
  connectionKeyFromAttested,
  parsePocketEntry,
  pocketBalance,
  pocketEntryTags,
  resolveEntries,
  toHex,
  unwrap,
  wrapDeletion,
  type PocketEntry,
  type PocketIdentity,
} from '../core/index.js'
import { tokenFacts, type Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { addHolding, appendActivity, updateHolding } from './ledger.js'
import type { Holding, PendingCall } from './model.js'
import { pocketHooks } from './runner.js'
import { statusByNode, type NodeStatus } from './status.js'

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))

function requirePocket(ctx: Ctx) {
  const p = ctx.deps.pocket
  if (p === undefined) throw new CashkitError('usage', 'no Cash Pocket is configured (WalletDeps.pocket)')
  return p
}

/**
 * Writes an entry at the next `rev`, above both this device's and any
 * `seenRev` read from the pocket (NIP-CP: the highest rev seen for that `w`
 * plus 1): a fresh wrap key first, sealed and wrapped; stored on enough
 * relays and read back, then the previous wrap deleted.
 */
export async function writeEntry(ctx: Ctx, entry: Omit<PocketEntry, 'rev' | 'wrapKey' | 'checkedAt'> & { readonly checkedAt?: number }, o: { readonly seenRev?: number } = {}): Promise<PocketEntry> {
  const pocket = requirePocket(ctx)
  const signer = await ctx.requireSigner()
  const prev = await ctx.read((t) => t.get('pocket', entry.w))
  const wrapKey = ctx.random(32)
  const full: PocketEntry = { ...entry, rev: Math.max(prev?.rev ?? 0, o.seenRev ?? 0) + 1, wrapKey: toHex(wrapKey), checkedAt: entry.checkedAt ?? ctx.nowSeconds() }
  const now = ctx.nowSeconds()
  const rumor = createRumor({ kind: KIND_POCKET_ENTRY, pubkey: signer.pubkey, created_at: now, tags: pocketEntryTags(full), content: '' })
  const seal = await createSeal(rumor, signer, { now, random: ctx.random })
  const wrap = createWrap(seal, wrapKey, signer.pubkey, { now, random: ctx.random })
  const stored = await pocket.publish(wrap)
  const need = Math.max(1, pocket.minRelays ?? 2)
  if (stored.length < need || !(await pocket.has(wrap.id))) throw new CashkitError('network', 'the Cash Pocket entry could not be stored on enough relays; nothing was sent', { reason: 'pocket_unavailable' })
  const sealedKey = await ctx.seal(toHex(wrapKey))
  await ctx.commit(async (t) => {
    const cur = await t.get('pocket', entry.w)
    await t.put('pocket', { id: entry.w, rev: full.rev, state: full.state, wrapId: wrap.id, wrapKey: sealedKey, at: ctx.now(), version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
  })
  if (prev !== undefined) {
    const oldKey = hexBytes(await ctx.open(prev.wrapKey))
    await pocket.remove(wrapDeletion(prev.wrapId, oldKey, { now, random: ctx.random })).catch(() => undefined)
  }
  return full
}

const chainOf = (token: string) => {
  try {
    return chainForHrp(decodeToken(token).hrp) ?? ''
  } catch {
    return ''
  }
}

/** Who can claim the bill (NIP-CP `identity`): for a bill held under a one-time merge key, that key's pubkey, not the user's. */
async function identityOf(ctx: Ctx, h: Holding): Promise<PocketIdentity> {
  if (h.mode === 'cash') return { type: 'cash' }
  if (h.throwawayKey !== undefined) return { type: 'pubkey', value: getPublicKey(fromHex(await ctx.open(h.throwawayKey), 'throwaway key')) }
  if (h.mode === 'connection_key' && h.connectionKey !== undefined) return { type: 'connection_key', value: connectionKeyFromAttested(h.connectionKey.platform, h.connectionKey.externalId), ia: h.connectionKey.iaPubkey }
  return { type: 'pubkey', value: (await ctx.requireSigner()).pubkey }
}

/** The live entry of a held bill: its token, identity, secret, minter and expiry. */
export async function heldEntry(ctx: Ctx, h: Holding, state: PocketEntry['state'] = 'live') {
  return {
    w: h.walletPubkey,
    state,
    amountMillis: h.amount ?? 0n,
    chain: chainOf(h.token),
    cash: h.token,
    identity: await identityOf(ctx, h),
    ...(h.minterPubkey !== undefined && { mint: h.minterPubkey }),
    ...(h.expiresAt !== undefined && { expiresAt: h.expiresAt }),
    ...(h.cashSecret !== undefined && { secrets: [{ secret: await ctx.open(h.cashSecret), role: '' }] }),
  }
}

const ROLE: Readonly<Record<string, string>> = { new: '', remainder: 'remainder', remint: 'remint' }

/** A call's pending entry: its id, deadline, target, device, amount and every secret it generated; an order's key and notify; a withdrawal's address and quote. */
async function pendingEntry(ctx: Ctx, call: PendingCall, state: 'pending' | 'done', extra: { receipt?: string; scrub?: boolean } = {}) {
  const secrets: { secret: string; role: string }[] = []
  for (const o of call.outputs) if (o.destination.kind === 'cash') secrets.push({ secret: await ctx.open(o.destination.secret), role: ROLE[o.role] ?? '' })
  const src = call.sources[0] !== undefined ? await ctx.read((t) => t.get('holdings', call.sources[0]!)) : undefined
  const orderKey = call.method === 'cash_order' && call.authorizer.kind === 'buyer' && secrets.length === 0 ? await ctx.open(call.authorizer.buyerKey) : undefined
  const p = call.params ?? {}
  const scrub = extra.scrub === true
  return {
    w: call.requestId,
    state,
    amountMillis: call.amount,
    chain: src !== undefined ? chainOf(src.token) : (p['chain'] ?? 'bitcoin'),
    requestId: call.requestId,
    deadline: call.deadline,
    target: call.target,
    device: call.device,
    ...(secrets.length > 0 && { secrets }),
    ...(orderKey !== undefined && { orderKey }),
    ...(p['notify'] !== undefined && { notify: p['notify'] }),
    ...(call.method === 'cash_withdraw' && !scrub && p['address'] !== undefined && { address: p['address'] }),
    ...(call.method === 'cash_withdraw' && !scrub && p['quote'] !== undefined && { quote: p['quote'] }),
    ...(!scrub && extra.receipt !== undefined && { receipt: extra.receipt }),
  }
}

/** Before a call goes out: its pending entry, stored and read back. */
async function writeAhead(ctx: Ctx, call: PendingCall): Promise<void> {
  const entry = await pendingEntry(ctx, call, 'pending')
  checkPendingEntry(call.method, { ...entry, rev: 1, wrapKey: '', checkedAt: ctx.nowSeconds() })
  await writeEntry(ctx, entry)
}

/**
 * After a call's outcome is saved: an entry for each bill this wallet keeps
 * (a bill moved in place rewritten at its next `rev`), read back; then, once
 * the call is done, its pending entry `done` and its sources `spent`.
 */
async function afterCall(ctx: Ctx, callId: string): Promise<void> {
  const call = await ctx.read((t) => t.get('pendingCalls', callId))
  if (call === undefined) return
  const kept = [...(call.created?.holdingIds ?? []), ...(call.created?.movedHoldingId !== undefined ? [call.created.movedHoldingId] : []), ...(call.order?.bills.flatMap((b) => (b.holdingId !== undefined ? [b.holdingId] : [])) ?? []), ...(call.withdrawal?.remintHoldingId !== undefined ? [call.withdrawal.remintHoldingId] : [])]
  for (const id of new Set(kept)) {
    const h = await ctx.read((t) => t.get('holdings', id))
    if (h === undefined || h.status !== 'held') continue
    const prev = await ctx.read((t) => t.get('pocket', h.walletPubkey))
    if (prev?.state === 'live' && id !== call.created?.movedHoldingId) continue
    await writeEntry(ctx, await heldEntry(ctx, h))
  }
  if (call.withdrawal?.receipt !== undefined && call.state !== 'done') {
    const cur = await ctx.read((t) => t.get('pocket', call.requestId))
    if (cur?.state === 'pending') await writeEntry(ctx, await pendingEntry(ctx, call, 'pending', { receipt: call.withdrawal.receipt }))
    // The Hub owes the payout from the verified receipt on: the source is spent now, its token and any secret kept for the lookups.
    await sourcesSpent(ctx, call)
  }
  if (call.state !== 'done') return
  const pending = await ctx.read((t) => t.get('pocket', call.requestId))
  if (pending === undefined || pending.state === 'done') return
  await writeEntry(ctx, await pendingEntry(ctx, call, 'done', { scrub: true }))
  if (call.outcome === 'applied') await sourcesSpent(ctx, call)
}

/** Writes a call's sources `spent` (not a bill moved in place), once each. */
async function sourcesSpent(ctx: Ctx, call: PendingCall): Promise<void> {
  for (const id of call.sources) {
    if (id === call.created?.movedHoldingId) continue
    const h = await ctx.read((t) => t.get('holdings', id))
    if (h === undefined) continue
    if ((await ctx.read((t) => t.get('pocket', h.walletPubkey)))?.state === 'spent') continue
    await writeEntry(ctx, await heldEntry(ctx, h, 'spent'))
  }
}

pocketHooks.writeAhead = writeAhead
pocketHooks.after = afterCall

export interface PocketSyncReport {
  readonly imported: readonly string[]
  readonly published: readonly string[]
  readonly conflicts: readonly string[]
  readonly pending: readonly string[]
  /** Live entries not imported: bound to a key this wallet does not sign with (another pubkey, or a ConnectionKey). */
  readonly foreign: readonly string[]
}

/** The wrap that carried an entry, with the key that deletes it. */
interface EntryWrap {
  readonly wrapId: string
  readonly wrapKey: string
  readonly rev: number
}

async function readPocket(ctx: Ctx, since?: number): Promise<{ entries: Map<string, PocketEntry>; conflicts: string[]; seen: Set<string>; wrapOf: Map<string, EntryWrap> }> {
  const pocket = requirePocket(ctx)
  const signer = await ctx.requireSigner()
  const wraps = await pocket.fetch(signer.pubkey, since)
  const rumors: { rumor: { id: string; created_at: number }; entry: PocketEntry & { recognised: boolean } }[] = []
  const seen = new Set<string>()
  const wrapOf = new Map<string, EntryWrap>()
  for (const w of wraps) {
    seen.add(w.id)
    const r = await unwrap(w, signer)
    if (r === undefined || r.kind !== KIND_POCKET_ENTRY) continue
    try {
      const entry = parsePocketEntry(r)
      rumors.push({ rumor: r, entry })
      const cur = wrapOf.get(entry.w)
      if (/^[0-9a-f]{64}$/.test(entry.wrapKey) && (cur === undefined || entry.rev > cur.rev)) wrapOf.set(entry.w, { wrapId: w.id, wrapKey: entry.wrapKey, rev: entry.rev })
    } catch {
      // not a readable entry
    }
  }
  return { ...resolveEntries(rumors), seen, wrapOf }
}

/**
 * Syncs the pocket: imports live entries for bills this device does not
 * hold (with their secret, and the entry's rev and wrap, so the next write
 * for that bill goes above it), writes entries for held bills the pocket
 * lacks, and marks bills this device no longer holds `spent`, each at the
 * highest rev seen plus 1. A held bill the pocket shows final is re-checked
 * with `cash_status` first: still there, its entry is written `live` again;
 * spent, the bill is marked spent here; no answer, it is reported as a
 * conflict and nothing is written. Pending entries are reported, never
 * re-placed from here.
 */
export async function syncPocket(ctx: Ctx): Promise<PocketSyncReport> {
  const { entries, conflicts, wrapOf } = await readPocket(ctx)
  const local = await ctx.read((t) => t.list('holdings'))
  const imported: string[] = []
  const published: string[] = []
  const foreign: string[] = []
  const me = (await ctx.requireSigner()).pubkey
  const seenRev = (w: string) => ({ seenRev: entries.get(w)?.rev ?? 0 })
  for (const e of entries.values()) {
    if (e.state !== 'live' || e.cash === undefined) continue
    if (local.some((h) => h.walletPubkey === e.w)) continue
    // Only a cash note or a bill bound to the user's own pubkey can be spent from here.
    if (e.identity !== undefined && e.identity.type !== 'cash' && !(e.identity.type === 'pubkey' && e.identity.value === me)) {
      foreign.push(e.w)
      continue
    }
    const f = tokenFacts(e.cash)
    const secret = e.secrets?.find((s) => s.role === '')?.secret
    const sealed = secret !== undefined ? await ctx.seal(secret) : undefined
    const wrap = wrapOf.get(e.w)
    const sealedWrapKey = wrap !== undefined && wrap.rev === e.rev ? await ctx.seal(wrap.wrapKey) : undefined
    const h = await ctx.commit(async (t) => {
      if (wrap !== undefined && sealedWrapKey !== undefined) {
        const cur = await t.get('pocket', e.w)
        if (cur === undefined || cur.rev < e.rev) await t.put('pocket', { id: e.w, rev: e.rev, state: e.state, wrapId: wrap.wrapId, wrapKey: sealedWrapKey, at: ctx.now(), version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
      }
      return addHolding(
        t,
        {
          token: e.cash!,
          walletPubkey: e.w,
          hubGroup: f.hubGroup,
          relayUrls: f.tok.relays,
          amount: e.amountMillis,
          verified: false,
          ...(e.identity?.type === 'cash' ? { mode: 'cash' as const, protection: 'protected' as const, ...(sealed !== undefined && { cashSecret: sealed }) } : { mode: 'pubkey' as const, protection: 'none' as const }),
          ...(f.minterPubkey !== undefined && { minterPubkey: f.minterPubkey }),
          ...(e.expiresAt !== undefined && { expiresAt: e.expiresAt }),
          origin: 'received',
        },
        { now: ctx.now(), random: ctx.random },
      )
    })
    imported.push(h.id)
  }
  const finalElsewhere = local.filter((h) => {
    const e = entries.get(h.walletPubkey)
    return h.status === 'held' && e !== undefined && e.state !== 'live' && e.state !== 'pending'
  })
  const recheck = finalElsewhere.length > 0 ? await statusByNode(ctx, finalElsewhere) : new Map<string, NodeStatus>()
  const spentHere = finalElsewhere.filter((h) => { const r = recheck.get(h.id); return r !== undefined && 'state' in r && r.state === 'spent' })
  if (spentHere.length > 0) {
    await ctx.commit(async (t) => {
      for (const h of spentHere) {
        await updateHolding(t, h.id, (x) => ({ ...x, status: 'spent' }))
        await appendActivity(t, ctx.now(), { action: 'spent', holdingId: h.id })
      }
    })
  }
  for (const h of local) {
    const e = entries.get(h.walletPubkey)
    if (h.status === 'held') {
      if (e !== undefined && finalElsewhere.includes(h)) {
        const r = recheck.get(h.id)
        if (r === undefined || !('state' in r) || r.state !== 'available') {
          if (!spentHere.includes(h)) conflicts.push(h.walletPubkey)
          continue
        }
      }
      if (e === undefined || e.state !== 'live') {
        await writeEntry(ctx, await heldEntry(ctx, h), seenRev(h.walletPubkey))
        published.push(h.walletPubkey)
      }
    } else if (e !== undefined && e.state === 'live' && h.status !== 'redeeming') {
      await writeEntry(ctx, await heldEntry(ctx, h, 'spent'), seenRev(h.walletPubkey))
      published.push(h.walletPubkey)
    }
  }
  const pending = [...entries.values()].filter((e) => e.state === 'pending').map((e) => e.w)
  return { imported, published, conflicts, pending, foreign }
}

/** The pocket's balance per chain: the sum over live entries. */
export async function pocketBalanceOf(ctx: Ctx): Promise<Map<string, bigint>> {
  return pocketBalance((await readPocket(ctx)).entries.values())
}

/** The pocket's resolved entries, without any secret. */
export async function pocketEntries(ctx: Ctx): Promise<{ w: string; state: string; amountMillis: bigint; chain: string; pending: boolean }[]> {
  return [...(await readPocket(ctx)).entries.values()].map((e) => ({ w: e.w, state: e.state, amountMillis: e.amountMillis, chain: e.chain, pending: e.state === 'pending' }))
}

