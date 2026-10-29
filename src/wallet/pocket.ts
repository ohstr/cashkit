// The Cash Pocket engine (NIP-CP §Writing, §Reading, §Balance), used when
// `WalletDeps.pocket` is set. Before a bill-creating call or a withdrawal
// goes out, its pending entry is stored and read back (failing that, the
// call is not sent). Once the outcome is saved, an entry is written for
// each bill this wallet keeps, then the pending entry is closed `done` with
// its sources `spent`; an order or a withdrawal stays pending until it is
// finished. A sync imports live entries this device does not hold,
// republishes what the relays no longer return, fills a missing
// `expires_at` from `cash_status`, and removes final entries after 30 days.
// Before a call is placed again under its derived id, the pocket is read:
// the old entry must still be open, and no entry may carry the derived id.
import {
  chainForHrp,
  createRumor,
  createSeal,
  createWrap,
  decodeToken,
  checkPendingEntry,
  derivedRequestId,
  FINAL_STATES,
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
  wrapExpiration,
  type PocketEntry,
  type PocketIdentity,
} from '../core/index.js'
import { tokenFacts, type Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { goneStatus, endHolding, pocketStateOf } from './billState.js'
import { addHolding } from './ledger.js'
import type { Holding, PendingCall } from './model.js'
import { pocketHooks } from './runner.js'
import { status, statusByNode, type NodeStatus } from './status.js'

/** A wrap the pocket holds for a `w`, with the key that deletes it. */
interface StoredWrap {
  readonly wrapId: string
  readonly wrapKey: string
}

/** How long a final entry is kept before its wraps are deleted (NIP-CP §Writing, Remove). */
export const POCKET_FINAL_KEEP_SECONDS = 30 * 86400

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))

function requirePocket(ctx: Ctx) {
  const p = ctx.deps.pocket
  if (p === undefined) throw new CashkitError('usage', 'no Cash Pocket is configured (WalletDeps.pocket)')
  return p
}

/**
 * Writes an entry at the next `rev` (above this device's and any `seenRev`
 * read from the pocket): a fresh wrap key first, sealed and wrapped (with a
 * NIP-40 `expiration` when `settings.pocketNip40` is on and the entry has an
 * `expires_at`); stored on enough relays and read back, then the previous
 * wrap and any `replaces` deleted.
 */
export async function writeEntry(
  ctx: Ctx,
  entry: Omit<PocketEntry, 'rev' | 'wrapKey' | 'checkedAt'> & { readonly checkedAt?: number },
  o: { readonly seenRev?: number; readonly replaces?: readonly StoredWrap[] } = {},
): Promise<PocketEntry> {
  const pocket = requirePocket(ctx)
  const signer = await ctx.requireSigner()
  const prev = await ctx.read((t) => t.get('pocket', entry.w))
  const wrapKey = ctx.random(32)
  const full: PocketEntry = { ...entry, rev: Math.max(prev?.rev ?? 0, o.seenRev ?? 0) + 1, wrapKey: toHex(wrapKey), checkedAt: entry.checkedAt ?? ctx.nowSeconds() }
  const now = ctx.nowSeconds()
  const nip40 = full.expiresAt !== undefined && (await ctx.settings()).pocketNip40
  const rumor = createRumor({ kind: KIND_POCKET_ENTRY, pubkey: signer.pubkey, created_at: now, tags: pocketEntryTags(full), content: '' })
  const seal = await createSeal(rumor, signer, { now, random: ctx.random })
  const wrap = createWrap(seal, wrapKey, signer.pubkey, { now, random: ctx.random, ...(nip40 && { expiration: wrapExpiration(full.expiresAt!, { random: ctx.random }) }) })
  const stored = await pocket.publish(wrap)
  const need = Math.max(1, pocket.minRelays ?? 2)
  if (stored.length < need || !(await pocket.has(wrap.id))) throw new CashkitError('network', 'the Cash Pocket entry could not be stored on enough relays; nothing was sent', { reason: 'pocket_unavailable' })
  const sealedKey = await ctx.seal(toHex(wrapKey))
  await ctx.commit(async (t) => {
    const cur = await t.get('pocket', entry.w)
    await t.put('pocket', { id: entry.w, rev: full.rev, state: full.state, wrapId: wrap.id, wrapKey: sealedKey, at: ctx.now(), ...(cur?.noExpiry === true && { noExpiry: true }), version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
  })
  const old: StoredWrap[] = [...(prev !== undefined ? [{ wrapId: prev.wrapId, wrapKey: await ctx.open(prev.wrapKey) }] : []), ...(o.replaces ?? [])]
  await deleteWraps(ctx, old.filter((x) => x.wrapId !== wrap.id))
  return full
}

/** Deletes wraps, each with a kind 5 signed by its own wrap key at a randomized time. */
async function deleteWraps(ctx: Ctx, wraps: readonly StoredWrap[]): Promise<void> {
  const pocket = requirePocket(ctx)
  const done = new Set<string>()
  for (const w of wraps) {
    if (done.has(w.wrapId) || !/^[0-9a-f]{64}$/.test(w.wrapKey)) continue
    done.add(w.wrapId)
    await pocket.remove(wrapDeletion(w.wrapId, hexBytes(w.wrapKey), { now: ctx.nowSeconds(), random: ctx.random })).catch(() => undefined)
  }
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
  if (h.mode === 'connection_key' && h.connectionKey !== undefined) return { type: 'connection_key', value: h.connectionKey.key ?? connectionKeyFromAttested(h.connectionKey.platform, h.connectionKey.externalId), ia: h.connectionKey.iaPubkey }
  return { type: 'pubkey', value: (await ctx.requireSigner()).pubkey }
}

/**
 * How an imported bill is held: a cash bill with its secret; a
 * connection-key bill bound to its key and IA, without the attestation
 * (receiving the bill again with it makes it spendable); else the identity.
 */
function modeOfEntry(id: PocketIdentity | undefined, sealed: Holding['cashSecret']) {
  if (id?.type === 'cash') return { mode: 'cash' as const, protection: 'protected' as const, ...(sealed !== undefined && { cashSecret: sealed }) }
  if (id?.type === 'connection_key') return { mode: 'connection_key' as const, protection: 'none' as const, connectionKey: { platform: '', externalId: '', attestationId: '', iaPubkey: id.ia, key: id.value } }
  return { mode: 'pubkey' as const, protection: 'none' as const }
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

/** Writes a call's sources `spent`, the wallet's own spend (not a bill moved in place), once each. */
async function sourcesSpent(ctx: Ctx, call: PendingCall): Promise<void> {
  const state = goneStatus({ result: 'own_spend' })!
  for (const id of call.sources) {
    if (id === call.created?.movedHoldingId) continue
    const h = await ctx.read((t) => t.get('holdings', id))
    if (h === undefined) continue
    if ((await ctx.read((t) => t.get('pocket', h.walletPubkey)))?.state === state) continue
    await writeEntry(ctx, await heldEntry(ctx, h, state))
  }
}

pocketHooks.writeAhead = writeAhead
pocketHooks.after = afterCall

export interface PocketSyncReport {
  readonly imported: readonly string[]
  readonly published: readonly string[]
  readonly conflicts: readonly string[]
  readonly pending: readonly string[]
  /** Final entries older than 30 days whose wraps were deleted. */
  readonly pruned: readonly string[]
  /** Entries rewritten with the `expires_at` `cash_status` reported. */
  readonly expiryFilled: readonly string[]
  /** Live entries not imported: bound to a pubkey this wallet does not sign with. */
  readonly foreign: readonly string[]
}

/** The wrap that carried an entry, with the key that deletes it. */
interface EntryWrap {
  readonly wrapId: string
  readonly wrapKey: string
  readonly rev: number
}

interface PocketRead {
  readonly entries: Map<string, PocketEntry>
  readonly conflicts: string[]
  readonly seen: Set<string>
  /** Every wrap read for each `w`, the stale ones included. */
  readonly wraps: Map<string, StoredWrap[]>
  /** Every `w` named by an entry of the user's, whatever its state, read or not. */
  readonly ws: Set<string>
  /** The wrap of each `w`'s newest readable entry, with its rev. */
  readonly wrapOf: Map<string, EntryWrap>
}

async function readPocket(ctx: Ctx, since?: number): Promise<PocketRead> {
  const pocket = requirePocket(ctx)
  const signer = await ctx.requireSigner()
  const fetched = await pocket.fetch(signer.pubkey, since)
  const rumors: { rumor: { id: string; created_at: number }; entry: PocketEntry & { recognised: boolean } }[] = []
  const seen = new Set<string>()
  const wraps = new Map<string, StoredWrap[]>()
  const ws = new Set<string>()
  const wrapOf = new Map<string, EntryWrap>()
  for (const w of fetched) {
    if (seen.has(w.id)) continue
    seen.add(w.id)
    const r = await unwrap(w, signer)
    if (r === undefined || r.kind !== KIND_POCKET_ENTRY) continue
    for (const t of r.tags) if (t[0] === 'w' && t[1] !== undefined) ws.add(t[1])
    let entry
    try {
      entry = parsePocketEntry(r)
    } catch {
      continue // not a readable entry; its `w` still counts for the derived-id check
    }
    rumors.push({ rumor: r, entry })
    if (entry.wrapKey !== '') wraps.set(entry.w, [...(wraps.get(entry.w) ?? []), { wrapId: w.id, wrapKey: entry.wrapKey }])
    const cur = wrapOf.get(entry.w)
    if (/^[0-9a-f]{64}$/.test(entry.wrapKey) && (cur === undefined || entry.rev > cur.rev)) wrapOf.set(entry.w, { wrapId: w.id, wrapKey: entry.wrapKey, rev: entry.rev })
  }
  return { ...resolveEntries(rumors), seen, wraps, ws, wrapOf }
}

/**
 * Before a call is placed again under its derived id (NIP-CP §Writing,
 * Placing it again): the pocket is read, the old entry must still be
 * `pending`, and no entry, in any state and recognised or not, may carry
 * the derived id. `derived`: one does, so the call is only closed;
 * `closed`: the old entry is final, so it is not placed again. A pocket
 * that cannot confirm the entry is open stops the re-placement.
 */
async function beforeReplace(ctx: Ctx, call: PendingCall): Promise<'place' | 'derived' | 'closed'> {
  const { entries, ws } = await readPocket(ctx)
  if (ws.has(derivedRequestId(call.requestId))) return 'derived'
  const old = entries.get(call.requestId)
  if (old === undefined) throw new CashkitError('network', 'the Cash Pocket did not show this call’s entry, so it was not placed again', { reason: 'pocket_unavailable', pendingCallId: call.id })
  if (old.state === 'pending') return 'place'
  // Closed elsewhere: record the pocket's state so closing the call here writes nothing over it.
  await ctx.commit(async (t) => {
    const cur = await t.get('pocket', call.requestId)
    if (cur !== undefined) await t.put('pocket', { ...cur, rev: Math.max(cur.rev, old.rev), state: old.state, version: cur.version + 1 }, cur.version)
  })
  return 'closed'
}

pocketHooks.beforeReplace = beforeReplace

/**
 * A call another device closed (its entry final): that device may have
 * applied it, so each still-held source the Hub reports gone ends by the
 * result to state table; one still there stays held; no answer writes nothing.
 */
async function closedElsewhere(ctx: Ctx, call: PendingCall): Promise<void> {
  const held = (await ctx.read((t) => Promise.all(call.sources.map((id) => t.get('holdings', id))))).filter((h): h is Holding => h?.status === 'held')
  if (held.length === 0) return
  const st = await statusByNode(ctx, held)
  await ctx.commit(async (t) => {
    for (const h of held) {
      const s = st.get(h.id)
      if (s !== undefined && 'state' in s && s.state === 'spent') await endHolding(t, ctx.now(), h.id, s.ends)
    }
  })
}

pocketHooks.closedElsewhere = closedElsewhere

const isFinalState = (s: string) => (FINAL_STATES as readonly string[]).includes(s)

/**
 * Whether a final entry is kept past 30 days: the `done` entry of a closed
 * on-chain order (how another device reads late payments), a withdrawal's
 * `done` entry not yet rewritten without its address, quote and receipt,
 * any `done` entry with a `notify` this device cannot place, and the source
 * of a call still open: a local call's sources, and the `target` of every
 * pending entry, whichever device placed it.
 */
function keptPastPrune(e: PocketEntry, calls: readonly PendingCall[], openSources: ReadonlySet<string>): boolean {
  if (openSources.has(e.w)) return true
  if (e.state !== 'done') return false
  const call = calls.find((c) => c.requestId === e.w)
  if (e.address !== undefined || e.quote !== undefined || e.receipt !== undefined) return true
  if (e.orderKey === undefined && e.notify === undefined) return false
  if (call === undefined) return true
  if (call.method === 'cash_order') return call.order?.payment === 'onchain' && call.order.state === 'closed'
  return false
}

/**
 * Syncs the pocket: imports live entries for bills this device does not
 * hold (with their secret, and the entry's rev and wrap, so the next write
 * for that bill goes above it), writes entries for held bills the pocket
 * lacks, marks bills this device no longer holds `spent`, each at the highest
 * rev seen plus 1, fills a missing `expires_at` from `cash_status`, and
 * deletes the wraps of final entries older than 30 days. A held bill the pocket shows final is re-checked
 * with `cash_status` first: still there, its entry is written `live` again;
 * spent, the bill is marked spent here; no answer, it is reported as a
 * conflict and nothing is written. Pending entries are reported, never
 * re-placed from here.
 */
export async function syncPocket(ctx: Ctx): Promise<PocketSyncReport> {
  const { entries, conflicts, wraps, wrapOf } = await readPocket(ctx)
  const local = await ctx.read((t) => t.list('holdings'))
  const imported: string[] = []
  const published: string[] = []
  const foreign: string[] = []
  const me = (await ctx.requireSigner()).pubkey
  const at = (w: string) => ({ seenRev: entries.get(w)?.rev ?? 0, replaces: wraps.get(w) ?? [] })
  for (const e of entries.values()) {
    if (e.state !== 'live' || e.cash === undefined) continue
    if (local.some((h) => h.walletPubkey === e.w)) continue
    // A bill bound to another pubkey (a merge key this device never held) cannot be spent from here.
    if (e.identity?.type === 'pubkey' && e.identity.value !== me) {
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
          ...modeOfEntry(e.identity, sealed),
          ...(f.minterPubkey !== undefined && { minterPubkey: f.minterPubkey }),
          ...(e.expiresAt !== undefined && { expiresAt: e.expiresAt }),
          origin: 'received',
        },
        { now: ctx.now(), random: ctx.random },
      )
    })
    imported.push(h.id)
  }
  // A bill held here whose entry another device rewrote above our record: remember that rev and wrap, so this
  // device's next write for it (a spend, from afterCall) goes above it and deletes it (NIP-CP §Writing).
  for (const h of local) {
    const e = entries.get(h.walletPubkey)
    const wrap = e === undefined ? undefined : wrapOf.get(e.w)
    if (e === undefined || wrap === undefined || wrap.rev !== e.rev) continue
    const cur = await ctx.read((t) => t.get('pocket', e.w))
    if (cur !== undefined && cur.rev >= e.rev) continue
    const sealedWrapKey = await ctx.seal(wrap.wrapKey)
    await ctx.commit(async (t) => {
      const now = await t.get('pocket', e.w)
      if (now !== undefined && now.rev >= e.rev) return
      await t.put('pocket', { id: e.w, rev: e.rev, state: e.state, wrapId: wrap.wrapId, wrapKey: sealedWrapKey, at: ctx.now(), ...(now?.noExpiry === true && { noExpiry: true }), version: (now?.version ?? 0) + 1 }, now?.version ?? 0)
    })
  }
  const finalElsewhere = local.filter((h) => {
    const e = entries.get(h.walletPubkey)
    return h.status === 'held' && e !== undefined && e.state !== 'live' && e.state !== 'pending'
  })
  // Another device's final state is rechecked and read with the same table (NIP-CP §Balance): a definitive
  // answer that the bill is gone is adopted here; the Hub showing it available is written live, and against a
  // final entry also reported as a conflict; no answer (or an unreadable status) writes nothing.
  const recheck = finalElsewhere.length > 0 ? await statusByNode(ctx, finalElsewhere) : new Map<string, NodeStatus>()
  const goneHere = finalElsewhere.flatMap((h) => {
    const r = recheck.get(h.id)
    return r !== undefined && 'state' in r && r.state === 'spent' ? [{ id: h.id, ends: r.ends }] : []
  })
  if (goneHere.length > 0) await ctx.commit(async (t) => { for (const g of goneHere) await endHolding(t, ctx.now(), g.id, g.ends) })
  for (const h of local) {
    const e = entries.get(h.walletPubkey)
    if (h.status === 'held') {
      if (e !== undefined && finalElsewhere.includes(h)) {
        const r = recheck.get(h.id)
        const available = r !== undefined && 'state' in r && r.state === 'available'
        if (available && isFinalState(e.state)) conflicts.push(h.walletPubkey)
        // An `unknown` entry the recheck answers definitively gets that final state.
        if (r !== undefined && 'state' in r && r.state === 'spent' && !isFinalState(e.state)) {
          await writeEntry(ctx, await heldEntry(ctx, h, r.ends), at(h.walletPubkey))
          published.push(h.walletPubkey)
        }
        if (!available) continue
      }
      if (e === undefined || e.state !== 'live') {
        await writeEntry(ctx, await heldEntry(ctx, h), at(h.walletPubkey))
        published.push(h.walletPubkey)
      }
    } else if (e !== undefined && e.state === 'live' && h.status !== 'redeeming' && !(h.status === 'redeemed' && h.redeem?.presumedAt !== undefined)) {
      // A redeem still in flight, or only presumed paid (a timeout), writes no final state (NIP-CP §Balance).
      await writeEntry(ctx, await heldEntry(ctx, h, pocketStateOf(h)), at(h.walletPubkey))
      published.push(h.walletPubkey)
    }
  }
  const expiryFilled = await fillExpiry(ctx, entries, wraps, new Set(published))
  const pruned = await prune(ctx, entries, wraps)
  const pending = [...entries.values()].filter((e) => e.state === 'pending').map((e) => e.w)
  return { imported, published, conflicts, pending, pruned, expiryFilled, foreign }
}

/**
 * NIP-CP §Reading, Older entries: a live entry of a held bill without
 * `expires_at` is rewritten with the expiry `cash_status` reports. A bill
 * whose status shows no expiry is remembered and not asked again.
 */
async function fillExpiry(ctx: Ctx, entries: ReadonlyMap<string, PocketEntry>, wraps: ReadonlyMap<string, StoredWrap[]>, written: ReadonlySet<string>): Promise<string[]> {
  const held = (await ctx.read((t) => t.list('holdings'))).filter((h) => h.status === 'held' && !written.has(h.walletPubkey))
  const missing = held.filter((h) => entries.get(h.walletPubkey)?.state === 'live' && entries.get(h.walletPubkey)?.expiresAt === undefined)
  const ask: Holding[] = []
  for (const h of missing) {
    if (h.expiresAt !== undefined) continue
    const row = await ctx.read((t) => t.get('pocket', h.walletPubkey))
    if (row?.noExpiry !== true) ask.push(h)
  }
  const shown = new Set<string>()
  if (ask.length > 0) {
    const r = await status(ctx, { holdings: ask.map((h) => h.id) }).catch(() => undefined)
    for (const o of r?.outcomes ?? []) if (o.ok && o.state === 'available') shown.add(o.holdingId)
  }
  const filled: string[] = []
  for (const before of missing) {
    const h = await ctx.read((t) => t.get('holdings', before.id))
    if (h === undefined || h.status !== 'held') continue
    if (h.expiresAt !== undefined) {
      const e = entries.get(h.walletPubkey)!
      await writeEntry(ctx, await heldEntry(ctx, h), { seenRev: e.rev, replaces: wraps.get(h.walletPubkey) ?? [] })
      filled.push(h.walletPubkey)
    } else if (shown.has(h.id)) {
      await ctx.commit(async (t) => {
        const cur = await t.get('pocket', h.walletPubkey)
        if (cur !== undefined) await t.put('pocket', { ...cur, noExpiry: true, version: cur.version + 1 }, cur.version)
      })
    }
  }
  return filled
}

/** Deletes the wraps of final entries checked more than 30 days ago (NIP-CP §Writing, Remove), with the exceptions of `keptPastPrune`; never a bill a pending entry names. */
async function prune(ctx: Ctx, entries: ReadonlyMap<string, PocketEntry>, wraps: ReadonlyMap<string, StoredWrap[]>): Promise<string[]> {
  const now = ctx.nowSeconds()
  const calls = await ctx.read((t) => t.list('pendingCalls'))
  const open = calls.filter((c) => c.state !== 'done')
  const openSources = new Set<string>()
  for (const c of open) {
    for (const id of c.sources) {
      const h = await ctx.read((t) => t.get('holdings', id))
      if (h !== undefined) openSources.add(h.walletPubkey)
    }
  }
  // A call another device placed (and may have lost its own store for) still needs its source's secret.
  for (const e of entries.values()) if (e.state === 'pending' && e.target !== undefined) openSources.add(e.target)
  const pruned: string[] = []
  for (const e of entries.values()) {
    if (!isFinalState(e.state) || now - e.checkedAt <= POCKET_FINAL_KEEP_SECONDS) continue
    if (keptPastPrune(e, calls, openSources)) continue
    await deleteWraps(ctx, wraps.get(e.w) ?? [])
    await ctx.commit(async (t) => {
      if ((await t.get('pocket', e.w)) !== undefined) await t.delete('pocket', e.w)
    })
    pruned.push(e.w)
  }
  return pruned
}

/** The pocket's balance per chain: the sum over live entries. */
export async function pocketBalanceOf(ctx: Ctx): Promise<Map<string, bigint>> {
  return pocketBalance((await readPocket(ctx)).entries.values())
}

/** The pocket's resolved entries, without any secret. */
export async function pocketEntries(ctx: Ctx): Promise<{ w: string; state: string; amountMillis: bigint; chain: string; pending: boolean }[]> {
  return [...(await readPocket(ctx)).entries.values()].map((e) => ({ w: e.w, state: e.state, amountMillis: e.amountMillis, chain: e.chain, pending: e.state === 'pending' }))
}

