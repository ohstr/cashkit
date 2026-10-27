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
import { addHolding } from './ledger.js'
import type { Holding, PendingCall } from './model.js'
import { pocketHooks } from './runner.js'

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))

function requirePocket(ctx: Ctx) {
  const p = ctx.deps.pocket
  if (p === undefined) throw new CashkitError('usage', 'no Cash Pocket is configured (WalletDeps.pocket)')
  return p
}

/** Writes an entry at the next `rev`: a fresh wrap key first, sealed and wrapped; stored on enough relays and read back, then the previous wrap deleted. */
export async function writeEntry(ctx: Ctx, entry: Omit<PocketEntry, 'rev' | 'wrapKey' | 'checkedAt'> & { readonly checkedAt?: number }): Promise<PocketEntry> {
  const pocket = requirePocket(ctx)
  const signer = await ctx.requireSigner()
  const prev = await ctx.read((t) => t.get('pocket', entry.w))
  const wrapKey = ctx.random(32)
  const full: PocketEntry = { ...entry, rev: (prev?.rev ?? 0) + 1, wrapKey: toHex(wrapKey), checkedAt: entry.checkedAt ?? ctx.nowSeconds() }
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

async function identityOf(ctx: Ctx, h: Holding): Promise<PocketIdentity> {
  if (h.mode === 'cash') return { type: 'cash' }
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
  await writeEntry(ctx, await pendingEntry(ctx, call, 'pending'))
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
  }
  if (call.state !== 'done') return
  const pending = await ctx.read((t) => t.get('pocket', call.requestId))
  if (pending === undefined || pending.state === 'done') return
  await writeEntry(ctx, await pendingEntry(ctx, call, 'done', { scrub: true }))
  if (call.outcome === 'applied') {
    for (const id of call.sources) {
      if (id === call.created?.movedHoldingId) continue
      const h = await ctx.read((t) => t.get('holdings', id))
      if (h !== undefined) await writeEntry(ctx, await heldEntry(ctx, h, 'spent'))
    }
  }
}

pocketHooks.writeAhead = writeAhead
pocketHooks.after = afterCall

export interface PocketSyncReport {
  readonly imported: readonly string[]
  readonly published: readonly string[]
  readonly conflicts: readonly string[]
  readonly pending: readonly string[]
}

async function readPocket(ctx: Ctx, since?: number): Promise<{ entries: Map<string, PocketEntry>; conflicts: string[]; seen: Set<string> }> {
  const pocket = requirePocket(ctx)
  const signer = await ctx.requireSigner()
  const wraps = await pocket.fetch(signer.pubkey, since)
  const rumors: { rumor: { id: string; created_at: number }; entry: PocketEntry & { recognised: boolean } }[] = []
  const seen = new Set<string>()
  for (const w of wraps) {
    seen.add(w.id)
    const r = await unwrap(w, signer)
    if (r === undefined || r.kind !== KIND_POCKET_ENTRY) continue
    try {
      rumors.push({ rumor: r, entry: parsePocketEntry(r) })
    } catch {
      // not a readable entry
    }
  }
  return { ...resolveEntries(rumors), seen }
}

/**
 * Syncs the pocket: imports live entries for bills this device does not
 * hold (with their secret), writes entries for held bills the pocket lacks
 * or still shows otherwise, and marks bills this device no longer holds
 * `spent`. Pending entries are reported, never re-placed from here.
 */
export async function syncPocket(ctx: Ctx): Promise<PocketSyncReport> {
  const { entries, conflicts } = await readPocket(ctx)
  const local = await ctx.read((t) => t.list('holdings'))
  const imported: string[] = []
  const published: string[] = []
  for (const e of entries.values()) {
    if (e.state !== 'live' || e.cash === undefined) continue
    if (local.some((h) => h.walletPubkey === e.w)) continue
    const f = tokenFacts(e.cash)
    const secret = e.secrets?.find((s) => s.role === '')?.secret
    const sealed = secret !== undefined ? await ctx.seal(secret) : undefined
    const h = await ctx.commit((t) =>
      addHolding(
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
      ),
    )
    imported.push(h.id)
  }
  for (const h of local) {
    const e = entries.get(h.walletPubkey)
    if (h.status === 'held') {
      if (e === undefined || e.state !== 'live') {
        await writeEntry(ctx, await heldEntry(ctx, h))
        published.push(h.walletPubkey)
      }
    } else if (e !== undefined && e.state === 'live' && h.status !== 'redeeming') {
      await writeEntry(ctx, await heldEntry(ctx, h, 'spent'))
      published.push(h.walletPubkey)
    }
  }
  const pending = [...entries.values()].filter((e) => e.state === 'pending').map((e) => e.w)
  return { imported, published, conflicts, pending }
}

/** The pocket's balance per chain: the sum over live entries. */
export async function pocketBalanceOf(ctx: Ctx): Promise<Map<string, bigint>> {
  return pocketBalance((await readPocket(ctx)).entries.values())
}

/** The pocket's resolved entries, without any secret. */
export async function pocketEntries(ctx: Ctx): Promise<{ w: string; state: string; amountMillis: bigint; chain: string; pending: boolean }[]> {
  return [...(await readPocket(ctx)).entries.values()].map((e) => ({ w: e.w, state: e.state, amountMillis: e.amountMillis, chain: e.chain, pending: e.state === 'pending' }))
}

