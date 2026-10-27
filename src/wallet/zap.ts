// Cash Zaps (NIP-CZ). Sending is a zap transfer (`zap_target` for a pubkey
// recipient on an event) of a pubkey bill, chosen by the recipient's 10522;
// once the bill exists (from the reply or a lookup after a lost reply) its
// 9522 is built, stored with the call and published once. Receiving lists
// incoming 9522s through rules 1–8; claiming checks rule 9 with the bill's
// own status and keeps the bill with its zap fields.
import {
  bySigning,
  cashZapTags,
  chainForHrp,
  decodeToken,
  incomingZapFilter,
  KIND_CASH_ZAP,
  KIND_CASH_ZAP_INFO,
  ownClaim,
  parseCashZapInfo,
  verifyCashZap,
  zapFieldsFromEvent,
  type CashZapInfo,
  type NostrEvent,
  type Target,
} from '../core/index.js'
import { CashClient, readEvents } from '../client/index.js'
import { lockedHoldings } from './bills.js'
import { tokenFacts, type Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { addHolding, appendActivity, heldHoldings } from './ledger.js'
import { runTransfer, setZapPublisher } from './kinds.js'
import type { Holding, PendingCall } from './model.js'
import { parseTarget } from './target.js'

const READ_MS = 2500

export interface ZapInput {
  /** A pubkey, npub or NIP-05 name; or a ConnectionKey taken from the recipient's 35522 or nconnection, with its platform and IA. */
  readonly to: string | { readonly connectionKey: string; readonly platform: string; readonly ia: string }
  readonly amountMillis: bigint
  /** The zapped event: its `a` coordinate (the bill is signed over it), else its `e` id; `k` its kind. None: a profile zap, never counted. */
  readonly target?: { readonly e?: string; readonly a?: string; readonly k?: string }
  readonly content?: string
  /** The sender's relays: read for the recipient's 10522, and written to. */
  readonly relays: readonly string[]
}

export interface ZapSent {
  readonly eventId?: string
  /** False when the Hub ignored `zap_target` (no zap signature) or the zap names no event: valid, never counted. */
  readonly countable: boolean
  readonly reason?: 'no_zap_signature' | 'no_target' | 'connection_key'
  readonly relays: readonly string[]
}

async function latestInfo(ctx: Ctx, pubkey: string, relays: readonly string[]): Promise<CashZapInfo | undefined> {
  const evs = await readEvents(ctx.deps.relays, relays, { kinds: [KIND_CASH_ZAP_INFO], authors: [pubkey] }, READ_MS).catch(() => [])
  const latest = evs.filter((e) => e.pubkey === pubkey).reduce<NostrEvent | undefined>((m, e) => (m === undefined || e.created_at > m.created_at ? e : m), undefined)
  if (latest === undefined) return undefined
  try {
    return parseCashZapInfo(latest)
  } catch {
    return undefined
  }
}

const life = (h: Holding) => h.expiresAt ?? Number.MAX_SAFE_INTEGER
const xonly = (k: string | undefined) => (k !== undefined && k.length === 66 ? k.slice(2) : k)

/** The bill to zap from: a pubkey bill on an accepted chain covering the amount; a listed minter first, then the longest life. */
function pickBill(held: readonly Holding[], amount: bigint, info: CashZapInfo | undefined): Holding | undefined {
  const ok = held.filter((h) => h.mode === 'pubkey' && h.throwawayKey === undefined && h.amount !== undefined && h.amount >= amount && (info === undefined || info.chains.length === 0 || info.chains.includes(chainForHrp(decodeToken(h.token).hrp) ?? '')))
  const listed = (h: Holding) => (info?.mints ?? []).some((m) => xonly(m.minter) === xonly(h.minterPubkey))
  const better = (a: Holding, b: Holding) => Number(listed(b)) - Number(listed(a)) || life(b) - life(a)
  return ok.reduce<Holding | undefined>((m, h) => (m === undefined || better(h, m) < 0 ? h : m), undefined)
}

export async function sendZap(ctx: Ctx, o: ZapInput): Promise<ZapSent> {
  if (o.amountMillis <= 0n) throw new CashkitError('invalid_input', 'a zap is for a positive amount')
  const signer = await ctx.requireSigner()
  let to: Target
  let p: { value: string; platform?: string }
  let ia: string | undefined
  let info: CashZapInfo | undefined
  if (typeof o.to === 'string') {
    const rt = await parseTarget(o.to, { ...(ctx.deps.fetch !== undefined && { fetch: ctx.deps.fetch }), random: ctx.random })
    if (rt.kind !== 'pubkey') throw new CashkitError('usage', 'zap a pubkey, or a ConnectionKey with its platform and IA')
    to = rt.target
    p = { value: rt.target.identityValue }
    info = await latestInfo(ctx, p.value, o.relays)
  } else {
    to = { identityType: 'connection_key', identityValue: o.to.connectionKey, iaPubkey: o.to.ia }
    p = { value: o.to.connectionKey, platform: o.to.platform }
    ia = o.to.ia
  }
  const locked = await lockedHoldings(ctx)
  const held = (await ctx.read(heldHoldings)).filter((h) => !locked.has(h.id))
  const h = pickBill(held, o.amountMillis, info)
  if (h === undefined) throw new CashkitError('invalid_input', 'no pubkey bill on a chain the recipient accepts covers this amount', { reason: 'no_zap_bill' })
  const zapTarget = to.identityType === 'pubkey' ? (o.target?.a ?? o.target?.e) : undefined
  const relays = [...new Set([...(info?.relays.length ? info.relays : []), ...o.relays])]
  await runTransfer(ctx, {
    op: 'zap',
    source: h,
    to,
    destination: to.identityType === 'pubkey' ? { kind: 'pubkey', pubkey: to.identityValue } : { kind: 'connection_key', key: to.identityValue, platform: p.platform ?? '', ia: ia ?? '' },
    keep: 'handoff',
    amount: o.amountMillis,
    ...(o.amountMillis < h.amount! && { split: o.amountMillis }),
    ...(zapTarget !== undefined && { zapTarget }),
    display: p.platform !== undefined ? `${p.platform} connection` : signer.pubkey === p.value ? 'self' : p.value,
    zap: JSON.stringify({ p: p.value, ...(p.platform !== undefined && { platform: p.platform }), ...(ia !== undefined && { ia }), ...(o.target?.e !== undefined && zapTarget !== o.target.a && { e: o.target.e }), ...(o.target?.a !== undefined && { a: o.target.a }), ...(o.target?.k !== undefined && { k: o.target.k }), content: o.content ?? '', relays }),
  })
  const call = (await ctx.read((t) => t.list('pendingCalls'))).filter((c) => c.kind === 'transfer' && c.params?.['zap'] !== undefined && c.sources[0] === h.id).reduce<PendingCall | undefined>((m, c) => (m === undefined || c.createdAt > m.createdAt ? c : m), undefined)
  const ev = call?.zapEvent !== undefined ? (JSON.parse(call.zapEvent) as NostrEvent) : undefined
  const countable = ev !== undefined && call?.created?.zap !== undefined && zapTarget !== undefined
  return {
    ...(ev !== undefined && { eventId: ev.id }),
    countable,
    ...(!countable && { reason: to.identityType !== 'pubkey' ? ('connection_key' as const) : zapTarget === undefined ? ('no_target' as const) : ('no_zap_signature' as const) }),
    relays,
  }
}

/** Builds and stores a zap's 9522 once, from its call's bill and context, then publishes it; a relay's acceptance is recorded. */
async function publishZap(ctx: Ctx, callId: string): Promise<void> {
  const call = await ctx.read((t) => t.get('pendingCalls', callId))
  const raw = call?.params?.['zap']
  if (call === undefined || raw === undefined) return
  const z = JSON.parse(raw) as { p: string; platform?: string; ia?: string; e?: string; a?: string; k?: string; content: string; relays: string[] }
  let ev: NostrEvent
  if (call.zapEvent !== undefined) ev = JSON.parse(call.zapEvent) as NostrEvent
  else {
    const hid = call.created?.handoffId
    const ho = hid !== undefined ? await ctx.read((t) => t.get('handoffs', hid)) : undefined
    if (ho === undefined) return
    const token = await ctx.open(ho.handoff)
    const tok = decodeToken(token)
    const signed = call.created?.zap
    const tags = cashZapTags({
      recipient: { value: z.p, ...(z.platform !== undefined && { platform: z.platform }) },
      amountMillis: call.amount,
      chain: chainForHrp(tok.hrp) ?? '',
      token,
      walletPubkey: tok.walletPubkey,
      ...(z.ia !== undefined && { ia: z.ia }),
      // An `a` tag only when the bill was signed over it; never `a` after signing over `e`.
      ...(z.e !== undefined && { e: z.e }),
      ...(z.a !== undefined && { a: z.a }),
      ...(z.k !== undefined && { k: z.k }),
      ...(signed !== undefined && { issuedAt: signed.issuedAt, expiresAt: signed.expiresAt }),
    })
    const signer = await ctx.requireSigner()
    ev = await signer.signEvent({ kind: KIND_CASH_ZAP, created_at: ctx.nowSeconds(), tags, content: z.content })
    await ctx.commit(async (t) => {
      const cur = (await t.get('pendingCalls', callId))!
      if (cur.zapEvent === undefined) await t.put('pendingCalls', { ...cur, zapEvent: JSON.stringify(ev), version: cur.version + 1 }, cur.version)
    })
  }
  const acks = await Promise.all(z.relays.map((r) => ctx.deps.relays.publish(r, ev).catch(() => undefined)))
  if (!acks.some((a) => a?.ok === true)) return
  await ctx.commit(async (t) => {
    const cur = await t.get('pendingCalls', callId)
    if (cur !== undefined && cur.zapPublished !== true) await t.put('pendingCalls', { ...cur, zapPublished: true, version: cur.version + 1 }, cur.version)
  })
}

/**
 * Publishes again every applied zap whose 9522 no relay has accepted yet
 * (signing failed, or every relay refused or was down): the 9522 is the
 * recipient's only notice of the zap. Returns how many were tried.
 */
export async function republishZaps(ctx: Ctx): Promise<number> {
  const due = (await ctx.read((t) => t.list('pendingCalls'))).filter((c) => c.kind === 'transfer' && c.state === 'done' && c.outcome === 'applied' && c.params?.['zap'] !== undefined && c.zapPublished !== true)
  for (const c of due) await publishZap(ctx, c.id).catch(() => undefined)
  return due.length
}

setZapPublisher(publishZap)

export interface ZapView {
  readonly id: string
  readonly from: string
  readonly amountMillis: bigint
  readonly chain?: string
  readonly minter?: string
  /** Rules 1–6 hold: shown. */
  readonly valid: boolean
  /** The minter is trusted by this wallet or listed in the user's 10522. */
  readonly trusted: boolean
  readonly countable: boolean
  /** "Issued", never "received" before rule 9. */
  readonly status: 'issued' | 'claimed' | 'invalid'
  readonly ia?: string
  readonly issuedAt?: number
  readonly expiresAt?: number
  readonly possiblyExpired: boolean
  readonly target?: string
}

/** Incoming 9522s for this user, each through rules 1–8. Nothing is claimed. */
export async function listZaps(ctx: Ctx, o: { relays: readonly string[]; connectionKeys?: readonly string[] }): Promise<ZapView[]> {
  const me = (await ctx.requireSigner()).pubkey
  const mine = await latestInfo(ctx, me, o.relays)
  const relays = [...new Set([...(mine?.relays ?? []), ...o.relays])]
  const evs = await readEvents(ctx.deps.relays, relays, incomingZapFilter([me, ...(o.connectionKeys ?? [])]), READ_MS).catch(() => [])
  const trusted = (await ctx.settings()).trustedMinters
  const held = await ctx.read((t) => t.list('holdings'))
  const now = ctx.nowSeconds()
  const seen = new Set<string>()
  const out: ZapView[] = []
  for (const ev of evs) {
    if (seen.has(ev.id)) continue
    seen.add(ev.id)
    const v = verifyCashZap(ev, { ...(mine !== undefined && { zapInfo: mine }), trusted })
    const t = v.tags
    const claimed = t !== undefined && held.some((h) => h.walletPubkey === t.w)
    out.push({
      id: ev.id,
      from: ev.pubkey,
      amountMillis: t?.amountMillis ?? 0n,
      ...(t?.chain !== undefined && { chain: t.chain }),
      ...(v.minter !== undefined && { minter: v.minter }),
      valid: v.valid,
      trusted: v.rules[8] === true,
      countable: v.countable,
      status: !v.valid ? 'invalid' : claimed ? 'claimed' : 'issued',
      ...(t?.ia !== undefined && { ia: t.ia }),
      ...(t?.issuedAt !== undefined && { issuedAt: t.issuedAt }),
      ...(t?.expiresAt !== undefined && { expiresAt: t.expiresAt }),
      possiblyExpired: t?.expiresAt !== undefined && t.expiresAt !== 0 && t.expiresAt < now,
      ...((t?.a ?? t?.e) !== undefined && { target: (t?.a ?? t?.e)! }),
    })
  }
  return out
}

/** Approves a minter for one chain. Its network cannot be verified from the token: the app should say so. */
export async function approveMinter(ctx: Ctx, minter: string, chain: string): Promise<{ readonly networkUnverifiable: true }> {
  if (!/^0[23][0-9a-f]{64}$/.test(minter)) throw new CashkitError('invalid_input', 'a minter is a 33-byte compressed key, 66 lowercase hex')
  await ctx.commit(async (t) => {
    const cur = await t.get('settings', 'settings')
    const list = cur?.trustedMinters ?? []
    if (list.some((m) => m.minter === minter && m.chain === chain)) return
    const next = { id: 'settings', autoProtect: true, allowAutoConsolidate: true, zapMinLifeSeconds: 2_592_000, ...cur, trustedMinters: [...list, { minter, chain }], version: (cur?.version ?? 0) + 1 }
    await t.put('settings', next, cur?.version ?? 0)
  })
  return { networkUnverifiable: true }
}

/**
 * Claims an incoming zap (rule 9): it must pass rules 1–6 and 8 (an
 * unlisted minter only once approved); then the bill's own `cash_status`
 * must show this wallet's slice unclaimed at exactly the zap's amount. The
 * bill is kept with its zap fields (its provenance needs them) and the
 * expiry its status reports. Nothing is published.
 */
export async function claimZap(ctx: Ctx, ev: NostrEvent): Promise<Holding> {
  const me = (await ctx.requireSigner()).pubkey
  const trusted = (await ctx.settings()).trustedMinters
  const v = verifyCashZap(ev, { trusted })
  if (!v.valid || v.tags === undefined || v.token === undefined) throw new CashkitError('invalid_input', `this Cash Zap fails rule ${v.failed}`, { reason: 'zap_invalid' })
  if (v.rules[8] !== true) throw new CashkitError('auth', 'this zap’s minter is not trusted: approve it first', { reason: 'minter_untrusted' })
  if (v.tags.p.kind !== 'pubkey' || v.tags.p.value !== me) throw new CashkitError('usage', 'only a zap to this wallet’s pubkey is claimed here', { reason: 'not_for_this_wallet' })
  const zap = zapFieldsFromEvent(ev, v.tags)
  const client = new CashClient(ctx.clientDeps, v.token, zap)
  const st = await client.statusMany([{ id: '1', bill: client.bill, credential: bySigning(await ctx.requireSigner()), scope: 'mine' }])
  const o = st.outcomes[0]
  if (o?.state !== 'result' || o.value === undefined || o.value.tombstone !== undefined) throw new CashkitError('spent', 'this zap’s bill is gone or did not answer', { reason: 'zap_unclaimable' })
  let own
  try {
    own = ownClaim(o.value.recipients, bySigning(await ctx.requireSigner()), ctx.nowSeconds())
  } catch {
    throw new CashkitError('invalid_input', 'this zap’s bill is not this wallet’s alone at its amount', { reason: 'rule_9' })
  }
  if (!own.claimable) throw new CashkitError('invalid_input', `this zap’s slice is ${own.reason}, so it cannot be claimed`, { reason: 'rule_9' })
  const full = own.row
  if (full.amount_millis !== v.tags.amountMillis) throw new CashkitError('invalid_input', 'this zap’s bill is not this wallet’s alone at its amount', { reason: 'rule_9' })
  const f = tokenFacts(v.tags.cash)
  return ctx.commit(async (t) => {
    const h = await addHolding(
      t,
      {
        token: v.tags!.cash,
        walletPubkey: v.tags!.w,
        hubGroup: f.hubGroup,
        relayUrls: v.token!.relays,
        amount: v.tags!.amountMillis,
        verified: true,
        mode: 'pubkey',
        protection: 'none',
        minterPubkey: v.minter!,
        minterXonly: xonly(v.minter)!,
        ...(full.expires_at !== undefined && { expiresAt: full.expires_at }),
        ...(zap !== undefined && { zap }),
        origin: 'zap',
      },
      { now: ctx.now(), random: ctx.random },
    )
    await appendActivity(t, ctx.now(), { action: 'receive', amount: v.tags!.amountMillis, holdingId: h.id, mode: 'pubkey' })
    return h
  })
}

