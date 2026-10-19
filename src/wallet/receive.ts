// Receive and protect (design §6.1, §6.4). Port of cashctl
// cmd/cash_receive.go runCashReceive and cmd/receive_secure.go
// protectRekeyOnly.
import { bySecret, bySigning, decodeToken, newCashTarget, sniff, splitCashString, type Credential, type Token } from '../core/index.js'
import { ClientError, WalletError } from '../client/index.js'
import { validateClaimedAmount } from './amounts.js'
import { followMove, getHeld } from './bills.js'
import { tokenFacts, type Ctx } from './context.js'
import { CashkitError, classifyReadError, isNotSent } from './errors.js'
import { addHolding, appendActivity, findByToken, updateHolding } from './ledger.js'
import type { Holding } from './model.js'
import { holdingView, type HoldingView } from './views.js'

/** What a token says about itself, read offline. Carries no secret. */
export interface TokenReport {
  readonly walletPubkey: string
  readonly relays: readonly string[]
  readonly identityRequired?: boolean
  readonly minterPubkey?: string
  readonly attestedAmount?: bigint
}

export interface Secured {
  readonly status: 'not_applicable' | 'declined' | 'failed' | 'rekeyed'
  /** The rekey may have landed; `settle()` resolves it. */
  readonly unresolved?: boolean
  /** The Hub did not recognise the cash secret. */
  readonly likelyWrongSecret?: boolean
}

export type ReceiveResult =
  | { readonly received: true; readonly holding: HoldingView; readonly secured: Secured }
  | { readonly received: false; readonly reason: 'no_embedded_secret'; readonly report: TokenReport }

function refuseKind(input: string): void {
  const kind = sniff(input)
  const why: Partial<Record<typeof kind, string>> = {
    circlehub: "that's a Circle Hub connection: join it with wallet.joinCircle()",
    cashhub: "that's a Cash Hub connection (for minting cash): minting needs the Hub operator's own tooling",
    nwc_uri: "that looks like a wallet connection, not a cash token: add it with wallet.connections.add()",
    nostr_entity: "that's a Nostr identifier, not a cash token",
    lightning_invoice: "that's a Lightning invoice, not a cash token: pay it from a wallet, or redeem into it with wallet.redeem({ invoice })",
    unknown: "doesn't look like a valid cash token",
  }
  const msg = why[kind]
  if (msg !== undefined) throw new CashkitError('invalid_input', msg, { input })
}

function reportOf(tok: Token): TokenReport {
  return {
    walletPubkey: tok.walletPubkey,
    relays: [...tok.relays],
    ...(tok.identityRequired !== undefined && { identityRequired: tok.identityRequired }),
    ...(tok.attestedAmountMillis !== undefined && { attestedAmount: tok.attestedAmountMillis }),
  }
}

/** `receive`: check the bill with its Hub, commit it, then protect a cash note. */
export async function receive(ctx: Ctx, rawInput: string, o: { protect?: boolean } = {}): Promise<ReceiveResult> {
  const { token: input, cashSecret: embedded } = splitCashString(rawInput.trim())
  refuseKind(input)
  let tok: Token
  try {
    tok = decodeToken(input)
  } catch (err) {
    throw new CashkitError('invalid_input', (err as Error).message, { input, cause: err })
  }
  const facts = tokenFacts(input)
  let isCash = tok.identityRequired === false || embedded !== ''
  const signer = await ctx.signer()
  if (isCash && embedded === '' && signer !== undefined) {
    // Metadata says cash, but a transfer may have bound it to us since.
    try {
      const live = await ctx.client(tok).checkClaim(bySigning(signer), signer.pubkey)
      if (!live.isCash) isCash = false
    } catch {
      // stays a cash bill without its secret
    }
  }
  if (isCash && embedded === '') {
    return { received: false, reason: 'no_embedded_secret', report: { ...reportOf(tok), ...(facts.minterPubkey !== undefined && { minterPubkey: facts.minterPubkey }) } }
  }
  const existing = await ctx.read((t) => findByToken(t, input))
  if (existing?.status === 'held') throw new CashkitError('conflict', 'this token is already in your wallet', { input: existing.id })

  let cred: Credential
  if (embedded !== '') cred = bySecret(embedded)
  else cred = bySigning(await ctx.requireSigner())
  let r
  try {
    r = await ctx.client(tok).checkClaim(cred, signer?.pubkey ?? '')
  } catch (err) {
    if (err instanceof ClientError && err.code === 'spent') throw new CashkitError('spent', 'the Hub says this bill is spent: its value has already moved and the bill is gone', { input })
    if (err instanceof ClientError && err.code === 'claim_not_found') {
      throw new CashkitError(
        'invalid_input',
        embedded !== ''
          ? "the cash secret after '#' does not match this bill (is it complete?) — refusing to receive it"
          : 'the Cash Hub has no matching recipient for this token — refusing to receive it',
        { input },
      )
    }
    throw classifyReadError(err)
  }
  validateClaimedAmount(tok, r.minterPubkey, r.amountMillis)
  const sealedSecret = embedded !== '' ? await ctx.seal(embedded) : undefined
  const holding = await ctx.commit(async (t) => {
    const h = await addHolding(
      t,
      {
        token: input,
        walletPubkey: tok.walletPubkey,
        hubGroup: facts.hubGroup,
        relayUrls: tok.relays,
        amount: r.amountMillis,
        verified: true,
        ...(r.minterPubkey !== undefined && { minterPubkey: r.minterPubkey }),
        ...(r.expiresAt !== undefined && { expiresAt: r.expiresAt }),
        ...(r.isCash ? { mode: 'cash' as const, protection: 'shared' as const, ...(sealedSecret !== undefined && { cashSecret: sealedSecret }) } : { mode: 'pubkey' as const, protection: 'none' as const }),
      },
      { now: ctx.now(), random: ctx.random },
    )
    await appendActivity(t, ctx.now(), { action: 'receive', amount: r.amountMillis, holdingId: h.id, mode: h.mode })
    return h
  })
  let secured: Secured = { status: 'not_applicable' }
  let final = holding
  if (r.isCash) {
    const protect = o.protect ?? (await ctx.settings()).autoProtect
    if (!protect) secured = { status: 'declined' }
    else ({ secured, holding: final } = await protectOne(ctx, holding))
  }
  return { received: true, holding: holdingView(final, ctx.nowSeconds()), secured }
}

/**
 * `protectRekeyOnly`: moves a shared cash note to a fresh secret only this
 * wallet knows. The secret is parked first; a definite refusal clears it,
 * silence keeps it for `settle()`.
 */
export async function protectOne(ctx: Ctx, h: Holding): Promise<{ secured: Secured; holding: Holding }> {
  const target = newCashTarget(ctx.random)
  const sealed = await ctx.seal(target.secret)
  let parked: Holding
  try {
    parked = await ctx.commit((t) => updateHolding(t, h.id, (x) => ({ ...x, pendingCashSecret: sealed }), h.version))
  } catch {
    return { secured: { status: 'failed' }, holding: h }
  }
  let res
  try {
    if (parked.amount === undefined || parked.cashSecret === undefined) throw new CashkitError('invalid_input', 'this holding has no amount or cash secret to protect')
    res = await ctx.client(parked.token).cashTransfer({ credential: bySecret(await ctx.open(parked.cashSecret)), to: target, currentAmount: parked.amount })
  } catch (err) {
    if (err instanceof WalletError || isNotSent(err) || err instanceof CashkitError) {
      const cleared = await ctx.commit((t) => updateHolding(t, h.id, ({ pendingCashSecret: _p, ...x }) => x)).catch(() => parked)
      return { secured: { status: 'failed', likelyWrongSecret: err instanceof WalletError && err.walletCode === 'NOT_FOUND' }, holding: cleared }
    }
    return { secured: { status: 'failed', unresolved: true }, holding: parked }
  }
  try {
    const done = await ctx.commit(async (t) => {
      const x = await updateHolding(t, h.id, (cur) => {
        const { pendingCashSecret: _p, ...rest } = followMove(cur, res)
        return { ...rest, cashSecret: sealed, protection: 'protected' }
      })
      await appendActivity(t, ctx.now(), { action: 'protect', holdingId: h.id })
      return x
    })
    return { secured: { status: 'rekeyed' }, holding: done }
  } catch {
    // The new secret is parked and committed; settle() promotes it.
    return { secured: { status: 'failed', unresolved: true }, holding: parked }
  }
}

/** Protects the named holdings, or every shared cash note. */
export async function protectMany(ctx: Ctx, ids: readonly string[] | undefined): Promise<{ holdingId: string; secured: Secured; holding: Holding; error?: CashkitError }[]> {
  const targets = ids !== undefined ? await Promise.all(ids.map((id) => getHeld(ctx, id))) : (await ctx.read((t) => t.list('holdings'))).filter((h) => h.status === 'held' && h.mode === 'cash' && h.protection === 'shared')
  const out: { holdingId: string; secured: Secured; holding: Holding; error?: CashkitError }[] = []
  for (const h of targets) {
    if (h.mode !== 'cash' || h.throwawayKey !== undefined) {
      out.push({ holdingId: h.id, secured: { status: 'not_applicable' }, holding: h })
      continue
    }
    const r = await protectOne(ctx, h)
    out.push({ holdingId: h.id, ...r })
  }
  return out
}
