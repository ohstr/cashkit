// Joining a circle (design §6.7). Port of cashctl cmd/circle.go
// runCircleJoin: the connection key is generated here and parked as a
// pending join before the request goes out; on success the connection is
// added and the pending join deleted in one transaction. The join travels
// over the private transport when the Hub offers it (NIP-CW §Private Join).
import { buildPairingURI, decodeCircleHubConnection, parsePairingURI, sniff } from '../core/index.js'
import { CircleClient, ClientError, PrivateJoinUnavailableError, WalletError, type JoinTransport } from '../client/index.js'
import { validateRequestedAmount } from './amounts.js'
import type { Ctx } from './context.js'
import { CashkitError, classifySpendError, fromWalletError, isNotSent } from './errors.js'
import { appendActivity } from './ledger.js'
import type { Connection } from './model.js'

export interface JoinInput {
  /** A circlehub1… string or the Hub's NWC URI. */
  readonly hub: string
  readonly maxAmount: bigint
  readonly name?: string
  readonly makeDefault?: boolean
  /** Requested lifetime in seconds; 0 lets the Hub choose. */
  readonly expirySeconds?: number
  readonly budgetRenewal?: string
  /** Refuse rather than join over the shared Hub connection when the private transport can't be used. */
  readonly requirePrivate?: boolean
}

/** Carries no connection string (§6.7). */
export interface JoinResult {
  readonly name: string
  readonly isDefault: boolean
  readonly walletPubkey: string
  readonly relays: readonly string[]
  readonly connectionPubkey: string
  readonly expiresAt: number
  readonly maxAmount?: bigint
  readonly feesPpm: number
  readonly budgetRenewal: string
  /** Whether the join went over the private transport. */
  readonly private: boolean
  /**
   * Why the join went over the standard transport although the Hub offers
   * Private Join. Show the member that the join was not private.
   */
  readonly fallbackReason?: string
}

const privateUnavailable = (err: unknown) =>
  new CashkitError('not_found', `this Hub's private transport can't be used, so nothing was sent: ${(err as Error).message}`, { cause: err })

/** The transport, chosen before anything is parked: nothing has been sent yet. */
async function chooseTransport(circle: CircleClient, requirePrivate: boolean): Promise<JoinTransport> {
  try {
    return await circle.chooseTransport({ requirePrivate })
  } catch (err) {
    if (err instanceof PrivateJoinUnavailableError) throw privateUnavailable(err)
    if (err instanceof ClientError) throw new CashkitError('network', `could not read the Hub's terms (get_info), so nothing was sent: ${err.message}`, { cause: err })
    throw new CashkitError('internal', `the Hub's get_info could not be read: ${(err as Error).message}`, { cause: err })
  }
}

const isReplayGuard = (err: unknown) =>
  err instanceof WalletError && err.walletCode === 'BAD_REQUEST' && err.walletMessage.includes('identity_event') && err.walletMessage.includes('already been used')

/** A pre-SD-20 Hub says "already has a wallet" as RESTRICTED (`walletExistsFromLegacyRefusal`). */
const normalizeExists = (err: unknown) =>
  err instanceof WalletError && err.walletCode === 'RESTRICTED' && err.walletMessage.includes('already has an active circle wallet') ? new WalletError(err.method, 'WALLET_EXISTS', err.walletMessage) : err

function resolveHub(hub: string): { uri: string; label: string } {
  switch (sniff(hub)) {
    case 'cashhub':
      throw new CashkitError('invalid_input', "that's a Cash Hub connection (for minting cash), not a Circle Hub connection", { input: hub })
    case 'circlehub': {
      try {
        const c = decodeCircleHubConnection(hub)
        return { uri: buildPairingURI(c.walletPubkey, c.relays, c.secret), label: c.label }
      } catch (err) {
        throw new CashkitError('invalid_input', (err as Error).message, { input: hub, cause: err })
      }
    }
    case 'nwc_uri':
      return { uri: hub.trim(), label: '' }
    default:
      throw new CashkitError('invalid_input', 'not a Circle Hub connection: pass a circlehub1… string or the Hub’s nostr+walletconnect:// URI', { input: hub })
  }
}

/** `SuggestName`: the label slugged, else "circle", made unique. */
export function suggestName(taken: readonly string[], base: string, label: string): string {
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
  const root = slug !== '' ? slug : base
  if (!taken.includes(root)) return root
  for (let i = 2; ; i++) if (!taken.includes(`${root}-${i}`)) return `${root}-${i}`
}

export async function joinCircle(ctx: Ctx, o: JoinInput, sleep: (ms: number) => Promise<void>): Promise<JoinResult> {
  if (o.maxAmount === 0n) throw new CashkitError('invalid_input', "0 isn't a spend cap: there's no \"0 means unlimited\" convention here, so pass the most this wallet may spend", { input: '0' })
  validateRequestedAmount(o.maxAmount, 'maxAmount')
  const { uri, label } = resolveHub(o.hub)
  let hubPubkey: string
  try {
    hubPubkey = parsePairingURI(uri).walletPubkey
  } catch (err) {
    throw new CashkitError('invalid_input', (err as Error).message, { input: o.hub, cause: err })
  }
  const signer = await ctx.requireSigner()
  return ctx.spend(async () => {
    const opId = ctx.newOpId('join')
    const circle = new CircleClient(ctx.clientDeps, uri)
    const connection = circle.newConnectionKey()
    const sealedSecret = await ctx.seal(connection.secret)
    const existing = await ctx.read((t) => t.list('connections'))
    const name = o.name ?? suggestName(existing.map((c) => c.id), 'circle', label)
    if (existing.some((c) => c.id === name)) throw new CashkitError('exists', `a connection named "${name}" already exists`, { input: name })
    const via = await chooseTransport(circle, o.requirePrivate === true)
    await ctx.commit((t) => t.put('pendingJoins', { id: connection.pubkey, connectionSecret: sealedSecret, hubPubkey, hubLabel: label, name, at: ctx.now(), version: 1 }, 0))
    ctx.emit({ op: 'join', phase: 'sent', id: opId })
    // The same transport for the retry: a sent private join never falls back.
    const attempt = () => circle.createCircleWallet({ signer, maxAmountMillis: o.maxAmount, expirySeconds: o.expirySeconds ?? 0, connection, ...(o.budgetRenewal !== undefined && { budgetRenewal: o.budgetRenewal }) }, via)
    let joined
    try {
      try {
        joined = await attempt()
      } catch (err) {
        if (!isReplayGuard(err)) throw err
        await sleep(1100)
        joined = await attempt()
      }
    } catch (raw) {
      const err = normalizeExists(raw)
      ctx.emit({ op: 'join', phase: 'failed', id: opId })
      if (isNotSent(err) || err instanceof WalletError || err instanceof PrivateJoinUnavailableError) {
        await ctx.commit((t) => t.delete('pendingJoins', connection.pubkey)).catch(() => undefined)
      }
      if (err instanceof PrivateJoinUnavailableError) throw privateUnavailable(err)
      if (isReplayGuard(err)) {
        throw new CashkitError('conflict', "the Hub's identity-proof replay guard rejected two attempts within the same second, even after retrying once: wait a few seconds and join again", { cause: err })
      }
      if (err instanceof WalletError) throw fromWalletError(err)
      if (isNotSent(err)) throw classifySpendError(err, 'join')
      throw new CashkitError(
        'indeterminate',
        `the join got no usable answer, so whether the wallet was created is unknown. If a later join says you already hold one, it is the wallet with connection key ${connection.pubkey} (listed in state.pendingJoins): ask the circle's host to delete it, then join again`,
        { cause: err },
      )
    }
    const { wallet } = joined
    const sealedUri = await ctx.seal(wallet.pairingUri)
    let isDefault = false
    try {
      isDefault = await ctx.commit(async (t) => {
        const conns = await t.list('connections')
        const makeDefault = o.makeDefault === true || conns.length === 0
        if (makeDefault) for (const c of conns.filter((x) => x.isDefault)) await t.put('connections', { ...c, isDefault: false, version: c.version + 1 }, c.version)
        const row: Connection = { id: name, uri: sealedUri, kind: 'circle', isDefault: makeDefault, version: 1 }
        await t.put('connections', row, 0)
        await t.delete('pendingJoins', connection.pubkey)
        await appendActivity(t, ctx.now(), { action: 'join', circle: label !== '' ? label : hubPubkey, connection: name })
        return makeDefault
      })
    } catch (err) {
      throw new CashkitError('internal', 'Your new circle wallet was created but could not be saved.', {
        cause: err,
        recovery: `Register it with wallet.connections.add("${name}", <connection>), using: ${wallet.pairingUri}`,
        recoveryHandoffs: [wallet.pairingUri],
      })
    }
    ctx.emit({ op: 'join', phase: 'committed', id: opId })
    return {
      name,
      isDefault,
      walletPubkey: wallet.walletPubkey,
      relays: wallet.relays,
      connectionPubkey: connection.pubkey,
      expiresAt: wallet.expiresAt,
      ...(wallet.maxAmountMillis !== undefined && { maxAmount: wallet.maxAmountMillis }),
      feesPpm: wallet.feesPpm,
      budgetRenewal: wallet.budgetRenewal,
      private: joined.private,
      ...(joined.fallbackReason !== undefined && { fallbackReason: joined.fallbackReason.message }),
    }
  })
}
