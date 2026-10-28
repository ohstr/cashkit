// NIP-CW, the member's side: the join request and its kind-23199 proof, the
// join's details, the Hub's `circle_wallet` terms, budget periods and member
// requests. Port of nmilat nipcw/{terms,create_circle_wallet,member_request,
// budget_period}.go.
import { isBlank } from './bytes.js'
import { CoreError } from './errors.js'
import type { Signer } from './identity.js'
import { eventJSON } from './claim.js'
import type { NostrEvent } from './nip01.js'

export const KIND_CIRCLE_IDENTITY_PROOF = 23199
export const METHOD_CREATE_CIRCLE_WALLET = 'create_circle_wallet'
export const METHOD_DELETE_CIRCLE_WALLET = 'delete_circle_wallet'
/** A join proof's freshness window into the past: its deadline is `created_at` plus this. */
export const JOIN_FRESHNESS = 300

/** `circle_policy` values (NIP-CW §Membership). */
export const CIRCLE_POLICY_ALLOWLIST = 'allowlist'
export const CIRCLE_POLICY_FOLLOW_SET = 'follow_set'
export type CirclePolicy = typeof CIRCLE_POLICY_ALLOWLIST | typeof CIRCLE_POLICY_FOLLOW_SET

/** Budget renewals, tightest first (NIP-CW §Budget Renewal Floor). */
export const RENEWALS = ['daily', 'weekly', 'monthly', 'yearly', 'never'] as const
export type Renewal = (typeof RENEWALS)[number]
export const isRenewal = (s: unknown): s is Renewal => typeof s === 'string' && (RENEWALS as readonly string[]).includes(s)

/** Whether `requested` (omitted = never) satisfies the Hub's floor (omitted = anything). */
export function renewalAtLeast(requested: string | undefined, floor: string | undefined): boolean {
  const r = requested === undefined || requested === '' ? 'never' : requested
  if (!isRenewal(r)) return false
  if (floor === undefined || floor === '') return true
  return isRenewal(floor) && RENEWALS.indexOf(r) >= RENEWALS.indexOf(floor)
}

const MAX_TERM = (1n << 63n) - 1n
const HEX64 = /^[0-9a-f]{64}$/
const bad = (msg: string) => new CoreError('invalid_request', `create_circle_wallet: ${msg}`)
const badDetails = (msg: string) => new CoreError('invalid_payload', `create_circle_wallet: ${msg}`)

/** The terms a join asks for: caps per budget period in milli-units, a lifetime in seconds (0 = the Hub's default). */
export interface JoinTerms {
  readonly maxAmount: bigint
  readonly maxReceive: bigint
  readonly expiry?: number
  readonly budgetRenewal?: Renewal
}

/**
 * The `terms` tag value `<max_amount>:<max_receive>:<expiry>:<budget_renewal>`
 * (NIP-CW §Identity Proof, check 7): unsigned decimals, an omitted expiry as
 * 0 and an omitted renewal as `never`.
 */
export function termsTag(t: JoinTerms): string {
  for (const [name, v] of [
    ['max_amount', t.maxAmount],
    ['max_receive', t.maxReceive],
    ['expiry', BigInt(t.expiry ?? 0)],
  ] as const) {
    if (typeof v !== 'bigint' || v < 0n || v > MAX_TERM) throw bad(`${name} must be a whole number from 0 to 2^63-1`)
  }
  if (t.expiry !== undefined && (!Number.isSafeInteger(t.expiry) || t.expiry < 0)) throw bad('expiry must be whole seconds')
  const r = t.budgetRenewal ?? 'never'
  if (!isRenewal(r)) throw bad(`budget_renewal ${String(r)} is not one of ${RENEWALS.join(', ')}`)
  return `${t.maxAmount}:${t.maxReceive}:${t.expiry ?? 0}:${r}`
}

export interface CreateCircleWalletRequest {
  pubkey: string
  connection_pubkey: string
  max_amount: bigint
  max_receive: bigint
  expiry: number
  budget_renewal: Renewal
  /** The kind-23199 identity proof, as JSON text. */
  identity_event: string
}

/** One signed join: the request, its proof's id and `created_at`, and the deadline a lost reply is looked up with. */
export interface PreparedJoin {
  readonly request: CreateCircleWalletRequest
  readonly proofId: string
  readonly createdAt: number
  readonly deadline: number
}

const usedJoins = new WeakSet<PreparedJoin>()

/**
 * Marks a prepared join as built into an item, refusing a second use: one
 * proof is never sent twice, and a retry needs a new join.
 */
export function claimPreparedJoin(join: PreparedJoin): void {
  if (usedJoins.has(join)) throw new CoreError('invalid_request', 'nipcw: this prepared join was already used; prepare a new one')
  usedJoins.add(join)
}

/** Whether a prepared join was already built into an item. */
export const preparedJoinUsed = (join: PreparedJoin): boolean => usedJoins.has(join)

/**
 * Signs a join bound to `hubPubkey` (the `circlehub1`'s TLV 0): the proof's
 * `d`, `connection` and `terms` tags, never `action`. The connection key is
 * the member's own and must differ from the requester's.
 */
export async function createCircleWalletRequest(p: { signer: Signer; connectionPubkey: string; hubPubkey: string; terms: JoinTerms; now: number }): Promise<PreparedJoin> {
  if (!HEX64.test(p.hubPubkey)) throw bad('the Hub pubkey must be 64 lowercase hex')
  if (!HEX64.test(p.connectionPubkey)) throw bad('a member-generated connection key is required')
  if (p.connectionPubkey === p.signer.pubkey) throw bad("the connection key must differ from the requester's own key")
  const terms = termsTag(p.terms)
  const proof: NostrEvent = await p.signer.signEvent({
    kind: KIND_CIRCLE_IDENTITY_PROOF,
    created_at: p.now,
    tags: [
      ['d', p.hubPubkey],
      ['connection', p.connectionPubkey],
      ['terms', terms],
    ],
    content: '',
  })
  return {
    request: {
      pubkey: p.signer.pubkey,
      connection_pubkey: p.connectionPubkey,
      max_amount: p.terms.maxAmount,
      max_receive: p.terms.maxReceive,
      expiry: p.terms.expiry ?? 0,
      budget_renewal: p.terms.budgetRenewal ?? 'never',
      identity_event: eventJSON(proof),
    },
    proofId: proof.id,
    createdAt: p.now,
    deadline: p.now + JOIN_FRESHNESS,
  }
}

/** A member's own Circle Wallet connection, as fields: never a URI. The secret is the member's. */
export interface CircleWalletConnection {
  readonly walletPubkey: string
  readonly relays: readonly string[]
  readonly secret: string
}

/** A join's details, as the Hub resolved them. Nothing here is secret. */
export interface CircleWalletDetails {
  readonly walletPubkey: string
  readonly connectionPubkey: string
  readonly relays: readonly string[]
  readonly maxAmount: bigint
  readonly maxReceive: bigint
  /** 0 = never. */
  readonly expiresAt: number
  readonly feesPpm: number
  readonly dustThresholdMillis: bigint
  /** Absent on a wallet that cannot be rotated. */
  readonly rotationDelaySecs?: number
  readonly budgetRenewal: string
  /** Required terms the details did not carry: the wallet exists all the same, shown as unknown. */
  readonly missingTerms: readonly string[]
  /** Keys that should never be there (a secret or URI form, or anything beside `encrypted_details`). */
  readonly leakedFields: readonly string[]
  /** A resolved cap above the requested one, which a Hub must not do. */
  readonly capsRaised: boolean
}

const REQUIRED_TERMS = ['max_amount', 'max_receive', 'expires_at', 'fees_ppm', 'dust_threshold_millis', 'budget_renewal'] as const
const leaky = (k: string) => /secret|uri/i.test(k)

const uint = (v: unknown): bigint | undefined => {
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v)
  if (typeof v === 'bigint' && v >= 0n) return v
  return undefined
}

/**
 * Reads a join's result: `encrypted_details` decrypts under the requester's
 * key and the Hub pubkey only, names this join's `connection_pubkey`, a valid
 * `wallet_pubkey` and at least one usable relay, or the result is refused.
 * Missing terms, leaked fields and raised caps are reported, not fatal: the
 * wallet exists.
 */
export async function parseCreateCircleWalletResult(result: unknown, p: { signer: Signer; hubPubkey: string; connectionPubkey: string; requested?: JoinTerms }): Promise<CircleWalletDetails> {
  if (result === null || typeof result !== 'object' || Array.isArray(result)) throw badDetails('the result is not an object')
  const outer = result as Record<string, unknown>
  const ct = outer['encrypted_details']
  if (typeof ct !== 'string' || ct === '') throw badDetails('the result carries no encrypted_details')
  let plain: string
  try {
    plain = await p.signer.nip44Decrypt(p.hubPubkey, ct)
  } catch {
    throw badDetails('the details do not decrypt under the Hub connection key')
  }
  let inner: Record<string, unknown>
  try {
    const v: unknown = JSON.parse(plain)
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object')
    inner = v as Record<string, unknown>
  } catch {
    throw badDetails('the details are not a JSON object')
  }
  if (inner['connection_pubkey'] !== p.connectionPubkey) throw badDetails('the details name another connection_pubkey than the request: an old reply, never this join’s')
  const walletPubkey = inner['wallet_pubkey']
  if (typeof walletPubkey !== 'string' || !HEX64.test(walletPubkey)) throw badDetails('the details carry no valid wallet_pubkey')
  const relays = (Array.isArray(inner['relays']) ? inner['relays'] : []).filter((r): r is string => typeof r === 'string' && !isBlank(r))
  if (relays.length === 0) throw badDetails('the details carry no usable relay, so the wallet is unreachable')
  const maxAmount = uint(inner['max_amount']) ?? 0n
  const maxReceive = uint(inner['max_receive']) ?? 0n
  const rot = uint(inner['rotation_delay_secs'])
  const missingTerms = REQUIRED_TERMS.filter((k) => inner[k] === undefined || inner[k] === null)
  const leakedFields = [...Object.keys(inner).filter(leaky), ...Object.keys(outer).filter((k) => k !== 'encrypted_details')]
  // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh array
  leakedFields.sort()
  return {
    walletPubkey,
    connectionPubkey: p.connectionPubkey,
    relays,
    maxAmount,
    maxReceive,
    expiresAt: Number(uint(inner['expires_at']) ?? 0n),
    feesPpm: Number(uint(inner['fees_ppm']) ?? 0n),
    dustThresholdMillis: uint(inner['dust_threshold_millis']) ?? 0n,
    ...(rot !== undefined && { rotationDelaySecs: Number(rot) }),
    budgetRenewal: typeof inner['budget_renewal'] === 'string' ? inner['budget_renewal'] : 'never',
    missingTerms,
    leakedFields,
    capsRaised: p.requested !== undefined && (maxAmount > p.requested.maxAmount || maxReceive > p.requested.maxReceive),
  }
}

/** The `circle_wallet` block of a Circle Wallet Hub's `get_info` (NIP-CW §The Circle Wallet Hub Connection). */
export interface CircleWalletInfo {
  /** A snapshot, not a reservation; shown as "up to". */
  readonly available_millis: bigint
  /** The Hub's expiry ceiling; 0 means never. */
  readonly max_exp_secs: number
  readonly fees_ppm: number
  readonly fee_reserve: { readonly ppm: number; readonly min_millis: bigint }
  readonly dust_threshold_millis: bigint
  /** Absent when the Hub reports a policy this SDK does not know. */
  readonly circle_policy?: CirclePolicy
  /** The node identity that signs the Hub's announcement (x-only, lowercase). */
  readonly identity?: string
  /** Present iff the Hub serves rotation. */
  readonly rotation_delay_secs?: number
  readonly per_wallet_max_millis?: bigint
  readonly per_wallet_max_receive_millis?: bigint
  readonly min_budget_renewal?: Renewal
  /** Whether the Hub takes joins now; a missing value reads as false. */
  readonly accepting: boolean
}

const badInfo = (msg: string) => new CoreError('invalid_payload', `get_info circle_wallet: ${msg}`)

/**
 * Decodes the `circle_wallet` block of a `get_info` result; undefined when
 * there is none, which means the connection is not a Circle Wallet Hub. A
 * 66-hex compressed `identity` is read in x-only form.
 */
export function parseCircleWalletInfo(getInfoResult: unknown): CircleWalletInfo | undefined {
  const top = getInfoResult !== null && typeof getInfoResult === 'object' && !Array.isArray(getInfoResult) ? (getInfoResult as Record<string, unknown>) : {}
  const block = top['circle_wallet']
  if (block === undefined || block === null) return undefined
  if (typeof block !== 'object' || Array.isArray(block)) throw badInfo('not an object')
  const b = block as Record<string, unknown>
  const num = (k: string): number | undefined => {
    const v = b[k]
    if (v === undefined || v === null) return undefined
    const u = uint(v)
    if (u === undefined) throw badInfo(`${k} must be a non-negative integer`)
    return Number(u)
  }
  const big = (k: string): bigint | undefined => {
    const v = b[k]
    if (v === undefined || v === null) return undefined
    const u = uint(v)
    if (u === undefined) throw badInfo(`${k} must be a non-negative integer`)
    return u
  }
  const fr = b['fee_reserve'] !== null && typeof b['fee_reserve'] === 'object' ? (b['fee_reserve'] as Record<string, unknown>) : {}
  const policy = b['circle_policy']
  if (b['identity'] !== undefined && b['identity'] !== null && typeof b['identity'] !== 'string') throw badInfo('identity must be a string')
  if (b['accepting'] !== undefined && b['accepting'] !== null && typeof b['accepting'] !== 'boolean') throw badInfo('accepting must be a boolean')
  let identity = typeof b['identity'] === 'string' ? b['identity'].toLowerCase() : ''
  if (/^0[23][0-9a-f]{64}$/.test(identity)) identity = identity.slice(2)
  const floor = b['min_budget_renewal']
  const rot = num('rotation_delay_secs')
  const perMax = big('per_wallet_max_millis')
  const perRecv = big('per_wallet_max_receive_millis')
  return {
    available_millis: big('available_millis') ?? 0n,
    max_exp_secs: num('max_exp_secs') ?? 0,
    fees_ppm: num('fees_ppm') ?? 0,
    fee_reserve: { ppm: Number(uint(fr['ppm']) ?? 0n), min_millis: uint(fr['min_millis']) ?? 0n },
    dust_threshold_millis: big('dust_threshold_millis') ?? 0n,
    ...((policy === CIRCLE_POLICY_ALLOWLIST || policy === CIRCLE_POLICY_FOLLOW_SET) && { circle_policy: policy }),
    ...(HEX64.test(identity) && { identity }),
    ...(rot !== undefined && { rotation_delay_secs: rot }),
    ...(perMax !== undefined && { per_wallet_max_millis: perMax }),
    ...(perRecv !== undefined && { per_wallet_max_receive_millis: perRecv }),
    ...(isRenewal(floor) && { min_budget_renewal: floor }),
    accepting: b['accepting'] === true,
  }
}

/**
 * Checks requested terms against what the Hub reports, before anything is
 * signed: the per-wallet ceilings, the renewal floor and the expiry ceiling.
 * Returns the offending field, or undefined. The Hub still decides.
 */
export function validateJoinTerms(info: CircleWalletInfo, t: JoinTerms): string | undefined {
  if (info.per_wallet_max_millis !== undefined && t.maxAmount > info.per_wallet_max_millis) return 'max_amount'
  if (info.per_wallet_max_receive_millis !== undefined && t.maxReceive > info.per_wallet_max_receive_millis) return 'max_receive'
  if (!renewalAtLeast(t.budgetRenewal, info.min_budget_renewal)) return 'budget_renewal'
  if (t.expiry !== undefined && t.expiry > 0 && info.max_exp_secs > 0 && t.expiry > info.max_exp_secs) return 'expiry'
  return undefined
}

// ---- budget periods (§Budget Renewal Floor), UTC

const DAY = 86400

function addMonthsClamped(createdAt: number, months: number): number {
  const d = new Date(createdAt * 1000)
  const y = d.getUTCFullYear()
  const m = d.getUTCMonth() + months
  const ty = y + Math.floor(m / 12)
  const tm = ((m % 12) + 12) % 12
  const last = new Date(Date.UTC(ty, tm + 1, 0)).getUTCDate()
  const day = Math.min(d.getUTCDate(), last)
  return Math.floor(Date.UTC(ty, tm, day, d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()) / 1000)
}

/** The start of the k-th period (k = 0 is the creation), counted from the creation day; undefined for a negative k and for `never` past k = 0. */
export function budgetPeriodStart(createdAt: number, renewal: string, k: number): number | undefined {
  if (!Number.isInteger(k) || k < 0) return undefined
  switch (renewal) {
    case 'daily':
      return createdAt + k * DAY
    case 'weekly':
      return createdAt + k * 7 * DAY
    case 'monthly':
      return addMonthsClamped(createdAt, k)
    case 'yearly':
      return addMonthsClamped(createdAt, 12 * k)
    default:
      return k === 0 ? createdAt : undefined
  }
}

/** The period `now` falls in: its start, inclusive, and the next start, exclusive (undefined for `never`). */
export function currentPeriod(createdAt: number, renewal: string, now: number): { start: number; end?: number } {
  if (!isRenewal(renewal) || renewal === 'never' || now < createdAt) return { start: createdAt }
  let k = renewal === 'daily' ? Math.floor((now - createdAt) / DAY) : renewal === 'weekly' ? Math.floor((now - createdAt) / (7 * DAY)) : 0
  if (renewal === 'monthly' || renewal === 'yearly') {
    const step = renewal === 'monthly' ? 1 : 12
    const d0 = new Date(createdAt * 1000)
    const dn = new Date(now * 1000)
    k = Math.max(0, Math.floor(((dn.getUTCFullYear() - d0.getUTCFullYear()) * 12 + dn.getUTCMonth() - d0.getUTCMonth()) / step) - 1)
  }
  while ((budgetPeriodStart(createdAt, renewal, k + 1) ?? Infinity) <= now) k++
  const end = budgetPeriodStart(createdAt, renewal, k + 1)
  return { start: budgetPeriodStart(createdAt, renewal, k)!, ...(end !== undefined && { end }) }
}

// ---- member requests (§Recovering a Lost Connection)

export type MemberAction = 'rotate' | 'freeze' | 'unfreeze'

/**
 * A member request: a kind-23199 event signed by the join's `pubkey`, with
 * `d` = the Hub pubkey, `action`, `wallet`, and `connection` only on a
 * rotate; never `terms`. The host submits it; cashkit never sends it.
 */
export async function buildMemberRequest(signer: Signer, p: { hubPubkey: string; action: MemberAction; walletPubkey: string; newConnectionPubkey?: string; now: number }): Promise<NostrEvent> {
  if (!HEX64.test(p.hubPubkey) || !HEX64.test(p.walletPubkey)) throw new CoreError('invalid_request', 'member request: the Hub and wallet pubkeys must be 64 lowercase hex')
  if ((p.action === 'rotate') !== (p.newConnectionPubkey !== undefined)) throw new CoreError('invalid_request', 'member request: a rotate names the new connection key, and nothing else does')
  if (p.newConnectionPubkey !== undefined && (!HEX64.test(p.newConnectionPubkey) || p.newConnectionPubkey === signer.pubkey)) throw new CoreError('invalid_request', 'member request: the new connection key must be 64 lowercase hex and not the member’s own')
  return signer.signEvent({
    kind: KIND_CIRCLE_IDENTITY_PROOF,
    created_at: p.now,
    tags: [['d', p.hubPubkey], ['action', p.action], ['wallet', p.walletPubkey], ...(p.newConnectionPubkey !== undefined ? [['connection', p.newConnectionPubkey]] : [])],
    content: '',
  })
}

// ---- payment preview (§Own Funds and Caps, §Fees)

/**
 * The most a Lightning payment of `amount` may cost: the amount, the
 * wallet's own `fees_ppm` fee and the routing-fee reserve, each rounded
 * down. Advisory: a payment on the node carries neither fee.
 */
export function maxPaymentCost(amount: bigint, feesPpm: number, reserve: { readonly ppm: number; readonly min_millis: bigint }): bigint {
  const fee = (amount * BigInt(feesPpm)) / 1_000_000n
  const r = (amount * BigInt(reserve.ppm)) / 1_000_000n
  return amount + fee + (r > reserve.min_millis ? r : reserve.min_millis)
}
