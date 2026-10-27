// Claim proofs and the requests that carry them: cash_redeem, cash_transfer
// and cash_consolidate. Port of nmilat nipcash/{proof,cash_redeem,
// cash_transfer,cash_consolidate,claim}.go. The objects returned use the
// wire's field names; amounts stay bigint until the transport serializes
// them.
import { sha256 } from '@noble/hashes/sha2.js'
import { decodeBolt11 } from './bolt11.js'
import { toHex, utf8 } from './bytes.js'
import { connectionKeyFromAttested } from './idna.js'
import { CoreError } from './errors.js'
import { toJSONText } from './json.js'
import { cashCommitment, isCommitment, newIdentityHash, type Credential, type IdentityType, type Target } from './identity.js'
import { isRequestId } from './requestId.js'
import type { NostrEvent } from './nip01.js'

/** NIP-CASH §Methods: the claim proof event kind. */
export const KIND_CLAIM_PROOF = 23198

/** The methods a claim proof can authorize (its `m` tag). */
export type ClaimMethod = 'cash_redeem' | 'cash_withdraw' | 'cash_transfer' | 'cash_consolidate'

/** What a claim proof commits to. */
export interface ProofBinding {
  readonly method: ClaimMethod
  /** The slice's wallet pubkey (the `d` tag). */
  readonly walletPubkey: string
  /** `cash_redeem`: the invoice's payment hash. */
  readonly bolt11Hash?: string
  /** `cash_withdraw`: the withdraw quote's event id (`q`). */
  readonly quoteId?: string
  /** `cash_transfer`, `cash_consolidate`. */
  readonly newIdentityHash?: string
  /** `cash_transfer`, `cash_consolidate`: the amount the call moves. */
  readonly amountMillis?: bigint
  /** `cash_consolidate`: `sourcesHash` of the call's sources (`s`). */
  readonly sourcesHash?: string
  /** A `connection_key` slice: its identity value and the attestation's id (`e`). */
  readonly connectionKey?: string
  readonly attestationId?: string
}

const HEX64 = /^[0-9a-f]{64}$/
const badProof = (msg: string) => new CoreError('invalid_request', `claim proof: ${msg}`)
const badTarget = (msg: string) => new CoreError('invalid_request', msg)
const badTransfer = (msg: string) => new CoreError('invalid_request', `cash_transfer: ${msg}`)
const NEEDS: Readonly<Record<ClaimMethod, readonly (keyof ProofBinding)[]>> = {
  cash_redeem: ['bolt11Hash'],
  cash_withdraw: ['quoteId'],
  cash_transfer: ['newIdentityHash', 'amountMillis'],
  cash_consolidate: ['newIdentityHash', 'amountMillis', 'sourcesHash'],
}
const OPTIONAL_FIELDS: readonly (keyof ProofBinding)[] = ['bolt11Hash', 'quoteId', 'newIdentityHash', 'amountMillis', 'sourcesHash']
const TAG: Readonly<Record<string, string>> = {
  bolt11Hash: 'bolt11_hash',
  quoteId: 'q',
  newIdentityHash: 'new_identity_hash',
  amountMillis: 'amount_millis',
  sourcesHash: 's',
}

/**
 * The claim proof's tags (NIP-CASH §Claim Proofs): exactly the set the
 * method and slice need, each once, in the encodings the NIP fixes. Refuses
 * a missing field, a field the method does not use, and a bad encoding.
 */
export function claimProofTags(b: ProofBinding): string[][] {
  if (!Object.hasOwn(NEEDS, b.method)) throw badProof(`no claim proof for ${String(b.method)}`)
  if (!HEX64.test(b.walletPubkey)) throw badProof('d must be 64 lowercase hex')
  const need = NEEDS[b.method]
  const tags = [
    ['d', b.walletPubkey],
    ['m', b.method],
  ]
  for (const f of OPTIONAL_FIELDS) {
    const v = b[f]
    if (!need.includes(f)) {
      if (v !== undefined) throw badProof(`${TAG[f]} is not used by ${b.method}`)
      continue
    }
    if (v === undefined) throw badProof(`${b.method} needs ${TAG[f]}`)
    if (f === 'amountMillis') {
      if (typeof v !== 'bigint' || v < 0n) throw badProof('amount_millis must be an unsigned integer')
      tags.push([TAG[f]!, v.toString(10)])
    } else {
      if (typeof v !== 'string' || !HEX64.test(v)) throw badProof(`${TAG[f]} must be 64 lowercase hex`)
      tags.push([TAG[f]!, v])
    }
  }
  if ((b.connectionKey === undefined) !== (b.attestationId === undefined)) throw badProof('connection_key and e go together')
  if (b.connectionKey !== undefined) {
    if (!HEX64.test(b.connectionKey) || !HEX64.test(b.attestationId!)) throw badProof('connection_key and e must be 64 lowercase hex')
    tags.push(['connection_key', b.connectionKey], ['e', b.attestationId!])
  }
  return tags
}

/** `s`: hex sha256 of every source's wallet pubkey, in `sources` order, as 64 lowercase hex each. */
export function sourcesHash(walletPubkeys: readonly string[]): string {
  for (const w of walletPubkeys) if (!HEX64.test(w)) throw new CoreError('invalid_request', 'a source wallet pubkey must be 64 lowercase hex')
  return toHex(sha256(utf8(walletPubkeys.join(''))))
}

/** The authorization fields a credential contributes to a request item. */
export interface ProofFields {
  identity_type?: IdentityType
  identity_value?: string
  /** The signed claim proof, as JSON text. */
  identity_event?: string
  /** The IA attestation, as JSON text (connection_key mode). */
  attestation_event?: string
  /** Secret-bearing (cash mode). */
  cash_secret?: string
}

/** Unix seconds, for signing and for checking attestation expiry. */
const nowSeconds = () => Math.floor(Date.now() / 1000)

/** Event JSON in nmilat's field order. */
export function eventJSON(e: NostrEvent): string {
  return toJSONText({
    id: e.id,
    pubkey: e.pubkey,
    created_at: e.created_at,
    kind: e.kind,
    tags: e.tags,
    content: e.content,
    sig: e.sig,
  })
}

/** Builds a credential's proof for `binding`. `now` is Unix seconds. */
export async function buildProof(c: Credential, binding: ProofBinding, now = nowSeconds()): Promise<ProofFields> {
  switch (c.kind) {
    case 'secret':
      return { cash_secret: c.secret }
    case 'signing': {
      const ev = await c.signer.signEvent({ kind: KIND_CLAIM_PROOF, created_at: now, tags: claimProofTags(binding), content: '' })
      return { identity_type: 'pubkey', identity_value: c.signer.pubkey, identity_event: eventJSON(ev) }
    }
    case 'connection_key': {
      const att = c.attestation
      if (att === undefined || att.expiresAt === undefined || now > att.expiresAt) {
        throw new CoreError('invalid_request', 'attestation has no expiration, or has already expired')
      }
      const connectionKey = connectionKeyFromAttested(c.platform, c.externalId)
      const tags = claimProofTags({ ...binding, connectionKey, attestationId: att.event.id })
      const ev = await c.signer.signEvent({ kind: KIND_CLAIM_PROOF, created_at: now, tags, content: '' })
      return {
        identity_type: 'connection_key',
        identity_value: connectionKey,
        identity_event: eventJSON(ev),
        attestation_event: eventJSON(att.event),
      }
    }
  }
}

function checkTarget(t: Target): void {
  switch (t.identityType) {
    case 'pubkey':
      if (!HEX64.test(t.identityValue)) throw badTarget('a pubkey identity is 64 lowercase hex')
      if (t.iaPubkey !== '') throw badTarget('a pubkey identity carries no ia_pubkey')
      return
    case 'connection_key':
      if (!HEX64.test(t.identityValue)) throw badTarget('a connection_key identity is 64 lowercase hex')
      if (!HEX64.test(t.iaPubkey)) throw badTarget('a connection_key identity requires an ia_pubkey')
      return
    case 'cash':
      if (!isCommitment(t.identityValue)) throw badTarget('a cash identity is a commitment of 64 lowercase hex')
      if (t.iaPubkey !== '') throw badTarget('a cash identity carries no ia_pubkey')
      return
    default:
      throw badTarget(`unknown identity type ${String((t as Target).identityType)}`)
  }
}

function checkRequestId(id: unknown): string {
  if (!isRequestId(id)) throw new CoreError('invalid_request', 'request_id must be 16 to 32 bytes of lowercase hex')
  return id
}

export interface NewIdentity {
  identity_type: IdentityType
  identity_value?: string
  ia_pubkey?: string
}

function newIdentity(t: Target): NewIdentity {
  return {
    identity_type: t.identityType,
    ...(t.identityValue !== '' && { identity_value: t.identityValue }),
    ...(t.iaPubkey !== '' && { ia_pubkey: t.iaPubkey }),
  }
}

export interface CashRedeemRequest extends ProofFields {
  invoice: string
  amount?: bigint
}

/** cash_redeem: pay `invoice` from the bill at `walletPubkey`. */
export async function cashRedeemRequest(p: {
  walletPubkey: string
  invoice: string
  credential: Credential
  amount?: bigint
  now?: number
}): Promise<CashRedeemRequest> {
  const { paymentHash, amountMillis } = decodeBolt11(p.invoice)
  if (p.amount !== undefined) {
    if (amountMillis !== 0n) throw new CoreError('invalid_request', 'amount is sent only with an amountless invoice')
    if (p.amount <= 0n) throw new CoreError('invalid_request', 'amount must be positive')
  }
  const proof = await buildProof(p.credential, { method: 'cash_redeem', walletPubkey: p.walletPubkey, bolt11Hash: paymentHash }, p.now)
  return { invoice: p.invoice, ...(p.amount !== undefined && { amount: p.amount }), ...proof }
}

export interface CashTransferRequest extends ProofFields {
  new_identity: NewIdentity
  amount_millis?: bigint
  zap_target?: string
  remainder_commitment?: string
  request_id: string
}

/**
 * cash_transfer: move the bill (or `splitAmount` of it) to `to`. The proof
 * binds the amount that moves: the split, or the whole current amount.
 *
 * - `zapTarget` makes it a zap transfer: only from a pubkey slice to a pubkey.
 * - `remainderCommitment` is required for a partial split of a cash source,
 *   and refused otherwise; it must be fresh, never the source's own.
 */
export async function cashTransferRequest(p: {
  walletPubkey: string
  credential: Credential
  to: Target
  currentAmount: bigint
  splitAmount?: bigint
  zapTarget?: string
  remainderCommitment?: string
  requestId: string
  now?: number
}): Promise<CashTransferRequest> {
  checkTarget(p.to)
  const requestId = checkRequestId(p.requestId)
  if (p.currentAmount <= 0n) throw badTransfer('the bill has no amount to move')
  if (p.splitAmount !== undefined && (p.splitAmount <= 0n || p.splitAmount > p.currentAmount)) throw badTransfer('amount must be positive and at most the current amount')
  const partial = p.splitAmount !== undefined && p.splitAmount < p.currentAmount
  if (p.zapTarget !== undefined) {
    if (p.zapTarget === '') throw badTransfer('zap_target must not be empty')
    if (p.credential.kind !== 'signing') throw badTransfer('a zap transfer needs a pubkey-bound source')
    if (p.to.identityType !== 'pubkey') throw badTransfer('a zap transfer goes to a pubkey')
  }
  const cashSplit = partial && p.credential.kind === 'secret'
  if (cashSplit) {
    if (p.remainderCommitment === undefined) throw badTransfer('a partial split of a cash source needs a remainder_commitment')
    if (!isCommitment(p.remainderCommitment)) throw badTransfer('remainder_commitment must be 64 lowercase hex')
    if (p.credential.kind === 'secret' && p.remainderCommitment === cashCommitment(p.credential.secret)) throw badTransfer("remainder_commitment must be fresh, not the source's own")
  } else if (p.remainderCommitment !== undefined) throw badTransfer('remainder_commitment is only for a partial split of a cash source')
  const binding: ProofBinding = {
    method: 'cash_transfer',
    walletPubkey: p.walletPubkey,
    newIdentityHash: newIdentityHash(p.to),
    amountMillis: p.splitAmount ?? p.currentAmount,
  }
  const proof = await buildProof(p.credential, binding, p.now)
  return {
    ...proof,
    new_identity: newIdentity(p.to),
    ...(p.splitAmount !== undefined && { amount_millis: p.splitAmount }),
    ...(p.zapTarget !== undefined && { zap_target: p.zapTarget }),
    ...(p.remainderCommitment !== undefined && { remainder_commitment: p.remainderCommitment }),
    request_id: requestId,
  }
}

/**
 * The outcome NIP-CASH §Which outcome a request produces predicts.
 * `in_place_or_spin_off_1` is a full transfer whose shape depends on the
 * wallet's state: to a pubkey or connection key (a spin-off if that identity
 * already holds a slice here), or to cash unless the caller knows from an
 * `all` roster that the wallet has only ever had one recipient.
 */
export type TransferOutcome = 'in_place' | 'spin_off_1' | 'spin_off_2' | 'in_place_or_spin_off_1'

export function expectedTransferOutcome(
  slice: { readonly currentAmount: bigint; readonly singleRecipientHistory?: boolean },
  req: { readonly to: Pick<Target, 'identityType'>; readonly splitAmount?: bigint; readonly zapTarget?: string },
): TransferOutcome {
  const partial = req.splitAmount !== undefined && req.splitAmount < slice.currentAmount
  if (req.zapTarget !== undefined) return partial ? 'spin_off_2' : 'spin_off_1'
  if (partial) return 'spin_off_2'
  if (req.to.identityType === 'cash' && slice.singleRecipientHistory === true) return 'in_place'
  return 'in_place_or_spin_off_1'
}

export interface CashStatusRequest {
  scope?: 'mine' | 'all'
  attestation_event?: string
}

/**
 * cash_status params. Never a `cash_secret`: a cash-mode status item is the
 * bearer item that carries neither proof nor secret, and a Hub refuses one
 * carrying the secret with `BAD_REQUEST`.
 */
export function cashStatusRequest(p: { readonly scope?: 'mine' | 'all'; readonly attestationEvent?: string } = {}): CashStatusRequest {
  const raw = p as Record<string, unknown>
  if ('cashSecret' in raw || 'cash_secret' in raw || 'secret' in raw) throw new CoreError('invalid_request', 'cash_status never carries a cash secret')
  if (p.scope !== undefined && p.scope !== 'mine' && p.scope !== 'all') throw new CoreError('invalid_request', 'cash_status scope is mine or all')
  return { ...(p.scope !== undefined && { scope: p.scope }), ...(p.attestationEvent !== undefined && { attestation_event: p.attestationEvent }) }
}

export interface ConsolidateSource {
  readonly walletPubkey: string
  readonly amount: bigint
  readonly credential: Credential
}

export interface CashConsolidateRequest {
  sources: ({ wallet_pubkey: string } & Omit<ProofFields, 'cash_secret'>)[]
  new_identity: NewIdentity
  request_id: string
}

/**
 * cash_consolidate: merge at least two non-cash bills into one owned by
 * `to`. A cash-mode source or the same source twice is refused.
 */
export async function cashConsolidateRequest(p: {
  sources: readonly ConsolidateSource[]
  to: Target
  requestId: string
  now?: number
}): Promise<CashConsolidateRequest> {
  if (p.sources.length < 2) throw new CoreError('invalid_request', 'cash_consolidate requires at least two sources')
  checkTarget(p.to)
  const requestId = checkRequestId(p.requestId)
  const hash = newIdentityHash(p.to)
  const s = sourcesHash(p.sources.map((x) => x.walletPubkey))
  const seen = new Set<string>()
  const sources: CashConsolidateRequest['sources'] = []
  for (const src of p.sources) {
    if (src.credential.kind === 'secret') throw new CoreError('invalid_request', 'cash_consolidate does not accept a cash-mode source')
    const proof = await buildProof(src.credential, { method: 'cash_consolidate', walletPubkey: src.walletPubkey, newIdentityHash: hash, amountMillis: src.amount, sourcesHash: s }, p.now)
    if (proof.identity_type === 'cash' || proof.cash_secret) {
      throw new CoreError('invalid_request', 'cash_consolidate does not accept a cash-mode source')
    }
    const key = `${src.walletPubkey}\0${proof.identity_type ?? ''}\0${proof.identity_value ?? ''}`
    if (seen.has(key)) throw new CoreError('invalid_request', 'cash_consolidate names the same source twice')
    seen.add(key)
    sources.push({ wallet_pubkey: src.walletPubkey, ...proof })
  }
  return { sources, new_identity: newIdentity(p.to), request_id: requestId }
}

/** The roster row fields `ownRow` and `claimable` read. */
export type RosterRow = Pick<
  import('./results.js').RecipientStatus,
  'identity_type' | 'identity_value' | 'ia_pubkey' | 'amount_millis' | 'claimed' | 'expires_at' | 'withdraw_request_id'
>

/**
 * The caller's own row, the identity taken from the credential, never from
 * the caller's word: a signing credential's pubkey matches a pubkey row; a
 * connection_key credential matches its attestation's key and IA; a cash
 * credential matches the cash row its secret commits to (exactly, lowercase).
 * With scope `mine` the answer must be exactly that one row, else it is
 * refused as widened; with `all`, the first matching row, else not found.
 */
export function ownRow<R extends RosterRow>(rows: readonly R[], credential: Credential, scope: 'mine' | 'all' = 'mine'): R {
  const match = rowMatcher(credential)
  if (scope === 'mine') {
    if (rows.length !== 1 || !match(rows[0]!)) throw new CoreError('invalid_payload', `a scope-mine answer is not exactly the caller's row: ${rows.length} rows`)
    return rows[0]!
  }
  const row = rows.find(match)
  if (row === undefined) throw new CoreError('invalid_payload', 'this bill has no slice for the caller')
  return row
}

function rowMatcher(c: Credential): (r: RosterRow) => boolean {
  switch (c.kind) {
    case 'signing':
      return (r) => r.identity_type === 'pubkey' && r.identity_value === c.signer.pubkey
    case 'connection_key': {
      const att = c.attestation
      if (att === undefined) throw new CoreError('invalid_request', 'a connection_key credential needs its attestation to match a row')
      return (r) => r.identity_type === 'connection_key' && r.identity_value === att.connectionKey && r.ia_pubkey === att.event.pubkey
    }
    default: {
      const commit = cashCommitment(c.secret)
      return (r) => r.identity_type === 'cash' && r.identity_value === commit
    }
  }
}

/**
 * Whether a row can still be spent at `now`, and if not why: `claimed`,
 * `withdrawn` (a cash_withdraw ended it) or `expired` (past a non-zero
 * `expires_at`; the second it names is still live).
 */
export function claimable(row: Pick<RosterRow, 'claimed' | 'withdraw_request_id' | 'expires_at'>, now: number): { readonly ok: boolean; readonly reason: NotClaimableReason } {
  if (row.claimed) return { ok: false, reason: 'claimed' }
  if (row.withdraw_request_id !== undefined && row.withdraw_request_id !== '') return { ok: false, reason: 'withdrawn' }
  if (row.expires_at !== undefined && row.expires_at !== 0 && now > row.expires_at) return { ok: false, reason: 'expired' }
  return { ok: true, reason: '' }
}

/** Why a row cannot be spent (`claimable`); empty when it can. */
export type NotClaimableReason = '' | 'claimed' | 'withdrawn' | 'expired'

/** The caller's own row of a scope-mine answer and whether it can still be spent. */
export interface OwnClaim<R extends RosterRow> {
  readonly row: R
  readonly claimable: boolean
  readonly reason: NotClaimableReason
}

/**
 * `ownRow` (scope `mine`) then `claimable`: the row is found from the
 * credential, and a claimed, withdrawn or expired row is returned as not
 * claimable, never as missing.
 */
export function ownClaim<R extends RosterRow>(rows: readonly R[], credential: Credential, now: number): OwnClaim<R> {
  const row = ownRow(rows, credential, 'mine')
  const c = claimable(row, now)
  return { row, claimable: c.ok, reason: c.reason }
}
