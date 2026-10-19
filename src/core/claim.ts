// Claim proofs and the requests that carry them: cash_redeem, cash_transfer
// and cash_consolidate. Port of nmilat nipcash/{proof,cash_redeem,
// cash_transfer,cash_consolidate,claim}.go. The objects returned use the
// wire's field names; amounts stay bigint until the transport serializes
// them.
import { decodeBolt11 } from './bolt11.js'
import { newConnectionKey } from './connectionKey.js'
import { CoreError } from './errors.js'
import { toJSONText } from './json.js'
import { newIdentityHash, type Credential, type IdentityType, type Target } from './identity.js'
import type { NostrEvent } from './nip01.js'

/** NIP-CASH §Methods: the claim proof event kind. */
export const KIND_CLAIM_PROOF = 23198

/** What a claim proof commits to. */
export interface ProofBinding {
  /** The bill's wallet pubkey (the `d` tag). */
  readonly walletPubkey: string
  readonly bolt11Hash?: string
  readonly newIdentityHash?: string
  readonly amountMillis?: bigint
}

/** The claim proof's tags, in nmilat's order. */
export function claimProofTags(b: ProofBinding): string[][] {
  const tags = [['d', b.walletPubkey]]
  if (b.bolt11Hash) tags.push(['bolt11_hash', b.bolt11Hash])
  if (b.newIdentityHash) tags.push(['new_identity_hash', b.newIdentityHash])
  if (b.amountMillis !== undefined) tags.push(['amount_millis', b.amountMillis.toString(10)])
  return tags
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
      const connectionKey = newConnectionKey(c.platform, c.externalId)
      const tags = [...claimProofTags(binding), ['connection_key', connectionKey], ['e', att.event.id]]
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
  if (t.identityType === 'connection_key' && t.iaPubkey === '') {
    throw new CoreError('invalid_request', 'a connection_key identity requires an ia_pubkey')
  }
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
  const { paymentHash } = decodeBolt11(p.invoice)
  const proof = await buildProof(p.credential, { walletPubkey: p.walletPubkey, bolt11Hash: paymentHash }, p.now)
  return { invoice: p.invoice, ...(p.amount !== undefined && { amount: p.amount }), ...proof }
}

export interface CashTransferRequest extends ProofFields {
  new_identity: NewIdentity
  amount_millis?: bigint
}

/**
 * cash_transfer: move the bill (or `splitAmount` of it) to `to`. The proof
 * binds the amount that moves: the split, or the whole current amount.
 */
export async function cashTransferRequest(p: {
  walletPubkey: string
  credential: Credential
  to: Target
  currentAmount: bigint
  splitAmount?: bigint
  now?: number
}): Promise<CashTransferRequest> {
  checkTarget(p.to)
  const binding: ProofBinding = {
    walletPubkey: p.walletPubkey,
    newIdentityHash: newIdentityHash(p.to),
    amountMillis: p.splitAmount ?? p.currentAmount,
  }
  const proof = await buildProof(p.credential, binding, p.now)
  return { ...proof, new_identity: newIdentity(p.to), ...(p.splitAmount !== undefined && { amount_millis: p.splitAmount }) }
}

export interface ConsolidateSource {
  readonly walletPubkey: string
  readonly amount: bigint
  readonly credential: Credential
}

export interface CashConsolidateRequest {
  sources: ({ wallet_pubkey: string } & Omit<ProofFields, 'cash_secret'>)[]
  new_identity: NewIdentity
}

/**
 * cash_consolidate: merge at least two non-cash bills into one owned by
 * `to`. A cash-mode source or the same source twice is refused.
 */
export async function cashConsolidateRequest(p: {
  sources: readonly ConsolidateSource[]
  to: Target
  now?: number
}): Promise<CashConsolidateRequest> {
  if (p.sources.length < 2) throw new CoreError('invalid_request', 'cash_consolidate requires at least two sources')
  checkTarget(p.to)
  const hash = newIdentityHash(p.to)
  const seen = new Set<string>()
  const sources: CashConsolidateRequest['sources'] = []
  for (const s of p.sources) {
    const proof = await buildProof(s.credential, { walletPubkey: s.walletPubkey, newIdentityHash: hash, amountMillis: s.amount }, p.now)
    if (proof.identity_type === 'cash' || proof.cash_secret) {
      throw new CoreError('invalid_request', 'cash_consolidate does not accept a cash-mode source')
    }
    const key = `${s.walletPubkey}\0${proof.identity_type ?? ''}\0${proof.identity_value ?? ''}`
    if (seen.has(key)) throw new CoreError('invalid_request', 'cash_consolidate names the same source twice')
    seen.add(key)
    sources.push({ wallet_pubkey: s.walletPubkey, ...proof })
  }
  return { sources, new_identity: newIdentity(p.to) }
}

/** One recipient row of a cash_status roster. */
export interface RecipientStatus {
  readonly identity_type: string
  readonly identity_value?: string
  readonly amount_millis: bigint
  readonly claimed: boolean
}

/** No local identity: pubkey rows never match. */
export const NO_LOCAL_IDENTITY = ''

function matches(r: RecipientStatus, isCash: boolean, asPubkey: string): boolean {
  if (r.claimed) return false
  if (isCash) return r.identity_type === 'cash'
  return r.identity_type === 'pubkey' && asPubkey !== NO_LOCAL_IDENTITY && r.identity_value === asPubkey
}

/**
 * The amount of the first unclaimed row this holder may claim: a cash row
 * for a cash claim, else a pubkey row naming `asPubkey`. Any other identity
 * type (including `bearer`) never matches.
 */
export function matchClaim(rows: readonly RecipientStatus[], isCash: boolean, asPubkey: string): bigint | undefined {
  return rows.find((r) => matches(r, isCash, asPubkey))?.amount_millis
}

/** The first unclaimed row that is cash, or a pubkey row naming `asPubkey`. */
export function matchClaimAuto(rows: readonly RecipientStatus[], asPubkey: string): RecipientStatus | undefined {
  return rows.find((r) => matches(r, true, asPubkey) || matches(r, false, asPubkey))
}
