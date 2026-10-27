// NIP-CO Cash Order, the buyer's side: the selling terms, the order fee and
// confirmation tiers, the `cash_order` request, the order reply, the buyer
// key and order notices. Port of nmilat nipCO/{terms,fees,request,order,
// buyer_key,notice}.go.
import { sha256 } from '@noble/hashes/sha2.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { bech32, bech32m } from '@scure/base'
import { decodeBolt11 } from './bolt11.js'
import { fromHex, toHex } from './bytes.js'
import { CoreError } from './errors.js'
import { newCashTarget, type CashTarget } from './identity.js'
import { tokenOrTombstone } from './lookup.js'
import { mintCashRequest, type MintRecipient } from './mint.js'
import type { NostrEvent } from './nip01.js'
import { verifyProvenance } from './provenance.js'
import { isRequestId } from './requestId.js'
import type { Tombstone } from './results.js'
import { decodeToken } from './token.js'

export const METHOD_CASH_ORDER = 'cash_order'
export const KIND_ORDER_NOTICE = 23189
export type Payment = 'lightning' | 'onchain'
export const PAYMENTS: readonly Payment[] = ['lightning', 'onchain']

const HEX64 = /^[0-9a-f]{64}$/
const badTerms = (m: string) => new CoreError('invalid_payload', `cash_order terms: ${m}`)
const badRequest = (m: string) => new CoreError('invalid_request', `cash_order: ${m}`)
const badReply = (m: string) => new CoreError('invalid_payload', `cash_order reply: ${m}`)

// ---- terms (§Terms)

export interface Tier {
  /** Absent on the last tier, which covers every larger value. */
  readonly upToMillis?: bigint
  readonly n: number
}

export interface KindTerms {
  readonly minMillis: bigint
  readonly maxMillis: bigint
  readonly feeBase: bigint
  readonly feePpm: bigint
  /** The payment window, in seconds. */
  readonly window: number
  /** On-chain only. */
  readonly confirmations?: readonly Tier[]
}

export interface BillTerms {
  readonly redeemFeeBase: bigint
  readonly redeemFeePpm: bigint
  readonly minTransferMillis: bigint
}

export interface OrderTerms {
  readonly lightning?: KindTerms
  readonly onchain?: KindTerms
  readonly bill: BillTerms
}

const uint = (v: unknown, what: string): bigint => {
  if (typeof v === 'bigint' && v >= 0n) return v
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v)
  throw badTerms(`${what} must be a non-negative integer`)
}
const obj = (v: unknown, what: string): Record<string, unknown> => {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw badTerms(`${what} is not an object`)
  return v as Record<string, unknown>
}

function parseKind(raw: unknown, onchain: boolean, what: string): KindTerms {
  const o = obj(raw, what)
  for (const k of ['min_millis', 'max_millis', 'fee_base', 'fee_ppm', 'window']) if (!(k in o)) throw badTerms(`${what}: missing ${k}`)
  let confirmations: Tier[] | undefined
  if ('confirmations' in o) {
    if (!onchain) throw badTerms('confirmations belong to on-chain terms only')
    if (!Array.isArray(o['confirmations'])) throw badTerms(`${what}: confirmations must be an array`)
    confirmations = o['confirmations'].map((t, i) => {
      const x = obj(t, `${what} tier ${i}`)
      if (!('n' in x)) throw badTerms(`${what} tier ${i}: missing n`)
      const n = uint(x['n'], `tier ${i} n`)
      if (n > 0xffffffffn) throw badTerms(`tier ${i}: n is not a 32-bit integer`)
      return { n: Number(n), ...('up_to_millis' in x && { upToMillis: uint(x['up_to_millis'], `tier ${i} up_to_millis`) }) }
    })
  }
  return {
    minMillis: uint(o['min_millis'], 'min_millis'),
    maxMillis: uint(o['max_millis'], 'max_millis'),
    feeBase: uint(o['fee_base'], 'fee_base'),
    feePpm: uint(o['fee_ppm'], 'fee_ppm'),
    window: Number(uint(o['window'], 'window')),
    ...(confirmations !== undefined && { confirmations }),
  }
}

/**
 * Reads the `cash_order` object of a `get_info` result (or the object
 * itself). An absent kind is not sold; neither kind (a retired connection's
 * `{}`) means nothing is sold. Not validated: see `validateTerms`.
 */
export function parseOrderInfo(getInfo: unknown): OrderTerms {
  const top = obj(getInfo, 'get_info')
  const o = 'cash_order' in top ? obj(top['cash_order'], 'cash_order') : top
  const b = 'bill' in o ? obj(o['bill'], 'bill') : {}
  const opt = (k: string) => (k in b ? uint(b[k], `bill ${k}`) : 0n)
  return {
    ...('lightning' in o && { lightning: parseKind(o['lightning'], false, 'lightning') }),
    ...('onchain' in o && { onchain: parseKind(o['onchain'], true, 'onchain') }),
    bill: { redeemFeeBase: opt('redeem_fee_base'), redeemFeePpm: opt('redeem_fee_ppm'), minTransferMillis: opt('min_transfer_millis') },
  }
}

export const sellsNothing = (t: OrderTerms): boolean => t.lightning === undefined && t.onchain === undefined

/** Tiers ascending, every `n` at least 1, the last tier open; `max_millis` within a known per-wallet ceiling. */
export function validateTerms(t: OrderTerms, perWalletMaxMillis?: bigint): void {
  for (const [name, k] of [
    ['lightning', t.lightning],
    ['onchain', t.onchain],
  ] as const) {
    if (k === undefined) continue
    if (k.minMillis > k.maxMillis) throw badTerms(`${name}: min_millis is above max_millis`)
    if (perWalletMaxMillis !== undefined && perWalletMaxMillis > 0n && k.maxMillis > perWalletMaxMillis) throw badTerms(`${name}: max_millis is above the per-wallet ceiling`)
    if (name === 'onchain') {
      const tiers = k.confirmations ?? []
      if (tiers.length === 0) throw badTerms('onchain: no confirmation tiers')
      let last: bigint | undefined
      tiers.forEach((tier, i) => {
        if (tier.n < 1) throw badTerms(`tier ${i}: n must be at least 1`)
        const open = tier.upToMillis === undefined
        if (open !== (i === tiers.length - 1)) throw badTerms('only the last tier is open, and it must be')
        if (tier.upToMillis !== undefined) {
          if (last !== undefined && tier.upToMillis <= last) throw badTerms('tiers must ascend')
          last = tier.upToMillis
        }
      })
    }
  }
}

/**
 * The order fee and what the buyer pays (§Response): `fee_base + ⌊fee_ppm ×
 * amount / 10^6⌋`; on-chain rounded up so `pay_millis` is whole base units,
 * and the amount itself must be.
 */
export function orderFee(payment: Payment, k: KindTerms, amountMillis: bigint): { feeMillis: bigint; payMillis: bigint } {
  if (payment === 'onchain' && amountMillis % 1000n !== 0n) throw badRequest('an on-chain amount is a whole number of base units (a multiple of 1000 millis)')
  let fee = k.feeBase + (k.feePpm * amountMillis) / 1_000_000n
  let pay = amountMillis + fee
  if (payment === 'onchain' && pay % 1000n !== 0n) {
    const up = 1000n - (pay % 1000n)
    pay += up
    fee += up
  }
  return { feeMillis: fee, payMillis: pay }
}

/** The `n` of the tier a payment of `valueMillis` falls in. */
export function confirmationsFor(tiers: readonly Tier[], valueMillis: bigint): number {
  for (const t of tiers) if (t.upToMillis === undefined || t.upToMillis >= valueMillis) return t.n
  throw badTerms(`no confirmation tier covers ${valueMillis} millis`)
}

/** The bills one payment mints (§Minting): none at or below the fee, else bills of `maxMillis` then the rest. */
export function mintSplit(receivedMillis: bigint, feeMillis: bigint, maxMillis: bigint): bigint[] {
  if (receivedMillis <= feeMillis) return []
  let rest = receivedMillis - feeMillis
  if (maxMillis === 0n) return [rest]
  const out: bigint[] = []
  while (rest > maxMillis) {
    out.push(maxMillis)
    rest -= maxMillis
  }
  out.push(rest)
  return out
}

// ---- request (§Request)

export interface CashOrderRequest {
  recipient: { identity_type: string; identity_value: string; ia_pubkey?: string }
  amount_millis: bigint
  payment: Payment
  notify: string
  request_id: string
}

/** The `cash_order` params: one recipient (validated as a `mint_cash` one), never `recipients`, `expiry` or a secret. */
export function cashOrderRequest(p: { recipient: MintRecipient; amountMillis: bigint; payment: Payment; notify: string; requestId: string }): CashOrderRequest {
  if (p.amountMillis <= 0n) throw badRequest('amount_millis must be positive')
  if (p.payment === 'onchain' && p.amountMillis % 1000n !== 0n) throw badRequest('an on-chain amount is a multiple of 1000 millis')
  if (p.payment !== 'lightning' && p.payment !== 'onchain') throw badRequest(`payment ${String(p.payment)}`)
  if (!HEX64.test(p.notify)) throw badRequest('notify is 64 lowercase hex')
  if (!isRequestId(p.requestId)) throw badRequest('request_id must be 16 to 32 bytes of lowercase hex')
  const m = mintCashRequest({ recipients: [{ ...p.recipient, amountMillis: p.amountMillis }], requestId: p.requestId })
  const r = m.recipients[0]!
  return {
    recipient: { identity_type: r.identity_type, identity_value: r.identity_value, ...(r.ia_pubkey !== undefined && { ia_pubkey: r.ia_pubkey }) },
    amount_millis: p.amountMillis,
    payment: p.payment,
    notify: p.notify,
    request_id: p.requestId,
  }
}

// ---- buyer key (§The Buyer Key)

const N = secp256k1.Point.CURVE().n
const LABEL = new TextEncoder().encode('cash-order-key:v1')

function keyFromDigest(d: Uint8Array): { secretKey: string; pubkey: string } {
  const k = BigInt(`0x${toHex(d)}`)
  if (k === 0n || k >= N) throw new CoreError('buyer_key_unusable', 'this cash secret gives an unusable buyer key: generate another')
  return { secretKey: toHex(d), pubkey: toHex(secp256k1.getPublicKey(d, true).subarray(1)) }
}

/** `SHA256("cash-order-key:v1" ‖ secret)`, over the secret's 32 raw bytes. */
export function buyerKeyFromSecret(secretHex: string): { secretKey: string; pubkey: string } {
  const s = fromHex(secretHex, 'cash secret')
  if (s.length !== 32) throw new CoreError('invalid_field', 'a cash secret is 32 bytes')
  const m = new Uint8Array(LABEL.length + 32)
  m.set(LABEL)
  m.set(s, LABEL.length)
  return keyFromDigest(sha256(m))
}

/** A cash secret whose buyer key is usable (drawn again otherwise). */
export function newCashOrderTarget(random?: (n: number) => Uint8Array): CashTarget & { readonly buyerKey: { secretKey: string; pubkey: string } } {
  for (let i = 0; i < 16; i++) {
    const t = newCashTarget(random)
    try {
      return { ...t, buyerKey: buyerKeyFromSecret(t.secret) }
    } catch (err) {
      if (!(err instanceof CoreError) || err.code !== 'buyer_key_unusable') throw err
    }
  }
  throw new CoreError('buyer_key_unusable', 'no usable buyer key could be drawn')
}

/** A fresh random buyer key (identity recipients): never a Nostr identity key. */
export function newBuyerKey(random: (n: number) => Uint8Array): { secretKey: string; pubkey: string } {
  for (let i = 0; i < 16; i++) {
    try {
      return keyFromDigest(random(32))
    } catch {
      // out of range: draw again
    }
  }
  throw new CoreError('buyer_key_unusable', 'no usable buyer key could be drawn')
}

export const newNotify = (random: (n: number) => Uint8Array): string => toHex(random(32))

// ---- notices (§Order Notice)

export const orderNoticeFilter = (notify: string) => ({ kinds: [KIND_ORDER_NOTICE], '#p': [notify] })

/** An order notice for `notify`: kind 23189, tags exactly `[["p", notify]]`, empty content. It proves nothing. */
export const isOrderNotice = (ev: Pick<NostrEvent, 'kind' | 'tags' | 'content'>, notify: string): boolean =>
  ev.kind === KIND_ORDER_NOTICE && ev.content === '' && ev.tags.length === 1 && ev.tags[0]!.length === 2 && ev.tags[0]![0] === 'p' && ev.tags[0]![1] === notify

// ---- on-chain addresses

/** Segwit address HRPs by chain and network, as `get_info` reports them. */
const SEGWIT_HRPS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  bitcoin: { mainnet: 'bc', testnet: 'tb', testnet4: 'tb', signet: 'tb', regtest: 'bcrt' },
  flokicoin: { mainnet: 'fc', testnet: 'tf', regtest: 'fcrt' },
}

/**
 * Normalizes a segwit address for the Hub's chain and network: all lower or
 * all upper case (returned lowercased); version 0 bech32 with a 20- or
 * 32-byte program, versions 1–16 bech32m with 2–40 bytes; the HRP of the
 * chain and network when known.
 */
export function normalizeAddress(addr: string, chain: string | undefined, network: string | undefined): string {
  if (addr.toLowerCase() !== addr && addr.toUpperCase() !== addr) throw new CoreError('invalid_address', 'the address mixes upper and lower case')
  const a = addr.toLowerCase()
  let dec: { prefix: string; words: number[] } | undefined
  let m = false
  try {
    dec = bech32.decode(a as `${string}1${string}`, 90)
  } catch {
    try {
      dec = bech32m.decode(a as `${string}1${string}`, 90)
      m = true
    } catch {
      throw new CoreError('invalid_address', 'not a segwit address')
    }
  }
  const want = chain !== undefined && network !== undefined ? SEGWIT_HRPS[chain]?.[network] : undefined
  if (want !== undefined && dec.prefix !== want) throw new CoreError('invalid_address', `the address is for ${dec.prefix}, not the Hub's ${chain} ${network}`)
  if (dec.words.length < 1) throw new CoreError('invalid_address', 'not a segwit address')
  const version = dec.words[0]!
  let prog: Uint8Array
  try {
    prog = Uint8Array.from(bech32.fromWords(dec.words.slice(1)))
  } catch {
    throw new CoreError('invalid_address', 'malformed witness program')
  }
  if (version > 16 || prog.length < 2 || prog.length > 40) throw new CoreError('invalid_address', 'malformed witness program')
  if (version === 0 && (m || (prog.length !== 20 && prog.length !== 32))) throw new CoreError('invalid_address', 'malformed version 0 address')
  if (version > 0 && !m) throw new CoreError('invalid_address', `a version ${version} address is bech32m`)
  return a
}

// ---- the order (§Response, §Reading an Order)

export const ORDER_STATES = ['open', 'paid', 'minted', 'expired', 'closed'] as const
export type OrderState = (typeof ORDER_STATES)[number]

export interface OrderBill {
  readonly walletPubkey: string
  /** The token, or the tombstone of a bill already destroyed. */
  readonly token: string | Tombstone
  readonly amountMillis: bigint
  readonly paidMillis: bigint
  readonly outpoint?: string
}

export interface Order {
  readonly state: OrderState
  readonly payment: Payment
  readonly amountMillis: bigint
  readonly feeMillis: bigint
  readonly payMillis: bigint
  readonly invoice?: string
  readonly address?: string
  readonly confirmations?: number
  readonly payBy: number
  readonly bills: readonly OrderBill[]
}

const hasKey = (v: unknown, name: string): boolean => {
  if (Array.isArray(v)) return v.some((x) => hasKey(x, name))
  if (v !== null && typeof v === 'object') return Object.entries(v).some(([k, x]) => k === name || hasKey(x, name))
  return false
}

const replyUint = (v: unknown, what: string): bigint => {
  try {
    return uint(v, what)
  } catch {
    throw badReply(`${what} must be a non-negative integer`)
  }
}

/**
 * Reads an order, as a reply or a lookup's `done` carries it (§Response).
 * Anything off its shape is an error, never a state: a `cash_secret`
 * anywhere; an unknown state or payment; a payment or amount that does not
 * echo the request; `pay_millis` ≠ amount + fee; the wrong of invoice and
 * address for the kind; a Lightning invoice not for exactly `pay_millis`; an
 * on-chain order without confirmations or an address not of the Hub's chain
 * and network; a bill whose token does not decode, names another wallet, or
 * was not minted by the Hub identity.
 */
export function parseOrder(v: unknown, p: { request?: Pick<CashOrderRequest, 'payment' | 'amount_millis'>; hubIdentity: string; chain?: string; network?: string }): Order {
  if (hasKey(v, 'cash_secret')) throw badReply('the Hub returned a cash secret')
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw badReply('not an object')
  const o = v as Record<string, unknown>
  const state = o['state']
  if (!(ORDER_STATES as readonly unknown[]).includes(state)) throw badReply(`unknown state ${String(state)}`)
  const payment = o['payment']
  if (payment !== 'lightning' && payment !== 'onchain') throw badReply(`unknown payment ${String(payment)}`)
  if (p.request !== undefined && payment !== p.request.payment) throw badReply(`payment ${payment}, ordered ${p.request.payment}`)
  const amountMillis = replyUint(o['amount_millis'], 'amount_millis')
  const feeMillis = replyUint(o['fee_millis'], 'fee_millis')
  const payMillis = replyUint(o['pay_millis'], 'pay_millis')
  if (p.request !== undefined && amountMillis !== p.request.amount_millis) throw badReply(`amount_millis ${amountMillis}, ordered ${p.request.amount_millis}`)
  if (amountMillis === 0n || payMillis !== amountMillis + feeMillis) throw badReply('pay_millis is not amount_millis + fee_millis')
  const payBy = Number(replyUint(o['pay_by'], 'pay_by'))
  if (payBy <= 0) throw badReply('no pay_by')
  const invoice = typeof o['invoice'] === 'string' && o['invoice'] !== '' ? o['invoice'] : undefined
  const rawAddress = typeof o['address'] === 'string' && o['address'] !== '' ? o['address'] : undefined
  if (invoice !== undefined && rawAddress !== undefined) throw badReply('both invoice and address')
  let address: string | undefined
  let confirmations: number | undefined
  if (payment === 'lightning') {
    if (invoice === undefined || (o['confirmations'] !== undefined && o['confirmations'] !== 0)) throw badReply('a Lightning order carries an invoice and no confirmations')
    let amt: bigint
    try {
      amt = decodeBolt11(invoice).amountMillis
    } catch {
      throw badReply('the invoice does not decode')
    }
    if (amt !== payMillis) throw badReply(amt === 0n ? 'the invoice names no amount' : `the invoice is for ${amt}, not pay_millis ${payMillis}`)
  } else {
    if (rawAddress === undefined || payMillis % 1000n !== 0n) throw badReply('an on-chain order carries an address and whole base units')
    confirmations = Number(replyUint(o['confirmations'], 'confirmations'))
    if (confirmations < 1) throw badReply('an on-chain order needs at least one confirmation')
    try {
      address = normalizeAddress(rawAddress, p.chain, p.network)
    } catch (err) {
      throw badReply((err as Error).message)
    }
  }
  const rawBills = o['bills'] ?? []
  if (!Array.isArray(rawBills)) throw badReply('bills must be an array')
  const bills = rawBills.map((b, i): OrderBill => {
    if (b === null || typeof b !== 'object' || Array.isArray(b)) throw badReply(`bill ${i} is not an object`)
    const x = b as Record<string, unknown>
    const walletPubkey = x['wallet_pubkey']
    if (typeof walletPubkey !== 'string' || !HEX64.test(walletPubkey)) throw badReply(`bill ${i}: wallet_pubkey`)
    const amt = replyUint(x['amount_millis'], `bill ${i} amount_millis`)
    if (amt === 0n) throw badReply(`bill ${i}: amount`)
    const outpoint = typeof x['outpoint'] === 'string' && x['outpoint'] !== '' ? x['outpoint'] : undefined
    if (payment === 'lightning' && outpoint !== undefined) throw badReply(`bill ${i}: an outpoint on a Lightning bill`)
    if (payment === 'onchain' && (outpoint === undefined || !/^[0-9a-fA-F]{64}:\d{1,10}$/.test(outpoint))) throw badReply(`bill ${i}: an on-chain bill names its outpoint`)
    let token: string | Tombstone
    try {
      const t = tokenOrTombstone(x['cash_token'])
      if (t === undefined) throw new Error('missing')
      token = t
    } catch {
      throw badReply(`bill ${i}: cash_token is neither a token nor a tombstone`)
    }
    if (typeof token === 'string') {
      let tok
      try {
        tok = decodeToken(token)
      } catch {
        throw badReply(`bill ${i}: the token does not decode`)
      }
      if (tok.walletPubkey !== walletPubkey) throw badReply(`bill ${i}: the token names another wallet`)
      const xonly = verifyProvenance(tok)?.xonly
      if (xonly === undefined || xonly !== p.hubIdentity) throw badReply(`bill ${i}: the token was not minted by this Hub`)
    }
    return { walletPubkey, token, amountMillis: amt, paidMillis: replyUint(x['paid_millis'] ?? 0, `bill ${i} paid_millis`), ...(outpoint !== undefined && { outpoint }) }
  })
  return { state: state as OrderState, payment, amountMillis, feeMillis, payMillis, ...(invoice !== undefined && { invoice }), ...(address !== undefined && { address }), ...(confirmations !== undefined && { confirmations }), payBy, bills }
}

/** Finished (§Client Behavior): Lightning at `minted` or `expired`, on-chain at `expired` or `closed` (which may still gain bills). */
export const finished = (o: Pick<Order, 'state' | 'payment'>): boolean => (o.payment === 'lightning' ? o.state === 'minted' || o.state === 'expired' : o.state === 'expired' || o.state === 'closed')

/** A held reply, past `pay_by`, never seen paid, minted or closed, and no bill: the order ended unpaid, whatever its lookup says. */
export const endedUnpaid = (o: Pick<Order, 'payBy' | 'bills'>, f: { heldReply: boolean; sawProgress: boolean; now: number }): boolean => f.heldReply && f.now > o.payBy && !f.sawProgress && o.bills.length === 0
