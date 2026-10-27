// Who a send goes to. Port of cashctl internal/credential (ParseTarget,
// ResolveConnectionTarget, LooksLikeTarget) and credential/nip05.go, whose
// lookup rules design §10 adopts: HTTPS only, no redirects, a 256 KiB body
// cap, a 15 s timeout, and the name must map to 64-hex.
import {
  decodeNConnection,
  decodeNpub,
  encodeNpub,
  newCashTarget,
  NCONNECTION_HRP,
  pubkeyTarget,
  resolvedConnectionKeyTarget,
  connectionKeyTarget,
  type CashTarget,
  type Target,
} from '../core/index.js'
import { CashkitError } from './errors.js'
import type { Fetch } from './ports.js'

export type TargetKind = 'pubkey' | 'connection' | 'cash'

export interface ResolvedTarget {
  readonly target: Target
  readonly kind: TargetKind
  /**
   * Public form only, safe for activity (§4.2): an npub, a NIP-05 name, a
   * platform label, or "cash". Never an nconnection string or a secret.
   */
  readonly display: string
  /** What a NIP-05 or nconnection target resolved to; "" otherwise. */
  readonly resolved: string
}

export const MAX_NIP05_BODY = 256 << 10
export const NIP05_TIMEOUT_MS = 15_000

const isHexPubkey = (s: string) => /^[0-9a-fA-F]{64}$/.test(s)
const NIP05_NAME = /^[A-Za-z0-9\-_.]+$/
const NIP05_DOMAIN = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/

/** `looksLikeNIP05`: name@domain under nmilat's name and domain rules. */
export function looksLikeNip05(s: string): boolean {
  const at = s.indexOf('@')
  if (at <= 0) return false
  return NIP05_NAME.test(s.slice(0, at)) && NIP05_DOMAIN.test(s.slice(at + 1))
}

/** `LooksLikeTarget`: how cashctl tells a target from an amount. */
export function looksLikeTarget(s: string): boolean {
  if (s === 'cash' || isHexPubkey(s) || s.startsWith('npub1') || looksLikeNip05(s) || s.startsWith(`${NCONNECTION_HRP}1`)) return true
  const colon = s.indexOf(':')
  return colon > 0 && ['pubkey', 'connection'].includes(s.slice(0, colon))
}

const invalid = (input: string, msg: string) => new CashkitError('invalid_input', msg, { input })

/** `resolveNIP05`. */
export async function resolveNip05(identifier: string, fetchFn: Fetch | undefined): Promise<string> {
  const at = identifier.indexOf('@')
  const name = identifier.slice(0, at)
  const domain = identifier.slice(at + 1)
  const f = fetchFn ?? (globalThis.fetch as unknown as Fetch | undefined)
  if (f === undefined) throw new CashkitError('network', `cannot resolve ${identifier}: no fetch available`)
  const url = `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(name)}`
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), NIP05_TIMEOUT_MS)
  let body: string
  try {
    let resp: Awaited<ReturnType<Fetch>>
    try {
      resp = await f(url, { redirect: 'error', signal: ctl.signal, headers: { accept: 'application/json' } })
    } catch (err) {
      throw new CashkitError('network', `could not reach ${domain}: ${(err as Error).message}`, { cause: err })
    }
    // A fetch that cannot refuse redirects still reports where it ended up.
    if (resp.redirected === true || (resp.url !== '' && resp.url !== url)) {
      throw new CashkitError('invalid_input', `${domain}'s nostr.json redirects, and cashkit does not follow redirects on an identity lookup`, { input: identifier })
    }
    if (resp.status !== 200) throw new CashkitError('network', `${domain} returned HTTP ${resp.status} for nostr.json`)
    body = await resp.text()
  } finally {
    clearTimeout(timer)
  }
  if (new TextEncoder().encode(body).length > MAX_NIP05_BODY) {
    throw invalid(identifier, `${domain}'s nostr.json is larger than the ${MAX_NIP05_BODY >> 10} KiB cashkit will read`)
  }
  let doc: unknown
  try {
    doc = JSON.parse(body)
  } catch {
    throw invalid(identifier, `${domain}'s nostr.json is not valid`)
  }
  const names = (doc as { names?: unknown } | null)?.names
  const pub = names !== null && typeof names === 'object' ? (names as Record<string, unknown>)[name] : undefined
  if (pub === undefined) throw new CashkitError('not_found', `${domain}'s nostr.json has no entry for "${name}"`, { input: identifier })
  if (typeof pub !== 'string' || !isHexPubkey(pub)) throw invalid(identifier, `${domain}'s nostr.json returned an invalid pubkey for "${name}"`)
  return pub
}

/** `resolveIdentityString`: hex, npub or NIP-05 to a lowercase hex pubkey. */
async function resolveIdentity(s: string, fetchFn: Fetch | undefined): Promise<{ hex: string; viaNip05: boolean }> {
  if (isHexPubkey(s)) return { hex: s.toLowerCase(), viaNip05: false }
  if (s.startsWith('npub1')) {
    try {
      return { hex: decodeNpub(s), viaNip05: false }
    } catch (err) {
      throw invalid(s, `not a valid npub: ${(err as Error).message}`)
    }
  }
  if (looksLikeNip05(s)) return { hex: await resolveNip05(s, fetchFn), viaNip05: true }
  throw invalid(s, 'must be a hex pubkey, npub1..., or a NIP-05 identifier (name@domain)')
}

export interface ParseTargetOptions {
  /** Identity Authority for an nconnection that doesn't name one. */
  readonly ia?: string
  readonly fetch?: Fetch
  readonly random?: (n: number) => Uint8Array
}

/**
 * `ParseTarget`, plus `ResolveConnectionTarget` when `ia` is given. An
 * nconnection without an IA is a `usage` error naming it, as cashctl's
 * `--json`/`--yes` path is.
 */
export async function parseTarget(input: string, o: ParseTargetOptions = {}): Promise<ResolvedTarget> {
  const s = input.trim()
  if (s === 'cash') {
    const target: CashTarget = newCashTarget(o.random)
    return { target, kind: 'cash', display: 'cash', resolved: '' }
  }
  if (isHexPubkey(s) || s.startsWith('npub1') || looksLikeNip05(s)) {
    const { hex, viaNip05 } = await resolveIdentity(s, o.fetch)
    return { target: pubkeyTarget(hex), kind: 'pubkey', display: viaNip05 ? s : encodeNpub(hex), resolved: viaNip05 ? `pubkey ${hex}` : '' }
  }
  if (s.startsWith(`${NCONNECTION_HRP}1`)) {
    let nc
    try {
      nc = decodeNConnection(s)
    } catch (err) {
      throw invalid(s, `not a valid nconnection: ${(err as Error).message}`)
    }
    const platform = nc.platform === '' ? 'this connection' : nc.platform
    if (o.ia === undefined || o.ia.trim() === '') {
      throw new CashkitError(
        'usage',
        `this nconnection doesn't specify who to trust as Identity Authority for ${platform}: pass ia (hex pubkey or NIP-05), or use the connection:<platform>:<external-id>:<ia-pubkey> form`,
        { input: s, hint: 'planSend({ ..., ia })' },
      )
    }
    const ia = await resolveIdentity(o.ia.trim(), o.fetch)
    const iaDisplay = ia.viaNip05 ? `${o.ia.trim()} (${ia.hex})` : ia.hex
    const label = nc.platform === '' ? 'unspecified-platform' : nc.platform
    return {
      target: resolvedConnectionKeyTarget(nc.connectionKey, nc.platform, ia.hex),
      kind: 'connection',
      display: `${label} connection`,
      resolved: `${label} connection; Identity Authority: ${iaDisplay}`,
    }
  }
  const colon = s.indexOf(':')
  if (colon < 0) {
    throw invalid(s, 'target must be a hex pubkey, npub1..., a NIP-05 identifier (name@domain), an nconnection1..., pubkey:<hex>, connection:<platform>:<external-id>:<ia-pubkey>, or cash')
  }
  const prefix = s.slice(0, colon)
  const rest = s.slice(colon + 1)
  switch (prefix) {
    case 'pubkey':
      if (rest === '') throw invalid(s, 'pubkey: target is missing a hex pubkey')
      return { target: pubkeyTarget(rest), kind: 'pubkey', display: isHexPubkey(rest) ? encodeNpub(rest.toLowerCase()) : 'pubkey', resolved: '' }
    case 'connection': {
      const parts = rest.split(':')
      if (parts.length !== 3) throw invalid(s, `connection: target needs platform:external-id:ia-pubkey, got ${parts.length} field(s)`)
      const [platform, externalId, ia] = parts as [string, string, string]
      let target: Target
      try {
        target = connectionKeyTarget(platform, externalId, ia)
      } catch (err) {
        throw invalid(s, `${(err as Error).message}; for this account, paste its nconnection1 string`)
      }
      return { target, kind: 'connection', display: `${platform || 'unspecified-platform'} connection`, resolved: '' }
    }
    default:
      throw invalid(s, `unknown target kind "${prefix}" (want pubkey, connection, or cash)`)
  }
}
