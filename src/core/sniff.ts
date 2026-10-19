// Classifies a pasted string without decoding it fully or touching the
// network. Port of cashctl internal/dial.Sniff, so a wallet's paste box
// routes input exactly as cashctl does.
import { bech32Decode } from './bech32.js'
import { trimSpace } from './bytes.js'
import { CASH_HUB_HRP, CIRCLE_HUB_HRP } from './hubConnection.js'

export type InputKind =
  | 'cash_token'
  | 'cashhub'
  | 'circlehub'
  | 'nwc_uri'
  | 'nostr_entity'
  | 'lightning_invoice'
  | 'unknown'

const NOSTR_ENTITY_HRPS = new Set(['npub', 'nsec', 'note', 'nprofile', 'nevent', 'naddr', 'nconnection'])

/** The bech32 HRP of `s` after trimming, or undefined if it is not bech32. */
export function bech32Hrp(s: string): string | undefined {
  try {
    return bech32Decode(trimSpace(s)).hrp
  } catch {
    return undefined
  }
}

/**
 * What kind of string `s` is. Only the framing is checked: a "cash_token"
 * may still fail `decodeToken`. Any bech32 HRP that is not a Hub, a Nostr
 * entity or `ln…` counts as a cash token, because a token may use any HRP.
 * Split off a `#<cash_secret>` first (`splitCashString`).
 */
export function sniff(s: string): InputKind {
  if (trimSpace(s).startsWith('nostr+walletconnect://')) return 'nwc_uri'
  const hrp = bech32Hrp(s)
  if (hrp === undefined) return 'unknown'
  if (hrp === CIRCLE_HUB_HRP) return 'circlehub'
  if (hrp === CASH_HUB_HRP) return 'cashhub'
  if (NOSTR_ENTITY_HRPS.has(hrp)) return 'nostr_entity'
  if (hrp.startsWith('ln')) return 'lightning_invoice'
  return 'cash_token'
}
