// What a wallet shows about a Hub connection string (NIP-CASH §Connection
// Signatures, §Network and Chain): who signed it, whether that verified,
// whether the online check passed, and on which network. The label is the
// issuer's claim, sanitized; it is never shown as verified on its own.
import { qrForm, sanitizeText, type ConnUnverifiedReason, type HubConnection } from '../core/index.js'

export interface HubView {
  readonly kind: 'cashhub' | 'cashorder' | 'circlehub'
  readonly connectionPubkey: string
  readonly hubIdentity: string
  /** TLV 4 in groups of four hex characters, for reading aloud. */
  readonly hubFingerprint: string
  readonly chain: string
  /** TLV 3, sanitized and capped at 40 characters: what the issuer calls itself. */
  readonly label: string
  readonly verified: boolean
  readonly verifyReason?: ConnUnverifiedReason
  readonly online: 'unchecked' | 'pass' | 'fail'
  readonly network?: string
  /** True for anything but `mainnet`, a missing or unknown network included. */
  readonly testNetwork: boolean
  /** The string in uppercase, for a QR code. */
  readonly qr: string
}

export function hubView(
  kind: HubView['kind'],
  s: string,
  c: HubConnection,
  verdict: { readonly verified: boolean; readonly reason?: ConnUnverifiedReason },
  online: HubView['online'],
  network?: string,
): HubView {
  return {
    kind,
    connectionPubkey: c.walletPubkey,
    hubIdentity: c.hubIdentity,
    hubFingerprint: c.hubIdentity.match(/.{4}/g)!.join(' '),
    chain: c.chain,
    label: sanitizeText(c.label, 40),
    verified: verdict.verified,
    ...(verdict.reason !== undefined && { verifyReason: verdict.reason }),
    online,
    ...(network !== undefined && { network }),
    testNetwork: network !== 'mainnet',
    qr: qrForm(s),
  }
}
