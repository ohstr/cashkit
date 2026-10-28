// What a signed connection string is, before anything is stored (NIP-CASH
// §Connection Signatures; NIP-CO §Wire Format; NIP-CW §The Circle Wallet Hub
// Connection): decoded, its signature checked and, when asked, its Hub's
// `get_info` read and compared with TLV 4 and TLV 6. Nothing is signed, sent
// or written, and no private transport is opened.
import { CoreError, decodeAnyConnection, onlineCheck, readNetworkChain, type HubConnection } from '../core/index.js'
import { ClientError } from './errors.js'
import { hubView, type HubView } from './hubView.js'
import { NwcClient } from './nwcClient.js'
import type { ClientDeps } from './ports.js'

/**
 * A `cashhub1`, `cashorder1` or `circlehub1` string as a `HubView`. Any other
 * form, a URI included, is `connection_invalid`. With `online`, the Hub's
 * `get_info` is read: its node identity (`pubkey`, or a Circle Wallet Hub's
 * `circle_wallet.identity`) and `chain` must match the string, else the view
 * says `online: 'fail'`; a Hub that does not answer throws as the transport
 * does. Without `online`, the view says `unchecked`.
 */
export async function inspectConnection(deps: ClientDeps, value: string, o: { readonly online?: boolean } = {}): Promise<HubView> {
  const s = value.trim()
  let d
  try {
    d = decodeAnyConnection(s)
  } catch (err) {
    throw new ClientError('connection_invalid', `not a cashhub1, cashorder1 or circlehub1 connection string: ${(err as Error).message}`, { cause: err })
  }
  if (o.online !== true) return hubView(d.kind, s, d.connection, d.verdict, 'unchecked')
  const r = await checkOnline(deps, d.kind, d.connection)
  return hubView(d.kind, s, d.connection, d.verdict, r.pass ? 'pass' : 'fail', r.network)
}

async function checkOnline(deps: ClientDeps, kind: HubView['kind'], c: HubConnection): Promise<{ pass: boolean; network?: string }> {
  const nwc = new NwcClient(deps, { walletPubkey: c.walletPubkey, relays: c.relays, secret: c.secret, extra: {} })
  const info = await nwc.getInfo()
  const nc = readNetworkChain(info)
  const network = nc.network ?? (nc.networkRaw !== undefined ? String(nc.networkRaw) : undefined)
  const identity = kind === 'circlehub' ? info.circle_wallet?.identity : typeof info.pubkey === 'string' ? info.pubkey : undefined
  try {
    onlineCheck(c, { ...(identity !== undefined && { identity }), ...(nc.chain !== undefined && { chain: nc.chain }) })
  } catch (err) {
    if (err instanceof CoreError) return { pass: false, ...(network !== undefined && { network }) }
    throw err
  }
  return { pass: true, ...(network !== undefined && { network }) }
}
