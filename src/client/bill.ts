// Which bill a batch item acts on, and the secret that proves it is held.
// Port of nmilat nipcash/client/bill.go: the two halves come from one token
// and cannot be supplied separately.
import { fromHex, verifyProvenance, type Token } from '../core/index.js'
import { normalizeNodeIdentity } from '../transport/index.js'
import { ClientError } from './errors.js'

export interface Bill {
  /** The bill's wallet pubkey. */
  readonly target: string
  /** Signs the item's kind 23193 bill proof. Secret-bearing. */
  readonly connectionSecret: Uint8Array
  /** x-only minting node, when the token's mint signature verifies. */
  readonly node?: string
}

/** The bill a token describes. */
export function billFor(token: Token): Bill {
  const minter = verifyProvenance(token)
  let node: string | undefined
  if (minter !== undefined) {
    try {
      node = normalizeNodeIdentity(minter)
    } catch {
      node = undefined
    }
  }
  return { ...billFromParts(token.walletPubkey, token.secret), ...(node !== undefined && { node }) }
}

/** A bill from pairing data (a raw pairing URI carries no token around them). */
export function billFromParts(walletPubkey: string, connectionSecretHex: string): Bill {
  if (walletPubkey === '') throw new ClientError('bad_input', 'a batch item needs the bill wallet pubkey')
  if (connectionSecretHex === '') throw new ClientError('bad_input', 'a bill needs its connection secret, which signs the proof that you hold it')
  return { target: walletPubkey, connectionSecret: fromHex(connectionSecretHex, 'connection secret') }
}

/** Refuses a bill minted by another node than the session's Hub. */
export function checkBill(b: Bill, id: string, sessionNode: string): void {
  if (b.target === '' || b.connectionSecret.length === 0) throw new ClientError('bad_input', `item ${id} has no bill`)
  if (b.node !== undefined && b.node !== sessionNode) {
    throw new ClientError('bad_input', `item ${id}'s bill was minted by another node than this session's hub`)
  }
}
