// NIP-CW create_circle_wallet: join a Circle Hub with a member-generated
// connection key. Port of nmilat nipcw/{create_circle_wallet,identity}.go.
import { isBlank } from './bytes.js'
import type { ConnectionKeyPair } from './connectionKey.js'
import { CoreError } from './errors.js'
import { decodeGoStruct, parseGoJSON } from './gojson.js'
import type { Signer } from './identity.js'
import { eventJSON } from './claim.js'
import { buildPairingURI } from './nip47.js'

export const KIND_CIRCLE_IDENTITY_PROOF = 23199
export const METHOD_CREATE_CIRCLE_WALLET = 'create_circle_wallet'

export interface CreateCircleWalletRequest {
  pubkey: string
  connection_pubkey: string
  max_amount: bigint
  /** Seconds. */
  expiry: number
  budget_renewal?: string
  /** The kind 23199 identity proof, as JSON text. */
  identity_event: string
}

/**
 * Builds the request. The proof binds the Hub (`d`) and the member's
 * connection key (`connection`), which must differ from the member's own.
 */
export async function createCircleWalletRequest(p: {
  signer: Signer
  connection: ConnectionKeyPair | undefined
  hubPubkey: string
  maxAmountMillis: bigint
  expirySeconds: number
  budgetRenewal?: string
  now?: number
}): Promise<CreateCircleWalletRequest> {
  if (p.connection === undefined || p.connection.secret === '') {
    throw new CoreError('invalid_request', 'create_circle_wallet requires a member-generated connection key')
  }
  if (p.connection.pubkey === p.signer.pubkey) {
    throw new CoreError('invalid_request', "the connection key must differ from the requester's own key")
  }
  if (!Number.isSafeInteger(p.expirySeconds) || p.expirySeconds < 0) {
    throw new CoreError('invalid_request', 'expiry must be a non-negative number of seconds')
  }
  const proof = await p.signer.signEvent({
    kind: KIND_CIRCLE_IDENTITY_PROOF,
    created_at: p.now ?? Math.floor(Date.now() / 1000),
    tags: [
      ['d', p.hubPubkey],
      ['connection', p.connection.pubkey],
    ],
    content: '',
  })
  return {
    pubkey: p.signer.pubkey,
    connection_pubkey: p.connection.pubkey,
    max_amount: p.maxAmountMillis,
    expiry: p.expirySeconds,
    ...(p.budgetRenewal !== undefined && p.budgetRenewal !== '' && { budget_renewal: p.budgetRenewal }),
    identity_event: eventJSON(proof),
  }
}

export interface CircleWallet {
  /** The member's NWC connection. Secret-bearing (design §10). */
  readonly pairingUri: string
  readonly walletPubkey: string
  readonly relays: readonly string[]
  readonly maxAmountMillis?: bigint
  readonly expiresAt: number
  readonly feesPpm: number
  readonly budgetRenewal: string
}

const DETAILS = {
  wallet_pubkey: 'string',
  relays: 'strings',
  max_amount: 'uint',
  expires_at: 'int',
  fees_ppm: 'int',
  budget_renewal: 'string',
} as const

/**
 * Parses the result: decrypts `encrypted_details` from the Hub with the
 * member's key and builds the pairing URI over the member's connection
 * secret. Blank relays are dropped and at least one must remain.
 */
export async function parseCreateCircleWalletResult(
  result: unknown,
  p: { signer: Signer; connection: ConnectionKeyPair | undefined; hubPubkey: string },
): Promise<CircleWallet> {
  const wire = decodeGoStruct(result, { encrypted_details: 'string' }, 'create_circle_wallet result')
  const ciphertext = (wire['encrypted_details'] as string | undefined) ?? ''
  if (ciphertext === '') throw new CoreError('invalid_payload', 'create_circle_wallet: response carries no encrypted_details')
  let plaintext: string
  try {
    plaintext = await p.signer.nip44Decrypt(p.hubPubkey, ciphertext)
  } catch {
    throw new CoreError('invalid_payload', 'create_circle_wallet: could not decrypt wallet details')
  }
  const d = decodeGoStruct(parseGoJSON(plaintext, 'wallet details'), DETAILS, 'wallet details')
  if (p.connection === undefined || p.connection.secret === '') {
    throw new CoreError('invalid_request', 'create_circle_wallet requires a member-generated connection key')
  }
  const walletPubkey = (d['wallet_pubkey'] as string | undefined) ?? ''
  if (!/^[0-9a-fA-F]{64}$/.test(walletPubkey)) throw new CoreError('invalid_payload', 'wallet details carry no valid wallet_pubkey')
  const relays = ((d['relays'] as string[] | undefined) ?? []).filter((r) => !isBlank(r))
  if (relays.length === 0) throw new CoreError('invalid_payload', 'wallet details carry no usable relay, so the wallet is unreachable')
  const max = d['max_amount'] as number | undefined
  return {
    pairingUri: buildPairingURI(walletPubkey, relays, p.connection.secret),
    walletPubkey,
    relays,
    ...(max !== undefined && { maxAmountMillis: BigInt(max) }),
    expiresAt: (d['expires_at'] as number | undefined) ?? 0,
    feesPpm: (d['fees_ppm'] as number | undefined) ?? 0,
    budgetRenewal: (d['budget_renewal'] as string | undefined) ?? '',
  }
}
