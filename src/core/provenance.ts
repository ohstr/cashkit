// Mint provenance (NIP-CASH §Mint Provenance). Port of nmilat
// nipcash/provenance.go: the minting node signs the payload with its
// Lightning identity key exactly as `signmessage` does, and anyone can
// recover that key from the token.
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes, toHex, utf8 } from './bytes.js'
import { MINT_SIGNATURE_LEN, type Token } from './token.js'

/** flnd's signed-message prefix, used for `lokicash`. */
export const FLND_SIGNED_MESSAGE_PREFIX = 'Flokicoin Lightning Signed Message:'
/** lnd's signed-message prefix, used for `satscash`. */
export const LND_SIGNED_MESSAGE_PREFIX = 'Lightning Signed Message:'

const PREFIXES: Readonly<Record<string, string>> = {
  lokicash: FLND_SIGNED_MESSAGE_PREFIX,
  satscash: LND_SIGNED_MESSAGE_PREFIX,
}

/**
 * The signed-message prefix for a token HRP, or undefined when the HRP has
 * none. A token under such an HRP can carry no verifiable provenance.
 */
export function signedMessagePrefix(hrp: string): string | undefined {
  return Object.hasOwn(PREFIXES, hrp) ? PREFIXES[hrp] : undefined
}

/** `lokicash-mint:v1:<hrp>:<wallet pubkey hex>:<amount millis>`. */
export function mintPayload(hrp: string, walletPubkeyHex: string, amountMillis: bigint): string {
  return `lokicash-mint:v1:${hrp}:${walletPubkeyHex}:${amountMillis.toString(10)}`
}

/**
 * Recovers the minter of a token: the compressed secp256k1 pubkey (hex)
 * whose key signed this token's wallet pubkey and amount, or undefined when
 * the token has no well-formed provenance.
 *
 * A tampered token usually still recovers SOME key, just not the real
 * minter's. Callers compare the result against a minter they trust.
 */
export function verifyProvenance(
  t: Pick<Token, 'hrp' | 'walletPubkey' | 'mintSignature' | 'attestedAmountMillis'>,
): string | undefined {
  const sig = t.mintSignature
  if (sig === undefined || t.attestedAmountMillis === undefined) return undefined
  if (sig.length !== MINT_SIGNATURE_LEN) return undefined
  const prefix = signedMessagePrefix(t.hrp)
  if (prefix === undefined) return undefined

  // Compact signature header: 27 + recovery id, +4 when the signer's key is
  // compressed. The key is returned compressed either way.
  const header = sig[0]!
  if (header < 27 || header > 34) return undefined
  const recovery = (header - 27) & 3

  const digest = sha256(sha256(utf8(prefix + mintPayload(t.hrp, t.walletPubkey, t.attestedAmountMillis))))
  try {
    const recovered = concatBytes(Uint8Array.of(recovery), sig.subarray(1))
    return toHex(secp256k1.recoverPublicKey(recovered, digest, { prehash: false }))
  } catch {
    return undefined
  }
}
