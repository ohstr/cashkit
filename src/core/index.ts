// @ohstr/cashkit/core: pure protocol codecs and crypto, no I/O (design §2.1).
export { CoreError, type CoreErrorCode } from './errors.js'
export { fromHex, fromUtf8, toHex, trimSpace, utf8 } from './bytes.js'
export { goString, toJSONText } from './json.js'
export { bech32Hrp, sniff, type InputKind } from './sniff.js'
export {
  decodeToken,
  encodeToken,
  hasProvenance,
  MINT_SIGNATURE_LEN,
  type Token,
} from './token.js'
export {
  CASH_HUB_HRP,
  CIRCLE_HUB_HRP,
  decodeCashHubConnection,
  decodeCircleHubConnection,
  encodeCashHubConnection,
  encodeCircleHubConnection,
  type HubConnection,
} from './hubConnection.js'
export { decodeNConnection, encodeNConnection, NCONNECTION_HRP, type NConnection } from './nconnection.js'
export { joinCashString, splitCashString } from './cashString.js'
export { HUB_GROUP_LEN, hubGroupFor, sameHubGroup } from './hubGroup.js'
export {
  FLND_SIGNED_MESSAGE_PREFIX,
  LND_SIGNED_MESSAGE_PREFIX,
  mintPayload,
  signedMessagePrefix,
  verifyProvenance,
} from './provenance.js'
export { connectionKeyFromSecret, newConnectionKey, type ConnectionKeyPair } from './connectionKey.js'
export { decodeBolt11, type Bolt11Invoice } from './bolt11.js'
export {
  decodeNaddr,
  decodeNevent,
  decodeNote,
  decodeNprofile,
  decodeNpub,
  decodeNsec,
  encodeNaddr,
  encodeNevent,
  encodeNote,
  encodeNprofile,
  encodeNpub,
  encodeNsec,
  type AddressPointer,
  type EventPointer,
  type ProfilePointer,
} from './nip19.js'
export {
  buildPairingURI,
  chooseEncryption,
  ENCRYPTION_NIP04,
  ENCRYPTION_NIP44_V2,
  KIND_NWC_INFO,
  KIND_NWC_REQUEST,
  KIND_NWC_RESPONSE,
  nwcRequestEvent,
  PAIRING_URI_SCHEME,
  parseInfoEvent,
  parsePairingURI,
  parseResponseEvent,
  type NWCEncryption,
  type NWCError,
  type NWCResponse,
  type PairingInfo,
  type WalletInfo,
} from './nip47.js'
export {
  createCircleWalletRequest,
  KIND_CIRCLE_IDENTITY_PROOF,
  METHOD_CREATE_CIRCLE_WALLET,
  parseCreateCircleWalletResult,
  type CircleWallet,
  type CreateCircleWalletRequest,
} from './nipcw.js'
export {
  bySecret,
  bySigning,
  bySigningConnectionKey,
  cashTargetFromSecret,
  connectionKeyTarget,
  decryptDelivery,
  localSigner,
  newCashTarget,
  newIdentityHash,
  pubkeyTarget,
  resolvedConnectionKeyTarget,
  type CashTarget,
  type Credential,
  type IdentityType,
  type Signer,
  type Target,
} from './identity.js'
export { KIND_ATTESTATION, parseAttestation, type Attestation, type Evidence } from './attestation.js'
export {
  buildProof,
  cashConsolidateRequest,
  cashRedeemRequest,
  cashTransferRequest,
  claimProofTags,
  eventJSON,
  KIND_CLAIM_PROOF,
  matchClaim,
  matchClaimAuto,
  NO_LOCAL_IDENTITY,
  type CashConsolidateRequest,
  type CashRedeemRequest,
  type CashTransferRequest,
  type ConsolidateSource,
  type NewIdentity,
  type ProofBinding,
  type ProofFields,
  type RecipientStatus,
} from './claim.js'
export {
  isSpent,
  parseCashConsolidateResult,
  parseCashRedeemResult,
  parseCashStatusResult,
  parseCashTransferResult,
  recipientToken,
  STATUS_SPENT,
  type CashConsolidateResult,
  type CashRedeemResult,
  type CashStatusResult,
  type CashTransferResult,
  type RecipientStatusRow,
} from './results.js'
export * as nip44 from './nip44.js'
export {
  finalizeEvent,
  getEventHash,
  getPublicKey,
  powDifficulty,
  serializeEvent,
  verifyEvent,
  type EventTemplate,
  type NostrEvent,
  type UnsignedEvent,
} from './nip01.js'
export { redact, sanitize } from './redact.js'
export { formatAmount, formatMillis, MAX_AMOUNT_MILLIS, MILLIS_PER_UNIT, parseUnits, unitForHrp } from './units.js'
export { NCRYPTSEC_HRP, nip49Decrypt, nip49Encrypt, type KeySecurity, type Nip49EncryptOptions } from './nip49.js'
export * as nip04 from './nip04.js'
