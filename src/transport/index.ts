// @ohstr/cashkit/transport: NIP-CASH's private transport, protocol only
// (design §2.2). No I/O, no keys held.
export { TransportError, type TransportErrorCode } from './errors.js'
export {
  DEFAULT_LIMITS,
  estimatedConsolidateItemBytes,
  estimatedWireBytes,
  MAX_ITEM_ID_BYTES,
  MAX_NIP44_PLAINTEXT,
  maxSourcesForEnvelope,
  MIN_PAD_BUCKET_BYTES,
  paddedSize,
  validateAnnouncedLimits,
  validateLimits,
  type Limits,
} from './limits.js'
export { canonicalParams, paramsHash, toJSONText } from './canonical.js'
export {
  checkFreshness,
  bearerShapeOK,
  decodeEnvelope,
  encodeEnvelope,
  hasBillProof,
  hasCashSecret,
  hasProof,
  isCancelRequest,
  KIND_BILL_PROOF,
  KIND_ITEM_PROOF,
  KIND_PRIVATE_REQUEST,
  KIND_PRIVATE_RESPONSE,
  newNonce,
  sourceCount,
  verificationCost,
  type Envelope,
  type Item,
  type ItemRejection,
} from './envelope.js'
export {
  buildBillProof,
  buildItemProof,
  PROOF_FRESHNESS_FUTURE,
  PROOF_FRESHNESS_PAST,
  verifyBillProof,
  verifyItemProof,
  type ProofBinding,
} from './proof.js'
export {
  conversationKeyFor,
  decodeResponse,
  deriveReplyKey,
  encodeResponse,
  MAX_CREATED_AT_BACKDATE,
  omittedIds,
  openReply,
  randomizedCreatedAt,
  sealReply,
  wrapRequest,
  type ItemResult,
  type ResponseEnvelope,
  type ResultError,
  type WrappedRequest,
} from './wrap.js'
export {
  announcementTags,
  hubUsableForBills,
  KIND_HUB_ANNOUNCEMENT,
  MIN_REQUEST_AGE,
  normalizeNodeIdentity,
  parseAnnouncement,
  validAddr,
  type Announcement,
} from './announcement.js'
export { isPowRejection, MAX_POW_AHEAD, mineNonce, parsePowRejection, relayPowMinimum, wrapRequestPow, type PowRequest } from './pow.js'
export { isServableMethod, validateEnvelope } from './validate.js'
export { goEventJSON, parseGoEvent } from './event.js'
export { parseJSONValue } from './gojson.js'
