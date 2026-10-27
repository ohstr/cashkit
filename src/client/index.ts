// @ohstr/cashkit/client: Hub and NWC clients over a RelayPool port
// (design §2.3). Stateless about the wallet.
export type { ClientDeps, Filter, RelayPool, SubscriptionHandlers } from './ports.js'
export { ClientError, NotServedError, WalletError, type ClientErrorCode } from './errors.js'
export { billFor, billFromParts, checkBill, minterOf, selectVerifiedCopy, type Bill } from './bill.js'
export {
  classifyCall,
  joinOutcomes,
  notServedOutcomes,
  oneItemError,
  safeToResend,
  succeeded,
  type BillState,
  type CallClass,
  type ItemOutcome,
  type OutcomeState,
} from './outcome.js'
export { BatchSession, deadlineFor, MIN_PUBLISH_MARGIN, openBatchSession, NOT_SENT, SUBSCRIPTION_ACK_WAIT_MS, type ItemBinding, type ItemBuilder, type SendOptions, type SendResult } from './session.js'
export {
  buildItem,
  consolidateMany,
  redeemMany,
  statusMany,
  transferMany,
  type BatchConsolidate,
  type BatchRedeem,
  type BatchResult,
  type BatchStatus,
  type BatchTransfer,
  type TypedOutcome,
} from './methods.js'
export {
  CashClient,
  type CheckClaimResult,
} from './cashClient.js'
export { NWC_CALL_TIMEOUT_MS, NwcClient, type GetInfoResult, type MakeInvoiceParams } from './nwcClient.js'
export { connectCircle, type CircleHub, type ConnectCircleOptions } from './circleClient.js'
export { cancelWithdraw, lookupWithdraw, placeWithdraw, quoteWithdraw, watchPayout } from './withdraw.js'
export { connectOrder, type ConnectOrderOptions, type OrderClient } from './order.js'
export { CircleWalletClient, type CircleBudget, type PaymentPreview } from './circleWalletClient.js'
export { createCircleWalletItem, createCircleWalletMany, type BatchCircleJoin, type CircleJoinOutcome } from './circleJoin.js'
export { EventQueue, fetchRelayInfo, readEvents } from './relayIO.js'
export { lookupMany, lookupOne, type BatchLookup, type LookupAuthorizer } from './lookup.js'
export { hubView, type HubView } from './hubView.js'
export { inspectConnection } from './inspect.js'
export { CashHubClient, type CashHubClientOptions } from './cashHubClient.js'
export {
  AnnouncementError,
  checkLive,
  fromLspsInfo,
  fromLspsName,
  KIND_LSP_ANNOUNCEMENT,
  LspSeen,
  newAnnouncement,
  newestAnnouncements,
  nodeIds,
  parseAnnouncement,
  parseListProtocols,
  parseLsps1Info,
  parseLsps2Menu,
  parseLsps5,
  signingPayload,
  toLspsName,
  type FeeRow,
  type FieldDiff,
  type LiveDiff,
  type LspAnnouncement,
  type LspFields,
  type LspOption,
  type LspStatus,
} from './lsp.js'
export { relayAttestationSource, resolveConnection, RESOLVE_READ_MS, type ResolveConnectionOptions, type ResolvedConnection } from './identity.js'
