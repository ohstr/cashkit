// @ohstr/cashkit/client: Hub and NWC clients over a RelayPool port
// (design §2.3). Stateless about the wallet.
export type { ClientDeps, Filter, RelayPool, SubscriptionHandlers } from './ports.js'
export { ClientError, fallbackReasonOf, NotServedError, PartialProgressError, PrivateJoinUnavailableError, WalletError, type ClientErrorCode } from './errors.js'
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
  type RekeyCashSliceParams,
  type RekeyCashSliceResult,
  type TransferFromSourcesParams,
  type TransferFromSourcesResult,
} from './cashClient.js'
export { NWC_CALL_TIMEOUT_MS, NwcClient, type GetInfoResult, type MakeInvoiceParams } from './nwcClient.js'
export { CircleClient, type CircleJoinResult, type JoinOptions, type JoinTransport } from './circleClient.js'
export { createCircleWalletItem, createCircleWalletMany, type BatchCircleJoin, type CircleJoinOutcome, type CreateCircleWalletParams } from './circleJoin.js'
export { EventQueue, readEvents } from './relayIO.js'
