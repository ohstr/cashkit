// @ohstr/cashkit/client: Hub and NWC clients over a RelayPool port
// (design §2.3). Stateless about the wallet.
export type { ClientDeps, Filter, RelayPool, SubscriptionHandlers } from './ports.js'
export { ClientError, NotServedError, PartialProgressError, WalletError, type ClientErrorCode } from './errors.js'
export { billFor, billFromParts, checkBill, type Bill } from './bill.js'
export {
  joinOutcomes,
  notServedOutcomes,
  oneItemError,
  safeToResend,
  succeeded,
  type BillState,
  type ItemOutcome,
  type OutcomeState,
} from './outcome.js'
export { BatchSession, NOT_AFTER_WINDOW, NOT_SENT, SUBSCRIPTION_ACK_WAIT_MS, type ItemBinding, type ItemBuilder, type SendResult } from './session.js'
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
export { NWC_CALL_TIMEOUT_MS, NwcClient, type MakeInvoiceParams } from './nwcClient.js'
export { CircleClient, type CreateCircleWalletParams } from './circleClient.js'
export { EventQueue, readEvents } from './relayIO.js'
