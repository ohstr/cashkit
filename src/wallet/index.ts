// @ohstr/cashkit/wallet: the wallet engine (design §4–§8).
export { Wallet, type ConnectionView, type IdentityView, type Lightning, type PendingJoinView, type ProtectOutcome, type WalletState } from './wallet.js'
export {
  CashkitError,
  codeForNwc,
  exitCode,
  isCashkitError,
  type CashkitErrorOptions,
  type ErrorCode,
} from './errors.js'
export type { OperationEvent, OperationPhase } from './context.js'
export type { Fetch, Lock, LogRecord, Logger, Pocket, Query, SecretVault, Storage, StorageTx, SyncChannel, SyncMessage, WalletDeps } from './ports.js'
export { ConcurrentUpdateError } from './ports.js'
export type {
  Activity,
  ActivityDetail,
  AppendOnly,
  Collection,
  Connection,
  ConnectionKind,
  Handoff,
  HandoffKind,
  HandoffStatus,
  Holding,
  HoldingMode,
  HoldingStatus,
  IdentityRow,
  Meta,
  NewRow,
  CallAuthorizer,
  CallMethod,
  CallNeedsUser,
  CallOutcome,
  CallOutput,
  CallState,
  DerivedIdRow,
  DeviceRow,
  HoldingOrigin,
  HubRow,
  PendingCall,
  PendingJoin,
  Protection,
  Row,
  Rows,
  Sealed,
  Settings,
  SettingsRow,
  TargetDisplay,
} from './model.js'
export { COLLECTIONS, DEFAULT_SETTINGS, LOCAL_ONLY, SCHEMA_VERSION } from './model.js'
export { holdingView, pendingCallView, toJSON, type HoldingView, type PendingCallView } from './views.js'
export { MAX_ATTEMPTS, type SettleCallsReport } from './runner.js'
export type { Outcome, Report } from './report.js'
export type { ReceiveOptions, ReceiveResult, Secured, TokenReport } from './receive.js'
export type { PlannedSource, SendInput, SendPlan, SendResult } from './send.js'
export type { MintInput, MintResult } from './mint.js'
export type { DiscoverOptions, DiscoverView, OfferCard, TapView } from './discover.js'
export type { PocketSyncReport } from './pocket.js'
export type { ZapInput, ZapSent, ZapView } from './zap.js'
export type { WithdrawalView, WithdrawPhase, WithdrawPrivacy, WithdrawQuoteView, WithdrawTermsView } from './withdraw.js'
export type { OrderQuote, OrderTo, OrderView, OrderWarning, PlaceOrderInput } from './orders.js'
export type { RedeemInput, RedeemOutcome, RedeemPlan, RedeemPlanItem } from './redeem.js'
export type { ConsolidateOutcome, ConsolidateReport } from './consolidate.js'
export type { StatusOutcome } from './status.js'
export type { SettleReport } from './wallet.js'
export type { RedeemingReport } from './redeem.js'
export type { ActivityItem, Balance, HandoffView, WalletBalance } from './feed.js'
export type { CircleAlert, CircleNotification, CircleView, JoinOptions, JoinResult, JoinTermsInput, RecoverOptions, RecoverResult, SettleJoinsReport } from './circle.js'
export { looksLikeTarget, parseTarget, resolveNip05, type ParseTargetOptions, type ResolvedTarget, type TargetKind } from './target.js'
export { selectForAmount, FundsFragmentedError, InsufficientFundsError, type SelectionPlan, type Selectable } from './select.js'
export { BACKUP_FORMAT, BACKUP_VERSION, SEALED_FIELDS, type BackupFile, type ImportSummary } from './backup.js'
export { decodeRow, encodeRow } from './codec.js'
