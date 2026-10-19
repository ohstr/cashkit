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
export type { Fetch, Lock, LogRecord, Logger, Query, SecretVault, Storage, StorageTx, SyncChannel, SyncMessage, WalletDeps } from './ports.js'
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
  PendingJoin,
  Protection,
  Row,
  Rows,
  Sealed,
  Settings,
  SettingsRow,
  TargetDisplay,
} from './model.js'
export { COLLECTIONS, DEFAULT_SETTINGS, SCHEMA_VERSION } from './model.js'
export { holdingView, toJSON, type HoldingView } from './views.js'
export type { Outcome, Report } from './report.js'
export type { ReceiveResult, Secured, TokenReport } from './receive.js'
export type { PlannedSource, SendInput, SendPlan, SendResult } from './send.js'
export type { RedeemInput, RedeemOutcome, RedeemPlan, RedeemPlanItem } from './redeem.js'
export type { ConsolidateOutcome, ConsolidateReport } from './consolidate.js'
export type { StatusOutcome } from './status.js'
export type { SettleReport } from './settle.js'
export type { ActivityItem, Balance, HandoffView, WalletBalance } from './feed.js'
export type { JoinInput, JoinResult } from './circle.js'
export { looksLikeTarget, parseTarget, resolveNip05, type ParseTargetOptions, type ResolvedTarget, type TargetKind } from './target.js'
export { selectForAmount, FundsFragmentedError, InsufficientFundsError, type SelectionPlan, type Selectable } from './select.js'
export { BACKUP_FORMAT, BACKUP_VERSION, SEALED_FIELDS, type BackupFile, type ImportSummary } from './backup.js'
export { decodeRow, encodeRow } from './codec.js'
