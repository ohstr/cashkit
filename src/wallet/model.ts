// The wallet's stored rows (design §4). Secret-bearing fields are always
// Sealed by the SecretVault; nothing in a row is a plaintext secret.

/** A vault-sealed value. `alg` names the vault that sealed it. */
export interface Sealed {
  readonly alg: string
  /** Opaque to the engine. */
  readonly data: string
}

export type HoldingStatus = 'held' | 'redeemed' | 'transferred' | 'consolidated' | 'spent'
export type HoldingMode = 'pubkey' | 'cash' | 'connection_key'
export type Protection = 'none' | 'shared' | 'protected'

export interface ConnectionKeyBinding {
  readonly platform: string
  readonly externalId: string
  readonly attestationId: string
  readonly iaPubkey: string
}

/** One bill the wallet knows about (cashctl `ledger.Entry`). */
export interface Holding {
  /** Opaque, e.g. "h-3f9a01c2"; stable across reactivation. */
  readonly id: string
  /** Lowercased; unique (design §4.1). */
  readonly token: string
  readonly walletPubkey: string
  readonly minterPubkey?: string
  /** Hex hub-group fingerprint from the token, "" when absent. */
  readonly hubGroup: string
  readonly relayUrls: readonly string[]
  readonly amount?: bigint
  readonly expiresAt?: number
  readonly verified: boolean
  readonly status: HoldingStatus
  readonly mode: HoldingMode
  /** Cash mode only. */
  readonly protection: Protection
  readonly cashSecret?: Sealed
  readonly connectionKey?: ConnectionKeyBinding
  // Write-ahead slots (§5.1).
  readonly pendingCashSecret?: Sealed
  readonly pendingDestinationCashSecret?: Sealed
  readonly pendingThrowawayKey?: Sealed
  readonly throwawayKey?: Sealed
  /** ms epoch. */
  readonly addedAt: number
  readonly version: number
}

/** What a send was addressed to, in public form only (§4.2). */
export type TargetDisplay = string

export type ActivityDetail =
  | { readonly action: 'receive'; readonly amount: bigint; readonly holdingId: string; readonly mode: HoldingMode }
  | { readonly action: 'protect'; readonly holdingId: string }
  | { readonly action: 'redeem'; readonly amount: bigint; readonly feesPaid: bigint; readonly into: string; readonly holdingIds: readonly string[] }
  | {
      readonly action: 'send'
      readonly amount: bigint
      readonly to: TargetDisplay
      readonly handoffId?: string
      readonly holdingIds: readonly string[]
      readonly remainderId?: string
    }
  | { readonly action: 'consolidate'; readonly amount: bigint; readonly from: readonly string[]; readonly into?: string }
  | { readonly action: 'spent'; readonly holdingId: string }
  | { readonly action: 'join'; readonly circle: string; readonly connection: string }

export type Activity = ActivityDetail & { readonly id: string; readonly at: number }

export type HandoffKind = 'cash_note' | 'gift'
export type HandoffStatus = 'unclaimed' | 'claimed' | 'expired' | 'sent'

export interface Handoff {
  readonly id: string
  readonly at: number
  readonly kind: HandoffKind
  /** A cash note `<token>#<secret>` or a gift token. Sealed. */
  readonly handoff: Sealed
  readonly amount: bigint
  readonly target: TargetDisplay
  readonly walletPubkey: string
  readonly expiresAt?: number
  readonly status: HandoffStatus
  readonly checkedAt?: number
  readonly version: number
}

export type ConnectionKind = 'nwc' | 'circle'

export interface Connection {
  /** The connection's name; the key. */
  readonly id: string
  readonly uri: Sealed
  readonly kind: ConnectionKind
  readonly isDefault: boolean
  readonly lastKnownBalance?: { readonly millis: bigint; readonly at: number }
  readonly version: number
}

export interface IdentityRow {
  /** Always "self". */
  readonly id: string
  readonly source: 'local' | 'signer'
  readonly pubkey: string
  readonly label?: string
  readonly priv?: Sealed
  readonly version: number
}

export interface PendingJoin {
  /** The connection pubkey. */
  readonly id: string
  readonly connectionSecret: Sealed
  readonly hubPubkey: string
  readonly hubLabel: string
  readonly name: string
  readonly at: number
  readonly version: number
}

export interface Settings {
  readonly autoProtect: boolean
  readonly allowAutoConsolidate: boolean
  readonly fallbackRelays: readonly string[]
  readonly timeouts: { readonly statusMs: number; readonly redeemPerBillMs: number; readonly redeemCapMs: number }
  readonly displayUnit?: 'loki' | 'sat' | 'millis'
}

export const DEFAULT_SETTINGS: Settings = {
  autoProtect: true,
  allowAutoConsolidate: true,
  fallbackRelays: [],
  timeouts: { statusMs: 15_000, redeemPerBillMs: 30_000, redeemCapMs: 300_000 },
}

export interface SettingsRow extends Settings {
  readonly id: string
  readonly version: number
}

export interface Meta {
  readonly id: string
  readonly schemaVersion: number
  readonly walletId: string
  /** ms epoch of the last backup export, and what it covered (see backup.ts valueFingerprint). */
  readonly lastBackupAt?: number
  readonly backupFingerprint?: string
  readonly version: number
}

export const SCHEMA_VERSION = 1

export interface Rows {
  holdings: Holding
  activity: Activity
  handoffs: Handoff
  connections: Connection
  identity: IdentityRow
  pendingJoins: PendingJoin
  settings: SettingsRow
  meta: Meta
}

export type Collection = keyof Rows
/** Collections rows are only ever added to. */
export type AppendOnly = 'activity'
export type Row<C extends Collection> = Rows[C]
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never
export type NewRow<C extends AppendOnly> = DistributiveOmit<Rows[C], 'id'>
export const COLLECTIONS: readonly Collection[] = ['holdings', 'activity', 'handoffs', 'connections', 'identity', 'pendingJoins', 'settings', 'meta']
