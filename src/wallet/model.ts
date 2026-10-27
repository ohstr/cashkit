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
  /** A merge key this wallet generated (not its identity): the bill is spent with it. */
  readonly throwawayKey?: Sealed
  /** The minter's x-only key, for comparing with Nostr keys. */
  readonly minterXonly?: string
  /**
   * How the wallet came to hold this bill (local, set once): drives the
   * warning that others may know its amount.
   */
  readonly origin?: HoldingOrigin
  /** Minted for this wallet's orders, or made only from such bills (local; never from the wire). */
  readonly ordered?: boolean
  /** ms epoch. */
  readonly addedAt: number
  readonly version: number
}

export type HoldingOrigin = 'received' | 'minted' | 'split' | 'remainder' | 'consolidated' | 'ordered' | 'reminted' | 'zap'

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
  | { readonly action: 'mint'; readonly amount: bigint; readonly to: TargetDisplay; readonly holdingId?: string; readonly handoffId?: string }
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

export type ConnectionKind = 'nwc' | 'circle' | 'cashhub'

export interface Connection {
  /** The connection's name; the key. */
  readonly id: string
  /** A NIP-47 pairing URI (`nwc`, `circle`). */
  readonly uri?: Sealed
  /** A signed connection string (`cashhub`): it carries the connection secret, so it is sealed. Never a URI built from it. */
  readonly connection?: Sealed
  /** `cashhub`: the Hub identity (TLV 4), the chain (TLV 6), whether the signature verified, when an unverified one was confirmed, the network `get_info` last reported. */
  readonly hubIdentity?: string
  readonly chain?: string
  readonly verified?: boolean
  readonly confirmedUnverifiedAt?: number
  readonly network?: string
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
}

export const DEFAULT_SETTINGS: Settings = {
  autoProtect: true,
  allowAutoConsolidate: true,
}

export interface SettingsRow extends Settings {
  readonly id: string
  readonly version: number
}

export interface Meta {
  readonly id: string
  readonly schemaVersion: number
  readonly walletId: string
  /** Written with the device row: a store whose device row names another fingerprint was copied or restored. */
  readonly storeFingerprint?: string
  /** ms epoch of the last backup export, and what it covered (see backup.ts valueFingerprint). */
  readonly lastBackupAt?: number
  readonly backupFingerprint?: string
  readonly version: number
}

export const SCHEMA_VERSION = 2

/** A call's method (NIP-CASH and NIP-CO calls that carry a request_id). */
export type CallMethod = 'mint_cash' | 'cash_transfer' | 'cash_consolidate' | 'cash_withdraw' | 'cash_order'

/** Who authorized a call, as its lookups must be signed. */
export type CallAuthorizer =
  | { readonly kind: 'identity' }
  | { readonly kind: 'throwaway'; readonly authorizerKey: Sealed }
  | { readonly kind: 'cash'; readonly holdingId: string }
  | { readonly kind: 'hub' }
  | { readonly kind: 'join' }
  | { readonly kind: 'buyer'; readonly buyerKey: Sealed }

/** What a call creates: its destination, with the secret written ahead for a cash one. */
export interface CallOutput {
  readonly role: 'new' | 'remainder' | 'remint'
  readonly destination:
    | { readonly kind: 'pubkey'; readonly pubkey: string }
    | { readonly kind: 'connection_key'; readonly key: string; readonly platform: string; readonly ia: string }
    | { readonly kind: 'cash'; readonly secret: Sealed }
    | { readonly kind: 'throwaway'; readonly pubkey: string; readonly key: Sealed }
}

/** What a finished call created, for the operation that ran it. */
export interface CallCreated {
  readonly holdingIds?: readonly string[]
  readonly handoffId?: string
  /** The holding a call moved in place (protect, a move onto a merge key). */
  readonly movedHoldingId?: string
}

export type CallState = 'prepared' | 'sent' | 'open_order' | 'open_withdraw' | 'done'
export type CallOutcome = 'applied' | 'not_applied' | 'not_sent' | 'lookup_expired' | 'user_closed' | 'replaced'
export type CallNeedsUser = 'confirm_replace' | 'replace_cap' | 'lookup_expired' | 'lookup_unanswered' | 'foreign_device' | 'refused' | 'receipt_invalid'

/**
 * A call written ahead before its first byte is sent (NIP-CASH §Lost
 * Replies): its id, exact deadline, target, sources, authorizer and every
 * secret it creates, so a crash or a lost reply can be settled by lookup.
 */
export interface PendingCall {
  /** `pc-<16 hex>`. */
  readonly id: string
  /** The operation kind that places, finishes and looks it up (a registered `CallKind`). */
  readonly kind: string
  readonly requestId: string
  readonly method: CallMethod
  /** The call's target: the bill, `sources[0]`, or the Hub connection. */
  readonly target: string
  /** The Hub's node identity (x-only). */
  readonly node: string
  readonly relays: readonly string[]
  /** The exact deadline sent (`not_after` or NIP-47 `expiration`). */
  readonly deadline: number
  /** The Hub's `max_request_age` when sent. */
  readonly hAtSend: number
  /** The device that placed it; another device's call is foreign and never re-placed. */
  readonly device: string
  readonly attempts: number
  readonly derivedFrom?: string
  readonly amount: bigint
  readonly chain?: string
  /** Holding ids the call spends or authorizes with. */
  readonly sources: readonly string[]
  readonly authorizer: CallAuthorizer
  readonly outputs: readonly CallOutput[]
  /** Display context only (op, target display); never a secret. */
  readonly context?: Readonly<Record<string, string>>
  /** The non-secret facts the kind needs to place the call again (amounts, the target identity). */
  readonly params?: Readonly<Record<string, string>>
  readonly state: CallState
  readonly outcome?: CallOutcome
  readonly lastCode?: string
  readonly lastDetail?: string
  readonly lookup?: { readonly status?: string; readonly retryAfter?: number; readonly checkedAt?: number; readonly omissions: number; readonly bearerStage?: 'without' | 'with' }
  readonly needsUser?: CallNeedsUser
  /** What the call created once applied. */
  readonly created?: CallCreated
  /** ms epoch. */
  readonly createdAt: number
  readonly version: number
}

/** This store's device (local, never exported). */
export interface DeviceRow {
  /** Always "self". */
  readonly id: string
  /** 16 random bytes, hex. */
  readonly deviceId: string
  readonly createdAt: number
  readonly storeFingerprint: string
  readonly version: number
}

/** A derived request id placed by a re-placement (local): blocks placing it twice. */
export interface DerivedIdRow {
  /** The derived request id. */
  readonly id: string
  readonly parentCallId: string
  readonly deadline: number
  /** Unix seconds: deadline + the largest H seen for the Hub. */
  readonly keepUntil: number
  readonly version: number
}

/** What the wallet saw of a Hub (local): the largest H, so records are kept long enough. */
export interface HubRow {
  /** The node identity, x-only. */
  readonly id: string
  readonly hMax: number
  readonly announcementCreatedAt?: number
  readonly version: number
}

export interface Rows {
  holdings: Holding
  activity: Activity
  handoffs: Handoff
  connections: Connection
  identity: IdentityRow
  pendingJoins: PendingJoin
  settings: SettingsRow
  meta: Meta
  pendingCalls: PendingCall
  device: DeviceRow
  derivedIds: DerivedIdRow
  hubs: HubRow
}

export type Collection = keyof Rows
/** Collections rows are only ever added to. */
export type AppendOnly = 'activity'
export type Row<C extends Collection> = Rows[C]
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never
export type NewRow<C extends AppendOnly> = DistributiveOmit<Rows[C], 'id'>
export const COLLECTIONS: readonly Collection[] = ['holdings', 'activity', 'handoffs', 'connections', 'identity', 'pendingJoins', 'settings', 'meta', 'pendingCalls', 'device', 'derivedIds', 'hubs']
/** Collections of this store only: never exported, never imported. */
export const LOCAL_ONLY: readonly Collection[] = ['device', 'derivedIds', 'hubs']
