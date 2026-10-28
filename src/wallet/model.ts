// The wallet's stored rows (design §4). Secret-bearing fields are always
// Sealed by the SecretVault; nothing in a row is a plaintext secret.

/** A vault-sealed value. `alg` names the vault that sealed it. */
export interface Sealed {
  readonly alg: string
  /** Opaque to the engine. */
  readonly data: string
}

/** `redeeming`: a redeem whose outcome is unclear left the row claimed; it is in no balance and no plan until a re-read settles it. */
export type HoldingStatus = 'held' | 'redeeming' | 'redeemed' | 'transferred' | 'consolidated' | 'spent'
export type HoldingMode = 'pubkey' | 'cash' | 'connection_key'
export type Protection = 'none' | 'shared' | 'protected'

/**
 * A connection-key slice's identity: the account the IA attested, and the
 * attestation (kind 35522, public) every claim proof on it names.
 */
export interface ConnectionKeyBinding {
  readonly platform: string
  readonly externalId: string
  readonly attestationId: string
  readonly iaPubkey: string
  /** The ConnectionKey (the slice's `identity_value`). */
  readonly key?: string
  /** The attestation event as JSON text; without it the bill cannot be spent. */
  readonly attestation?: string
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
  /**
   * Sets of holdings (ids, sorted, joined by commas) whose merge the Hub
   * refused `RESTRICTED` (fee terms that differ, which the client cannot
   * see): such a set is not planned again.
   */
  readonly refusedMerges?: readonly string[]
  /** A zap bill's Cash Zap fields (NIP-CZ): its provenance, and so its Hub, is recovered only with them. */
  readonly zap?: { readonly recipient: string; readonly sender: string; readonly zapTarget: string; readonly issuedAt: number; readonly expiresAt: number }
  /** Kept out of every merge the wallet plans (local; set by the user). */
  readonly excludeFromMerge?: boolean
  /** `min_transfer_millis` as `cash_status` last reported it: bills merge only with bills of the same figure. */
  readonly minTransfer?: bigint
  /** While `redeeming`: the invoice the Hub was asked to pay, where it was made, and when it expires. */
  readonly redeem?: {
    readonly invoice: string
    readonly into: string
    readonly invoiceExpiresAt?: number
    readonly since: number
    /**
     * Set when the bill became `redeemed` only because its row stayed claimed
     * a day past the invoice's expiry ("presumed paid"): it is still re-read
     * by `settle()`, and goes back to held if a later read shows it unclaimed.
     */
    readonly presumedAt?: number
  }
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
  | { readonly action: 'withdraw'; readonly amount: bigint; readonly holdingId: string }
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

export type ConnectionKind = 'nwc' | 'circle_wallet' | 'cashhub' | 'circlehub'

export interface Connection {
  /** The connection's name; the key. */
  readonly id: string
  /** A NIP-47 pairing URI (`nwc`, `circle`). */
  readonly uri?: Sealed
  /** A signed connection string (`cashhub`, `circlehub`): it carries the connection secret, so it is sealed. Never a URI built from it. */
  readonly connection?: Sealed
  /** `cashhub`, `circlehub`: the Hub identity (TLV 4), the chain (TLV 6), whether the signature verified, when an unverified one was confirmed, the network `get_info` last reported. */
  readonly hubIdentity?: string
  readonly chain?: string
  readonly verified?: boolean
  readonly confirmedUnverifiedAt?: number
  readonly network?: string
  /** `circle_wallet`: the wallet's fields (never a URI) and the member's own secret, sealed. `circlehub`: the Hub pubkey (TLV 0) the string names. */
  readonly walletPubkey?: string
  readonly relays?: readonly string[]
  readonly secret?: Sealed
  /** `circle_wallet`: the circle it belongs to and the terms its details fixed. */
  readonly circle?: CircleDetailsRow
  /** `circle_wallet`: a rotation this device asked for: the new key, its secret sealed, and when it completes. */
  readonly rotation?: { readonly newConnectionPubkey: string; readonly newSecret: Sealed; readonly completesAt?: number; readonly requestedAt: number }
  /** `circle_wallet`: frozen (no payment is attempted until unfrozen or rotated), or moved to a key this device does not hold. */
  readonly frozen?: boolean
  readonly moved?: boolean
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

/** A Circle Wallet's circle and the terms its join details fixed (NIP-CW §Response). */
export interface CircleDetailsRow {
  /** The Hub connection's pubkey (TLV 0): one wallet per Hub pubkey. */
  readonly hubPubkey: string
  readonly hubIdentity: string
  readonly hubLabel: string
  /** The `circlehub1` the join used, sealed (it carries the Hub connection's secret). */
  readonly hubConnection: Sealed
  /** The member key the join was signed with: member requests and lookups are signed by it. */
  readonly memberPubkey: string
  readonly connectionPubkey: string
  readonly maxAmount: bigint
  readonly maxReceive: bigint
  readonly expiresAt: number
  readonly feesPpm: number
  readonly dustThresholdMillis: bigint
  readonly rotationDelaySecs?: number
  readonly budgetRenewal: string
  readonly createdAt: number
}

export type PendingJoinNeedsUser = 'join_not_made' | 'lookup_expired' | 'lookup_unanswered' | 'auth'

/** A join written ahead before it is sent (NIP-CW §Lost Join Reply): settled by a join lookup. */
export interface PendingJoin {
  /** The connection pubkey. */
  readonly id: string
  readonly connectionSecret: Sealed
  readonly hubPubkey: string
  readonly hubLabel: string
  /** The `circlehub1` the join goes through, sealed. */
  readonly hubConnection: Sealed
  readonly signerPubkey: string
  readonly name: string
  readonly makeDefault: boolean
  readonly proofCreatedAt: number
  /** `proofCreatedAt + 300`, as the lookup must send it. */
  readonly deadline: number
  readonly terms: { readonly maxAmount: bigint; readonly maxReceive: bigint; readonly expiry: number; readonly budgetRenewal: string }
  readonly device: string
  readonly sent: boolean
  /**
   * `omissions` counts lookups that went unanswered; `viaOther` is set once a
   * lookup went through another held `circlehub1` of the same Hub pubkey.
   */
  readonly lookup?: { readonly retryAfter?: number; readonly omissions: number; readonly viaOther?: boolean }
  readonly needsUser?: PendingJoinNeedsUser
  readonly at: number
  readonly version: number
}

export interface Settings {
  readonly autoProtect: boolean
  readonly allowAutoConsolidate: boolean
  /** Minters the user approved, each for one chain (NIP-CZ rule 8). */
  readonly trustedMinters: readonly { readonly minter: string; readonly chain: string }[]
  /** The least life a Cash Zap needs to be totalled (NIP-CZ §Counting). */
  readonly zapMinLifeSeconds: number
  /**
   * Set a NIP-40 `expiration` on Cash Pocket wraps of entries with an
   * `expires_at` (NIP-CP §Writing, Expiration). Off by default; the wrap is
   * deleted all the same.
   */
  readonly pocketNip40: boolean
  /** Discover: the user's curators. Absent until set. */
  readonly discover?: DiscoverSettings
}

/** Whose lists rank offers besides the user's follows (NIP-CASH §Curators). */
export interface DiscoverSettings {
  readonly curators: readonly string[]
  /** `app`: defaults an app supplied; any edit by the user makes them `user`. */
  readonly curatorSource: 'user' | 'app'
  /** The app's name for its defaults ("Curated by …"). */
  readonly curatorSourceName?: string
  /** Publish the set with private items (NIP-44 to self). Default true. */
  readonly curatorsPrivate?: boolean
}

export const DEFAULT_SETTINGS: Settings = {
  autoProtect: true,
  allowAutoConsolidate: true,
  trustedMinters: [],
  zapMinLifeSeconds: 2_592_000,
  pocketNip40: false,
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
  /** A zap transfer's bill: its signed `issued_at` and `expires_at` (absent when the Hub ignored `zap_target`). */
  readonly zap?: { readonly issuedAt: number; readonly expiresAt: number }
}

/** An order as the wallet last read it (NIP-CO §Response), and what the wallet learned about it. */
/** A bill of an order as last read. */
export interface OrderRecordBill {
  readonly walletPubkey: string
  readonly amountMillis: bigint
  readonly paidMillis: bigint
  readonly outpoint?: string
  readonly holdingId?: string
  readonly spent: boolean
  /**
   * The bill's own row, read before it is kept, is not what was ordered:
   * `not_ours` (another recipient: no holding is made) or `expires` (it
   * carries an expiry: kept, not marked ordered).
   */
  readonly problem?: 'not_ours' | 'expires'
}

export interface OrderRecord {
  readonly state: 'open' | 'paid' | 'minted' | 'expired' | 'closed'
  readonly payment: 'lightning' | 'onchain'
  readonly amountMillis: bigint
  readonly feeMillis: bigint
  readonly payMillis: bigint
  readonly invoice?: string
  readonly invoiceExpiresAt?: number
  readonly address?: string
  readonly confirmations?: number
  readonly payBy: number
  readonly bills: readonly OrderRecordBill[]
  /** Ever seen `paid`, `minted` or `closed`. */
  readonly sawProgress: boolean
  /** The reply's fee or confirmations differ from the terms read before placing. */
  readonly termsChanged?: boolean
  /** The Hub committed a reply this wallet refuses to show for payment (an invoice for another amount, an address of another chain). */
  readonly invalidReply?: string
  readonly endedUnpaid?: boolean
  readonly finished: boolean
  readonly checkedAt: number
}

/** A payout as the wallet last read it (NIP-CASH §Response). */
export interface WithdrawalRecord {
  readonly address?: string
  readonly receipt?: string
  readonly amountMillis: bigint
  readonly feeMillis: bigint
  readonly payoutMillis: bigint
  readonly sentBy: number
  readonly finalDepth: number
  readonly state: 'queued' | 'broadcast' | 'confirmed' | 'final' | 'cancelled'
  readonly signed: boolean
  readonly depth?: number
  readonly tx?: string
  readonly txid?: string
  readonly vout?: number
  /** Ever seen `confirmed` or `final`: a later `broadcast` is a reorganisation, shown neutrally. */
  readonly sawConfirmed: boolean
  readonly txCheck?: 'ok' | 'mismatch'
  readonly remintHoldingId?: string
  /** A cancelled payout whose re-minted bill was already a tombstone: nothing came back (`remint_gone`, a notice, never a question). */
  readonly remintGone?: { readonly reason?: string }
  readonly checkedAt: number
}

export type CallState = 'prepared' | 'sent' | 'open_order' | 'open_withdraw' | 'done'
export type CallOutcome = 'applied' | 'not_applied' | 'not_sent' | 'lookup_expired' | 'user_closed' | 'replaced'
/**
 * `remint_gone` is only read from rows stored by an earlier version: a
 * cancelled payout whose re-mint is gone is now recorded on the withdrawal
 * (`WithdrawalRecord.remintGone`) and told as a notice, never left waiting
 * for the user.
 */
export type CallNeedsUser = 'confirm_replace' | 'replace_cap' | 'lookup_expired' | 'lookup_unanswered' | 'foreign_device' | 'refused' | 'receipt_invalid' | 'remint_gone'

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
  /** The call was once answered `REQUEST_REUSED`: an `unknown` then asks the user before placing it again. */
  readonly sawReused?: boolean
  readonly lookup?: { readonly status?: string; readonly retryAfter?: number; readonly checkedAt?: number; readonly omissions: number; readonly bearerStage?: 'without' | 'with' }
  readonly needsUser?: CallNeedsUser
  /** What the call created once applied. */
  readonly created?: CallCreated
  /** A `cash_order` call: the order as last read (no secret, no `notify`, no request id). */
  readonly order?: OrderRecord
  /** A zap transfer: the signed kind-9522 event, once built and published. */
  readonly zapEvent?: string
  /** A zap transfer: at least one relay accepted its 9522. Until then settle() publishes it again. */
  readonly zapPublished?: boolean
  /** A `cash_withdraw` call: the payout as last read; the address, receipt and transaction only until it ends. */
  readonly withdrawal?: WithdrawalRecord
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

/** What discover keeps between runs (local): version floors, tap outcomes and whom it ranked by. */
export interface DiscoverBookRow {
  /** Always "self". */
  readonly id: string
  /** VersionBook snapshot: the newest version seen and the deletion floor per address. */
  readonly book: string
  /** TapCache snapshot. */
  readonly taps: string
  readonly follows: readonly string[]
  readonly curators: readonly string[]
  /** Per verified operator, the follows that follow it. */
  readonly operatorFollowers: readonly (readonly [string, readonly string[]])[]
  /** The relays the last refresh read: a recommendation's relay hint. */
  readonly relays: readonly string[]
  /** What the last refresh accepted: chains held, test networks shown. */
  readonly chains: readonly string[]
  readonly testNetworks: boolean
  readonly version: number
}

/** An event discover holds (local): a current listing, a signal, a deletion or operator offers. */
export interface DiscoverEventRow {
  /** The event id. */
  readonly id: string
  /** The event, as JSON. */
  readonly event: string
  /** A listing only the global request found: shown apart. */
  readonly unreviewed: boolean
  readonly version: number
}

/** A recommendation or report waiting to be signed and published (local). */
export interface DiscoverOutboxRow {
  /** `rec:<node>` (one per node) or `rep:<random>`. */
  readonly id: string
  readonly kind: 'recommendation' | 'report'
  readonly node: string
  readonly address?: string
  readonly reason?: string
  /** The unsigned event, as JSON; signed only when published. */
  readonly template: string
  readonly relays: readonly string[]
  /** Unix seconds: never published before. */
  readonly dueAt: number
  /** Unix seconds. */
  readonly createdAt: number
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
  pocket: PocketRow
  discoverBook: DiscoverBookRow
  discoverEvents: DiscoverEventRow
  discoverOutbox: DiscoverOutboxRow
}

/** What this device last wrote to the Cash Pocket for a `w`: its revision, state and the wrap (with its key, to delete it). */
export interface PocketRow {
  /** The entry's `w`. */
  readonly id: string
  readonly rev: number
  readonly state: string
  readonly wrapId: string
  readonly wrapKey: Sealed
  readonly at: number
  /** `cash_status` showed the bill has no expiry, so its missing `expires_at` is not looked up again. */
  readonly noExpiry?: boolean
  readonly version: number
}

export type Collection = keyof Rows
/** Collections rows are only ever added to. */
export type AppendOnly = 'activity'
export type Row<C extends Collection> = Rows[C]
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never
export type NewRow<C extends AppendOnly> = DistributiveOmit<Rows[C], 'id'>
export const COLLECTIONS: readonly Collection[] = ['holdings', 'activity', 'handoffs', 'connections', 'identity', 'pendingJoins', 'settings', 'meta', 'pendingCalls', 'device', 'derivedIds', 'hubs', 'pocket', 'discoverBook', 'discoverEvents', 'discoverOutbox']
/** Collections of this store only: never exported, never imported. */
export const LOCAL_ONLY: readonly Collection[] = ['device', 'derivedIds', 'hubs', 'pocket', 'discoverBook', 'discoverEvents', 'discoverOutbox']
