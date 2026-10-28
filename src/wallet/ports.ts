// The wallet's side-effecting interfaces (design §3). The engine reaches the
// platform only through these; adapters implement them.
import type { NostrEvent, Signer } from '../core/index.js'
import type { RelayPool } from '../client/index.js'
import type { AppendOnly, Collection, NewRow, Row, Sealed } from './model.js'

/** A filter over one collection's rows; the memory adapter evaluates it in place. */
export interface Query<C extends Collection> {
  readonly where?: Partial<Row<C>>
}

export interface StorageTx {
  get<C extends Collection>(c: C, key: string): Promise<Row<C> | undefined>
  /** Rows in insertion order. */
  list<C extends Collection>(c: C, q?: Query<C>): Promise<Row<C>[]>
  /**
   * Writes a row. With `expectVersion`, the stored row's version must equal
   * it (0 meaning "no row yet"), or the write fails with ConcurrentUpdateError
   * and the transaction rolls back. It is never retried silently.
   */
  put<C extends Collection>(c: C, row: Row<C>, expectVersion?: number): Promise<void>
  /** Adds a row to an append-only collection; returns its new key. */
  insert<C extends AppendOnly>(c: C, row: NewRow<C>): Promise<string>
  delete<C extends Collection>(c: C, key: string): Promise<void>
}

/**
 * A transactional store of versioned rows. A `tx` callback MUST NOT await
 * anything but operations on that tx: IndexedDB commits on a foreign await,
 * so network calls happen between transactions, never inside one.
 */
export interface Storage {
  tx<T>(mode: 'r' | 'rw', fn: (t: StorageTx) => Promise<T>): Promise<T>
}

/** A row changed under us (cashctl `ErrConcurrentUpdate`). */
export class ConcurrentUpdateError extends Error {
  override readonly name = 'ConcurrentUpdateError'
  constructor(
    readonly collection: string,
    readonly key: string,
  ) {
    super(`${collection}/${key} changed since it was read`)
  }
}

/** Encrypts secret fields at rest (§10). */
export interface SecretVault {
  seal(plain: Uint8Array): Promise<Sealed>
  open(sealed: Sealed): Promise<Uint8Array>
  /** A locked vault cannot open; money-moving operations then refuse. */
  locked(): boolean
}

/** Serialises money-moving operations per wallet (§5.4). */
export interface Lock {
  withLock<T>(name: string, fn: () => Promise<T>): Promise<T>
}

export interface LogRecord {
  readonly level: 'debug' | 'info' | 'warn' | 'error'
  readonly msg: string
  readonly fields?: Readonly<Record<string, string | number | boolean>>
}

/** Receives already-redacted records only (§9). */
export interface Logger {
  log(r: LogRecord): void
}

export interface SyncMessage {
  readonly walletId: string
  readonly at: number
}

/** Tells the other tabs of this wallet that something committed (§5.4). */
export interface SyncChannel {
  post(msg: SyncMessage): void
  subscribe(fn: (msg: SyncMessage) => void): () => void
}

export type Fetch = (url: string, init?: { redirect?: 'error' | 'follow' | 'manual'; signal?: AbortSignal; headers?: Record<string, string> }) => Promise<{
  readonly ok: boolean
  readonly status: number
  readonly url: string
  readonly redirected?: boolean
  text(): Promise<string>
}>

export interface WalletDeps {
  readonly storage: Storage
  /** Required: vault-none must be chosen explicitly, never implied. */
  readonly vault: SecretVault
  readonly relays: RelayPool
  /** The identity signer; absent means no identity yet, or a stored local key. */
  readonly signer?: Signer
  /** Default: a per-process lock. */
  readonly lock?: Lock
  /** For NIP-05. Default globalThis.fetch. */
  readonly fetch?: Fetch
  /** ms epoch. */
  readonly clock?: () => number
  readonly random?: (n: number) => Uint8Array
  readonly logger?: Logger
  /** The longest a private send waits for its reply, in ms (never past the call's deadline); tests shorten it. */
  readonly replyWaitMs?: number
  /** How long an NWC call waits for its answer, in ms; default 60 s. */
  readonly nwcTimeoutMs?: number
  /** Cross-tab change notices; other tabs reload their state on one. */
  readonly sync?: SyncChannel
  /**
   * Asks the platform to keep this wallet's storage from being evicted
   * (`navigator.storage.persist`). Called once at open; the answer is
   * `state.storagePersisted`.
   */
  readonly persist?: () => Promise<boolean>
  /** A Cash Pocket (NIP-CP): the wallet's tokens and calls in flight, gift-wrapped to the user on relays. */
  readonly pocket?: Pocket
}

/**
 * Where a Cash Pocket's gift wraps live (`adapters/sync-pocket`): the
 * user's inbox relays. `publish` resolves with the relays that stored the
 * wrap; `has` reads one back.
 */
export interface Pocket {
  publish(wrap: NostrEvent): Promise<readonly string[]>
  has(wrapId: string): Promise<boolean>
  fetch(pubkey: string, since?: number): Promise<NostrEvent[]>
  remove(deletion: NostrEvent): Promise<void>
  /** How many relays must store a wrap before it counts as stored (default 2, capped at the relays configured). */
  readonly minRelays?: number
}
