// `openWallet`: Wallet.open with the platform's defaults filled in (design
// §3). Only browser-safe adapters are imported here; on Node, pass
// `storage` (SqliteStorage from @ohstr/cashkit/adapters/storage-sqlite).
// `@ohstr/cashkit/wallet` keeps the fully explicit Wallet.open.
import { MemoryLock } from './adapters/lock-memory.js'
import { WebLocksLock } from './adapters/lock-weblocks.js'
import { RelayWs } from './adapters/relay-ws.js'
import { IndexedDbStorage } from './adapters/storage-indexeddb.js'
import { BroadcastSync } from './adapters/sync-broadcast.js'
import { CashkitError, Wallet, type SecretVault, type WalletDeps } from './wallet/index.js'

export interface OpenWalletOptions extends Partial<Omit<WalletDeps, 'vault'>> {
  /** Required: how secrets are sealed at rest. There is no default vault. */
  readonly vault: SecretVault
  /** The IndexedDB database and sync channel name, for several wallets in one origin. Default "cashkit". */
  readonly name?: string
}

interface Platform {
  indexedDB?: IDBFactory
  navigator?: { storage?: { persist?: () => Promise<boolean> } }
}

/**
 * Opens a wallet with these defaults, each used only when not given:
 * - storage: IndexedDB in a browser; required elsewhere
 * - relays: relay-ws on the global WebSocket
 * - lock: Web Locks where present (every tab of the origin), else per-process
 * - sync: BroadcastChannel in a browser, so other tabs reload after a commit
 * - persist: navigator.storage.persist() where present (§10)
 */
export async function openWallet(o: OpenWalletOptions): Promise<Wallet> {
  const g = globalThis as Platform
  const name = o.name ?? 'cashkit'
  const browser = g.indexedDB !== undefined
  let storage = o.storage
  if (storage === undefined) {
    if (!browser) {
      throw new CashkitError('usage', 'openWallet needs storage outside a browser: pass SqliteStorage from @ohstr/cashkit/adapters/storage-sqlite')
    }
    storage = await IndexedDbStorage.open({ name })
  }
  const sync = o.sync ?? (browser && BroadcastSync.available() ? new BroadcastSync(`cashkit:${name}`) : undefined)
  const storageApi = g.navigator?.storage
  const persist = o.persist ?? (storageApi?.persist !== undefined ? () => storageApi.persist!() : undefined)
  const deps: WalletDeps = {
    ...o,
    storage,
    relays: o.relays ?? new RelayWs(),
    lock: o.lock ?? (WebLocksLock.available() ? new WebLocksLock() : new MemoryLock()),
    ...(sync !== undefined && { sync }),
    ...(persist !== undefined && { persist }),
  }
  return Wallet.open(deps)
}
