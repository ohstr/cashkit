// A Cash Pocket: the wallet's bills and calls in flight, gift-wrapped to the user on relays.
import { RelayWs } from '../src/adapters/relay-ws.js'
import { syncPocket } from '../src/adapters/sync-pocket.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { NoneVault } from '../src/adapters/vault-none.js'
import { Wallet } from '../src/index.js'

export async function example() {
  const storage = new MemoryStorage()
  const vault = new NoneVault()
  // #region readme
  const relays = new RelayWs()
  const wallet = await Wallet.open({
    storage,
    vault,
    relays,
    // The user's inbox relays: each call's entry is stored and read back
    // before the call goes out.
    pocket: syncPocket({ pool: relays, relays: ['wss://inbox.example', 'wss://inbox2.example'] }),
  })

  // On another device with the same identity: bring in what it holds.
  const r = await wallet.pocket.sync()
  console.log('imported', r.imported.length, 'conflicts', r.conflicts.length)
  console.log(await wallet.pocket.balance()) // per chain
  // #endregion
}
