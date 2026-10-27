// Sending and claiming Cash Zaps.
import type { NostrEvent } from '../src/core/index.js'
import type { Wallet } from '../src/index.js'

export async function example(wallet: Wallet, note: NostrEvent, incoming: NostrEvent) {
  const relays = ['wss://relay.example']
  // #region readme
  // A zap on a note: a bill signed over the note, published as a 9522 to the
  // recipient's 10522 relays and yours.
  const sent = await wallet.zaps.send({ to: note.pubkey, amountMillis: 21_000n, target: { e: note.id, k: '1' }, relays })
  if (!sent.countable) console.log('valid, but never counted:', sent.reason)

  // Incoming zaps are shown as issued until claimed; a claim checks the
  // bill with its Hub first.
  for (const z of await wallet.zaps.list({ relays })) console.log(z.status, z.amountMillis, z.trusted)
  const holding = await wallet.zaps.claim(incoming)
  console.log('claimed', holding.amount)
  // #endregion
}
