// Minting from a Cash Hub you operate or are allowed to mint on.
import type { Wallet } from '../src/index.js'

export async function example(wallet: Wallet, cashhub: string) {
  // #region readme
  // A Cash Hub connection is its signed cashhub1 string, never a URI. It is
  // checked online (get_info must name the same node and chain) before it is stored.
  await wallet.connections.add('hub', cashhub, {
    confirmUnverified: async (view) => window.confirm(`Not confirmed: ${view.hubFingerprint}. Use it anyway?`),
  })

  const note = await wallet.mint({ hub: 'hub', amount: 50_000n }) // to: 'cash' by default
  console.log('hand this over:', note.cashNote)

  const kept = await wallet.mint({ hub: 'hub', amount: 20_000n, to: 'self' })
  console.log('kept as holding', kept.holdingId)
  // #endregion
}
