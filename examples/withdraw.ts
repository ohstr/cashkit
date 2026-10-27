// Withdrawing a bill on-chain.
import type { Wallet } from '../src/index.js'

declare function askTheUser(question: string): Promise<boolean>

export async function example(wallet: Wallet, holdingId: string, address: string) {
  // #region readme
  const terms = await wallet.withdraw.terms(holdingId)
  if (!terms.offered || terms.inRange !== 'ok') throw new Error('this bill cannot be withdrawn on-chain')

  // The quote is checked against what was asked and held in memory only.
  const quote = await wallet.withdraw.quote(holdingId, address)
  const view = await wallet.withdraw.send(quote, {
    // Irreversible: show the exact payout, the fees and the privacy warnings.
    confirm: async (v) => askTheUser(`Send ${v.payoutMillis} to ${v.addressGroups.join(' ')} (fee ${v.feeMillis})?`),
  })

  const stop = await wallet.withdraw.watch(view.id, {
    onUpdate: (v) => {
      if (v.phase === 'final') console.log('paid in', v.txid)
      if (v.phase === 'cancelled') console.log('returned as holding', v.remintHoldingId)
      if (v.phase === 'final' || v.phase === 'cancelled') stop()
    },
  })

  // Still broadcast 7 days after sent_by: it may be cancelled, and the
  // amount comes back as a new bill.
  const late = await wallet.withdraw.get(view.id)
  if (late?.cancelAvailableAt !== undefined && late.cancelAvailableAt <= Date.now() / 1000) await wallet.withdraw.cancel(view.id)
  // #endregion
}
