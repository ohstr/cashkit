// Ordering cash from a Hub that sells it.
import type { Wallet } from '../src/index.js'

declare function show(text: string): void

export async function example(wallet: Wallet, cashorder: string) {
  // #region readme
  // Quote: nothing is written or sent.
  const q = await wallet.orders.quote(cashorder, { amountMillis: 21_000_000n, payment: 'lightning' })
  console.log(`pay ${q.payMillis} (fee ${q.feeMillis}); the bill will carry a redeem fee of ${q.billRedeemFeeMillis}`)

  // Place: written ahead, then sent. The reply opens the order.
  const order = await wallet.orders.place({ connection: cashorder, amountMillis: 21_000_000n, payment: 'lightning' })
  if (order.invoice !== undefined) show(`Pay before ${new Date(order.payBy * 1000).toLocaleString()}: ${order.invoice}`)

  // Watch until it is finished: each new bill becomes a holding.
  const ac = new AbortController()
  await wallet.orders.watch(order.id, {
    signal: ac.signal,
    onUpdate: (v) => {
      if (v.finished) ac.abort()
      console.log(v.state, v.bills.length, 'bills')
    },
  })

  // A closed order can be read again at any time.
  console.log(await wallet.orders.refresh(order.id))
  // #endregion
}
