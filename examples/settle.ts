// Settling calls a crash, a closed tab or a lost reply left open.
import type { Wallet } from '../src/index.js'

declare function askTheUser(question: string): Promise<boolean>

export async function example(wallet: Wallet) {
  // #region readme
  // Every bill-creating call is written ahead with its request id; a lost
  // reply is looked up, never resent. settle() runs on open and on demand.
  const report = await wallet.settle()
  console.log('applied', report.applied.length, 'still open', report.open.length)

  for (const call of await wallet.pendingCalls.list()) {
    // The Hub never saw it: placing it again is a new call the user decides on.
    if (call.needsUser === 'confirm_replace' && (await askTheUser(`Place the ${call.op} of ${call.amount} again?`))) {
      await wallet.pendingCalls.confirmReplace(call.id)
    }
  }

  const stop = wallet.autoSettle() // settles again when the app is idle; call stop() on exit
  // #endregion
  stop()
}
