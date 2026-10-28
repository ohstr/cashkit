// Confirmations: the typed requests the wallet raises and the app answers
// (`wallet.on('confirm', …)`, or `useConfirmations()` in React). A request is
// either a question (the wallet waits for `true` before acting) or a notice
// (something the user must see; the answer is ignored). With no handler,
// every question is answered no: nothing is signed, written, sent or
// published on the user's behalf.
import type { HubView } from '../client/index.js'
import type { PendingCallView } from './views.js'
import type { WithdrawQuoteView } from './withdraw.js'

/** A withdrawal quote as the user confirms it: every figure, nothing preset. */
export interface ConfirmWithdrawData extends WithdrawQuoteView {
  /** No default action: the app uses a hold or a slide, never a single tap. */
  readonly deliberate: true
}

/** The audience and what publishing tells it, for a recommendation, a report, or a recommendation's withdrawal. */
export interface PublishNotice {
  /** The offer's address (`31190:<pubkey>:<d>`), when the event names one offer. */
  readonly address?: string
  /** The node identity the event names. */
  readonly node: string
  readonly audience: { readonly public: true }
  /** A recommendation of a circle shows that the user is a member. */
  readonly revealsMembership: boolean
  /** The event is signed by the user's Nostr key, linking it to them. */
  readonly linksIdentity: true
  /** Published after a random delay in this range (0 to 0: at once). */
  readonly delay: { readonly minSecs: number; readonly maxSecs: number }
  /** The deletion of the user's recommendation of `node`, published at once. */
  readonly withdrawal?: true
}

/** Questions: the wallet acts only on `true`. */
export type ConfirmQuestion =
  /** A connection string whose signature does not verify; raised after the online check passed. */
  | { readonly type: 'confirmUnverified'; readonly view: HubView }
  /** A mint, order or withdrawal call was not applied and may be placed again (a new call, fresh deadline). */
  | { readonly type: 'confirmMintReplace'; readonly call: PendingCallView }
  | { readonly type: 'confirmOrderReplace'; readonly call: PendingCallView }
  | { readonly type: 'confirmWithdrawReplace'; readonly call: PendingCallView }
  /**
   * Joining a circle whose Hub cannot rotate the wallet: losing the
   * connection secret loses the balance. Offer the backup
   * (`circles.exportConnectionSecret`) after the join.
   */
  | { readonly type: 'confirmNoRecovery'; readonly view: HubView }
  /** Deleting a circle wallet that still holds dust, which goes to the host. */
  | { readonly type: 'confirmDelete'; readonly name: string; readonly dust: bigint }
  /** Trusting a zap's minter; the minter's network cannot be verified from the zap. */
  | { readonly type: 'approveMinter'; readonly minter: string; readonly chain: string; readonly networkUnverifiable: true }
  /** Sending an on-chain withdrawal: irreversible once sent. */
  | { readonly type: 'confirmWithdraw'; readonly quote: ConfirmWithdrawData }
  /** Publishing a recommendation (or withdrawing one) or a report: who will see it. */
  | ({ readonly type: 'confirmRecommend' } & PublishNotice)
  | ({ readonly type: 'confirmReport' } & PublishNotice)

/** Notices: shown to the user; the answer is ignored. */
export type ConfirmNotice =
  /** An unexpected rotation of a circle wallet: pay out of it now. */
  | { readonly type: 'rotationAlert'; readonly name: string }
  /** A frozen circle wallet pays nothing until unfrozen or rotated. */
  | { readonly type: 'walletFrozen'; readonly name: string }
  /** A call's lookup window passed without an answer: the outcome is unknown. */
  | { readonly type: 'lookupExpired'; readonly call: PendingCallView }
  /** A withdrawal quote expires within two minutes. */
  | { readonly type: 'expiringSoon'; readonly holdingId: string; readonly expiresAt: number }
  /** A withdrawal not broadcast by its send-by time. */
  | { readonly type: 'withdrawLate'; readonly id: string; readonly signed: boolean; readonly returnsBy?: number; readonly owed?: true; readonly cancelAvailableAt?: number; readonly canSendItMyself?: boolean }
  /** A withdrawal cancelled by the Hub; its value came back as a new bill, unless `remintGone` says that bill was already gone. */
  | {
      readonly type: 'withdrawCancelled'
      readonly id: string
      readonly remintHoldingId?: string
      readonly amountMillis: bigint
      /** The re-minted bill was already gone (a tombstone, its reason when given): nothing came back. */
      readonly remintGone?: { readonly reason?: string }
    }

export type ConfirmRequest = ConfirmQuestion | ConfirmNotice

/** Answers a request: `true` to go ahead (questions only). */
export type ConfirmHandler = (request: ConfirmRequest) => Promise<boolean> | boolean

const NOTICES: ReadonlySet<ConfirmRequest['type']> = new Set(['rotationAlert', 'walletFrozen', 'lookupExpired', 'expiringSoon', 'withdrawLate', 'withdrawCancelled'])

/** Whether a request is a notice (its answer is ignored). */
export const isNotice = (r: ConfirmRequest): r is ConfirmNotice => NOTICES.has(r.type)

/** The handlers of one wallet: the most recently added answers. */
export class Confirmations {
  private readonly handlers: ConfirmHandler[] = []

  add(fn: ConfirmHandler): () => void {
    this.handlers.push(fn)
    return () => {
      const i = this.handlers.lastIndexOf(fn)
      if (i >= 0) this.handlers.splice(i, 1)
    }
  }

  get handled(): boolean {
    return this.handlers.length > 0
  }

  /** Asks a question: true only if a handler answered exactly `true`; a handler that throws is a no. */
  async ask(q: ConfirmQuestion): Promise<boolean> {
    const h = this.handlers.at(-1)
    if (h === undefined) return false
    try {
      return (await h(q)) === true
    } catch {
      return false
    }
  }

  /** Tells the user something; never waits and never fails the caller. */
  notify(n: ConfirmNotice): void {
    const h = this.handlers.at(-1)
    if (h === undefined) return
    try {
      void Promise.resolve(h(n)).catch(() => undefined)
    } catch {
      // a handler that throws must not fail the operation that raised the notice
    }
  }
}

/** The caller's `confirmUnverified`, else the wallet's confirmation handler. */
export function unverifiedAnswer(c: Confirmations, given?: (view: HubView) => Promise<boolean>): (view: HubView) => Promise<boolean> {
  return given ?? ((view) => c.ask({ type: 'confirmUnverified', view }))
}
