// @ohstr/cashkit/react: React bindings over the wallet (design §6.11).
// Nothing here knows how a wallet is stored or sealed: the app opens one
// (openWallet or Wallet.open) and hands it, or a way to open it, to the
// provider. React is an optional peer dependency.
//
//   <WalletProvider open={() => openWallet({ vault })} fallback={<Spinner />}>
//     <App />
//   </WalletProvider>
//
// Below the provider every hook can rely on a ready wallet. State hooks
// re-render on every commit, in this tab or another one (§5.4); query hooks
// re-run on every commit; action hooks track one call's pending and error.
import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react'
import type {
  ActivityItem,
  Balance,
  CashkitError,
  CircleView,
  ConfirmRequest,
  ConnectionView,
  DiscoverOptions,
  DiscoverView,
  OrderView,
  PendingCallView,
  PocketSyncReport,
  TapView,
  WithdrawalView,
  WithdrawQuoteView,
  WithdrawTermsView,
  ZapView,
  HandoffView,
  HoldingView,
  IdentityView,
  OperationEvent,
  ReceiveResult,
  RedeemInput,
  RedeemOutcome,
  RedeemPlan,
  Report,
  SendInput,
  SendPlan,
  SendResult,
  ConsolidateReport,
  Wallet,
  WalletState,
} from '../wallet/index.js'

type Opened = { readonly status: 'opening' } | { readonly status: 'ready'; readonly wallet: Wallet } | { readonly status: 'error'; readonly error: unknown }

const WalletContext = createContext<Opened | undefined>(undefined)

export interface WalletProviderProps {
  /** An open wallet. */
  readonly wallet?: Wallet
  /** Or a way to open one; called once, on mount. */
  readonly open?: () => Promise<Wallet>
  /** Rendered until the wallet is open. */
  readonly fallback?: ReactNode
  /** Rendered if opening fails. */
  readonly errorFallback?: (error: unknown) => ReactNode
  /** Close a wallet this provider opened when it unmounts. Default true. */
  readonly closeOnUnmount?: boolean
  readonly children?: ReactNode
}

/** Provides a wallet to the hooks below it; its children render once it is open. */
export function WalletProvider(p: WalletProviderProps): ReactNode {
  const [opened, setOpened] = useState<Opened>(p.wallet !== undefined ? { status: 'ready', wallet: p.wallet } : { status: 'opening' })
  const open = useRef(p.open)
  useEffect(() => {
    if (p.wallet !== undefined) {
      setOpened({ status: 'ready', wallet: p.wallet })
      return
    }
    if (open.current === undefined) {
      setOpened({ status: 'error', error: new Error('WalletProvider needs a wallet or an open function') })
      return
    }
    let alive = true
    let mine: Wallet | undefined
    open.current().then(
      (w) => {
        mine = w
        if (alive) setOpened({ status: 'ready', wallet: w })
        else w.close()
      },
      (error: unknown) => {
        if (alive) setOpened({ status: 'error', error })
      },
    )
    return () => {
      alive = false
      if (p.closeOnUnmount !== false) mine?.close()
    }
  }, [p.wallet, p.closeOnUnmount])
  let body: ReactNode
  if (opened.status === 'ready') body = p.children
  else if (opened.status === 'error') body = p.errorFallback?.(opened.error) ?? null
  else body = p.fallback ?? null
  return createElement(WalletContext.Provider, { value: opened }, body)
}

/** Whether the provider's wallet is opening, ready or failed. Works above the gate too. */
export function useWalletStatus(): Opened {
  const v = useContext(WalletContext)
  if (v === undefined) throw new Error('cashkit/react: use this inside a <WalletProvider>')
  return v
}

/** The wallet. Below the provider's gate it is always ready. */
export function useWallet(): Wallet {
  const v = useWalletStatus()
  if (v.status !== 'ready') throw new Error('cashkit/react: the wallet is not open yet; render this below <WalletProvider> children')
  return v.wallet
}

/**
 * The wallet's state snapshot, or a slice of it. Re-renders when a commit
 * changes it, in this tab or (with a SyncChannel) another one. A selector's
 * result is kept while the snapshot is the same, so it may build new objects.
 */
export function useWalletState(): WalletState
export function useWalletState<T>(select: (s: WalletState) => T): T
export function useWalletState<T>(select?: (s: WalletState) => T): WalletState | T {
  const wallet = useWallet()
  const memo = useRef<{ state: WalletState; value: unknown } | undefined>(undefined)
  const get = useCallback(() => {
    const s = wallet.state
    if (select === undefined) return s
    if (memo.current?.state !== s) memo.current = { state: s, value: select(s) }
    return memo.current.value as T
  }, [wallet, select])
  return useSyncExternalStore(useCallback((cb: () => void) => wallet.subscribe(cb), [wallet]), get, get)
}

/** Calls `fn` with every operation event (planned, sent, committed, failed). */
export function useOperationEvents(fn: (e: OperationEvent) => void): void {
  const wallet = useWallet()
  const ref = useRef(fn)
  ref.current = fn
  useEffect(() => wallet.on('operation', (e) => ref.current(e)), [wallet])
}

// ---- actions

export interface Action<A extends unknown[], R> {
  /** Runs the call; resolves with its result or rejects with its error (also kept in `error`). */
  readonly run: (...args: A) => Promise<R>
  readonly pending: boolean
  readonly result: R | undefined
  /** A CashkitError for every engine failure; `error.code` is cashctl's code. */
  readonly error: CashkitError | Error | undefined
  readonly reset: () => void
}

/** One wallet call with its pending, result and error. The base of every action hook. */
export function useAction<A extends unknown[], R>(fn: (wallet: Wallet, ...args: A) => Promise<R>): Action<A, R> {
  const wallet = useWallet()
  const [s, setS] = useState<{ pending: boolean; result: R | undefined; error: CashkitError | Error | undefined }>({ pending: false, result: undefined, error: undefined })
  const alive = useRef(true)
  const fnRef = useRef(fn)
  fnRef.current = fn
  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])
  const run = useCallback(
    async (...args: A): Promise<R> => {
      setS((x) => ({ ...x, pending: true, error: undefined }))
      try {
        const result = await fnRef.current(wallet, ...args)
        if (alive.current) setS({ pending: false, result, error: undefined })
        return result
      } catch (err) {
        if (alive.current) setS((x) => ({ ...x, pending: false, error: err as Error }))
        throw err
      }
    },
    [wallet],
  )
  const reset = useCallback(() => setS({ pending: false, result: undefined, error: undefined }), [])
  return { run, pending: s.pending, result: s.result, error: s.error, reset }
}

export const useReceive = (): Action<[input: string, o?: { protect?: boolean }], ReceiveResult> => useAction((w, input: string, o?: { protect?: boolean }) => w.receive(input, o))

/** Plan then execute, as a confirm screen needs; `send` does both. */
export function useSend(): { plan: Action<[SendInput], SendPlan>; execute: Action<[SendPlan], SendResult>; send: Action<[SendInput], SendResult> } {
  return {
    plan: useAction((w, o: SendInput) => w.planSend(o)),
    execute: useAction((w, p: SendPlan) => w.executeSend(p)),
    send: useAction((w, o: SendInput) => w.send(o)),
  }
}

export function useRedeem(): { plan: Action<[RedeemInput?], RedeemPlan>; execute: Action<[RedeemPlan], Report<RedeemOutcome>>; redeem: Action<[RedeemInput?], Report<RedeemOutcome>> } {
  return {
    plan: useAction((w, o?: RedeemInput) => w.planRedeem(o)),
    execute: useAction((w, p: RedeemPlan) => w.executeRedeem(p)),
    redeem: useAction((w, o?: RedeemInput) => w.redeem(o)),
  }
}

export const useConsolidate = (): Action<[o?: { holdings?: readonly string[]; to?: string }], ConsolidateReport> => useAction((w, o?: { holdings?: readonly string[]; to?: string }) => w.consolidate(o))

// ---- queries

export interface Query<R> {
  readonly data: R | undefined
  readonly loading: boolean
  readonly error: CashkitError | Error | undefined
  /** Runs it again now. */
  readonly refresh: () => Promise<void>
}

/**
 * A read that re-runs whenever the wallet commits (and when `deps` change).
 * Answers that arrive out of order are dropped, so `data` is never older
 * than what is on screen.
 */
export function useQuery<R>(fn: (wallet: Wallet) => Promise<R>, deps: readonly unknown[] = []): Query<R> {
  const wallet = useWallet()
  const state = useWalletState()
  const [s, setS] = useState<{ data: R | undefined; loading: boolean; error: CashkitError | Error | undefined }>({ data: undefined, loading: true, error: undefined })
  const seq = useRef(0)
  const fnRef = useRef(fn)
  fnRef.current = fn
  const load = useCallback(async () => {
    const mine = ++seq.current
    setS((x) => ({ ...x, loading: true }))
    try {
      const data = await fnRef.current(wallet)
      if (mine === seq.current) setS({ data, loading: false, error: undefined })
    } catch (err) {
      if (mine === seq.current) setS((x) => ({ ...x, loading: false, error: err as Error }))
    }
  }, [wallet])
  useEffect(() => {
    void load()
    return () => {
      seq.current++
    }
  }, [load, state, ...deps])
  return { data: s.data, loading: s.loading, error: s.error, refresh: load }
}

/**
 * The balance. On commits it is recomputed from cached wallet figures;
 * `refresh()` asks every wallet connection live (NWC), as cashctl does.
 */
export function useBalance(): Query<Balance> & { refreshLive: () => Promise<Balance> } {
  const wallet = useWallet()
  const q = useQuery((w) => w.balance({ refresh: false }))
  const refreshLive = useCallback(async () => {
    const b = await wallet.balance({ refresh: true })
    await q.refresh()
    return b
  }, [wallet, q.refresh])
  return { ...q, refreshLive }
}

export const useHoldings = (o: { includeSpent?: boolean } = {}): Query<HoldingView[]> => useQuery((w) => w.holdings(o), [o.includeSpent])

export const useActivity = (o: { limit?: number; before?: number; includeSecrets?: boolean } = {}): Query<ActivityItem[]> =>
  useQuery((w) => w.activity(o), [o.limit, o.before, o.includeSecrets])

export const useHandoffs = (o: { includeSecrets?: boolean } = {}): Query<HandoffView[]> => useQuery((w) => w.handoffs(o), [o.includeSecrets])

export const useConnections = (): Query<ConnectionView[]> => useQuery((w) => w.connections.list())

export const useIdentity = (): Query<IdentityView | undefined> => useQuery((w) => w.identity.get())

// ---- confirmations

/** One request the wallet raised, waiting for the user. */
export interface PendingConfirmation {
  /** Stable while the request is pending; for React keys. */
  readonly key: number
  readonly request: ConfirmRequest
  /** Answers it: `true` goes ahead (questions); any answer dismisses a notice. */
  readonly answer: (yes: boolean) => void
}

let confirmSeq = 0

/**
 * The wallet's confirmation requests as a queue the app renders and answers
 * (it registers as the wallet's `confirm` handler while mounted). Questions
 * left unanswered when the component unmounts are answered no.
 */
export function useConfirmations(): readonly PendingConfirmation[] {
  const wallet = useWallet()
  const [queue, setQueue] = useState<readonly PendingConfirmation[]>([])
  useEffect(() => {
    const open = new Map<number, (yes: boolean) => void>()
    const off = wallet.on(
      'confirm',
      (request) =>
        new Promise<boolean>((resolve) => {
          const key = ++confirmSeq
          const answer = (yes: boolean) => {
            if (!open.delete(key)) return
            setQueue((q) => q.filter((x) => x.key !== key))
            resolve(yes)
          }
          open.set(key, answer)
          setQueue((q) => [...q, { key, request, answer }])
        }),
    )
    return () => {
      off()
      for (const a of open.values()) a(false)
    }
  }, [wallet])
  return queue
}

// ---- calls in flight

/** Calls in flight or waiting for the user, with the two answers a user can give. */
export function usePendingCalls(): { calls: readonly PendingCallView[]; close: Action<[id: string], void>; confirmReplace: Action<[id: string], void> } {
  return {
    calls: useWalletState(selectPendingCalls),
    close: useAction((w, id: string) => w.pendingCalls.close(id)),
    confirmReplace: useAction((w, id: string) => w.pendingCalls.confirmReplace(id)),
  }
}
const selectPendingCalls = (s: { pendingCalls: readonly PendingCallView[] }) => s.pendingCalls

/**
 * Calls whose outcome can no longer be learned. `secrets` lists their
 * written-ahead roles; the secrets themselves only with `includeSecrets`.
 */
export function useUnreconciled(o: { includeSecrets?: boolean } = {}): { count: number; secrets: Query<{ pendingCallId: string; role: string; cashSecret?: string }[]> } {
  return {
    count: useWalletState(selectUnreconciled),
    secrets: useQuery((w) => w.unreconciledSecrets(o), [o.includeSecrets]),
  }
}
const selectUnreconciled = (s: { unreconciled: number }) => s.unreconciled

// ---- circles, zaps, pocket

/** A stored Circle Wallet: budget, rotation and frozen flags; undefined if none has that name. */
export const useCircleWallet = (name: string): Query<CircleView | undefined> => useQuery(async (w) => (await w.circles.list()).find((c) => c.name === name), [name])

export const useCircles = (): Query<CircleView[]> => useQuery((w) => w.circles.list())

/** Cash Zaps to (and linked to) the user, read from `relays`. */
export const useCashZaps = (o: { relays: readonly string[]; connectionKeys?: readonly string[] }): Query<ZapView[]> =>
  useQuery((w) => w.zaps.list(o), [o.relays.join(' '), (o.connectionKeys ?? []).join(' ')])

/** The Cash Pocket: sync it, with the last report (`pending`, `conflicts`). */
export function usePocket(): { sync: Action<[], PocketSyncReport>; lastSync: PocketSyncReport | undefined } {
  const sync = useAction((w) => w.pocket.sync())
  return { sync, lastSync: sync.result }
}

// ---- orders

export const useOrders = (): Query<OrderView[]> => useQuery((w) => w.orders.list())

/** One order: state, invoice or address, `payBy` and bills; never its keys. */
export const useOrder = (id: string): Query<OrderView> => useQuery((w) => w.orders.get(id), [id])

// ---- withdrawals

export const useWithdrawTerms = (holdingId: string): Query<WithdrawTermsView> => useQuery((w) => w.withdraw.terms(holdingId), [holdingId])

/** What changed between two quotes for the same bill and address. */
export interface QuoteChange {
  readonly field: 'amountMillis' | 'feeMillis' | 'networkFeeMillis' | 'hubFeeMillis' | 'payoutMillis' | 'sentBy'
  readonly before: bigint | number
  readonly after: bigint | number
}

const QUOTE_FIELDS: readonly QuoteChange['field'][] = ['amountMillis', 'feeMillis', 'networkFeeMillis', 'hubFeeMillis', 'payoutMillis', 'sentBy']

/** The figures that differ between two quotes. */
export function quoteChanges(before: WithdrawQuoteView, after: WithdrawQuoteView): QuoteChange[] {
  return QUOTE_FIELDS.flatMap((field) => (before[field] !== after[field] ? [{ field, before: before[field], after: after[field] }] : []))
}

/**
 * Quote and re-quote a withdrawal. A re-quote for the same bill and address
 * carries `quoteChanged`, the figures that moved; the user confirms the new
 * figures before `withdraw.send`.
 */
export function useWithdrawQuote(): Action<[holdingId: string, address: string, o?: { sendBefore?: number }], WithdrawQuoteView> & { quoteChanged: readonly QuoteChange[] | undefined } {
  const last = useRef<WithdrawQuoteView | undefined>(undefined)
  const [changed, setChanged] = useState<readonly QuoteChange[] | undefined>(undefined)
  const action = useAction(async (w, holdingId: string, address: string, o?: { sendBefore?: number }) => {
    const q = await w.withdraw.quote(holdingId, address, o)
    const prev = last.current
    setChanged(prev !== undefined && prev.holdingId === q.holdingId && prev.address === q.address ? quoteChanges(prev, q) : undefined)
    last.current = q
    return q
  })
  return { ...action, quoteChanged: changed }
}

export const useWithdrawals = (): Query<WithdrawalView[]> => useQuery((w) => w.withdraw.list())

/** One withdrawal: phase, payout, fee, depth, `sentBy`; the address only while it is open. */
export const useWithdrawal = (id: string): Query<WithdrawalView> => useQuery((w) => w.withdraw.get(id), [id])

// ---- discover

/** The Discover sections as the wallet ranks them; `refresh` fetches listings (never contacting a Hub). */
export function useDiscover(): { view: DiscoverView | undefined; refresh: Action<[o: DiscoverOptions], void> } {
  const refresh = useAction((w, o: DiscoverOptions) => w.discover.refresh(o))
  const q = useQuery((w) => Promise.resolve(w.discover.list()), [refresh.result, refresh.pending])
  return { view: q.data, refresh }
}

/** How a tap is going: `slow` once it has taken 5 s. */
export type TapState = 'idle' | 'checking' | 'slow' | 'available' | 'unavailable_for_now' | 'hidden'

/** Taps one offer (an anonymous `get_info`), with its state for the card. */
export function useTap(address: string): { tapState: TapState; view: TapView | undefined; error: CashkitError | Error | undefined; tap: () => Promise<TapView> } {
  const wallet = useWallet()
  const [s, setS] = useState<{ tapState: TapState; view: TapView | undefined; error: CashkitError | Error | undefined }>({ tapState: 'idle', view: undefined, error: undefined })
  const seq = useRef(0)
  useEffect(() => () => void seq.current++, [address])
  const tap = useCallback(async () => {
    const mine = ++seq.current
    setS({ tapState: 'checking', view: undefined, error: undefined })
    const slow = setTimeout(() => {
      if (mine === seq.current) setS((x) => (x.tapState === 'checking' ? { ...x, tapState: 'slow' } : x))
    }, 5000)
    try {
      const view = await wallet.discover.tap(address)
      if (mine === seq.current) setS({ tapState: tapStateOf(view), view, error: undefined })
      return view
    } catch (err) {
      if (mine === seq.current) setS({ tapState: 'unavailable_for_now', view: undefined, error: err as Error })
      throw err
    } finally {
      clearTimeout(slow)
    }
  }, [wallet, address])
  return { ...s, tap }
}

function tapStateOf(v: TapView): TapState {
  if (v.outcome === 'show') return 'available'
  if (v.outcome === 'unavailable') return 'unavailable_for_now'
  return 'hidden'
}

/** The test-network banner for a Hub or offer, or undefined on mainnet. */
export function useTestNetworkBanner(view: { readonly testNetwork: boolean; readonly network?: string } | undefined): string | undefined {
  if (view === undefined || !view.testNetwork) return undefined
  return view.network === undefined || view.network === '' ? 'This Hub does not say which network it runs on: treat its money as test money.' : `This Hub runs on ${view.network}, a test network: its money is not real.`
}
