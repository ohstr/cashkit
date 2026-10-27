// @vitest-environment jsdom
// @ohstr/cashkit/react against real wallets on FakeBank (design §6.11).
import { act, render, renderHook, screen, waitFor } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { describe, expect, test, vi } from 'vitest'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { BroadcastSync } from '../src/adapters/sync-broadcast.js'
import {
  quoteChanges,
  useActivity,
  useBalance,
  useConfirmations,
  usePendingCalls,
  useTap,
  useTestNetworkBanner,
  useUnreconciled,
  useWithdrawals,
  useWithdrawQuote,
  useHoldings,
  useOperationEvents,
  useReceive,
  useSend,
  useWallet,
  useWalletState,
  useWalletStatus,
  WalletProvider,
} from '../src/react/index.js'
import type { CashkitError, OperationEvent, Wallet } from '../src/wallet/index.js'
import { harness, type Harness } from './walletHarness.js'
import { FakeWithdraw, PAYTO } from './fakeWithdraw.js'
import type { TapView, WithdrawQuoteView } from '../src/wallet/index.js'

const wrap = (wallet: Wallet) =>
  function W({ children }: { children?: ReactNode }) {
    return createElement(WalletProvider, { wallet }, children)
  }

function Child() {
  return createElement('p', null, `wallet ${useWallet().walletId}`)
}

async function withBill(amount = 5000n): Promise<{ h: Harness; token: string }> {
  const h = await harness()
  return { h, token: h.bank.mintToPubkey(amount, h.me).token }
}

describe('WalletProvider', () => {
  test('shows the fallback while opening, then the children with a ready wallet', async () => {
    const h = await harness()
    let release!: (w: Wallet) => void
    const opening = new Promise<Wallet>((r) => (release = r))
    render(createElement(WalletProvider, { open: () => opening, fallback: createElement('p', null, 'opening…') }, createElement(Child)))
    expect(screen.getByText('opening…')).toBeTruthy()
    await act(async () => release(h.wallet))
    expect(await screen.findByText(`wallet ${h.wallet.walletId}`)).toBeTruthy()
  })
  test('renders errorFallback when opening fails', async () => {
    render(
      createElement(WalletProvider, {
        open: () => Promise.reject(new Error('locked out')),
        errorFallback: (e) => createElement('p', null, `failed: ${(e as Error).message}`),
      }),
    )
    expect(await screen.findByText('failed: locked out')).toBeTruthy()
  })
  test('closes the wallet it opened when it unmounts', async () => {
    const h = await harness()
    const close = vi.spyOn(h.wallet, 'close')
    const r = render(createElement(WalletProvider, { open: async () => h.wallet }, createElement('p', null, 'in')))
    await screen.findByText('in')
    r.unmount()
    expect(close).toHaveBeenCalled()
  })
  test('hooks outside a provider say so', () => {
    expect(() => renderHook(() => useWalletStatus())).toThrow(/inside a <WalletProvider>/)
  })
})

describe('state', () => {
  test('useWalletState re-renders on a commit', async () => {
    const { h, token } = await withBill()
    const { result } = renderHook(() => useWalletState(), { wrapper: wrap(h.wallet) })
    expect(result.current.holdings).toHaveLength(0)
    await act(async () => void (await h.wallet.receive(token)))
    expect(result.current.holdings).toHaveLength(1)
    expect(result.current.balance.held).toBe(5000n)
  })
  test('a selector keeps its value between renders of the same snapshot', async () => {
    const { h, token } = await withBill()
    let renders = 0
    const { result, rerender } = renderHook(
      () => {
        renders++
        return useWalletState((s) => ({ held: s.balance.held }))
      },
      { wrapper: wrap(h.wallet) },
    )
    const first = result.current
    rerender()
    expect(result.current).toBe(first)
    await act(async () => void (await h.wallet.receive(token)))
    expect(result.current).toEqual({ held: 5000n })
    expect(renders).toBeLessThan(10)
  })
  test('a commit in another tab re-renders this one (BroadcastChannel)', async () => {
    const storage = new MemoryStorage()
    const name = `react-${Date.now()}`
    const a = await harness({ storage, deps: { sync: new BroadcastSync(name) } })
    const b = await a.reopen({ sync: new BroadcastSync(name) })
    const { result } = renderHook(() => useWalletState((s) => s.holdings.length), { wrapper: wrap(b) })
    expect(result.current).toBe(0)
    await act(async () => void (await a.wallet.receive(a.bank.mintToPubkey(1000n, a.me).token)))
    await waitFor(() => expect(result.current).toBe(1))
    b.close()
  })
})

describe('actions', () => {
  test('useReceive tracks pending and the result', async () => {
    const { h, token } = await withBill()
    const { result } = renderHook(() => useReceive(), { wrapper: wrap(h.wallet) })
    let p!: Promise<unknown>
    act(() => {
      p = result.current.run(token)
    })
    expect(result.current.pending).toBe(true)
    await act(async () => void (await p))
    expect(result.current.pending).toBe(false)
    expect(result.current.result).toMatchObject({ received: true })
  })
  test('useSend: plan for a confirm screen, then execute', async () => {
    const { h, token } = await withBill()
    await h.wallet.receive(token)
    const { result } = renderHook(() => useSend(), { wrapper: wrap(h.wallet) })
    let plan!: Awaited<ReturnType<typeof result.current.plan.run>>
    await act(async () => void (plan = await result.current.plan.run({ amount: 2000n })))
    expect(plan).toMatchObject({ amount: 2000n, to: 'cash', split: true })
    await act(async () => void (await result.current.execute.run(plan)))
    expect(result.current.execute.result?.cashNote).toMatch(/#/)
  })
  test('a failing call keeps its CashkitError, with cashctl\'s code', async () => {
    const { h } = await withBill()
    const { result } = renderHook(() => useSend(), { wrapper: wrap(h.wallet) })
    await act(async () => {
      await result.current.send.run({ amount: 1n }).catch(() => undefined)
    })
    expect((result.current.send.error as CashkitError).code).toBe('not_found')
    act(() => result.current.send.reset())
    expect(result.current.send.error).toBeUndefined()
  })
  test('useOperationEvents hears every phase', async () => {
    const { h, token } = await withBill()
    await h.wallet.receive(token)
    const seen: OperationEvent[] = []
    renderHook(() => useOperationEvents((e) => seen.push(e)), { wrapper: wrap(h.wallet) })
    await act(async () => void (await h.wallet.send({ amount: 1000n })))
    expect(seen.map((e) => e.phase)).toEqual(['planned', 'sent', 'committed'])
  })
})

describe('queries', () => {
  test('useHoldings and useActivity re-run on every commit', async () => {
    const { h, token } = await withBill()
    const { result } = renderHook(() => ({ holdings: useHoldings(), activity: useActivity({ limit: 5 }) }), { wrapper: wrap(h.wallet) })
    await waitFor(() => expect(result.current.holdings.loading).toBe(false))
    expect(result.current.holdings.data).toEqual([])
    await act(async () => void (await h.wallet.receive(token)))
    await waitFor(() => expect(result.current.holdings.data).toHaveLength(1))
    await waitFor(() => expect(result.current.activity.data?.[0]).toMatchObject({ type: 'activity', action: 'receive' }))
  })
  test('useBalance follows the held total', async () => {
    const { h, token } = await withBill()
    const { result } = renderHook(() => useBalance(), { wrapper: wrap(h.wallet) })
    await waitFor(() => expect(result.current.data?.total).toBe(0n))
    await act(async () => void (await h.wallet.receive(token)))
    await waitFor(() => expect(result.current.data?.total).toBe(5000n))
  })
})

describe('confirmations (T-952, T-953)', () => {
  test('a question waits in the queue; answering yes lets the withdrawal go out', async () => {
    const h = await harness()
    const hub = new FakeWithdraw(h.bank)
    const r = await h.wallet.receive(h.bank.mintToPubkey(21_000_000n, h.me).token)
    expect(hub).toBeDefined()
    const id = r.received ? r.holding.id : ''
    const { result } = renderHook(() => ({ queue: useConfirmations(), quote: useWithdrawQuote(), list: useWithdrawals() }), { wrapper: wrap(h.wallet) })
    let q!: WithdrawQuoteView
    await act(async () => void (q = await result.current.quote.run(id, PAYTO)))
    let sent!: Promise<unknown>
    act(() => void (sent = h.wallet.withdraw.send(q)))
    await waitFor(() => expect(result.current.queue).toHaveLength(1))
    expect(result.current.queue[0]!.request).toMatchObject({ type: 'confirmWithdraw', quote: { address: PAYTO, deliberate: true, irreversible: true } })
    await act(async () => {
      result.current.queue[0]!.answer(true)
      await sent
    })
    expect(result.current.queue).toEqual([])
    await waitFor(() => expect(result.current.list.data).toHaveLength(1))
  })
  test('unmounting answers what is still open with no', async () => {
    const h = await harness()
    const ctx = (h.wallet as unknown as { ctx: { confirmations: { ask: (q: unknown) => Promise<boolean> } } }).ctx
    const r = renderHook(() => useConfirmations(), { wrapper: wrap(h.wallet) })
    let answer!: Promise<boolean>
    act(() => void (answer = ctx.confirmations.ask({ type: 'confirmDelete', name: 'c', dust: 3n })))
    await waitFor(() => expect(r.result.current).toHaveLength(1))
    r.unmount()
    expect(await answer).toBe(false)
    expect(await ctx.confirmations.ask({ type: 'confirmDelete', name: 'c', dust: 3n })).toBe(false)
  })
  test('a re-quote names the figures that moved', () => {
    const a = { holdingId: 'h', address: PAYTO, amountMillis: 10n, feeMillis: 2n, networkFeeMillis: 1n, hubFeeMillis: 1n, payoutMillis: 8n, sentBy: 100 } as WithdrawQuoteView
    expect(quoteChanges(a, { ...a, feeMillis: 3n, hubFeeMillis: 2n, payoutMillis: 7n })).toEqual([
      { field: 'feeMillis', before: 2n, after: 3n },
      { field: 'hubFeeMillis', before: 1n, after: 2n },
      { field: 'payoutMillis', before: 8n, after: 7n },
    ])
    expect(quoteChanges(a, a)).toEqual([])
  })
})

describe('hooks render without secrets (T-951)', () => {
  test('pending calls and unreconciled calls carry no secret unless asked', async () => {
    const h = await harness()
    const secret = 'ab'.repeat(32)
    await h.wallet.receive(`${h.bank.mintToCash(700n, secret).token}#${secret}`, { protect: false })
    const { result } = renderHook(() => ({ calls: usePendingCalls(), un: useUnreconciled() }), { wrapper: wrap(h.wallet) })
    await waitFor(() => expect(result.current.un.secrets.loading).toBe(false))
    expect(result.current.un.count).toBe(0)
    const text = JSON.stringify({ calls: result.current.calls.calls, un: result.current.un.secrets.data }, (_k, v) => (typeof v === 'bigint' ? String(v) : v))
    expect(text).not.toContain(secret)
  })
})

describe('discover hooks (T-954)', () => {
  test('a tap goes checking, slow after 5 s, then available', async () => {
    const h = await harness()
    let done!: (v: TapView) => void
    vi.spyOn(h.wallet.discover, 'tap').mockReturnValue(new Promise<TapView>((r) => (done = r)))
    vi.useFakeTimers()
    try {
      const { result } = renderHook(() => useTap('31190:aa:bb'), { wrapper: wrap(h.wallet) })
      expect(result.current.tapState).toBe('idle')
      let p!: Promise<TapView>
      act(() => void (p = result.current.tap()))
      expect(result.current.tapState).toBe('checking')
      act(() => void vi.advanceTimersByTime(4999))
      expect(result.current.tapState).toBe('checking')
      act(() => void vi.advanceTimersByTime(1))
      expect(result.current.tapState).toBe('slow')
      await act(async () => {
        done({ outcome: 'show', reason: '', banners: { termsDiffer: false, testNetwork: false }, label: 'x', hubFingerprint: 'aaaa', notice: 'tap_visible' })
        await p
      })
      expect(result.current.tapState).toBe('available')
    } finally {
      vi.useRealTimers()
    }
  })
  test('the test-network banner shows off mainnet only', () => {
    const { result } = renderHook(() => [useTestNetworkBanner({ testNetwork: false, network: 'mainnet' }), useTestNetworkBanner({ testNetwork: true, network: 'regtest' }), useTestNetworkBanner({ testNetwork: true })])
    expect(result.current[0]).toBeUndefined()
    expect(result.current[1]).toMatch(/regtest, a test network/)
    expect(result.current[2]).toMatch(/does not say which network/)
  })
})
