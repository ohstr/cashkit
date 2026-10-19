// @vitest-environment jsdom
// @ohstr/cashkit/react against real wallets on FakeBank (design §6.11).
import { act, render, renderHook, screen, waitFor } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { describe, expect, test, vi } from 'vitest'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { BroadcastSync } from '../src/adapters/sync-broadcast.js'
import {
  useActivity,
  useBalance,
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
