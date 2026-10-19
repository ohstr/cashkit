// Cash selection. Ported from cashctl internal/ledger/cashselect_test.go
// (test names in comments) and cmd/cash_redeem.go exactSubsetSumNet.
import { describe, expect, test } from 'vitest'
import { hubGroupFor, toHex } from '../src/core/index.js'
import {
  exactSameHubSum,
  exactSubsetSum,
  FundsFragmentedError,
  groupableForConsolidation,
  InsufficientFundsError,
  selectForAmount,
  sumAmounts,
  type Selectable,
} from '../src/wallet/select.js'

const minterA = 'aaaa111122223333444455556666777788889999aaaabbbbccccddddeeee00'
const minterB = 'bbbb111122223333444455556666777788889999aaaabbbbccccddddeeee00'
const hubA = toHex(hubGroupFor(minterA))
const hubB = toHex(hubGroupFor(minterB))

const h = (id: string, amount?: number, hub = '', extra: Partial<Selectable> = {}): Selectable => ({
  id,
  ...(amount !== undefined && { amount: BigInt(amount) }),
  hubGroup: hub,
  mode: 'pubkey',
  hasCashSecret: false,
  ...extra,
})

const ids = (hs: readonly Selectable[]) => new Set(hs.map((x) => x.id))

describe('selectForAmount', () => {
  test('exact match is a full send (TestSelectForAmount_ExactMatch)', () => {
    const p = selectForAmount([h('tok-1', 3000), h('tok-2', 5000)], 5000n)
    expect(p).toMatchObject({ kind: 'single', split: false })
    expect(p.kind === 'single' && p.holding.id).toBe('tok-2')
  })
  test('best fit is the smallest covering bill (TestSelectForAmount_BestFitSplit)', () => {
    const p = selectForAmount([h('tok-big', 20000), h('tok-small', 5000), h('tok-mid', 9000)], 4000n)
    expect(p.kind === 'single' && p.holding.id).toBe('tok-small')
    expect(p.split).toBe(true)
  })
  test('consolidates a same-hub subset, largest first (TestSelectForAmount_ConsolidatesSameMinterSubset)', () => {
    const p = selectForAmount([h('tok-1', 2000, hubA), h('tok-2', 3000, hubA), h('tok-3', 1000, hubA)], 4000n)
    expect(p.kind).toBe('consolidate')
    expect(p.kind === 'consolidate' && ids(p.consolidateFirst)).toEqual(new Set(['tok-1', 'tok-2']))
    expect(p.split).toBe(true)
  })
  test('a consolidated exact sum does not split (TestSelectForAmount_ConsolidatedSumExactMatch)', () => {
    const p = selectForAmount([h('tok-1', 2000, hubA), h('tok-2', 3000, hubA)], 5000n)
    expect(p.kind === 'consolidate' && p.consolidateFirst.length).toBe(2)
    expect(p.split).toBe(false)
  })
  test('groups cash notes with a secret, never connection-key or bare cash (TestSelectForAmount_GroupsCashNotesButNotConnectionKeyOrBareCash)', () => {
    const p = selectForAmount(
      [
        h('tok-cash', 3000, hubA, { mode: 'cash', hasCashSecret: true }),
        h('tok-bare', 3000, hubA, { mode: 'cash', hasCashSecret: false }),
        h('tok-connkey', 3000, hubA, { mode: 'connection_key' }),
        h('tok-pubkey', 3000, hubA),
      ],
      6000n,
    )
    expect(p.kind === 'consolidate' && ids(p.consolidateFirst)).toEqual(new Set(['tok-cash', 'tok-pubkey']))
  })
  test('bills without a hub group are never grouped (TestSelectForAmount_ExcludesNoMinterFromGrouping)', () => {
    expect(() => selectForAmount([h('tok-1', 3000), h('tok-2', 3000)], 5000n)).toThrow(FundsFragmentedError)
  })
  test('different hubs never group together (TestSelectForAmount_DifferentMintersNotGroupedTogether)', () => {
    expect(() => selectForAmount([h('tok-1', 3000, hubA), h('tok-2', 3000, hubB)], 5000n)).toThrow(FundsFragmentedError)
  })
  test('a plain overdraft is InsufficientFunds, not fragmentation (TestSelectForAmount_InsufficientFunds)', () => {
    const err = (() => {
      try {
        selectForAmount([h('tok-1', 1000, hubA)], 5000n)
      } catch (e) {
        return e
      }
    })()
    expect(err).toBeInstanceOf(InsufficientFundsError)
    expect(err).toMatchObject({ totalHeld: 1000n, target: 5000n })
  })
  test('unknown amounts are ignored (TestSelectForAmount_UnknownAmountEntriesIgnored)', () => {
    const p = selectForAmount([h('tok-unknown'), h('tok-known', 5000)], 5000n)
    expect(p.kind === 'single' && p.holding.id).toBe('tok-known')
  })
  test('falls through to a later hub group that covers (TestSelectForAmount_FallsThroughToASecondMinterGroupThatCovers)', () => {
    const p = selectForAmount([h('a1', 1000, hubA), h('a2', 2000, hubA), h('b1', 2500, hubB), h('b2', 2500, hubB)], 5000n)
    expect(p.kind === 'consolidate' && ids(p.consolidateFirst)).toEqual(new Set(['b1', 'b2']))
  })
  test('a group may need every bill (TestSelectForAmount_GroupNeedsAllThreeEntries)', () => {
    const p = selectForAmount([h('1', 1000, hubA), h('2', 1000, hubA), h('3', 1000, hubA)], 2500n)
    expect(p.kind === 'consolidate' && p.consolidateFirst.length).toBe(3)
    expect(p.split).toBe(true)
  })
  test('several covering groups: the first hub key in sort order wins (TestSelectForAmount_MultipleCoveringMintersPicksLexicographicallyFirst)', () => {
    const [first, second] = hubA < hubB ? [hubA, hubB] : [hubB, hubA]
    const p = selectForAmount([h('x1', 3000, second), h('x2', 3000, second), h('y1', 3000, first), h('y2', 3000, first)], 5000n)
    expect(p.kind === 'consolidate' && ids(p.consolidateFirst)).toEqual(new Set(['y1', 'y2']))
  })
  test('empty is InsufficientFunds of 0 (TestSelectForAmount_EmptyHeldIsInsufficientFunds)', () => {
    expect(() => selectForAmount([], 5000n)).toThrow(InsufficientFundsError)
  })
  test('all-unknown amounts is InsufficientFunds of 0 (TestSelectForAmount_AllUnknownAmountsIsInsufficientFunds)', () => {
    expect(() => selectForAmount([h('1'), h('2')], 5000n)).toThrow(expect.objectContaining({ totalHeld: 0n }))
  })
  test('net plus fee across bills (TestSelectForAmount_NetPlusFeeAcrossBills)', () => {
    const p = selectForAmount([h('100', 100, hubA), h('400', 400, hubA), h('50', 50, hubA)], 506n)
    expect(p.kind === 'consolidate' && sumAmounts(p.consolidateFirst)).toBe(550n)
    expect(p.split).toBe(true)
  })
  test('the fee tips it over the edge (TestSelectForAmount_FeeIsWhatTipsItOverTheEdge)', () => {
    expect(selectForAmount([h('500', 500)], 500n).kind).toBe('single')
    expect(() => selectForAmount([h('500', 500)], 506n)).toThrow(InsufficientFundsError)
  })
  test('a fee shortfall across hubs stays fragmented (TestSelectForAmount_FeeShortfallAcrossMintersIsFragmented)', () => {
    expect(() => selectForAmount([h('a', 300, hubA), h('b', 300, hubB)], 506n)).toThrow(FundsFragmentedError)
  })
  test('a zero fee leaves the target unchanged (TestSelectForAmount_ZeroFeeTargetIsUnchanged)', () => {
    const p = selectForAmount([h('1', 400), h('2', 900)], 500n)
    expect(p.kind === 'single' && p.holding.id).toBe('2')
    expect(p.split).toBe(true)
  })
})

test('sumAmounts skips unknown amounts (TestSumAmounts)', () => {
  expect(sumAmounts([h('1', 1000), h('2'), h('3', 2500)])).toBe(3500n)
  expect(sumAmounts([])).toBe(0n)
})

test('groupableForConsolidation needs amount and hub group', () => {
  expect(ids(groupableForConsolidation([h('a', 1, hubA), h('b', undefined, hubA), h('c', 1)]))).toEqual(new Set(['a']))
})

describe('exact redeem subset (cmd/cash_redeem.go exactSubsetSumNet)', () => {
  test('finds an exact subset', () => {
    expect(exactSubsetSum([100n, 400n, 50n], 450n)).toEqual([1, 2])
    expect(exactSubsetSum([100n, 400n, 50n], 551n)).toBeUndefined()
  })
  test('refuses more than 20 values', () => {
    expect(exactSubsetSum(Array.from({ length: 21 }, () => 1n), 1n)).toBeUndefined()
    expect(exactSubsetSum(Array.from({ length: 20 }, () => 1n), 20n)).toHaveLength(20)
  })
  test('exactSameHubSum stays within one hub and skips hubless quotes', () => {
    const q = [
      { id: 'a', hubGroup: hubA, net: 300n },
      { id: 'b', hubGroup: hubB, net: 200n },
      { id: 'c', hubGroup: hubB, net: 300n },
      { id: 'd', hubGroup: '', net: 200n },
    ]
    expect(exactSameHubSum(q, 500n)?.map((x) => x.id)).toEqual(['b', 'c'])
    expect(exactSameHubSum(q, 800n)).toBeUndefined()
  })
})
