// NIP-CASH §Looking Up a Call, Finality: a mint_cash is never placed again without its user's explicit
// confirmation, while a cash_transfer or cash_consolidate is re-placed automatically by its device.
import { expect, test, vi } from 'vitest'
import type { CallKind } from '../src/wallet/runner.js'

const seen = new Map<string, CallKind>()
vi.mock('../src/wallet/runner.js', async (orig) => {
  const m = await orig<typeof import('../src/wallet/runner.js')>()
  return { ...m, registerCallKind: (name: string, kind: CallKind) => (seen.set(name, kind), m.registerCallKind(name, kind)) }
})

test('the registered kinds: mint asks the user before placing again; transfer and consolidate are placed again by their device', async () => {
  await import('../src/wallet/index.js')
  expect(seen.get('mint')).toMatchObject({ autoReplace: false, replaceRequest: 'confirmMintReplace' })
  expect(seen.get('transfer')?.autoReplace).toBe(true)
  expect(seen.get('consolidate')?.autoReplace).toBe(true)
})
