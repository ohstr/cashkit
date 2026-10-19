// End to end against a live Hub over real relays (design §11.3). Opt-in:
//
//   CASHKIT_E2E_BILL=lokicash1...  a bill minted with a mint signature
//   CASHKIT_E2E_SECRET=<64 hex>    its cash secret (cash-mode bill), or
//   CASHKIT_E2E_IDENTITY=<64 hex>  the identity key it is bound to
//
//   just e2e
//
// Read-only: it asks the bill's status and never moves value.
import { describe, expect, test } from 'vitest'
import { bySecret, bySigning, fromHex, localSigner } from '../../src/core/index.js'
import { CashClient } from '../../src/client/index.js'
import { RelayWs } from '../../src/adapters/relay-ws.js'

const bill = process.env['CASHKIT_E2E_BILL']
const secret = process.env['CASHKIT_E2E_SECRET']
const identity = process.env['CASHKIT_E2E_IDENTITY']

describe.skipIf(bill === undefined || (secret === undefined && identity === undefined))('live hub', () => {
  test('cash_status over the private transport', async () => {
    const pool = new RelayWs()
    try {
      const credential = secret !== undefined ? bySecret(secret) : bySigning(localSigner(fromHex(identity!)))
      const c = new CashClient({ relays: pool }, bill!)
      const s = await c.session()
      expect(s.inbox).toMatch(/^[0-9a-f]{64}$/)
      const st = await c.state(credential)
      expect(st.state).not.toBe('indeterminate')
    } finally {
      pool.close()
    }
  }, 120_000)
})
