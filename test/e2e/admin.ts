// The live Hub's admin API, for the opt-in end-to-end suites (design §11.3):
//
//   CASHKIT_E2E_ADMIN_URL=http://...   the Hub's admin API
//   CASHKIT_E2E_ADMIN_TOKEN=...        an admin API token (never logged)
//
// or CASHKIT_E2E_CONFIG=<path to cashctl/integration/config.local.yaml, or the
// one lokihub's `just dev bootstrap` writes>,
// which carries both under admin_api. Port of cashctl integration/admin_client.go.
import { readFileSync } from 'node:fs'

interface Admin {
  readonly url: string
  readonly token: string
}

function adminConfig(): Admin | undefined {
  const url = process.env['CASHKIT_E2E_ADMIN_URL']
  const token = process.env['CASHKIT_E2E_ADMIN_TOKEN']
  if (url !== undefined && token !== undefined) return { url, token }
  const path = process.env['CASHKIT_E2E_CONFIG']
  if (path === undefined) return undefined
  // Just the two scalars under admin_api; not a YAML parser.
  const text = readFileSync(path, 'utf8')
  const block = /^admin_api:\n((?:[ \t]+.*\n?)*)/m.exec(text)?.[1] ?? ''
  const field = (k: string) => new RegExp(`^\\s+${k}:\\s*"?([^"\\n#]+?)"?\\s*$`, 'm').exec(block)?.[1]
  const u = field('base_url')
  const t = field('token')
  return u !== undefined && t !== undefined ? { url: u, token: t } : undefined
}

export const admin = adminConfig()

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(admin!.url + path, {
    method,
    headers: { authorization: `Bearer ${admin!.token}`, ...(body !== undefined && { 'content-type': 'application/json' }) },
    ...(body !== undefined && { body: JSON.stringify(body) }),
  })
  const text = await res.text()
  // The response body, never the request: the token stays out of errors.
  if (!res.ok) throw new Error(`${method} ${path}: HTTP ${res.status}: ${text.slice(0, 300)}`)
  return (text === '' ? undefined : JSON.parse(text)) as T
}

export interface CreatedApp {
  readonly id: number
  readonly pairingUri: string
  readonly cashHubToken?: string
  readonly circleHubToken?: string
}

// The Hub's own relay: CASHKIT_E2E_RELAY, else relay_url in CASHKIT_E2E_CONFIG
// (lokihub's `just dev bootstrap` writes it into integration/config.local.yaml).
function relayConfig(): string | undefined {
  const env = process.env['CASHKIT_E2E_RELAY']
  if (env !== undefined && env !== '') return env
  const path = process.env['CASHKIT_E2E_CONFIG']
  if (path === undefined) return undefined
  return /^relay_url:\s*"?([^"\n#]+?)"?\s*$/m.exec(readFileSync(path, 'utf8'))?.[1]
}

export const relayUrl = relayConfig()

/** A throwaway, self-funded cash_hub (cashctl integration/cash_test.go setUpCashHubOpts). */
export async function createCashHub(o: { name: string; perWalletMaxMloki?: number; fundLoki?: number }): Promise<CreatedApp> {
  const hub = await api<CreatedApp>('POST', '/api/apps', {
    name: o.name,
    kind: 'cash_hub',
    maxAmount: 0,
    scopes: ['cash_hub', 'pay_invoice', 'make_invoice', 'get_balance'],
    cashPerWalletMaxMloki: o.perWalletMaxMloki ?? 10_000_000,
    cashMaxExpSecs: 3600,
  })
  await api('POST', '/api/transfers', { toAppId: hub.id, amountLoki: o.fundLoki ?? 2000 })
  return hub
}

/** Deletes every child wallet of a cash_hub, then the hub; a hub an order or a mint record still holds stays. */
export async function deleteCashHub(hub: CreatedApp | undefined): Promise<void> {
  if (hub === undefined) return
  try {
    const { claims } = await api<{ claims: { wallet_app_id: number }[] }>('GET', `/api/apps/${hub.id}/cash-wallets?limit=0`)
    for (const id of new Set(claims.map((c) => c.wallet_app_id))) {
      await api('DELETE', `/api/apps/${hub.id}/cash-wallets/${id}`).catch(() => undefined)
    }
  } finally {
    await api('DELETE', `/api/apps/${hub.id}`).catch(() => undefined)
  }
}

// The regtest dev stack's chain and payer hooks (lokihub http/testhooks.go,
// served under /api/test behind the admin token, regtest only).
// CASHKIT_E2E_HOOKS=0 turns them off.
export const hooks = {
  /** Whether the Hub answers the hooks at all. */
  async available(): Promise<boolean> {
    if (admin === undefined || process.env['CASHKIT_E2E_HOOKS'] === '0') return false
    return api('GET', '/api/test/chain/tip').then(
      () => true,
      () => false,
    )
  },
  mine: (blocks = 1): Promise<{ blocks: string[] }> => api('POST', '/api/test/chain/mine', { blocks }),
  tip: (): Promise<{ height: number; hash: string }> => api('GET', '/api/test/chain/tip'),
  tx: (txid: string): Promise<{ txid: string; hex: string; depth: number }> => api('GET', `/api/test/chain/tx/${txid}`),
  withhold: (txid: string, on: boolean): Promise<void> => api('POST', '/api/test/chain/withhold', { txid, on }),
  payInvoice: (invoice: string): Promise<{ status: string; preimage?: string; failure_reason?: string }> => api('POST', '/api/test/payer/pay-invoice', { invoice }),
  payAddress: async (address: string, amountMillis: bigint): Promise<string> =>
    (await api<{ txid: string }>('POST', '/api/test/payer/pay-address', { address, amount_millis: Number(amountMillis) })).txid,
  payerInvoice: async (amountMillis: bigint): Promise<string> =>
    (await api<{ payment_request: string }>('POST', '/api/test/payer/invoice', { amount_millis: Number(amountMillis) })).payment_request,
  payerAddress: async (): Promise<string> => (await api<{ address: string }>('GET', '/api/test/payer/address')).address,
}

/** Polls cond every 3 s until it holds, mining one block between polls when mine is set. */
export async function until(what: string, cond: () => Promise<boolean>, o: { tries?: number; mine?: boolean } = {}): Promise<void> {
  const tries = o.tries ?? 40
  for (let i = 0; i < tries; i++) {
    if (await cond()) return
    if (o.mine === true) await hooks.mine(1)
    await new Promise((r) => setTimeout(r, 3000))
  }
  throw new Error(`${what}: not reached after ${tries} tries`)
}
