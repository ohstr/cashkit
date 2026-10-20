// The live Hub's admin API, for the opt-in end-to-end suites (design §11.3):
//
//   CASHKIT_E2E_ADMIN_URL=http://...   the Hub's admin API
//   CASHKIT_E2E_ADMIN_TOKEN=...        an admin API token (never logged)
//
// or CASHKIT_E2E_CONFIG=<path to cashctl/integration/config.local.yaml>,
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
  readonly circleHubToken?: string
}
