// Decode parity with `cashctl decode --json` (design §11). Opt-in: it
// needs a cashctl binary, so it runs only when CASHCTL_BIN points at one.
//
//   go -C ../cashctl build -o /tmp/cashctl . && CASHCTL_BIN=/tmp/cashctl pnpm test
//
// For every corpus string, cashkit's view of it (sniff, split, decode,
// verifyProvenance) must produce exactly the JSON cashctl prints, and must
// fail exactly when cashctl does.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { bech32Encode, toWords } from '../../src/core/bech32.js'
import {
  bech32Hrp,
  decodeCircleHubConnection,
  decodeToken,
  encodeToken,
  fromHex,
  hasProvenance,
  sniff,
  splitCashString,
  toHex,
  trimSpace,
  verifyProvenance,
} from '../../src/core/index.js'

type Json = any

const bin = process.env['CASHCTL_BIN']
const home = mkdtempSync(join(tmpdir(), 'cashkit-parity-'))

function cashctl(input: string): Json | undefined {
  try {
    const stdout = execFileSync(bin!, ['decode', '--json', '--', input], {
      env: { PATH: process.env['PATH'] ?? '', HOME: home, XDG_CONFIG_HOME: home, NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 20_000,
    }).toString()
    // attested_amount_millis is a uint64: read it as a bigint, not a double.
    return JSON.parse(stdout, (key, value, ctx?: { source?: string }) =>
      key === 'attested_amount_millis' && ctx?.source !== undefined ? BigInt(ctx.source) : value,
    )
  } catch (err: Json) {
    if (typeof err?.status === 'number' && err.status !== 0) return undefined
    throw err
  }
}

/** What cashctl decode prints for `input`, built from cashkit; undefined = refused. */
function cashkit(input: string): Json | undefined {
  const { token: value, cashSecret } = splitCashString(trimSpace(input))
  try {
    switch (sniff(value)) {
      case 'cash_token': {
        const tok = decodeToken(value)
        const out: Json = {
          type: 'cash_token',
          hrp: tok.hrp,
          wallet_pubkey: tok.walletPubkey,
          relays: [...tok.relays],
          identity_required: tok.identityRequired ?? null,
        }
        if (tok.hubGroup !== undefined && tok.hubGroup.length > 0) out.cash_hub = toHex(tok.hubGroup)
        if (cashSecret !== '') out.embedded_cash_secret_present = true
        if (hasProvenance(tok)) {
          out.mint_signature = toHex(tok.mintSignature!)
          out.attested_amount_millis = tok.attestedAmountMillis
          const minter = verifyProvenance(tok)
          out.mint_signature_valid = minter !== undefined
          if (minter !== undefined) out.minter_pubkey = minter
        }
        return out
      }
      case 'circlehub': {
        const c = decodeCircleHubConnection(value)
        return { type: 'circlehub', hrp: 'circlehub', wallet_pubkey: c.walletPubkey, relays: [...c.relays], label: c.label }
      }
      case 'nostr_entity':
        // npub is decoded by nip19, which cashctl decode doesn't expand; only
        // the routing is compared here.
        return bech32Hrp(value) === 'npub' ? { type: 'npub' } : undefined
      case 'nwc_uri':
        return { type: 'nwc_uri' }
      default:
        return undefined
    }
  } catch {
    return undefined
  }
}

function corpus(): [string, string][] {
  const out: [string, string][] = []
  const tlv: Json = JSON.parse(readFileSync(new URL('../../vectors/tlv.json', import.meta.url), 'utf8'))
  for (const c of tlv.decode) {
    out.push([`${c.kind}: ${c.name}`, c.input])
    if (!c.error && c.kind === 'token') {
      out.push([`${c.kind}: ${c.name} (padded)`, `  ${c.input}\n`])
      out.push([`${c.kind}: ${c.name} (#secret)`, `${c.input}#${'ab'.repeat(32)}`])
    }
  }
  const prov: Json = JSON.parse(readFileSync(new URL('../../vectors/provenance.json', import.meta.url), 'utf8'))
  for (const c of prov.verify) {
    if (c.mintSignature === null || c.attestedAmountMillis === null || c.mintSignature.length !== 130) continue
    out.push([
      `provenance: ${c.name}`,
      encodeToken({
        hrp: c.hrp,
        walletPubkey: c.walletPubkey,
        secret: '33'.repeat(32),
        relays: ['wss://r.example'],
        scheme: 'mint_v1',
        mintSignature: fromHex(c.mintSignature),
        attestedAmountMillis: BigInt(c.attestedAmountMillis),
      }),
    ])
  }
  const key = toWords(fromHex('22'.repeat(32)))
  out.push(['routing: npub', bech32Encode('npub', key)])
  out.push(['routing: nsec', bech32Encode('nsec', key)])
  out.push(['routing: lightning invoice prefix', bech32Encode('lnbc10u', key)])
  out.push(['routing: cashhub is refused', bech32Encode('cashhub', key)])
  out.push(['routing: not bech32', 'hello world'])
  return out
}

describe.skipIf(bin === undefined)('decode parity with cashctl', () => {
  test.each(corpus())('%s', (_, input) => {
    const want = cashctl(input)
    const got = cashkit(input)
    if (want === undefined) {
      expect(got).toBeUndefined()
    } else if (want.type === 'npub' || want.type === 'nwc_uri') {
      expect(got).toEqual({ type: want.type })
    } else {
      expect(got).toEqual(want)
    }
  })
})
