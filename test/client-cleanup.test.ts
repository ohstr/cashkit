// The client keeps no composite flows and never reads a Hub's message
// (NIP-CASH §Errors); every bill-creating call carries the caller's
// request_id; wallet notifications (NIP-47 kinds 23196/23197) are read only
// from the wallet. T-1801..T-1803.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { beforeEach, describe, expect, test } from 'vitest'
import { bySigning, finalizeEvent, KIND_NWC_NOTIFICATION, localSigner, nip44, pubkeyTarget, type NWCNotification } from '../src/core/index.js'
import * as client from '../src/client/index.js'
import { CashClient, NwcClient } from '../src/client/index.js'
import { FakeBank } from './fakeBank.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill } from './helpers.js'
import { FakeNwcWallet } from './walletHarness.js'

const R1 = 'wss://hub.test'
const alice = localSigner(fill(3, 32))
let pool: MemoryRelayPool
let bank: FakeBank
beforeEach(async () => {
  pool = new MemoryRelayPool()
  bank = new FakeBank(pool, [R1])
  await bank.start()
})

describe('T-1801 no composite flows', () => {
  test('transferFromSources, rekeyCashSlice, reconnect and PartialProgressError are gone', () => {
    for (const m of ['transferFromSources', 'rekeyCashSlice', 'reconnect']) expect(m in CashClient.prototype).toBe(false)
    expect('PartialProgressError' in client).toBe(false)
  })
})

describe('T-1802 no bill-creating call without the caller’s request_id', () => {
  test('a transfer or consolidate item without one is bad_input before anything is sent', async () => {
    const w = bank.mintToPubkey(1000n, alice.pubkey)
    const c = new CashClient({ relays: pool, replyWaitMs: 1000 }, w.token)
    const before = pool.published.filter((p) => p.event.kind === 23190).length
    await expect(c.cashTransfer({ credential: bySigning(alice), to: pubkeyTarget(alice.pubkey), currentAmount: 1000n } as never)).rejects.toMatchObject({ code: 'bad_input' })
    await expect(c.cashConsolidate(bySigning(alice), { sources: [], to: pubkeyTarget(alice.pubkey) } as never)).rejects.toMatchObject({ code: 'bad_input' })
    expect(pool.published.filter((p) => p.event.kind === 23190).length).toBe(before)
  })
})

const run = (dir: string) => spawnSync(process.execPath, ['tools/lint-no-message-match.mjs', dir], { encoding: 'utf8' })

describe('T-1803 no code acts on a Hub message', () => {
  test('src is clean', () => {
    expect(run('src').status).toBe(0)
  })
  test('each kind of message test is flagged; a presence check is not', () => {
    const dir = mkdtempSync(join(tmpdir(), 'msg-'))
    const bad = ["if (e.walletMessage.includes('x')) {}", "if (e.rawMessage === 'y') {}", "if (/z/.test(e.walletMessage)) {}", "if (e.walletMessage.toLowerCase().startsWith('a')) {}"]
    bad.forEach((l, i) => writeFileSync(join(dir, `b${i}.ts`), l + '\n'))
    writeFileSync(join(dir, 'ok.ts'), 'if (e.rawMessage !== undefined) show(e.rawMessage)\n')
    const r = run(dir)
    expect(r.status).toBe(1)
    expect(r.stderr.split('\n').filter((l) => l.includes(': '))).toHaveLength(bad.length)
    expect(r.stderr).not.toContain('ok.ts')
  })
})

describe('NWC notifications', () => {
  test('a notification from the wallet is delivered once; one from another key is not', async () => {
    const nwc = new FakeNwcWallet(pool, 0x71, R1)
    const c = new NwcClient({ relays: pool }, nwc.uri)
    const got: NWCNotification[] = []
    const stop = c.notifications((n) => got.push(n))
    const clientPub = (await import('../src/core/index.js')).getPublicKey(nwc.appSecret)
    const note = (key: Uint8Array, type: string) =>
      finalizeEvent(
        { kind: KIND_NWC_NOTIFICATION, created_at: 1, tags: [['p', clientPub]], content: nip44.encrypt(JSON.stringify({ notification_type: type, notification: { at: 1 } }), nip44.getConversationKey(key, clientPub)) },
        key,
      )
    const real = note(nwc.key, 'rotation_pending')
    await pool.publish(R1, real)
    await pool.publish(R1, real)
    await pool.publish(R1, note(fill(0x99, 32), 'wallet_frozen'))
    await new Promise((r) => setTimeout(r, 20))
    stop()
    expect(got).toEqual([{ type: 'rotation_pending', notification: { at: 1 } }])
  })
})
