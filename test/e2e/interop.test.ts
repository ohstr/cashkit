// cashkit's half of the cross-client round with cashctl against one live Hub
// (design §11.3). A driver outside this repo runs cashctl and this file in
// turns, handing bills over through files in CASHKIT_E2E_INTEROP_DIR:
//
//   hub.txt             in   a funded Hub's signed cashhub1 string
//   ctl-note.txt        in   <token>#<secret> cashctl minted          -> kit-received.json
//   ctl-pubkey.txt      in   cashctl's identity (hex)                  -> kit-zap.json (a zap to it)
//   ctl-lost-note.txt   in   a note cashctl moved while its reply was lost -> kit-lost.json
//                       out  kit-note.txt: a note this side minted, for cashctl
//                       out  kit-lost-note.txt + kit-lost-pending.json: a note this
//                            side transferred while it lost the reply (settled after)
//
// Each test runs only when its input file is there, so the driver chooses the
// phase by what it has written. Every output is JSON or one line of text.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, test } from 'vitest'
import { RelayWs } from '../../src/adapters/relay-ws.js'
import { MemoryStorage } from '../../src/adapters/storage-memory.js'
import { NoneVault } from '../../src/adapters/vault-none.js'
import { Wallet, CashkitError } from '../../src/wallet/index.js'
import type { WalletDeps } from '../../src/wallet/ports.js'
import { relayUrl } from './admin.js'

const dir = process.env['CASHKIT_E2E_INTEROP_DIR']
const has = (f: string) => dir !== undefined && existsSync(join(dir, f))
const read = (f: string) => readFileSync(join(dir!, f), 'utf8').trim()
const write = (f: string, v: unknown) => writeFileSync(join(dir!, f), typeof v === 'string' ? `${v}\n` : JSON.stringify(v, (_k, x: unknown) => (typeof x === 'bigint' ? x.toString() : x), 2))

const pool = new RelayWs()
const opened: Wallet[] = []
async function openWallet(o: Partial<WalletDeps> = {}, settle = true): Promise<Wallet> {
  const w = await Wallet.open({ storage: new MemoryStorage(), vault: new NoneVault(), relays: pool, ...o }, { settle })
  opened.push(w)
  return w
}
const errCode = (e: unknown) => (e instanceof CashkitError ? e.code : e instanceof Error ? e.message : String(e))

afterAll(() => {
  for (const w of opened) w.close()
  pool.close()
})

describe.skipIf(dir === undefined)('interop with cashctl', () => {
  test.skipIf(!has('ctl-note.txt'))('receives a note cashctl minted and reads it available', async () => {
    const w = await openWallet()
    await w.identity.generate()
    const got = await w.receive(read('ctl-note.txt'))
    expect(got.received).toBe(true)
    const st = await w.status()
    write('kit-received.json', { received: got.received, amount: got.received ? got.holding.amount : undefined, outcomes: st.outcomes })
    expect(st.firstError).toBeUndefined()
    expect(st.outcomes).toMatchObject([{ ok: true, state: 'available' }])
  }, 300_000)

  test.skipIf(!has('hub.txt'))('mints a note for cashctl over the shared cashhub1', async () => {
    const w = await openWallet()
    await w.identity.generate()
    await w.connections.add('hub', read('hub.txt'), { confirmUnverified: async () => false })
    const m = await w.mint({ hub: 'hub', amount: 7_000n, to: 'cash' })
    expect(m.cashNote).toMatch(/#[0-9a-f]{64}$/)
    write('kit-note.txt', m.cashNote!)
  }, 300_000)

  test.skipIf(!has('hub.txt') || !has('ctl-pubkey.txt') || relayUrl === undefined)('zaps the identity cashctl holds', async () => {
    const w = await openWallet()
    await w.identity.generate()
    await w.connections.add('hub', read('hub.txt'), { confirmUnverified: async () => false })
    await w.mint({ hub: 'hub', amount: 20_000n, to: 'self' })
    const sent = await w.zaps.send({ to: read('ctl-pubkey.txt'), amountMillis: 8_000n, target: { e: 'cd'.repeat(32), k: '1' }, relays: [relayUrl!] })
    write('kit-zap.json', { eventId: sent.eventId, countable: sent.countable, reason: sent.reason, relays: sent.relays })
    expect(sent.eventId).toMatch(/^[0-9a-f]{64}$/)
  }, 300_000)

  test.skipIf(!has('ctl-lost-note.txt'))('sees a note cashctl spent while its reply was lost as gone', async () => {
    const w = await openWallet()
    await w.identity.generate()
    const out = await w.receive(read('ctl-lost-note.txt')).then(
      (r) => ({ received: r.received }),
      (e: unknown) => ({ error: errCode(e) }),
    )
    write('kit-lost.json', out)
    expect('received' in out && out.received).toBeFalsy()
  }, 300_000)

  test.skipIf(!has('hub.txt'))('transfers a note while losing the reply, hands it to cashctl, then settles', async () => {
    const storage = new MemoryStorage()
    const vault = new NoneVault()
    const a = await openWallet({ storage, vault })
    await a.identity.generate()
    await a.connections.add('hub', read('hub.txt'), { confirmUnverified: async () => false })
    const m = await a.mint({ hub: 'hub', amount: 11_000n, to: 'cash' })
    // Hold the note ourselves, then move it while the reply is lost.
    await a.receive(m.cashNote!)
    a.close()
    write('kit-lost-note.txt', m.cashNote!)
    const lossy = await openWallet({ storage, vault, replyWaitMs: 1 }, false)
    const lost = await lossy.send({ amount: 4_000n }).catch((e: unknown) => e)
    lossy.close()
    const w = await openWallet({ storage, vault }, false)
    let report = await w.settle()
    for (let i = 0; i < 20 && report.open.length > 0; i++) {
      await new Promise((r) => setTimeout(r, 5000))
      report = await w.settle()
    }
    write('kit-lost-pending.json', { lost: errCode(lost), settle: report, held: (await w.balance()).holdings.held })
    expect(report.open).toEqual([])
    expect((await w.balance()).holdings.held).toBe(7_000n)
  }, 600_000)
})
