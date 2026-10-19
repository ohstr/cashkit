// Backups (design §10): export, restore elsewhere, and spend.
import { describe, expect, test } from 'vitest'
import { newCashTarget } from '../src/core/index.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { NoneVault } from '../src/adapters/vault-none.js'
import { PassphraseVault } from '../src/adapters/vault-passphrase.js'
import { BACKUP_FORMAT, decodeRow, type BackupFile } from '../src/wallet/index.js'
import { FakeNwcWallet, harness, type Harness } from './walletHarness.js'

const LOGN = { logN: 4 }

async function loaded(): Promise<{ h: Harness; nwc: FakeNwcWallet; cashSecret: string; note: string }> {
  const vault = await PassphraseVault.create('device pw', LOGN)
  const h = await harness({ deps: { vault } })
  const nwc = new FakeNwcWallet(h.pool)
  await h.wallet.connections.add('main', nwc.uri)
  const t = newCashTarget()
  await h.wallet.receive(`${h.bank.mintToCash(3000n, t.secret).token}#${t.secret}`)
  await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
  const sent = await h.wallet.send({ holdings: [(await h.wallet.holdings())[1]!.id], amount: 1000n })
  const cash = (await h.wallet.holdings()).find((x) => x.mode === 'cash')!
  return { h, nwc, cashSecret: (await h.wallet.exportHolding(cash.id)).split('#')[1]!, note: sent.cashNote! }
}

describe('backup', () => {
  test('restores into a fresh wallet with another vault, intact and spendable', async () => {
    const { h, cashSecret, note } = await loaded()
    const text = await h.wallet.exportBackup('backup pw', LOGN)
    const fresh = await harness({ identity: false, pool: h.pool, bank: h.bank, deps: { vault: new NoneVault(), storage: new MemoryStorage() } })
    const sum = await fresh.wallet.importBackup(text, 'backup pw')
    expect(sum).toMatchObject({ walletId: h.wallet.walletId, holdings: 3, handoffs: 1, connections: 1, identity: true })
    const w = fresh.wallet
    expect(w.walletId).toBe(h.wallet.walletId)
    expect((await w.identity.get())?.pubkey).toBe(h.me)
    expect((await w.holdings()).map((x) => [x.mode, x.amount])).toEqual((await h.wallet.holdings()).map((x) => [x.mode, x.amount]))
    const cash = (await w.holdings()).find((x) => x.mode === 'cash')!
    expect((await w.exportHolding(cash.id)).split('#')[1]).toBe(cashSecret)
    expect((await w.handoffs({ includeSecrets: true }))[0]!.handoff).toBe(note)
    expect((await w.connections.list())[0]).toMatchObject({ name: 'main', isDefault: true })
    // The restored wallet can move the money: its keys and secrets are real.
    expect((await w.send({ amount: 3500n })).sent).toBe(3500n)
  })
  test('the file holds no secret in the clear, and amounts as exact integers', async () => {
    const { h, nwc, cashSecret, note } = await loaded()
    const text = await h.wallet.exportBackup('backup pw', LOGN)
    const priv = (await h.wallet.identity.export('x', LOGN)).length > 0
    expect(priv).toBe(true)
    for (const secret of [cashSecret, note.split('#')[1]!, Buffer.from(nwc.appSecret).toString('hex')]) expect(text).not.toContain(secret)
    const f = decodeRow<BackupFile>(text)
    expect(f).toMatchObject({ format: BACKUP_FORMAT, version: 1, kdf: { name: 'scrypt', logN: 4, r: 8, p: 1 } })
    expect((f.collections.holdings as { amount?: bigint }[]).map((x) => x.amount)).toContain(3000n)
    expect(text).toContain('{"$bigint":"3000"}')
    expect(JSON.stringify(f.collections.identity)).toContain('"priv":{"sealed":')
  })
  test('refuses a wrong passphrase, a damaged or foreign file, a newer format, and a wallet that is not empty', async () => {
    const { h } = await loaded()
    const text = await h.wallet.exportBackup('backup pw', LOGN)
    const fresh = async () => (await harness({ identity: false, pool: h.pool, bank: h.bank })).wallet
    await expect((await fresh()).importBackup(text, 'nope')).rejects.toMatchObject({ code: 'auth' })
    await expect((await fresh()).importBackup('not json', 'backup pw')).rejects.toMatchObject({ code: 'invalid_input' })
    await expect((await fresh()).importBackup('{"format":"other"}', 'backup pw')).rejects.toMatchObject({ code: 'invalid_input' })
    await expect((await fresh()).importBackup(text.replace('"version":1', '"version":9'), 'backup pw')).rejects.toMatchObject({ code: 'usage' })
    const f = decodeRow<BackupFile>(text)
    const row = (f.collections.holdings as { cashSecret?: { sealed: string } }[]).find((x) => x.cashSecret !== undefined)!
    row.cashSecret = { sealed: row.cashSecret!.sealed.slice(0, -4) + 'AAAA' }
    const { encodeRow } = await import('../src/wallet/index.js')
    await expect((await fresh()).importBackup(encodeRow(f), 'backup pw')).rejects.toThrow(/damaged/)
    await expect(h.wallet.importBackup(text, 'backup pw')).rejects.toMatchObject({ code: 'exists' })
  })
  test('state.backupStale: false when empty, true after value moves, false after an export', async () => {
    const h = await harness({ identity: false })
    expect(h.wallet.state.backupStale).toBe(false)
    await h.wallet.identity.generate()
    await h.wallet.reload()
    expect(h.wallet.state.backupStale).toBe(true)
    await h.wallet.exportBackup('pw', LOGN)
    await h.wallet.reload()
    expect(h.wallet.state).toMatchObject({ backupStale: false })
    expect(h.wallet.state.lastBackupAt).toBeGreaterThan(0)
    await h.wallet.receive(h.bank.mintToPubkey(5000n, (await h.wallet.identity.get())!.pubkey).token)
    await h.wallet.reload()
    expect(h.wallet.state.backupStale).toBe(true)
  })
  test('an empty passphrase is refused', async () => {
    const h = await harness()
    await expect(h.wallet.exportBackup('')).rejects.toMatchObject({ code: 'usage' })
  })
})
