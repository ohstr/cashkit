// SecretVault adapters (design §3, §10): one contract for every vault, plus
// what each adds.
import { indexedDB } from 'fake-indexeddb'
import { describe, expect, test } from 'vitest'
import { DeviceVault } from '../src/adapters/vault-device.js'
import { NoneVault } from '../src/adapters/vault-none.js'
import { PassphraseVault, WrongPassphraseError } from '../src/adapters/vault-passphrase.js'
import type { SecretVault } from '../src/wallet/index.js'
import { harness } from './walletHarness.js'

const enc = (s: string) => new TextEncoder().encode(s)
let dbn = 0

function vaultContract(name: string, make: () => Promise<SecretVault>, o: { encrypts: boolean }) {
  describe(`SecretVault contract: ${name}`, () => {
    test('seal then open round-trips, empty and large values included', async () => {
      const v = await make()
      for (const plain of [new Uint8Array(0), enc('ab'.repeat(32)), new Uint8Array(100_000).fill(7)]) expect(await v.open(await v.seal(plain))).toEqual(plain)
    })
    test('refuses a value sealed by another kind of vault', async () => {
      const v = await make()
      await expect(v.open({ alg: 'something-else', data: 'AA' })).rejects.toThrow(/cannot open/)
    })
    if (o.encrypts) {
      test('the sealed form does not contain the secret', async () => {
        const v = await make()
        const secret = 'ab'.repeat(32)
        const s = await v.seal(enc(secret))
        expect(JSON.stringify(s)).not.toContain(secret)
        expect(JSON.stringify(s)).not.toContain(Buffer.from(secret).toString('base64').slice(0, 20))
      })
      test('two seals of one value differ (fresh nonce each time)', async () => {
        const v = await make()
        expect((await v.seal(enc('x'))).data).not.toBe((await v.seal(enc('x'))).data)
      })
      test('a tampered value is refused', async () => {
        const v = await make()
        const s = await v.seal(enc('secret'))
        const last = s.data.at(-2) === 'A' ? 'B' : 'A'
        await expect(v.open({ ...s, data: `${s.data.slice(0, -2)}${last}${s.data.slice(-1)}` })).rejects.toThrow()
      })
    }
  })
}

vaultContract('none', async () => new NoneVault(), { encrypts: false })
vaultContract('passphrase', () => PassphraseVault.create('correct horse', { logN: 4 }), { encrypts: true })
vaultContract('device', () => DeviceVault.open({ name: `v${++dbn}`, indexedDB }), { encrypts: true })

describe('PassphraseVault', () => {
  test('unlocks with its params in a later process; a wrong passphrase fails at unlock', async () => {
    const a = await PassphraseVault.create('correct horse', { logN: 4 })
    const sealed = await a.seal(enc('the secret'))
    const params = JSON.parse(JSON.stringify(a.params))
    await expect(PassphraseVault.unlock('wrong', params)).rejects.toBeInstanceOf(WrongPassphraseError)
    const b = await PassphraseVault.unlock('correct horse', params)
    expect(new TextDecoder().decode(await b.open(sealed))).toBe('the secret')
  })
  test('the passphrase is NFKC-normalized, as NIP-49 does', async () => {
    const a = await PassphraseVault.create('Å', { logN: 4 })
    await expect(PassphraseVault.unlock('Å', a.params)).resolves.toBeInstanceOf(PassphraseVault)
  })
  test('lock forgets the key; unlock brings it back', async () => {
    const v = await PassphraseVault.create('pw', { logN: 4 })
    const s = await v.seal(enc('x'))
    v.lock()
    expect(v.locked()).toBe(true)
    await expect(v.open(s)).rejects.toThrow(/locked/)
    await expect(v.seal(enc('y'))).rejects.toThrow(/locked/)
    await expect(v.unlock('nope')).rejects.toBeInstanceOf(WrongPassphraseError)
    await v.unlock('pw')
    expect(new TextDecoder().decode(await v.open(s))).toBe('x')
  })
  test('a value from another vault is refused plainly, even with the same passphrase', async () => {
    const a = await PassphraseVault.create('pw', { logN: 4 })
    const b = await PassphraseVault.create('pw', { logN: 4 })
    await expect(b.open(await a.seal(enc('x')))).rejects.toThrow(/different vault/)
  })
  test('the params carry no secret and an empty passphrase is refused', async () => {
    const v = await PassphraseVault.create('pw', { logN: 4 })
    expect(new Set(Object.keys(v.params))).toEqual(new Set(['check', 'logN', 'salt', 'v']))
    await expect(PassphraseVault.create('')).rejects.toThrow(/empty/)
  })
})

describe('DeviceVault', () => {
  test('reopening the same profile finds the same key', async () => {
    const name = `v${++dbn}`
    const a = await DeviceVault.open({ name, indexedDB })
    const s = await a.seal(enc('kept'))
    const b = await DeviceVault.open({ name, indexedDB })
    expect(new TextDecoder().decode(await b.open(s))).toBe('kept')
  })
  test('another profile cannot open it', async () => {
    const a = await DeviceVault.open({ name: `v${++dbn}`, indexedDB })
    const b = await DeviceVault.open({ name: `v${++dbn}`, indexedDB })
    await expect(b.open(await a.seal(enc('x')))).rejects.toThrow(/another device/)
  })
  test('the key is not extractable', async () => {
    const name = `v${++dbn}`
    await DeviceVault.open({ name, indexedDB })
    const db = await new Promise<IDBDatabase>((r) => {
      const q = indexedDB.open(name, 1)
      q.addEventListener('success', () => r(q.result))
    })
    const key = await new Promise<CryptoKey>((r) => {
      const q = db.transaction('keys').objectStore('keys').get('device')
      q.addEventListener('success', () => r(q.result as CryptoKey))
    })
    expect(key.extractable).toBe(false)
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow()
    db.close()
  })
  test('two tabs opening at once share one key', async () => {
    const name = `v${++dbn}`
    const [a, b] = await Promise.all([DeviceVault.open({ name, indexedDB }), DeviceVault.open({ name, indexedDB })])
    expect(new TextDecoder().decode(await b.open(await a.seal(enc('x'))))).toBe('x')
  })
})

describe('a wallet over a locked vault', () => {
  test('refuses to move money with auth, and works again once unlocked', async () => {
    const vault = await PassphraseVault.create('pw', { logN: 4 })
    const h = await harness({ deps: { vault } })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    vault.lock()
    await expect(h.wallet.send({ amount: 1000n })).rejects.toMatchObject({ code: 'auth' })
    await vault.unlock('pw')
    expect((await h.wallet.send({ amount: 1000n })).sent).toBe(1000n)
  })
  test('every secret at rest is sealed by the vault', async () => {
    const vault = await PassphraseVault.create('pw', { logN: 4 })
    const h = await harness({ deps: { vault } })
    await h.wallet.receive(h.bank.mintToPubkey(5000n, h.me).token)
    const r = await h.wallet.send({ amount: 1000n })
    const dump = JSON.stringify(await h.storage.tx('r', async (t) => [await t.list('holdings'), await t.list('handoffs'), await t.list('identity')]), (_k, x: unknown) => (typeof x === 'bigint' ? x.toString() : x))
    expect(dump).not.toContain(r.cashNote!.split('#')[1])
    expect(dump).toContain('passphrase-v1')
  })
})
