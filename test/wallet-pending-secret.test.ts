// An unresolved pending cash secret is never overwritten or dropped: a
// second protect, settle() and the return to cash notes all leave it alone
// until the Hub answers definitely. Ports cashctl
// cmd/pending_secret_batch_test.go and cmd/receive_secure_test.go
// (protectRekeyOnly) for the same slot rules.
import { describe, expect, test } from 'vitest'
import { fromHex, getPublicKey, newCashTarget, toHex, utf8 } from '../src/core/index.js'
import type { Holding, Sealed } from '../src/wallet/index.js'
import { clearPendingKey, clearPendingSecret, hasOpenPendingSecret } from '../src/wallet/bills.js'
import { commitment } from './fakeBank.js'
import { harness, type Harness } from './walletHarness.js'

const seal = (s: string): Sealed => ({ alg: 'none', data: toHex(utf8(s)) })
const unseal = (s: Sealed | undefined) => (s === undefined ? undefined : new TextDecoder().decode(fromHex(s.data)))
const row = (h: Harness, id: string) => h.storage.tx('r', (t) => t.get('holdings', id)) as Promise<Holding>
const transfers = (h: Harness) => h.bank.hub.requests.filter((r) => r.item.method === 'cash_transfer').length

/** The secret that controls the holding's bill now is the one stored as its current secret. */
async function controlledByCurrent(h: Harness, id: string) {
  const r = await row(h, id)
  const w = h.bank.wallets.get(r.walletPubkey)!
  expect(w.spent).toBe(false)
  expect(w.identity).toEqual({ type: 'cash', value: commitment(unseal(r.cashSecret)!) })
}

/** A cash note received unprotected, then a protect whose reply is lost: the Hub applied it, only the pending secret works. */
async function rekeyLostReply(h: Harness) {
  const t = newCashTarget()
  const w = h.bank.mintToCash(5000n, t.secret)
  const r = await h.wallet.receive(`${w.token}#${t.secret}`, { protect: false })
  if (!r.received) throw new Error('not received')
  h.bank.loseReplyFor.add('cash_transfer')
  const p = await h.wallet.protect({ holdings: [r.holding.id] })
  h.bank.loseReplyFor.clear()
  expect(p.outcomes[0]).toMatchObject({ ok: false })
  const parked = await row(h, r.holding.id)
  expect(parked.pendingCashSecret).toBeDefined()
  expect(w.identity).toEqual({ type: 'cash', value: commitment(unseal(parked.pendingCashSecret)!) })
  return { id: r.holding.id, w, pending: parked.pendingCashSecret! }
}

const rateLimitedStatus = (h: Harness) => {
  h.bank.override = (m) => (m === 'cash_status' ? { error: { code: 'RATE_LIMITED', message: 'slow down' } } : undefined)
}

describe('T-501 a second protect never overwrites an open pending secret', () => {
  test('while settle cannot resolve the slot, protect sends nothing and keeps it', async () => {
    const h = await harness()
    const { id, w, pending } = await rekeyLostReply(h)
    rateLimitedStatus(h)
    const before = transfers(h)
    const p = await h.wallet.protect({ holdings: [id] })
    expect(p.outcomes[0]).toMatchObject({ ok: false, error: { code: 'indeterminate' } })
    expect(transfers(h)).toBe(before)
    const r = await row(h, id)
    expect(r.pendingCashSecret).toEqual(pending)
    expect(w.identity.value).toBe(commitment(unseal(pending)!))
  })
  test('protect with no holdings named skips the open slot as well', async () => {
    const h = await harness()
    const { id, pending } = await rekeyLostReply(h)
    rateLimitedStatus(h)
    const before = transfers(h)
    const p = await h.wallet.protect()
    expect(p.outcomes.map((o) => o.ok)).toEqual([false])
    expect(transfers(h)).toBe(before)
    expect((await row(h, id)).pendingCashSecret).toEqual(pending)
  })
  test('a pending copy of the current secret is not an open slot', () => {
    const s = seal('ab'.repeat(32))
    expect(hasOpenPendingSecret({ cashSecret: s, pendingCashSecret: { ...s } } as Holding)).toBe(false)
    expect(hasOpenPendingSecret({ cashSecret: s, pendingCashSecret: seal('cd'.repeat(32)) } as Holding)).toBe(true)
    expect(hasOpenPendingSecret({ cashSecret: s } as Holding)).toBe(false)
  })
})

describe('T-502 settle and toCashNotes skip an open slot', () => {
  test('a merge-key holding whose return to a cash note is unresolved is not returned again', async () => {
    const h = await harness()
    const key = newCashTarget().secret // 32 random bytes, used as a private key
    const w = h.bank.mintToPubkey(4000n, getPublicKey(fromHex(key)))
    const r = await h.wallet.receive(h.bank.mintToPubkey(1n, h.me).token)
    if (!r.received) throw new Error('not received')
    // A holding on the merge key whose earlier return to cash landed unseen.
    const fresh = newCashTarget()
    await h.storage.tx('rw', async (t) => {
      const cur = (await t.get('holdings', r.holding.id))!
      await t.put('holdings', { ...cur, token: w.token, walletPubkey: w.walletPubkey, amount: 4000n, mode: 'pubkey', protection: 'none', throwawayKey: seal(key), pendingCashSecret: seal(fresh.secret), version: cur.version + 1 }, cur.version)
    })
    w.identity = { type: 'cash', value: commitment(fresh.secret) }
    rateLimitedStatus(h)
    const before = transfers(h)
    const rep = await h.wallet.settle()
    expect(transfers(h)).toBe(before)
    expect(rep.returnedToCash).toBe(0)
    expect(rep.unresolved).toContain(r.holding.id)
    expect(unseal((await row(h, r.holding.id)).pendingCashSecret)).toBe(fresh.secret)
    h.bank.override = undefined
    const healed = await h.wallet.settle()
    expect(healed.cashSecretsPromoted).toEqual([r.holding.id])
    await controlledByCurrent(h, r.holding.id)
  })
  test('a consolidate naming a note with an open slot refuses before moving anything', async () => {
    const h = await harness()
    const { id } = await rekeyLostReply(h)
    const t = newCashTarget()
    await h.wallet.receive(`${h.bank.mintToCash(1000n, t.secret).token}#${t.secret}`, { protect: false })
    rateLimitedStatus(h)
    const ids = (await h.wallet.holdings()).map((x) => x.id)
    const before = transfers(h)
    await expect(h.wallet.consolidate({ holdings: ids })).rejects.toMatchObject({ code: 'conflict' })
    expect(transfers(h)).toBe(before)
    expect((await row(h, id)).pendingCashSecret).toBeDefined()
  })
})

describe('T-503 protect settles first, inside the spend lock', () => {
  test('a landed rekey is promoted before the next protect, and its secret keeps control', async () => {
    const h = await harness()
    const { id, pending } = await rekeyLostReply(h)
    const p = await h.wallet.protect({ holdings: [id] })
    expect(p.outcomes[0]).toMatchObject({ ok: true })
    const r = await row(h, id)
    expect(r.pendingCashSecret).toBeUndefined()
    expect(r.protection).toBe('protected')
    expect(r.cashSecret).not.toEqual(pending)
    await controlledByCurrent(h, id)
  })
  test('protect with no holdings named promotes the landed rekey and leaves nothing open', async () => {
    const h = await harness()
    const { id, pending } = await rekeyLostReply(h)
    await h.wallet.protect()
    const r = await row(h, id)
    expect(r.cashSecret).toEqual(pending)
    expect(r.pendingCashSecret).toBeUndefined()
    await controlledByCurrent(h, id)
  })
})

describe('T-504 compare-and-clear', () => {
  test('a slot is cleared only when it still holds the value this call wrote', () => {
    const mine = seal('01'.repeat(32))
    const theirs = seal('02'.repeat(32))
    const a = { id: 'h-1', pendingCashSecret: theirs } as Holding
    expect(clearPendingSecret(a, mine)).toBe(a)
    expect(clearPendingSecret({ id: 'h-1', pendingCashSecret: mine } as Holding, mine).pendingCashSecret).toBeUndefined()
    const b = { id: 'h-1', pendingThrowawayKey: theirs } as Holding
    expect(clearPendingKey(b, mine)).toBe(b)
    expect(clearPendingKey({ id: 'h-1', pendingThrowawayKey: mine } as Holding, mine).pendingThrowawayKey).toBeUndefined()
  })
  test('a definite refusal of a protect clears the slot it parked', async () => {
    const h = await harness()
    const t = newCashTarget()
    const r = await h.wallet.receive(`${h.bank.mintToCash(700n, t.secret).token}#${t.secret}`, { protect: false })
    if (!r.received) throw new Error('not received')
    h.bank.override = (m) => (m === 'cash_transfer' ? { error: { code: 'NOT_FOUND', message: 'no' } } : undefined)
    const p = await h.wallet.protect({ holdings: [r.holding.id] })
    expect(p.outcomes[0]).toMatchObject({ ok: false })
    expect((await row(h, r.holding.id)).pendingCashSecret).toBeUndefined()
  })
})

describe('T-505 settle probes: only a no-match answer is definite', () => {
  for (const code of ['RATE_LIMITED', 'INTERNAL', 'QUOTA_EXCEEDED']) {
    test(`${code} on the pending-secret probe leaves the slot open, even when the current secret answers`, async () => {
      const h = await harness()
      const t = newCashTarget()
      const r = await h.wallet.receive(`${h.bank.mintToCash(5000n, t.secret).token}#${t.secret}`, { protect: false })
      if (!r.received) throw new Error('not received')
      const id = r.holding.id
      const pending = seal(newCashTarget().secret)
      await h.storage.tx('rw', async (tx) => {
        const cur = (await tx.get('holdings', id))!
        await tx.put('holdings', { ...cur, pendingCashSecret: pending, version: cur.version + 1 }, cur.version)
      })
      let n = 0
      h.bank.override = (m) => (m === 'cash_status' && n++ === 0 ? { error: { code, message: 'later' } } : undefined)
      const rep = await h.wallet.settle()
      expect(rep.unresolved).toEqual([id])
      expect(rep.cashSecretsCleared).toEqual([])
      expect((await row(h, id)).pendingCashSecret).toEqual(pending)
    })
  }
  test('NOT_FOUND for the pending secret, then a match for the current one, clears the slot', async () => {
    const h = await harness()
    const t = newCashTarget()
    const w = h.bank.mintToCash(5000n, t.secret)
    const r = await h.wallet.receive(`${w.token}#${t.secret}`, { protect: false })
    if (!r.received) throw new Error('not received')
    // A rekey that never landed: the Hub still knows only the current secret.
    const fresh = newCashTarget()
    await h.storage.tx('rw', async (tx) => {
      const cur = (await tx.get('holdings', r.holding.id))!
      await tx.put('holdings', { ...cur, pendingCashSecret: seal(fresh.secret), version: cur.version + 1 }, cur.version)
    })
    let n = 0
    h.bank.override = (m) => (m === 'cash_status' && n++ === 0 ? { error: { code: 'NOT_FOUND', message: 'no' } } : undefined)
    const rep = await h.wallet.settle()
    expect(rep.cashSecretsCleared).toEqual([r.holding.id])
    expect((await row(h, r.holding.id)).pendingCashSecret).toBeUndefined()
    await controlledByCurrent(h, r.holding.id)
  })
})
