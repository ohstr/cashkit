// pocket.json: NIP-CP pocket entries (kind 9525 rumors) — their tags and
// rumor ids (K-POCKET-1..2, 5, 6), rumor parsing, version resolution
// (K-POCKET-3) and the balance (K-POCKET-4). When an order or a withdrawal
// writes an entry is the wallet's (src/wallet/pocket.ts) and is not run here:
// only the entries those sections give.
import { describe, expect, test } from 'vitest'
import { createRumor, eventJSON, KIND_POCKET_ENTRY, parsePocketEntry, pocketBalance, pocketEntryTags, resolveEntries, verifyWithdrawReceipt, type PocketEntry } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('pocket.json')
const wd = load('withdraw.json')

const MISMATCH = new Set([
  // cashkit's parsePocketEntry does not check that w is lowercase hex; nmilat refuses it.
  'uppercase w',
  // cashkit's parsePocketEntry does not check mint is a 66-hex compressed key; nmilat refuses a 64-hex one.
  '64-hex mint',
  // cashkit reads a state tag without its check time as checked at 0; nmilat refuses it.
  'no state time',
  // cashkit's parsePocketEntry reads the first of two amount tags; nmilat refuses a repeated tag.
  'two amounts',
  // cashkit's parsePocketEntry keeps expires_at 0; nmilat refuses it (0 means never and is not stored).
  'expires_at 0',
  // cashkit's pocketEntryTags does not check a cash_order or cash_withdraw entry's shape (notify, address, quote, its secrets); nmilat refuses to write these.
  'a cash_order entry without notify',
  'refused: no notify',
  'refused: no address',
  'refused: no quote',
  'refused: a remainder secret',
  // The winner agrees, but cashkit's resolveEntries names a conflict for any w with two distinct rumors; nmilat only when distinct rumors tie at the winning rev.
  'v5 spent over v3 live',
  'a higher rev supersedes a final state',
])

const rumorOf = (e: PocketEntry) => createRumor({ kind: KIND_POCKET_ENTRY, pubkey: v.user, created_at: v.createdAt, tags: pocketEntryTags(e), content: '' })
/** Re-encodes a rumor's entry: the same tags and so the same rumor id. */
function roundTrip(r: Json) {
  const e = parsePocketEntry(r)
  const again = createRumor({ kind: r.kind, pubkey: r.pubkey, created_at: r.created_at, tags: pocketEntryTags(e), content: r.content })
  expect(again.tags).toEqual(r.tags)
  expect(again.id).toBe(r.id)
}

// The K-POCKET-6 entries, built from withdraw.json's values rather than read back.
const QUOTE = eventJSON(wd.quotes[0].event)
const RECEIPT = eventJSON(wd.receipts[0].event)
const REQ = wd.inputs.requestId
const call: PocketEntry = { w: REQ, rev: 1, state: 'pending', checkedAt: v.createdAt, wrapKey: v.wrapKey, amountMillis: 21000000n, chain: 'bitcoin', requestId: REQ, deadline: 1720000300, target: wd.inputs.wallet, device: 'dd'.repeat(16), notify: '55'.repeat(32), address: wd.inputs.address, quote: QUOTE }
/** The entry without the named fields. */
const without = (e: PocketEntry, ...ks: (keyof PocketEntry)[]): PocketEntry => Object.fromEntries(Object.entries(e).filter(([x]) => !ks.includes(x as keyof PocketEntry))) as unknown as PocketEntry
const FROZEN: Record<string, PocketEntry> = {
  c49dbd482343b3c68e9ba59ae6d120b991f17bd88b98620145eac562ad6b2c39: call,
  '1add82fd822acf561e8934d09f063894eb5dbb38979794c392135676899ba246': { ...call, secrets: [{ secret: '77'.repeat(32), role: 'remint' }] },
  '37e38de3fba644966e59095d2da2b7d51277137ee6ee43024ea0b227dcf7a661': { ...call, rev: 2, receipt: RECEIPT },
  '3137f0f66c68af647fe3f2f2942042c8346ce4e6c63ad952c5aea820373fa0e4': { ...without(call, 'address', 'quote'), rev: 4, state: 'done' },
}

describe('pocket.json K-POCKET-6 frozen ids', () => {
  test.each(Object.entries(FROZEN))('%s', (id, e) => {
    expect(rumorOf(e).id).toBe(id)
  })
})

/** The refused entries carry no input: each is the entry its name changes. */
const order: PocketEntry = { w: '22'.repeat(16), rev: 1, state: 'pending', checkedAt: v.createdAt, wrapKey: v.wrapKey, amountMillis: 21000n, chain: 'bitcoin', requestId: '22'.repeat(16), deadline: 1720000300, target: 'bb'.repeat(32), device: 'dd'.repeat(16), secrets: [{ secret: '88'.repeat(32), role: '' }] }
const REFUSED: Record<string, PocketEntry> = {
  'a cash_order entry without notify': order,
  'refused: no notify': without(call, 'notify'),
  'refused: no address': without(call, 'address'),
  'refused: no quote': without(call, 'quote'),
  'refused: a remainder secret': { ...call, secrets: [{ secret: '77'.repeat(32), role: 'remainder' }] },
}

const entryCase = (name: string, c: Json) => {
  if (MISMATCH.has(name)) return
  if (c.error !== undefined) {
    expect(REFUSED[name]).toBeDefined()
    expect(() => pocketEntryTags(REFUSED[name]!)).toThrow()
    return
  }
  roundTrip(c.rumor)
}

describe('pocket.json entries', () => {
  test.each(named(v.rumors))('rumor: %s', entryCase)
  test.each(named(v.withdraw))('withdraw: %s', entryCase)
  test.each(named(v.parseRumor))('parse: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    if (c.error !== undefined) {
      expect(() => parsePocketEntry(c.rumor)).toThrow()
      return
    }
    const e = parsePocketEntry(c.rumor)
    const raw = c.rumor.tags.find((t: string[]) => t[0] === 'state')[1]
    expect({ amount: Number(e.amountMillis), chain: e.chain, rawState: e.recognised ? '' : raw, rev: e.rev, state: e.recognised ? e.state : '', w: e.w }).toEqual(c.want)
  })
})

describe('pocket.json resolve and balance', () => {
  test.each(named(v.resolve))('resolve: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const w = '11'.repeat(32)
    const rumors = c.entries.map((x: Json) => ({ rumor: { id: x.rumorId, created_at: x.createdAt }, entry: { w, rev: x.rev, state: x.state, checkedAt: 0, wrapKey: v.wrapKey, amountMillis: 1n, chain: 'bitcoin' } as PocketEntry }))
    const { entries, conflicts } = resolveEntries(rumors)
    const winner = rumors.find((x: { entry: PocketEntry }) => x.entry === entries.get(w))
    expect({ id: winner?.rumor.id, state: entries.get(w)?.state, conflicts }).toEqual({ id: c.winnerRumorId, state: c.winnerState, conflicts: c.conflicts })
  })
  test('K-POCKET-4 balance', () => {
    const b = v.balance
    const got = pocketBalance(b.entries.map((x: Json) => ({ w: x.w, rev: 1, state: x.state, checkedAt: 0, wrapKey: v.wrapKey, amountMillis: BigInt(x.amount), chain: x.chain }) as PocketEntry))
    expect(Object.fromEntries([...got].map(([k, n]) => [k, Number(n)]))).toEqual(b.balance)
  })
})

describe('pocket.json withdrawal entries', () => {
  test.each(named(v.applyWithdraw))('%s', (_, c: Json) => {
    if (c.error !== undefined) {
      // No receipt: cashkit refuses it as the vector does, and writes nothing.
      expect(() => verifyWithdrawReceipt('', { hubXOnly: wd.inputs.hub, target: wd.inputs.wallet, quoteId: wd.quotes[0].event.id, requestId: REQ, address: wd.inputs.address, payoutMillis: 19258000n, sentBy: 1720003600 })).toThrow()
      return
    }
    for (const w of c.writes) roundTrip(w.rumor)
    if (c.done !== undefined) roundTrip(c.done.rumor)
  })
})
