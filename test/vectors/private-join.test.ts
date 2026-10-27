// private-join.json: create_circle_wallet as a private-transport item (its
// target and both proofs' d are the Hub connection, h the node), the join
// lookup, and the Hub's admission of a join's two proofs.
import { describe, expect, test } from 'vitest'
import { billFromParts } from '../../src/client/bill.js'
import { createCircleWalletItem } from '../../src/client/circleJoin.js'
import { buildItem } from '../../src/client/methods.js'
import { bySigning, cashLookupParams, createCircleWalletRequest, fromHex, getPublicKey, localSigner, verifyEvent } from '../../src/core/index.js'
import { paramsHash, verifyBillProof, verifyItemProof, type Item } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('private-join.json')
// The requester's key: 4d4b6cd1… is the pubkey of 0x02 repeated.
const requester = () => localSigner(fromHex('02'.repeat(32)))
const binding = { hub: v.node, nonce: v.nonce, notAfter: v.notAfter }

// An item as the vector writes it: params parsed (identity_event with `valid`), proofs as kind, pubkey and tags with ph elided.
function shown(it: Item): Json {
  const params = JSON.parse(it.params ?? '{}')
  const ph = paramsHash(it.params ?? '')
  const proof = (p: string | undefined) => {
    const ev = JSON.parse(p ?? '{}')
    expect(ev.tags.find((t: string[]) => t[0] === 'ph')[1]).toBe(ph)
    return { kind: ev.kind, pubkey: ev.pubkey, tags: ev.tags.map((t: string[]) => (t[0] === 'ph' ? ['ph', '<params hash>'] : t)) }
  }
  if (typeof params.identity_event === 'string') {
    const ev = JSON.parse(params.identity_event)
    params.identity_event = { content: ev.content, kind: ev.kind, pubkey: ev.pubkey, tags: ev.tags, valid: verifyEvent(ev) }
  }
  return { billProof: proof(it.billProof), id: it.id, method: it.method, params, ...(it.proof !== undefined && { proof: proof(it.proof) }), target: it.target }
}

async function build(c: Json): Promise<Item[]> {
  const i = c.inputs
  const hub = billFromParts(v.hub, i.hubConnectionSecret)
  if ('connectionPubkey' in i) return [await buildItem('lookup', hub, 'cash_lookup', cashLookupParams({ connectionPubkey: i.connectionPubkey }, i.deadline), bySigning(requester()), binding, v.now)]
  const join = await createCircleWalletRequest({
    signer: requester(),
    connectionPubkey: i.connectionSecret === '' ? '' : getPublicKey(fromHex(i.connectionSecret)),
    hubPubkey: v.hub,
    terms: { maxAmount: BigInt(i.maxAmountMillis), maxReceive: 0n, expiry: i.expirySeconds, ...(i.budgetRenewal !== '' && { budgetRenewal: i.budgetRenewal }) },
    now: i.now,
  })
  const first = await createCircleWalletItem('join', hub, requester(), join, binding, i.now)
  if (!c.name.includes('a second Item')) return [first]
  return [first, await createCircleWalletItem('join', hub, requester(), join, binding, i.now)]
}

describe('private-join.json', () => {
  test.each(named(v.build))('build: %s', async (_: string, c: Json) => {
    if (c.error) {
      await expect(build(c)).rejects.toThrow()
      return
    }
    const [it] = await build(c)
    expect(shown(it!)).toEqual(c.item)
  })
  test.each(named(v.verify))('verify: %s', (_: string, c: Json) => {
    const want = { target: c.target, hub: v.node, method: 'create_circle_wallet', paramsHash: paramsHash(c.params), nonce: v.nonce, notAfter: v.notAfter }
    const item = () => verifyItemProof(c.proof, want, v.now)
    const bill = () => verifyBillProof(c.billProof, want, v.now)
    if (c.itemError) {
      expect(item).toThrow()
      expect(bill).toThrow()
      expect(c.admitted).toBe(false)
      return
    }
    expect([item(), bill()]).toEqual([c.itemSigner, c.billSigner])
    // The Hub admits a join that targets its connection, whose item proof is the requester's and whose bill proof is a live Hub connection's.
    expect(c.target === v.hub && item() === JSON.parse(c.params).pubkey && v.liveConnections.includes(bill())).toBe(c.admitted)
  })
})
