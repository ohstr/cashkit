// nip01.json: NIP-01 serialization, ids and event verification.
import { describe, expect, test } from 'vitest'
import { getEventHash, serializeEvent, verifyEvent } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('nip01.json')

describe('nip01.json', () => {
  test.each(named(v.serialize))('serialize: %s', (_: string, c: Json) => {
    const e = { pubkey: c.pubkey, created_at: c.created_at, kind: c.kind, tags: c.tags ?? [], content: c.content }
    expect(serializeEvent(e)).toBe(c.serialized)
    expect(getEventHash(e)).toBe(c.id)
  })
  test.each(named(v.verify))('verify: %s', (_: string, c: Json) => {
    expect(verifyEvent({ ...c.event, tags: c.event.tags ?? [] })).toBe(c.valid)
  })
})
