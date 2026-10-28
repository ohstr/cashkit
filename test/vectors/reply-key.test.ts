// reply-key.json: the response key, HKDF-Expand over the request's conversation key.
import { describe, expect, test } from 'vitest'
import { fromHex, toHex } from '../../src/core/index.js'
import { deriveReplyKey } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('reply-key.json')

describe('reply-key.json', () => {
  test.each(named(v.derive, (c, i) => c.id ?? `${c.replyTo} (${i})`))('derive %s', (_: string, c: Json) => {
    if (c.error !== undefined) expect(() => deriveReplyKey(fromHex(c.conversationKey), c.replyTo)).toThrow()
    else expect(toHex(deriveReplyKey(fromHex(c.conversationKey), c.replyTo))).toBe(c.replyKey)
  })
  test.each(named(v.negative, (c) => `${c.id}: ${c.note}`))('a wrong construction gives another key: %s', (_: string, c: Json) => {
    expect(toHex(deriveReplyKey(fromHex(c.conversationKey), c.replyTo))).not.toBe(c.replyKey)
  })
})
