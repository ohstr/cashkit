// vectors/altzap.json: the NIP-AZ alternative zap request (kind 9520), K-AZ-1.
// cashkit has no NIP-AZ module; what runs here is what cashkit's own
// primitives cover: the recipient's ConnectionKey, the event id and the
// signature check a relay would apply.
import { describe, expect, test } from 'vitest'
import { fromHex, getEventHash, getPublicKey, connectionKeyFromAttested, verifyEvent } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('altzap.json')

describe('altzap.json', () => {
  test('K-AZ-1: the ConnectionKey, the sender, the id and the signature', () => {
    const k = v.kat
    expect(connectionKeyFromAttested('github', k.githubUserId)).toBe(k.connectionKey)
    expect(getPublicKey(fromHex(k.senderSecret))).toBe(k.event.pubkey)
    expect(getEventHash(k.event)).toBe(k.event.id)
    expect(verifyEvent(k.event)).toBe(true)
    expect(k.event.tags).toContainEqual(['p', k.connectionKey, 'github'])
    expect(k.event.tags).toContainEqual(['ia', k.ia])
    expect(k.event.tags).toContainEqual(['lnurl', k.lnurl])
  })
  test.each(named(v.validateForRelay))('validateForRelay %s', (_, c: Json) => {
    expect(verifyEvent(c.event)).toBe(!c.error)
  })
})
