// hub-group.json: the hub-group fingerprint and the grouping rule.
import { describe, expect, test } from 'vitest'
import { fromHex, hubGroupFor, sameHubGroup, toHex } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('hub-group.json')
const bytes = (h: string | null) => (h === null ? undefined : h === '' ? new Uint8Array(0) : fromHex(h))

describe('hub-group.json', () => {
  test.each(named(v.hubGroupFor, (c) => JSON.stringify(c.hub)))('hubGroupFor(%s)', (_: string, c: Json) => {
    const got = toHex(hubGroupFor(c.hub))
    expect(got).toBe(c.group)
    if (c.notRawBytes) expect(got).not.toBe(c.notRawBytes)
  })
  test.each(named(v.sameHubGroup))('sameHubGroup: %s', (_: string, c: Json) => {
    expect(sameHubGroup(bytes(c.a), bytes(c.b))).toBe(c.same)
  })
})
