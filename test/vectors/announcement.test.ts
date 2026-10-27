// announcement.json: kind 11190 Hub announcements in tag form.
import { describe, expect, test } from 'vitest'
import { announcementTags, effectiveLimits, hubUsableForBills, parseAnnouncement } from '../../src/transport/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('announcement.json')

describe('announcement.json', () => {
  test.each(named(v.parse))('%s', (_: string, c: Json) => {
    const go = () => parseAnnouncement(c.event, c.expectedNode)
    if (c.error) {
      expect(go).toThrow()
      return
    }
    const a = go()
    // nmilat reports an absent max_request_age as 0; cashkit leaves it out.
    expect({ ...a, maxRequestAge: a.maxRequestAge ?? 0 }).toEqual(c.want)
    expect(hubUsableForBills(a)).toBe(c.billCalls === undefined)
    if (c.name === 'max_bytes above the NIP-44 ceiling') expect(effectiveLimits(a).maxEnvelopeBytes).toBe(65535)
    if (c.name === 'NewAnnouncement with the default limits') expect(announcementTags(c.want)).toEqual(c.event.tags)
  })
})
