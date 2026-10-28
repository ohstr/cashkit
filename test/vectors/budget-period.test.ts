// budget-period.json: NIP-CW §Budget Renewal Floor, period starts counted from the creation day.
import { describe, expect, test } from 'vitest'
import { budgetPeriodStart } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('budget-period.json')

describe('budget-period.json', () => {
  test.each(named(v.start, (c) => `${c.renewal || 'omitted'} k=${c.k}`))('start: %s', (_, c: Json) => {
    const got = budgetPeriodStart(c.created, c.renewal === '' ? 'never' : c.renewal, c.k)
    if (c.error !== undefined) expect(got).toBeUndefined()
    else expect(got).toBe(c.start)
  })
})
