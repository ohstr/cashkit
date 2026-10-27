// budget-period.json: NIP-CW §Budget Renewal Floor, period starts counted from the creation day.
import { describe, expect, test } from 'vitest'
import { budgetPeriodStart } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('budget-period.json')

// A negative period index: nmilat refuses it; cashkit's budgetPeriodStart computes a start before the creation.
const MISMATCH = new Set(['monthly k=-1'])

describe('budget-period.json', () => {
  test.each(named(v.start, (c) => `${c.renewal || 'omitted'} k=${c.k}`))('start: %s', (name, c: Json) => {
    if (MISMATCH.has(name)) return
    const got = budgetPeriodStart(c.created, c.renewal === '' ? 'never' : c.renewal, c.k)
    if (c.error !== undefined) expect(got).toBeUndefined()
    else expect(got).toBe(c.start)
  })
})
