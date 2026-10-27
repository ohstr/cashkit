// cash-string.json: <token>#<cash_secret>, split on the first '#'.
import { describe, expect, test } from 'vitest'
import { splitCashString } from '../../src/core/index.js'
import { load, named, type Json } from './helpers.js'

const v = load('cash-string.json')

describe('cash-string.json', () => {
  test.each(named(v.split, (c) => JSON.stringify(c.input)))('split %s', (_: string, c: Json) => {
    expect(splitCashString(c.input)).toEqual({ token: c.token, cashSecret: c.cashSecret })
  })
})
