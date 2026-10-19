import { expect, test } from 'vitest'
import * as core from '../src/core/index.js'

test('core entry loads', () => {
  expect(core).toBeTypeOf('object')
})
