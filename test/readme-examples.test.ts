// The README's examples are copies of examples/*.ts, which the typecheck
// compiles: each block marked `<!-- example: examples/<file> -->` must equal
// that file's `#region readme`, unindented.
import { readFileSync } from 'node:fs'
import { describe, expect, test } from 'vitest'

const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
const blocks = [...readme.matchAll(/<!-- example: (examples\/[\w-]+\.ts) -->\n```ts\n([\s\S]*?)\n```/g)].map((m) => [m[1]!, m[2]!] as const)

function region(file: string): string {
  const s = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8')
  const body = s.split('// #region readme\n')[1]!.split('  // #endregion')[0]!
  return body
    .trimEnd()
    .split('\n')
    .map((l) => (l.startsWith('  ') ? l.slice(2) : l))
    .join('\n')
}

describe('README examples', () => {
  test('there are examples to check', () => {
    expect(blocks.length).toBeGreaterThanOrEqual(6)
  })
  test.each(blocks)('%s matches the type-checked file', (file, block) => {
    expect(block).toBe(region(file))
  })
})
