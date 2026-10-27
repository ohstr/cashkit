#!/usr/bin/env node
// Fails when code acts on a Hub's error message (NIP-CASH §Errors: a client
// acts on the code; the message is for people). Flags `walletMessage` or
// `rawMessage` used in a comparison or a text test anywhere under the given
// directories (default: src).
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const FIELD = /\b(?:walletMessage|rawMessage)\b/
const USES = [
  /\b(?:walletMessage|rawMessage)\b[\w.?()[\]'"]*?\s*\.(?:includes|startsWith|endsWith|match|search|indexOf)\s*\(/,
  /\b(?:walletMessage|rawMessage)\b[\w.?()[\]]*\s*[!=]==?/,
  /[!=]==?\s*[\w.?]*\b(?:walletMessage|rawMessage)\b/,
  /\.test\(\s*[\w.?]*\b(?:walletMessage|rawMessage)\b/,
  /\bswitch\s*\(\s*[\w.?]*\b(?:walletMessage|rawMessage)\b/,
]

function* files(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) yield* files(p)
    else if (/\.(?:ts|tsx|js|mjs)$/.test(name)) yield p
  }
}

/** Lines that act on a message, as `path:line: text`. */
export function findMessageMatches(dirs) {
  const out = []
  for (const dir of dirs) {
    for (const p of files(dir)) {
      readFileSync(p, 'utf8')
        .split('\n')
        .forEach((line, i) => {
          // A presence check (against undefined or null) reads nothing of the text.
          const l = line.replace(/\b(?:walletMessage|rawMessage)\s*[!=]==?\s*(?:undefined|null)\b/g, '').replace(/\b(?:undefined|null)\s*[!=]==?\s*[\w.?]*\b(?:walletMessage|rawMessage)\b/g, '')
          if (FIELD.test(l) && USES.some((re) => re.test(l))) out.push(`${p}:${i + 1}: ${line.trim()}`)
        })
    }
  }
  return out
}

const dirs = process.argv.slice(2)
const found = findMessageMatches(dirs.length > 0 ? dirs : ['src'])
if (found.length > 0) {
  console.error('code acts on a Hub error message; act on its code instead:\n' + found.join('\n'))
  process.exit(1)
}
