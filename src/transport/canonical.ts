// The params hash (ph) every item proof binds (design §2.2). Keys sorted
// and strings escaped as RFC 8785 does, no whitespace, and number literals
// exactly as written.
// JSON.stringify over JS numbers would round big amounts, so params travel
// as JSON text and are canonicalised with a tokenizer that keeps literals.
import { sha256 } from '@noble/hashes/sha2.js'
import { toHex, trimSpace } from '../core/index.js'
import { parseGoStream, type JNode } from './gojson.js'

const HEX = '0123456789abcdef'
const encoder = new TextEncoder()

/** RFC 8785 string escaping: only ", \ and C0 controls are escaped. */
function canonicalString(s: string): string {
  let out = '"'
  for (const ch of s) {
    const c = ch.codePointAt(0)!
    if (ch === '"') out += '\\"'
    else if (ch === '\\') out += '\\\\'
    else if (c === 0x08) out += '\\b'
    else if (c === 0x09) out += '\\t'
    else if (c === 0x0a) out += '\\n'
    else if (c === 0x0c) out += '\\f'
    else if (c === 0x0d) out += '\\r'
    else if (c < 0x20) out += '\\u00' + HEX[c >> 4]! + HEX[c & 15]!
    else out += ch
  }
  return out + '"'
}

/** RFC 8785 §3.2.3 key order: by UTF-16 code units, which is how JS strings compare. */
function utf16Compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function write(n: JNode): string {
  switch (n.kind) {
    case 'null':
      return 'null'
    case 'bool':
      return n.value ? 'true' : 'false'
    case 'number':
      return n.literal
    case 'string':
      return canonicalString(n.value)
    case 'array':
      return '[' + n.items.map(write).join(',') + ']'
    case 'object': {
      // A repeated key: the last occurrence wins, as in a Go map.
      const byKey = new Map<string, JNode>()
      for (const [k, v] of n.members) byKey.set(k, v)
      const keys = [...byKey.keys()]
      // oxlint-disable-next-line unicorn/no-array-sort -- sorts a fresh copy
      keys.sort(utf16Compare)
      return '{' + keys.map((k) => canonicalString(k) + ':' + write(byKey.get(k)!)).join(',') + '}'
    }
  }
}

/** The canonical text of params; empty or whitespace-only params read as {}. */
export function canonicalParams(params: string): string {
  return write(parseGoStream(trimSpace(params) === '' ? '{}' : params))
}

/** ph: hex(sha256(canonical params)). Throws on params that are not JSON. */
export function paramsHash(params: string): string {
  return toHex(sha256(encoder.encode(canonicalParams(params))))
}

/** Re-exported: params text is written with core's Go-compatible writer. */
export { toJSONText } from '../core/index.js'
