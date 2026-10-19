// JSON text as Go's json.Marshal writes it, with bigint support: big
// integers are written as digits, never through a double, and strings are
// escaped HTML-safely, so payloads match nmilat's byte for byte.

const HEX = '0123456789abcdef'

/** A string as json.Marshal writes it (HTML escaping on). */
export function goString(s: string): string {
  let out = '"'
  for (const ch of s) {
    const c = ch.codePointAt(0)!
    switch (ch) {
      case '"':
        out += '\\"'
        continue
      case '\\':
        out += '\\\\'
        continue
      case '\n':
        out += '\\n'
        continue
      case '\r':
        out += '\\r'
        continue
      case '\t':
        out += '\\t'
        continue
      case '\b':
        out += '\\b'
        continue
      case '\f':
        out += '\\f'
        continue
      case '<':
        out += '\\u003c'
        continue
      case '>':
        out += '\\u003e'
        continue
      case '&':
        out += '\\u0026'
        continue
    }
    if (c < 0x20) out += '\\u00' + HEX[c >> 4]! + HEX[c & 15]!
    else if (c === 0x2028 || c === 0x2029) out += `\\u${c.toString(16)}`
    else if (c >= 0xd800 && c <= 0xdfff) out += '\\ufffd'
    else out += ch
  }
  return out + '"'
}

/**
 * JSON text for a value built in code. Object keys keep insertion order;
 * undefined fields are omitted.
 */
export function toJSONText(v: unknown): string {
  if (v === null) return 'null'
  switch (typeof v) {
    case 'bigint':
      return v.toString(10)
    case 'number':
      if (!Number.isFinite(v)) throw new TypeError('json: non-finite number')
      return String(v)
    case 'boolean':
      return v ? 'true' : 'false'
    case 'string':
      return goString(v)
    case 'object':
      if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : toJSONText(x))).join(',') + ']'
      return (
        '{' +
        Object.entries(v as Record<string, unknown>)
          .filter(([, x]) => x !== undefined)
          .map(([k, x]) => goString(k) + ':' + toJSONText(x))
          .join(',') +
        '}'
      )
    default:
      throw new TypeError(`json: cannot encode ${typeof v}`)
  }
}
