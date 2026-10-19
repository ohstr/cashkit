// Go encoding/json behaviour the private transport depends on, so envelopes
// are byte-identical to nmilat's and are accepted or refused exactly as the
// Hub decides:
// - a strict parser that keeps every value's raw text (json.RawMessage) and
//   every number's literal (json.Number);
// - json.Marshal's string escaping, HTML escaping included;
// - json.Compact as Marshal applies it to a RawMessage;
// - struct decoding: keys matched case-insensitively (an exact match
//   preferred), the last occurrence winning, unknown keys ignored, and a type
//   mismatch recorded while decoding carries on.
import { CoreError } from '../core/index.js'

export type JNode =
  | { readonly kind: 'object'; readonly members: readonly (readonly [string, JNode])[]; readonly raw: string }
  | { readonly kind: 'array'; readonly items: readonly JNode[]; readonly raw: string }
  | { readonly kind: 'string'; readonly value: string; readonly raw: string }
  | { readonly kind: 'number'; readonly literal: string; readonly raw: string }
  | { readonly kind: 'bool'; readonly value: boolean; readonly raw: string }
  | { readonly kind: 'null'; readonly raw: string }

export class JSONSyntaxError extends CoreError {
  constructor(message: string) {
    super('invalid_payload', `json: ${message}`)
  }
}

const isWS = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r'
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y

class Parser {
  pos = 0
  constructor(readonly text: string) {}

  ws(): void {
    while (this.pos < this.text.length && isWS(this.text[this.pos]!)) this.pos++
  }

  value(): JNode {
    this.ws()
    const start = this.pos
    const c = this.text[this.pos]
    if (c === undefined) throw new JSONSyntaxError('unexpected end of input')
    if (c === '{') return this.object(start)
    if (c === '[') return this.array(start)
    if (c === '"') {
      const value = this.string()
      return { kind: 'string', value, raw: this.text.slice(start, this.pos) }
    }
    for (const [lit, node] of [
      ['true', { kind: 'bool', value: true }],
      ['false', { kind: 'bool', value: false }],
      ['null', { kind: 'null' }],
    ] as const) {
      if (this.text.startsWith(lit, this.pos)) {
        this.pos += lit.length
        return { ...node, raw: lit } as JNode
      }
    }
    NUMBER.lastIndex = this.pos
    const m = NUMBER.exec(this.text)
    if (m === null || m[0] === '' || m[0] === '-') throw new JSONSyntaxError(`invalid character at offset ${this.pos}`)
    this.pos += m[0].length
    return { kind: 'number', literal: m[0], raw: m[0] }
  }

  object(start: number): JNode {
    this.pos++
    const members: [string, JNode][] = []
    this.ws()
    if (this.text[this.pos] === '}') {
      this.pos++
      return { kind: 'object', members, raw: this.text.slice(start, this.pos) }
    }
    for (;;) {
      this.ws()
      if (this.text[this.pos] !== '"') throw new JSONSyntaxError(`expected a key at offset ${this.pos}`)
      const key = this.string()
      this.ws()
      if (this.text[this.pos] !== ':') throw new JSONSyntaxError(`expected ':' at offset ${this.pos}`)
      this.pos++
      members.push([key, this.value()])
      this.ws()
      const c = this.text[this.pos]
      this.pos++
      if (c === '}') return { kind: 'object', members, raw: this.text.slice(start, this.pos) }
      if (c !== ',') throw new JSONSyntaxError(`expected ',' or '}' at offset ${this.pos - 1}`)
    }
  }

  array(start: number): JNode {
    this.pos++
    const items: JNode[] = []
    this.ws()
    if (this.text[this.pos] === ']') {
      this.pos++
      return { kind: 'array', items, raw: this.text.slice(start, this.pos) }
    }
    for (;;) {
      items.push(this.value())
      this.ws()
      const c = this.text[this.pos]
      this.pos++
      if (c === ']') return { kind: 'array', items, raw: this.text.slice(start, this.pos) }
      if (c !== ',') throw new JSONSyntaxError(`expected ',' or ']' at offset ${this.pos - 1}`)
    }
  }

  /** A string body, unescaped as Go does: a lone surrogate becomes U+FFFD. */
  string(): string {
    this.pos++
    let out = ''
    for (;;) {
      const c = this.text[this.pos]
      if (c === undefined) throw new JSONSyntaxError('unterminated string')
      if (c === '"') {
        this.pos++
        return out
      }
      if (c.charCodeAt(0) < 0x20) throw new JSONSyntaxError('control character in string')
      if (c !== '\\') {
        out += c
        this.pos++
        continue
      }
      const e = this.text[this.pos + 1]
      this.pos += 2
      const simple: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
      if (e !== undefined && Object.hasOwn(simple, e)) {
        out += simple[e]
        continue
      }
      if (e !== 'u') throw new JSONSyntaxError('invalid escape')
      const u = this.hex4()
      if (u >= 0xd800 && u < 0xdc00) {
        if (this.text.startsWith('\\u', this.pos)) {
          const save = this.pos
          this.pos += 2
          const lo = this.hex4()
          if (lo >= 0xdc00 && lo < 0xe000) {
            out += String.fromCharCode(u, lo)
            continue
          }
          this.pos = save
        }
        out += '�'
      } else if (u >= 0xdc00 && u < 0xe000) {
        out += '�'
      } else {
        out += String.fromCharCode(u)
      }
    }
  }

  hex4(): number {
    const h = this.text.slice(this.pos, this.pos + 4)
    if (!/^[0-9a-fA-F]{4}$/.test(h)) throw new JSONSyntaxError('invalid \\u escape')
    this.pos += 4
    return parseInt(h, 16)
  }
}

/** json.Unmarshal's parse: one value, only whitespace after it. */
export function parseGo(text: string): JNode {
  const p = new Parser(text)
  const v = p.value()
  p.ws()
  if (p.pos !== text.length) throw new JSONSyntaxError('invalid character after top-level value')
  return v
}

/**
 * json.Decoder.Decode followed by More(), as CanonicalParamsHash reads
 * params: content after the value is refused unless it starts with ']' or
 * '}', which More() reports as "no more".
 */
export function parseGoStream(text: string): JNode {
  const p = new Parser(text)
  const v = p.value()
  p.ws()
  const next = text[p.pos]
  if (next !== undefined && next !== ']' && next !== '}') {
    throw new JSONSyntaxError('params carry trailing content')
  }
  return v
}

export { goString } from '../core/index.js'

/**
 * json.Compact with HTML escaping, as json.Marshal applies to a RawMessage:
 * whitespace outside strings removed; inside strings, literal <, >, &,
 * U+2028 and U+2029 escaped; everything else kept as written.
 */
export function compactGo(raw: string): string {
  parseGo(raw) // Marshal refuses invalid JSON
  let out = ''
  let inString = false
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i]!
    if (inString) {
      if (c === '\\') {
        out += c + raw[i + 1]!
        i++
      } else if (c === '"') {
        inString = false
        out += c
      } else if (c === '<') out += '\\u003c'
      else if (c === '>') out += '\\u003e'
      else if (c === '&') out += '\\u0026'
      else if (c === ' ') out += '\\u2028'
      else if (c === ' ') out += '\\u2029'
      else out += c
    } else if (c === '"') {
      inString = true
      out += c
    } else if (!isWS(c)) {
      out += c
    }
  }
  return out
}

/**
 * A parsed value as plain JS data, integers as bigint so amounts beyond 2^53
 * survive. A repeated key: the last occurrence wins.
 */
export function goValue(n: JNode): unknown {
  switch (n.kind) {
    case 'null':
      return null
    case 'bool':
    case 'string':
      return n.value
    case 'number':
      return /^-?[0-9]+$/.test(n.literal) ? BigInt(n.literal) : Number(n.literal)
    case 'array':
      return n.items.map(goValue)
    case 'object':
      return Object.fromEntries(n.members.map(([k, v]) => [k, goValue(v)]))
  }
}

/** Parses JSON text into plain data with bigint integers. */
export const parseJSONValue = (text: string): unknown => goValue(parseGo(text))

// ---- struct decoding

export type GoType =
  | 'string'
  | 'int'
  | 'uint'
  | 'bool'
  /** json.RawMessage: the value's raw text, "null" included. */
  | 'raw'
  | { readonly array: GoType }
  | { readonly object: Readonly<Record<string, GoType>> }

const INT = /^-?[0-9]+$/

function intOk(literal: string, unsigned: boolean): boolean {
  if (!INT.test(literal)) return false
  const v = BigInt(literal)
  return unsigned ? v >= 0n && v < 1n << 64n : v >= -(1n << 63n) && v < 1n << 63n
}

/**
 * Decodes `n` into `t` as json.Unmarshal would. Returns the decoded value and
 * whether any type mismatch occurred (Go reports the first and carries on).
 * An absent field is absent from the result; null leaves a field at its zero
 * value, except for 'raw', which keeps the literal "null".
 */
export function decodeGo(root: JNode, rootType: GoType): { value: unknown; typeError: boolean } {
  let typeError = false
  const go = (n: JNode, t: GoType): unknown => {
    if (t === 'raw') return n.raw
    if (n.kind === 'null') return undefined
    if (typeof t === 'string') {
      switch (t) {
        case 'string':
          if (n.kind === 'string') return n.value
          break
        case 'bool':
          if (n.kind === 'bool') return n.value
          break
        case 'int':
        case 'uint':
          if (n.kind === 'number' && intOk(n.literal, t === 'uint')) return BigInt(n.literal)
          break
      }
      typeError = true
      return undefined
    }
    if ('array' in t) {
      if (n.kind !== 'array') {
        typeError = true
        return undefined
      }
      return n.items.map((i) => go(i, t.array) ?? zeroOf(t.array))
    }
    if (n.kind !== 'object') {
      typeError = true
      return undefined
    }
    const names = Object.keys(t.object)
    const out: Record<string, unknown> = {}
    for (const [k, v] of n.members) {
      const name = names.find((x) => x === k) ?? names.find((x) => x.toLowerCase() === k.toLowerCase())
      if (name === undefined) continue
      // null, or a mismatched type, leaves the field as it was.
      const got = go(v, t.object[name]!)
      if (got !== undefined) out[name] = got
    }
    return out
  }
  const value = go(root, rootType)
  return { value, typeError }
}

function zeroOf(t: GoType): unknown {
  if (t === 'string') return ''
  if (t === 'int' || t === 'uint') return 0n
  if (t === 'bool') return false
  if (t === 'raw') return 'null'
  if ('array' in t) return []
  return {}
}

/** Parses then decodes; a syntax error throws, a type mismatch is reported. */
export function unmarshalGo(text: string, t: GoType): { value: unknown; typeError: boolean } {
  return decodeGo(parseGo(text), t)
}
