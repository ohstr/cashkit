// Decoding JSON the way Go's encoding/json fills a struct, for the payloads
// nmilat reads that way (attestation evidence, NIP-CW wallet details), so a
// payload nmilat accepts is accepted here and one it refuses is refused.
//
// The rules ported: an object or null at the top; keys matched to fields
// case-insensitively, the last occurrence winning; unknown keys and null
// values ignored; a wrongly typed known field refused; an integer field
// refusing a literal with a fraction or exponent, even "1.0".
import { CoreError } from './errors.js'

export type GoFieldType = 'string' | 'int' | 'uint' | 'bool' | 'strings'

const NOT_AN_INT = Object.freeze({ notAnInt: true })

/** JSON.parse that marks number literals Go would not read as integers. */
export function parseGoJSON(text: string, what: string): unknown {
  try {
    return JSON.parse(text, (_key, value, ctx?: { source?: string }) =>
      typeof value === 'number' && ctx?.source !== undefined && /[.eE]/.test(ctx.source) ? NOT_AN_INT : value,
    )
  } catch {
    throw new CoreError('invalid_payload', `${what}: not valid JSON`)
  }
}

/**
 * JSON.parse, except that an integral number written with a fraction or an
 * exponent ("1.0", "1e3") is read as a marker no integer field accepts, as
 * Go refuses it for an integer field. Every other number is a plain number.
 */
export function parseJSONStrictIntegers(text: string): unknown {
  return JSON.parse(text, (_key, value, ctx?: { source?: string }) =>
    typeof value === 'number' && Number.isInteger(value) && ctx?.source !== undefined && /[.eE]/.test(ctx.source) ? NOT_AN_INT : value,
  )
}

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v)

function check(v: unknown, type: GoFieldType): boolean {
  switch (type) {
    case 'string':
      return typeof v === 'string'
    case 'bool':
      return typeof v === 'boolean'
    case 'int':
      return isInt(v)
    case 'uint':
      return isInt(v) && v >= 0
    case 'strings':
      return Array.isArray(v) && v.every((s) => typeof s === 'string' || s === null)
  }
}

/**
 * Fills the struct `fields` (JSON name → type) from a value produced by
 * `parseGoJSON`. Missing fields are absent from the result.
 */
export function decodeGoStruct(v: unknown, fields: Readonly<Record<string, GoFieldType>>, what: string): Record<string, unknown> {
  const fail = () => new CoreError('invalid_payload', `${what}: not valid JSON for its type`)
  const out: Record<string, unknown> = {}
  if (v === null) return out
  if (typeof v !== 'object' || Array.isArray(v) || v === NOT_AN_INT) throw fail()
  const names = Object.keys(fields)
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    const name = names.find((n) => n === k) ?? names.find((n) => n.toLowerCase() === k.toLowerCase())
    if (name === undefined || val === null) continue
    const type = fields[name]!
    if (!check(val, type)) throw fail()
    out[name] = type === 'strings' ? (val as (string | null)[]).map((s) => s ?? '') : val
  }
  return out
}
