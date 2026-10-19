// Rows as JSON text, for stores and backups that hold text (SQLite, a
// backup file). A bigint is written as {"$bigint":"<decimal>"} so amounts
// round-trip exactly; undefined fields are dropped, as structured clone
// keeps them absent.

const TAG = '$bigint'

export function encodeRow(v: unknown): string {
  return JSON.stringify(v, (_k, x: unknown) => (typeof x === 'bigint' ? { [TAG]: x.toString() } : x))
}

export function decodeRow<T = unknown>(text: string): T {
  return JSON.parse(text, (_k, x: unknown) => {
    if (x !== null && typeof x === 'object' && !Array.isArray(x)) {
      const keys = Object.keys(x)
      if (keys.length === 1 && keys[0] === TAG && typeof (x as Record<string, unknown>)[TAG] === 'string') return BigInt((x as Record<string, string>)[TAG]!)
    }
    return x
  }) as T
}
