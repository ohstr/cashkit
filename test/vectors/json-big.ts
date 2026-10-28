// Vector JSON with integers past 2^53 kept exact, as bigints (the vectors carry 2^63-1 and 2^64-1 bounds).
import { readFileSync } from 'node:fs'
import type { Json } from './helpers.js'

type Reviver = (this: unknown, key: string, value: unknown, context?: { source?: string }) => unknown

const exact: Reviver = (_k, v, c) => (typeof v === 'number' && !Number.isSafeInteger(v) && c?.source !== undefined && /^-?\d+$/.test(c.source) ? BigInt(c.source) : v)

export const loadExact = (name: string): Json => JSON.parse(readFileSync(new URL(`../../vectors/${name}`, import.meta.url), 'utf8'), exact as Parameters<typeof JSON.parse>[1])

/** Both sides of a comparison with every number and bigint as its decimal string. */
export const canon = (v: unknown): unknown => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' || typeof x === 'number' ? String(x) : x)))
