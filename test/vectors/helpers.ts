// Shared helpers for the vector suites: every file in vectors/ comes from
// nmilat's vectors package (tools/export-vectors), and each suite runs
// cashkit's port against it.
import { readFileSync } from 'node:fs'

// oxlint-disable-next-line typescript/no-explicit-any -- vector JSON is read as data
export type Json = any

export const load = (name: string): Json => JSON.parse(readFileSync(new URL(`../../vectors/${name}`, import.meta.url), 'utf8'))

/** test.each rows of [title, case]. */
export const named = (cases: Json[], title: (c: Json, i: number) => string = (c, i) => String(c.name ?? c.id ?? i)): [string, Json][] => cases.map((c, i) => [title(c, i), c])

/** JSON with bigints as decimal strings, for comparing with vector values. */
export const plain = (v: unknown): unknown => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x)))
