// Partial success over several independent commits (design §8): the engine
// returns a report instead of throwing once anything has been committed.
import type { CashkitError } from './errors.js'

export interface Failure {
  readonly ok: false
  readonly error: CashkitError
  readonly holdingIds: readonly string[]
}

export type Outcome<O> = (O & { readonly ok: true }) | Failure

export interface Report<O> {
  readonly outcomes: readonly Outcome<O>[]
  readonly firstError?: CashkitError
}

export function report<O>(outcomes: Outcome<O>[]): Report<O> {
  const first = outcomes.find((o) => !o.ok) as Failure | undefined
  return { outcomes, ...(first !== undefined && { firstError: first.error }) }
}
