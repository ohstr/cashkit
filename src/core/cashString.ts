/**
 * Splits `<token>#<cash_secret>` on the first `#`. Without one, the whole
 * string is the token and the secret is "". The combined string is
 * secret-bearing (design §10).
 */
export function splitCashString(s: string): { token: string; cashSecret: string } {
  const i = s.indexOf('#')
  if (i < 0) return { token: s, cashSecret: '' }
  return { token: s.slice(0, i), cashSecret: s.slice(i + 1) }
}

/** Joins a token and its cash secret into the combined presentation. */
export function joinCashString(token: string, cashSecret: string): string {
  return `${token}#${cashSecret}`
}
