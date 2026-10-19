// redact(): what cashkit does to any text before it reaches a log, an
// error or an event (design §9, §10). Port of cashctl
// internal/output.RedactSecretInput followed by output.Sanitize.
//
// The patterns are cashctl's RE2 expressions. RE2's \s is only
// [\t\n\f\r ] and its \b is ASCII-only, so both are spelled out here rather
// than left to JavaScript's broader Unicode \s.

const S = '[\\t\\n\\f\\r ]'
const NS = '[^\\t\\n\\f\\r ]'

const secretLike = new RegExp(`^${S}*(nsec1[a-z0-9]+|[0-9a-f]{64})${S}*$`, 'i')
const credentialPrefix = new RegExp(`\\b(cash|pubkey|connection-key)${S}*:${S}*(${NS}+)`, 'gi')
const nwcSecret = /([?&]secret=)[0-9a-f]+/gi
const giftSecret = /#[0-9a-fA-F]{64}\b/g
const secretBearingBech32 = /\b(cashhub|circlehub|nconnection)1[a-z0-9]{20,}/gi

/**
 * Blanks secret-shaped parts of `s`, wherever they appear in it:
 * - a whole value that is an nsec or 64-hex becomes "";
 * - `cash:`, `pubkey:` and `connection-key:` credentials lose their secret
 *   part (for connection-key, only the leading private key);
 * - `secret=` in an NWC URI and `#<64 hex>` in a cash string are blanked;
 * - cashhub1, circlehub1 and nconnection1 strings become `<hrp>1<redacted>`.
 * The result is then sanitised (see `sanitize`).
 */
export function redact(s: string): string {
  return sanitize(redactSecrets(s))
}

function redactSecrets(s: string): string {
  if (secretLike.test(s)) return ''
  let out = s.replace(credentialPrefix, (_m, prefix: string, rest: string) => {
    if (prefix.toLowerCase() === 'connection-key') {
      const comma = rest.indexOf(',')
      if (comma >= 0) return `${prefix}:<redacted>,${rest.slice(comma + 1)}`
    }
    return `${prefix}:<redacted>`
  })
  out = out.replace(nwcSecret, '$1<redacted>')
  out = out.replace(giftSecret, '#<redacted>')
  out = out.replace(secretBearingBech32, (_m, hrp: string) => `${hrp}1<redacted>`)
  return out
}

/**
 * Replaces every character that can rewrite or disguise displayed text with
 * U+FFFD: C0 controls, DEL, C1 controls, U+2028/U+2029 and the bidi
 * controls U+202A-U+202E and U+2066-U+2069. Replaced rather than removed,
 * so tampering stays visible. A lone surrogate also becomes U+FFFD, as an
 * invalid byte does in Go.
 */
export function sanitize(s: string): string {
  let out = ''
  for (const ch of s) {
    const c = ch.codePointAt(0)!
    out += isUnsafe(c) || (c >= 0xd800 && c <= 0xdfff) ? '�' : ch
  }
  return out
}

function isUnsafe(c: number): boolean {
  return (
    c < 0x20 ||
    c === 0x7f ||
    (c >= 0x80 && c <= 0x9f) ||
    c === 0x2028 ||
    c === 0x2029 ||
    (c >= 0x202a && c <= 0x202e) ||
    (c >= 0x2066 && c <= 0x2069)
  )
}
