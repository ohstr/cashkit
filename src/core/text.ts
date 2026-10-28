// Untrusted display text (NIP-CASH §Listing Offers, "Untrusted text and
// images"): a lister's title, location, content and a connection string's
// TLV 3 label. Port of nmilat nipcash/listing.SanitizeText.

/** Check-mark look-alikes a lister could use to fake a verified badge. */
export const LOOKALIKE_MARKS: readonly string[] = ['✓', '✔', '✅', '☑', '\u{1F5F8}', '√']

// One pass, as each code point is read: a look-alike mark (with an emoji
// variation selector U+FE0F right after it), a bidirectional control
// U+202A–U+202E or U+2066–U+2069, a directional mark U+200E, U+200F or
// U+061C, a zero-width U+200B–U+200D, U+2060, U+FEFF, or any other C0 or C1
// control or DEL (an ESC starting a terminal escape, a BEL) is removed; CR
// LF and every other line break or tab is one space. Removing the other
// controls goes beyond nmilat's SanitizeText, as NIP-LSP's client rules ask.
const STRIP = `[${LOOKALIKE_MARKS.join('')}]\\uFE0F?|[\\u202A-\\u202E\\u2066-\\u2069\\u200B-\\u200F\\u061C\\u2060\\uFEFF]|\\p{Cc}`
const BREAK = '\\r\\n|[\\r\\n\\t\\v\\f\\u0085\\u2028\\u2029]'
const SCAN = new RegExp(`(${BREAK})|${STRIP}`, 'gu')

/**
 * Strips look-alike marks, bidirectional controls and marks, zero-width
 * characters and other control characters, turns every line break and tab into one space, and keeps at
 * most `maxClusters` user-perceived characters (extended grapheme clusters;
 * no cap when `maxClusters` is 0 or less).
 * Links stay plain text: nothing here parses or renders one.
 */
export function sanitizeText(s: string, maxClusters: number): string {
  const clean = s.replace(SCAN, (_, lineBreak?: string) => (lineBreak === undefined ? '' : ' '))
  if (maxClusters <= 0) return clean
  const seg = new Intl.Segmenter(undefined, { granularity: 'grapheme' })
  let out = ''
  let n = 0
  for (const { segment } of seg.segment(clean)) {
    if (n === maxClusters) break
    out += segment
    n++
  }
  return out
}
