// Untrusted display text (NIP-CASH §Listing Offers, "Untrusted text and
// images"): a lister's title, location, content and a connection string's
// TLV 3 label. Port of nmilat nipcash/listing.SanitizeText.

/** Check-mark look-alikes a lister could use to fake a verified badge. */
export const LOOKALIKE_MARKS: readonly string[] = ['✓', '✔', '✅', '☑', '\u{1F5F8}', '√']

// Bidirectional controls U+202A–U+202E and U+2066–U+2069; zero-width U+200B–U+200D, U+2060, U+FEFF.
const INVISIBLE = new RegExp('[\\u202A-\\u202E\\u2066-\\u2069\\u200B-\\u200D\\u2060\\uFEFF]', 'gu')
const MARKS = new RegExp(`[${LOOKALIKE_MARKS.join('')}]`, 'gu')
const BREAKS = new RegExp('\\r\\n|[\\r\\n\\t\\v\\f\\u0085\\u2028\\u2029]', 'gu')

/**
 * Strips look-alike marks, bidirectional controls and zero-width
 * characters, turns every line break and tab into one space, and keeps at
 * most `maxClusters` user-perceived characters (extended grapheme clusters).
 * Links stay plain text: nothing here parses or renders one.
 */
export function sanitizeText(s: string, maxClusters: number): string {
  const clean = s.replace(INVISIBLE, '').replace(MARKS, '').replace(BREAKS, ' ')
  if (maxClusters <= 0) return ''
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
