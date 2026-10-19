// Cases ported from cashctl internal/output/errors_test.go TestRedactSecretInput
// (cashctl is not importable from tools/export-vectors, so there is no JSON
// vector for it), plus the sanitising step design §10 adds.
import { describe, expect, test } from 'vitest'
import { redact, sanitize } from '../src/core/index.js'

const hex = 'bb7a99ee8fc7ac5529e0747fc12f438f8e3c7765cd0a887e33d16dee8c0ba7a6'
const token = 'lokicash1qypqxpq9qcrsszg2pvxq6rs0zqg3zyg3zygs9qypqxpq'

describe('redact (cashctl RedactSecretInput)', () => {
  test.each([
    ['bare 64-hex secret', hex, ''],
    ['nsec', 'nsec1' + 'q'.repeat(58), ''],
    ['pubkey credential redacts the privkey', `pubkey:${hex}`, 'pubkey:<redacted>'],
    ['cash credential redacts the secret', 'cash:' + 'deadbeef'.repeat(8), 'cash:<redacted>'],
    [
      'connection-key credential redacts only the leading privkey',
      `connection-key:${hex},discord,482910,./attestation.json`,
      'connection-key:<redacted>,discord,482910,./attestation.json',
    ],
    ['an ordinary non-secret value passes through unchanged', 'circle:family', 'circle:family'],
    ['a cash token passes through unchanged', token, token],
    ['uppercase nsec is still redacted', 'NSEC1' + 'Q'.repeat(58), ''],
    ['whitespace-padded hex is still redacted', `  ${hex}  `, ''],
    ['uppercase PUBKEY: prefix and a leading space are still caught', ` 'PUBKEY:${hex}'`, " 'PUBKEY:<redacted>"],
    [
      'a credential embedded after other fields is redacted, the rest stays legible',
      `tok-c12d:notanumber:pubkey:${hex}`,
      'tok-c12d:notanumber:pubkey:<redacted>',
    ],
    [
      "an NWC URI's secret= value is redacted, the rest is not",
      `nostr+walletconnect://${'a1'.repeat(32)}?relay=wss%3A%2F%2Fx.invalid&secret=${'b2'.repeat(32)}`,
      `nostr+walletconnect://${'a1'.repeat(32)}?relay=wss%3A%2F%2Fx.invalid&secret=<redacted>`,
    ],
    ["a cash string's #secret half is redacted", `${token}#${'c3'.repeat(32)}`, `${token}#<redacted>`],
    ['a Cash Hub connection string is redacted wholesale', 'cashhub1qqsxyzsomefakepayloadthatlookslikebech32qqq', 'cashhub1<redacted>'],
    ['a Circle Hub connection string is redacted wholesale', 'circlehub1qqsxyzsomefakepayloadthatlookslikebech32qqq', 'circlehub1<redacted>'],
  ])('%s', (_, input, want) => {
    expect(redact(input)).toBe(want)
  })

  // RE2's \s is [\t\n\f\r ]; JavaScript's would also take \v and U+00A0.
  test('a vertical tab is not whitespace to the secret-shaped match', () => {
    expect(redact(`\v${hex}`)).not.toBe('')
  })
  test('an nconnection1 string is redacted wholesale', () => {
    expect(redact('see nconnection1' + 'q'.repeat(40))).toBe('see nconnection1<redacted>')
  })
  test('65 hex digits after # are not a cash secret', () => {
    expect(redact(`${token}#${'c'.repeat(65)}`)).toBe(`${token}#${'c'.repeat(65)}`)
  })
})

describe('sanitize', () => {
  test.each([
    ['ESC', 'a\u001b[2Jb', 'a�[2Jb'],
    ['NUL', 'a\u0000b', 'a�b'],
    ['newline', 'a\nb', 'a�b'],
    ['DEL', 'a\u007fb', 'a�b'],
    ['C1 CSI', 'a\u009bb', 'a�b'],
    ['line separator', 'a b', 'a�b'],
    ['paragraph separator', 'a b', 'a�b'],
    ['bidi override', 'a‮b', 'a�b'],
    ['bidi isolate', 'a⁦b', 'a�b'],
    ['lone surrogate', 'a\ud800b', 'a�b'],
  ])('replaces %s with U+FFFD', (_, input, want) => {
    expect(sanitize(input)).toBe(want)
  })
  // cashctl internal/output/output_test.go.
  test('strips ANSI escape sequences, keeping the printable suffix', () => {
    const got = sanitize('\x1b[2J\x1b[Hlegit-looking-label')
    expect(got).not.toContain('\x1b')
    expect(got).toContain('legit-looking-label')
  })
  test('replaces control characters visibly, never silently deleting them', () => {
    expect([...sanitize('a\x00b\x07c\x1bd\x7fe')].filter((c) => c === '�')).toHaveLength(4)
  })
  test('strips C1 controls (CSI, OSC, ST)', () => {
    const got = sanitize('\u009b31m\u009b2J\u009d0;PWNED-TITLE\u009c')
    for (const c of ['\u009b', '\u009c', '\u009d']) expect(got).not.toContain(c)
  })
  test.each([0x2028, 0x2029, 0x202a, 0x202e, 0x2066, 0x2069])('strips U+%s', (cp) => {
    expect(sanitize(`before${String.fromCodePoint(cp)}after`)).toBe('before�after')
  })
  test('ordinary text and the empty string are unchanged', () => {
    expect(sanitize("Alice's Family Circle — v2 (日本語 OK)")).toBe("Alice's Family Circle — v2 (日本語 OK)")
    expect(sanitize('')).toBe('')
  })
  test('leaves ordinary text, emoji and accents alone', () => {
    expect(sanitize('Café ☕ 🦄 wss://r.example')).toBe('Café ☕ 🦄 wss://r.example')
  })
  test('redact sanitises after redacting', () => {
    expect(redact(`relay\u001b]0;evil\u0007 pubkey:${hex}`)).toBe('relay�]0;evil� pubkey:<redacted>')
  })
})
