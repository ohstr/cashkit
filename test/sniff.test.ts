// Ported from cashctl internal/dial/sniff_test.go.
import { describe, expect, test } from 'vitest'
import { bech32Encode, toWords } from '../src/core/bech32.js'
import {
  bech32Hrp,
  encodeCashHubConnection,
  encodeCircleHubConnection,
  encodeNConnection,
  encodeToken,
  sniff,
  trimSpace,
} from '../src/core/index.js'

const pk = 'aa'.repeat(32)
const sk = 'bb'.repeat(32)
const conn = { walletPubkey: pk, secret: sk, relays: ['wss://relay.example'], label: '' }

describe('sniff', () => {
  test('NWC URI (TestSniff_NWCURI)', () => {
    expect(sniff('nostr+walletconnect://abc?relay=wss://relay.example&secret=xyz')).toBe('nwc_uri')
    expect(sniff('  nostr+walletconnect://abc')).toBe('nwc_uri')
  })
  test('cash token (TestSniff_CashToken)', () => {
    expect(sniff(encodeToken({ hrp: 'lokicash', walletPubkey: pk, secret: sk, relays: ['wss://relay.example'] }))).toBe('cash_token')
  })
  test('any other HRP is a cash token too', () => {
    expect(sniff(bech32Encode('xyzcash', toWords(new Uint8Array(8))))).toBe('cash_token')
  })
  test('circle hub and cash hub (TestSniff_CircleHub, TestSniff_CashHub)', () => {
    expect(sniff(encodeCircleHubConnection(conn))).toBe('circlehub')
    expect(sniff(encodeCashHubConnection(conn))).toBe('cashhub')
  })
  test.each(['npub', 'nsec', 'note', 'nprofile', 'nevent', 'naddr', 'nconnection'])(
    'nostr entity %s (TestSniff_NostrEntity_AllRecognizedHRPs)',
    (hrp) => {
      const s = bech32Encode(hrp, Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8))
      expect(sniff(s)).toBe('nostr_entity')
      expect(bech32Hrp(s)).toBe(hrp)
    },
  )
  test('a real nconnection1 string is a nostr entity (TestSniff_NostrEntity_RealEncoders)', () => {
    expect(sniff(encodeNConnection({ connectionKey: 'a1b2'.repeat(16), relays: ['wss://relay.example'], platform: 'discord' }))).toBe('nostr_entity')
  })
  test.each(['lnfc600n', 'lnbc10u', 'lntb', 'lnurl'])('lightning %s (TestSniff_LightningInvoice)', (hrp) => {
    expect(sniff(bech32Encode(hrp, toWords(new Uint8Array(40))))).toBe('lightning_invoice')
  })
  test.each(['not a connection string at all', '', 'http://example.com', '1234567890'])('unknown %j (TestSniff_Unknown)', (s) => {
    expect(sniff(s)).toBe('unknown')
  })
  test('surrounding whitespace is ignored, as Go TrimSpace does', () => {
    const s = encodeCircleHubConnection(conn)
    expect(sniff(`\n  ${s}\u0085`)).toBe('circlehub')
    expect(bech32Hrp('not bech32')).toBeUndefined()
  })
})

describe('trimSpace (Go strings.TrimSpace)', () => {
  test.each([
    ['  a  ', 'a'],
    ['\t\n\v\f\r a \u0085 　', 'a'],
    ['﻿a', '﻿a'],
    ['a b', 'a b'],
    ['', ''],
    ['   ', ''],
  ])('%j → %j', (input, want) => {
    expect(trimSpace(input)).toBe(want)
  })
})
