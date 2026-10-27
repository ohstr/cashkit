# cashkit design

cashkit is a TypeScript SDK for building a [NIP-CASH](https://github.com/ohstr/nips/blob/main/NIP-CASH.md)
and [NIP-CW](https://github.com/ohstr/nips/blob/main/NIP-CW.md) wallet in a
browser, a PWA, Node or Bun. It has two jobs. It ports the protocol layers of
the Go SDK [nmilat](https://github.com/ohstr/nmilat) (`nipcash`,
`nipcash/transport`, `nipcash/client`, `nipcw`). It also turns the wallet
behaviour that lives in [cashctl](https://github.com/ohstr/cashctl) today
into a reusable engine. That behaviour covers write-ahead, recovery, cash
selection, auto-consolidate, protect-on-receive, spent tombstones and handoff
history.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
RFC 2119.

## Design principles

- **Own repo, one package.** `ohstr/cashkit` publishes a single npm package,
  `@ohstr/cashkit`, with layered subpath exports (§2). It is not a
  multi-package monorepo, because one version line and one install suit an
  SDK whose layers always ship together. Package boundaries are replaced by
  lint-enforced import rules.
- **Spec-first engine.** The wallet engine is defined in this document as a
  language-neutral behaviour spec: operations, journal state machine,
  invariants and vectors (§4–§8). cashkit implements it, mirroring
  cashctl's behaviour; nothing is extracted from cashctl into a Go library.
- **No UI in the SDK.** Framework bindings live in their own entry point
  (`@ohstr/cashkit/react`), with the framework an optional peer.

## 1. Goals and non-goals

Goals:

1. Give a client everything a normal wallet offers: balance, activity
   history, send, receive, redeem to Lightning, plus the cash-specific
   features (cash notes, protect, consolidate, status, circle join) and
   settings.
2. Match cashctl's behaviour. The same input and the same Hub answers MUST
   produce the same money outcome and the same error code.
3. Run unchanged in a browser, a service worker, Node ≥ 22 and Bun. Platform
   access only happens through ports (§3).
4. Never lose money silently. Every secret that controls value is persisted
   before the wire call that creates or moves it (§5).
5. Keep the public API about amounts and activity, not about bills. Internal
   bill IDs stay available to advanced callers but no flow requires them.
   This is the lesson of cashctl's wallet-abstraction plan.

Non-goals:

- A general Nostr SDK. Only the Nostr pieces cash, CW and NWC need are
  included: NIP-01 events, NIP-19, NIP-44 v2, NIP-47, NIP-05 lookup and the
  NIP-IC attestation parse.
- Hub, mint or relay server code.
- UI components, or React in the core.
- Key management beyond what a wallet needs. Identity signing MAY be
  delegated (NIP-07 or NIP-46, see §3).

## 2. Layers and module layout

```
@ohstr/cashkit/core        pure: codecs, crypto, protocol messages     (no I/O)
@ohstr/cashkit/transport   private transport: envelope, proofs, keys   (no I/O)
@ohstr/cashkit/client      Hub + NWC clients over a RelayPool port     (network)
@ohstr/cashkit/wallet      the engine: journal, ledger, operations     (stateful)
@ohstr/cashkit/adapters/*  Storage / RelayPool / Signer / Vault / Lock implementations
@ohstr/cashkit             re-exports wallet + core decode helpers
```

Import direction is one-way:
`core ← transport ← client ← wallet ← adapters`. Lint (dependency-cruiser)
MUST enforce it. Code under `core`, `transport`, `client` and `wallet` MUST
NOT reference `window`, `document`, `indexedDB`, `node:*` or a concrete
relay or storage library. The one allowed exception is
`globalThis.crypto.getRandomValues`, reached through the default `Random`
port.

Source tree:

```
src/
  core/        bech32tlv, token, cashhub, circlehub, cashString, identity,
               claimProof, provenance, hubGroup, nip01, nip19, nip44, nip47,
               nipcw, bolt11, units, redact
  transport/   envelope, canonicalParams, padding, limits, proof,
               request (wrap), response (reply key), announcement, validate
  client/      relayIO, batchSession, batchPack, batchSend, outcome,
               billState, cashClient,
               nwcClient, circleClient
  wallet/      Wallet, ports, model, journal, ledger, select, ops/*,
               errors, events, migrations
  adapters/    storage-memory, storage-indexeddb, storage-sqlite,
               relay-ws, relay-nostr-tools, relay-ndk,
               signer-local, signer-nip07, signer-nip46,
               vault-none, vault-passphrase, vault-device,
               lock-weblocks, lock-memory
vectors/       JSON conformance vectors exported from nmilat (§11)
tools/export-vectors/   Go module that imports nmilat and writes vectors/
```

### 2.1 core

A port of the protocol-only parts of `nmilat/nipcash` and `nmilat/nipcw`:

- **TLV strings.** Covers the token (types 0–8), the signed Hub connections
  `cashhub1`, `cashorder1` and `circlehub1` (0/1/2, 3 = label, 4 = Hub
  identity, 5 = connection signature, 6 = chain) and `nconnection1`.
  - Decoding MUST apply no length limit (go-flokicoin's
    `bech32.DecodeNoLimit`), so `core/bech32.ts` implements the framing
    itself. Credentials are NIP-19 bech32 (BIP-173): every credential decoder
    (token, Hub connection strings, `nconnection1`) refuses a bech32m
    checksum, and encoding always writes bech32. An all-uppercase string
    decodes as its lowercase form; a mixed-case one is refused (`CoreError`
    `mixed_case`), and a token encoder refuses an HRP that is not lowercase.
  - Unknown TLV types (4 included) are ignored; entries decode in any order.
  - A duplicate or wrong-length pubkey, secret or identity_required is
    fatal, and so is a token with no usable relay hint. A hint is blank
    when it is empty once ASCII whitespace is trimmed; any other hint,
    non-ASCII included, is usable and listed in `relays`.
  - `nconnection1` is strict: exactly one 32-byte key, at most one platform
    matching `[a-z0-9._-]+`, and a truncated or overrunning TLV is refused.
    The encoder refuses a key that is not 64 lowercase hex, a non-ASCII or
    over-long relay and a bad platform name.
  - `Token.scheme` says what the mint signature signs: `mint_v1` (TLV 8 = 1),
    `zap_v1` (2), `malformed` (TLV 8 absent, wrong-length, repeated or
    unknown, or TLV 5/6 unpaired or malformed) or `none` (no 5/6). Only the
    first two carry `mintSignature`/`attestedAmountMillis`; a malformed one
    still decodes. A malformed 7 (hub group) is dropped silently.
  - `Token.relays` holds only the hints a client dials (non-blank printable
    ASCII), in encoded order; `Token.relayBytes` keeps every TLV 1 exactly
    as encoded, for the relay hash.
  - `encodeToken` writes entries in ascending type order (TLV 8 last) and
    refuses a token without provenance and a scheme, an empty or non-ASCII
    hint, and a wrong-length hub group. Source: `nmilat/nipcash/token.go`.
- **Connection signatures** (`core/connection.ts`). The node identity signs
  `<label>:<chain>:<connection_pubkey>:<hub_identity>:<relay_hash>:<label_hash>`
  (`cash-hub:v1`, `cash-order:v1`, `circle-hub:v1`), hashed with the
  chain's signed-message prefix exactly as a mint signature; `label_hash` is
  `''` without TLV 3, so the text ends with `:`.
  - A decoder refuses a missing, repeated or malformed TLV 4, 5 or 6 (a
    chain is 1–32 bytes of `a`–`z`, `0`–`9`, `-`) and ignores a type above
    6, which is outside the signature. Encoders refuse an unsigned string and
    an empty TLV 3.
  - `verify*Connection` returns `{verified: true}` or `{verified: false,
    reason: 'chain_no_prefix' | 'signer_mismatch'}`; an unverified string
    still decodes, and its label and identity are claims only.
    `decodeAnyConnection` returns kind, connection and verdict for a paste
    box. `sign*Connection` exist for the fake Hub and tests: cashkit issues no
    strings.
  - `onlineCheck` compares a `get_info` identity with TLV 4
    (`hubIdentityEqual`: lowercase, a `02`/`03` prefix dropped) and its
    `chain` with TLV 6. `qrForm` renders a string in uppercase for a QR code.
- **Untrusted text.** `sanitizeText(s, maxClusters)` strips check-mark
  look-alikes, bidirectional controls and zero-width characters, turns line
  breaks into spaces and caps grapheme clusters (`Intl.Segmenter`).
- **`<token>#<cash_secret>`.** Split on the first `#`, as
  `SplitCashSliceString` does. The combined string is secret-bearing (§10).
- **Hub group.** `HubGroupFor(hub)` is `sha256(utf8(hex(hub)))[:4]`. It
  hashes the 64-character hex text, not the 32 raw bytes. This is a porting
  trap, and a vector covers it.
- **Identities, recipients and credentials.**
  - Builders: `pubkeyTarget`, `connectionTarget`, `newCashTarget`, and
    credentials `bySecret`, `bySigning`, `bySigningConnectionKey`.
  - A NIP-IC ConnectionKey never travels without its IA: a connection-key
    target is built from a `ConnectionKeyRef {key, platform, ia}` only, and
    a ref comes from `connectionKeyRefFromTyped` (x, discord, email and dns,
    the canonical form hashed), `connectionKeyFromAttestation` (the
    attestation's `d` with its author as the IA, taken only when `d` is the
    hash of its `platform` and `evidence.user_id` byte for byte and that id
    is canonical on a canonical platform), `connectionKeyFromNConnection`
    (the key byte for byte, an IA and a platform required) or
    `connectionKeyRef` (a key already held, never hashed). A Nostr pubkey is
    never hashed into a key.
  - `parseAttestation` refuses a repeated `d`, `p`, `platform`, `evidence`
    or `expiration` tag, a `d` or `p` that is not 64 lowercase hex, an
    invalid platform name, a non-empty `content`, a malformed `expiration`,
    and evidence that is not version 1 with an `auth_type` (`public_post`
    evidence carries `evidence_url`, `challenge` and `pre_auth_code`).
  - On the wire, a cash target is `hex(sha256(secret))`, hashing the 32
    raw secret bytes (not their hex text).
- **Canonical platform user ids** (`core/idna.ts`, NIP-IC). `canonicalUserId`
  accepts `x` and `discord` ids as 1–20 digits with no leading zero and
  below 2^64, and `email` and `dns` with the domain as an IDNA A-label:
  UTS #46 ToASCII, non-transitional, with the hyphen, Bidi, joiner, STD3
  and DNS-length checks. Input that UTS #46 mapping or NFC would change, a
  deviation character (ß, ς, U+200C, U+200D) and a trailing dot are refused,
  never mapped. The tables (`core/idnaData.ts`) are generated by
  `tools/gen-idna-tables.mjs` from Unicode 15.0.0, the version nmilat's
  IDNA library is built on, and the generated file records each source's
  SHA-256. NFC runs through `String.prototype.normalize` only on code points
  already known to be valid, so an engine with older Unicode data can only
  refuse more. `connectionKeyFromTyped` hashes the canonical id of a
  canonical platform and refuses every other platform (its key comes from
  the recipient's attestation or `nconnection`);
  `connectionKeyFromAttested` hashes the attested id as given.
- **Claim proof.**
  - Kind 23198 with exactly the tags its method and slice need
    (`claimProofTags`): `d` and `m` always; `bolt11_hash` (redeem), `q`
    (withdraw), `new_identity_hash` and `amount_millis` (transfer,
    consolidate), `s` = `sourcesHash` of the sources in order (consolidate);
    plus `connection_key`/`e` and the embedded NIP-IC 35522 attestation for
    a connection-key slice (`checkAttestationForClaim` runs the NIP's checks
    on it). A missing, extra or badly encoded tag is refused locally.
  - `new_identity_hash = sha256(type ":" value ":" ia)`.
  - Tokens delivered to the claimant are NIP-44 decrypted with
    ECDH(own priv, new wallet pubkey).
- **Requests.** `request_id` (`newRequestId`, 32 random bytes;
  `derivedRequestId` = sha256 of `retry:<id>` for a re-placed call, which
  refuses an `<id>` that is not a request id) is
  required on `cash_transfer`, `cash_consolidate` and `mint_cash`; the
  client draws one when the caller gives none. `cashTransferRequest`
  refuses a zero or excess amount, takes `zap_target` (pubkey slice to a
  pubkey only) and requires a fresh `remainder_commitment` for a partial
  split of a cash source (refused anywhere else).
  `expectedTransferOutcome` predicts the NIP's outcome table.
  `cashStatusRequest` never carries a cash secret. `mintCashRequest` and
  `parseMintCashResult` apply the recipient rules; the token alone is the
  credential. `nwcRequestEvent` takes an `expiration`.
- **Results.** A destroyed bill answers any bill method with a tombstone
  (`parseTombstone`: `status: spent`, `reason` when it is one of the five,
  `retained_until`); the client reports it as `spent`. An expiry of 0 or
  null reads as never. `parseCashRedeemResult` requires a 64-hex
  `preimage` and `fees_paid`. A `cash_status` row is `RecipientStatus`
  (with `ia_pubkey`, `claimed_at`, `withdraw_request_id`); the result may
  carry `withdraw` terms, dropped when invalid.
- **Lookups.** `cashLookupParams`, `parseCashLookupResult` and
  `decodeLookupDone` (a destroyed bill's token field holds its tombstone);
  `decideLookup` is the NIP's status table. `redeemFeeQuote` and
  `readNetworkChain` cover the fee quote and `get_info`'s `network`/`chain`.
- **Provenance.**
  - Scheme 1 signs `cash-mint:v1:<hrp>:<wallet>:<amount>:<relay_hash>`;
    scheme 2 (a zap bill) signs `cash-zap:v1:…:<relay_hash>:pubkey/<recipient>:pubkey/<sender>:<target_hash>:<issued_at>:<expires_at>`.
    The labels are the same for every HRP. `relay_hash` (`relayHashOf`) is
    the sha256 of every TLV 1 as encoded, each after its 1-byte length, then
    the 32-byte secret.
  - The digest is `sha256d(prefix ‖ payload)`, the prefix chosen from the
    token's HRP through `CHAIN_TABLE` (`satscash` → `bitcoin` →
    `Lightning Signed Message:`, plus implementation-local rows). An HRP
    with no row decodes with no provenance.
  - It is a 65-byte recoverable compact ECDSA signature; a header of 27..34
    or a raw recid 0..3 is accepted.
  - `verifyProvenance(token)` returns `{minter, xonly}` for scheme 1, or
    `undefined`. A zap bill needs its Cash Zap's fields
    (`verifyZapProvenance`); without them `CashClient` fails `no_zap_event`
    before contacting any relay. `sameMinter` compares x-only.
  - Among copies of one bill, `selectVerifiedCopy` keeps only one whose
    provenance recovers the trusted minter; a failing copy's hints are never
    dialled.
- **NIP-47 messages and pairing URI**, and **NIP-CW** `create_circle_wallet`
  request/response, including decrypting `encrypted_details`.
- **NIP-44 plaintext length.** 1 to 2^32−1 bytes, with NIP-44 v2's extended
  length prefix from 65536; an empty plaintext is refused. The cash
  transport's own envelope ceiling (65535, §Limits) is separate.
- **Units.** Amounts are `bigint` millis everywhere, never `number`. The
  display unit comes from the token's HRP (`lokicash` → loki, `satscash` →
  sat, with 1 unit = 1000 millis).

### 2.2 transport

A port of `nmilat/nipcash/transport`, which carries every bill method
(`cash_status`, `cash_redeem`, `cash_withdraw_quote`, `cash_withdraw`,
`cash_transfer`, `cash_consolidate`), `cash_lookup`, `cash_order` and
`create_circle_wallet` (an explicit allowlist; `mint_cash` never travels
here).

- **Envelope** `{not_after, nonce, reply_to, items, pad}` (no version
  field; responses carry none either). Each item is
  `{id, target, method, params, proof, bill_proof}`. Kinds:
  - 23190 request, 23191 response
  - 23192 item proof, 23193 bill proof
  - 11190 Hub announcement
- **Bearer shapes** (`bearerShapeOK`), judged on the method an item is
  served under (`servingMethod`: a `cash_withdraw` cancel is served as
  `cash_lookup`, and a malformed cancel is refused `bad_cancel`): never both
  `proof` and a `cash_secret`; a value method needs one of them;
  `cash_order` needs `proof`; a `cash_status` or `cash_withdraw_quote`
  carries no secret (a cash-mode one passes on its bill proof alone, so the
  client checks a cash secret against the row's commitment instead); any
  other method may go either way. Two items of one envelope never carry the
  same `request_id`.
- **Decoding an envelope** (`decodeEnvelope`, the Hub's side) is structural,
  as nmilat's: the size limit, the header, 1 to `max_items` items, unique
  item ids (two items sharing one refuse the envelope), and the budget over
  the items kept. Only an item that is not well formed, or declares too many
  consolidate sources, is dropped; `servableItems` then applies the per-item
  serving checks (target, method, params, bearer shape, bill proof, an
  identical item repeated).
- **Verification budget** (`verificationCost`): the bill proof, the item
  proof when present, and every signed event in params (`identity_event`,
  `attestation_event`, `quote`, each source's events); a cash secret costs
  nothing.
- **Canonical params hash (`ph`).** The format is nmilat-specific and is not
  stock RFC 8785:
  - Keys are sorted by byte order.
  - Strings use RFC 8785 escaping.
  - Number literals are preserved exactly as written.

  An off-the-shelf JCS library (or `JSON.stringify` over JS numbers)
  normalises numbers and loses big integers, so it MUST NOT be used. cashkit
  MUST serialise params to text with a bigint-aware writer and compute `ph`
  by canonicalising that exact text with a small tokenizer that keeps number
  tokens verbatim.
- **Padding.**
  - T is the smallest multiple of `pad_bucket_bytes` at least L, or
    `max_bytes` when that multiple is larger; only L above `max_bytes` is
    refused.
  - cashkit SHOULD escape `<`, `>` and `&` the way Go's `json.Marshal`
    does, so envelopes are byte-identical to nmilat's and vectors can
    compare them directly.
- **Limits.**
  - An announced bucket is at least 2 KiB, and NIP-44 plaintext is at most
    65535 bytes: an announced `max_bytes` above it is kept as announced and
    read as 65535 for sizing (`effectiveLimits`).
- **Request wrap.**
  - A fresh ephemeral key signs the event: kind 23190, `["p", inbox]`, and a
    randomized `created_at` up to 2 days in the past.
  - The content is NIP-44 v2 under ECDH(ephemeral, inbox). It is not a gift
    wrap.
  - Under proof of work (`wrapRequestPow`) the event also carries a NIP-13
    `nonce` and an `expiration` equal to `not_after` (at most 1 day ahead);
    `remine` re-mines the same event (key, content, `created_at`) after a
    relay's `pow:` refusal (`parsePowRejection`), and `relayPowMinimum`
    reads a relay's NIP-11 minimum. Difficulty 0 adds neither tag.
- **Reply key.**
  - HKDF-Expand only (SHA-256): PRK = the conversation key, info =
    `"nipcash-reply-v1" || reply_to hex`, L = 32.
  - The response (kind 23191, p-tagged `reply_to`) is NIP-44 v2 encrypted
    with that key used directly as the conversation key.
- **Responses.** Written with `results` last (`[]` for a reply of
  omissions), padded to the Hub's bucket under the 65535 ceiling.
  `decodeResponseChunk`, which the session uses, rejects a chunk only for
  bad JSON, a `req_nonce` mismatch or a plaintext over 65535 bytes: an
  unknown id is dropped (`unknownIds`), an id answered twice or with both a
  result and an error has no outcome (`conflictedIds`), a `seq` outside 1 to
  `total` is flagged (`malformedSeq`); errors keep their `detail`.
  `decodeResponse` is the strict single-event reading, refusing each of
  those instead.
- **Proofs** carry `d`, `h`, `m`, `ph`, `en` and an `expiration` equal to
  the envelope's `not_after`, each once, with empty content; verification
  checks every one. Freshness is 5 min in the past and 1 min in the future on
  `created_at`. A Hub accepts a `not_after` up to its own `max_request_age`
  ahead (`checkFreshness`, used by the fake Hub).
- **Announcement** (tags, `content` empty).
  - Fetch the newest `{kinds:[11190], authors:[hub]}`; verify the author and
    the BIP-340 signature.
  - Exactly one `inbox` (used as announced, even when it is the author), one
    `limit` per name (unknown names ignored), `r` relays in order, `addr`
    hints kept for display (a malformed one dropped). A malformed `inbox`,
    `limit` or `r`, or a missing envelope limit, rejects it: there are no
    defaults.
  - `max_request_age` (H) may be missing or below 60: the Hub then stays
    usable for reads and redeems, but `hubUsableForBills` is false.

### 2.3 client

A port of `nmilat/nipcash/client`, `nipcw/client` and the NWC client:

- **`BatchSession(hub, relays)`.**
  - Fetches the announcement from the relay hints only and refreshes it,
    keeping the newest by `created_at` (rollback guard).
  - Publishes to the announcement's `r` relays first, then the hints in
    encoded order, each once, blanks skipped.
  - Packs items greedily into envelopes with a fresh nonce and `reply_to`
    per envelope. The deadline (`not_after`) is `deadlineFor(H, now)` =
    now + min(60, ⌊H/2⌋), from the Hub's announced `max_request_age`, or one
    the caller passes (already written ahead); it is never an app setting.
  - `send(builders, {notAfter, singleEnvelope, beforePublish})`: a
    bill-creating item to a Hub without a usable H is refused
    (`hub_unusable`); `beforePublish` runs once the envelope and its
    deadline are final (the caller's write-ahead), and with less than 20 s
    then left nothing is sent (`deadline_too_close`); `singleEnvelope`
    refuses a batch that would split.
- **Proof of work.** Before the first publish the session reads each
  publish relay's NIP-11 minimum (`relayInfo` port, the pool's, else an
  HTTP fetch; cached, re-read after a refusal) and mines the request to the
  highest one (plain when all are 0). Order: write-ahead, mine, the 20 s
  check, publish. Over `powBudget` nothing is sent (`pow_too_hard`). A
  relay's `pow: …` refusal re-mines the same event (same key, content,
  `created_at`, so the same envelope and ids) and publishes it to that relay
  again, until the deadline. NIP-47 calls are never mined. Relay adapters
  return the relay's own OK message verbatim, or none.
- **Send.**
  - Per relay: subscribe to `{kinds:[23191], #p:[reply_to]}`, wait up to 2 s
    for EOSE, then publish. The first relay to accept wins
    (`acceptedRelays`); every subscription opened is kept until the reply
    is collected.
  - Collect replies until `not_after` (or `replyWaitMs`, if shorter), per
    NIP-CASH §Chunked Replies: every decided outcome is kept; chunks
    disagreeing about `total`, two events with one `seq` or a `seq` out of
    range make the reply incomplete, never void; an item answered twice is
    `conflicted`; the same event from two relays is one chunk; `total` is
    bounded by the items sent.
- **Per-item `ItemOutcome`.**
  - `state` is `not_served` (the zero value: **unknown**, possibly applied),
    `result`, `error`, `conflicted` (answered twice, possibly applied) or
    `tombstone` (the bill is gone, the call never ran).
  - `classifyCall` reads it for a pending call: `applied`;
    `final_not_applied` for `BAD_REQUEST` (item- or envelope-level, with its
    `detail`); `tombstone`; `not_sent` for a local refusal; `open` for any
    other code, an omission, a conflict or an undecodable success, which is
    looked up and never resent.
- **`BillState`** is `indeterminate` (the zero value), `available` or
  `spent`. Only an explicit `"spent"` answer produces `spent`; a timeout
  never does.
- **No composite flows.** A send from several bills or a protect that
  merges is a wallet operation whose every step is its own call; the client
  only places single calls. `cashTransfer`, `cashConsolidate` and every
  transfer or consolidate item take the caller's `request_id`
  (`bad_input` without it).
- **Codes, never messages.** No code acts on a Hub's error message
  (NIP-CASH §Errors); `rawMessage` is kept for display only, and
  `tools/lint-no-message-match.mjs` (run by `pnpm lint`) fails the build on
  any comparison or text test of it.
- **Notifications.** `NwcClient.notifications(handler)` delivers the
  wallet's NIP-47 notifications (kind 23197, and 23196 when the wallet speaks
  NIP-04), each once, only from the wallet's own key.
- **Lookups** (`lookupMany`, `lookupOne`): a `cash_lookup` item names the
  original call's target and is signed as that call was authorized (the
  claim-proof key, the Cash Hub connection's own key for a mint, or a cash
  secret: first without it, then with it only after `UNAUTHORIZED`). A
  `REQUEST_REUSED` or an omission is routed as not served, never as
  `unknown`.
- **`CashHubClient(deps, cashhub1, {confirmUnverified})`** takes the string
  only (a URI or any other form is `connection_invalid`, nothing dialled).
  Every `get_info` read runs the online check (`pubkey` = TLV 4, `chain` =
  TLV 6, else `connection_mismatch`); an unverified string is used only after
  that check passed and `confirmUnverified` resolved true, asked once per
  client. `node()` is TLV 4; `mint` sends `request_id` with the deadline as
  NIP-47 `expiration` (refused to a Hub without a usable H); `lookupMint`
  finds a lost mint. `view()` returns a `HubView` (fingerprint, sanitized
  label, verdict, online state, network, QR form).
- **`NwcClient`** (subscriptions opened and EOSE awaited, bounded, before the
  first publish; `call(…, {expiration})` for a deadline): `getInfo` (typing
  `pubkey`, `network`, `chain`), `getBalance`, `makeInvoice`, `payInvoice`,
  `listTransactions`, `signMessage`. The scheme comes from the wallet's
  kind 13194 info event: `nip44_v2` when listed, `nip04` when the wallet
  lists only that or nothing. Only a reply authored and signed by
  the wallet is accepted.
- **`connectCircle(deps, circlehub1, { confirmUnverified?, purpose? })`**:
  decodes and verifies the string, reads `get_info` and checks
  `circle_wallet.identity` and `chain` against it (no `circle_wallet` block
  or no `identity` is no Circle Wallet Hub), asks `confirmUnverified` for an
  unverified string, refuses a Hub not `accepting` joins (joins only), and
  opens the private transport from the announcement of `identity`
  (`join_unavailable` when none verifies). Joins and join lookups go over
  that transport only (NIP-CW §Private Join); there is no standard-transport
  join. `createCircleWalletMany` sends prepared joins; the details decrypt
  from the Hub connection key only and must name the join's
  `connection_pubkey`.
- **`CircleWalletClient(connection)`**: a member's Circle Wallet from its
  fields (`walletPubkey`, `relays`, the member's own `secret`), never a URI:
  `getInfo`, `getBalance`, `getBudget`, `makeInvoice` (amount above zero),
  `payInvoice`, `payKeysend`, `lookupInvoice`, `listTransactions`,
  `deleteWallet`, and the advisory `previewPayment`.

- **NIP-IC verification** (`core/icVerify.ts`, `client/identity.ts`).
  `evaluateConnection` runs the Verification Model over the 35521s found
  for a key, with the relay reads behind an `AttestationSource`;
  `resolveConnection(pool, key, {trustedIas, relays, now})` queries the
  35521s, fetches each referenced 35522 from its relay hint (the query
  relays when there is none) and returns `verified`, `unverified` or
  `spoofed` with one verdict per claim. A reference counts only when it is
  a valid 35522 from a trusted IA other than the claim's author, its `d`
  and `platform` equal the claim's and `p` is the claim's author, it is
  unexpired, dated at most 900 s ahead, not deleted by the IA itself and
  the IA's current attestation for the key; each failed check is its own
  reason. A claim whose `content` names another `user_id` or `username`
  than the evidence is spoofed, and the handle to show is the evidence's.
  Of the attestations that count the latest `created_at` wins (ties: the
  lowest id) and claims by every other pubkey are spoofed. It is for
  display and linking; a claim is checked by the Hub, never by this.

- **`client/lsp.ts`** (NIP-LSP): `newAnnouncement` builds the unsigned
  kind-10735 event from an LSP's fields (tags in the NIP's order; the
  example is reproduced byte for byte) and `fromLspsInfo` builds the fields
  from its own live LSPS answers in either unit dialect; `signingPayload`
  refuses any kind but 10735. `parseAnnouncement` runs §Client Behavior
  steps 1–5 and reports the first failure as `AnnouncementError`; `LspSeen`
  keeps the newest per node with no fallback to an older one; `checkLive`
  compares with the live LSPS answers, which decide.

The client layer is stateless about the wallet. It never persists anything,
and it returns enough for the engine to journal before and after each call.

## 3. Ports

Everything with side effects is an interface the app passes to
`Wallet.open`. Defaults are listed under each one.

```ts
interface WalletDeps {
  storage: Storage            // required
  vault: SecretVault          // required (vault-none is explicit, never implicit)
  relays: RelayPool           // default: adapters/relay-ws on globalThis.WebSocket
  signer?: Signer             // identity signer; absent = no identity yet
  lock?: Lock                 // default: lock-weblocks in browsers, lock-memory elsewhere
  fetch?: typeof fetch        // NIP-05; default globalThis.fetch
  clock?: () => number        // ms epoch
  random?: (n: number) => Uint8Array
  logger?: Logger             // receives already-redacted records only
}
```

**Storage.** A transactional store of versioned rows.

```ts
interface Storage {
  tx<T>(mode: 'r' | 'rw', fn: (t: StorageTx) => Promise<T>): Promise<T>
}
interface StorageTx {
  get<C extends Collection>(c: C, key: string): Promise<Row<C> | undefined>
  list<C extends Collection>(c: C, q?: Query<C>): Promise<Row<C>[]>
  put<C extends Collection>(c: C, row: Row<C>, expectVersion?: number): Promise<void> // ConcurrentUpdate on mismatch
  insert<C extends AppendOnly>(c: C, row: NewRow<C>): Promise<string>
  delete<C extends Collection>(c: C, key: string): Promise<void>
}
```

- Every mutable row carries `version`. A `put` with `expectVersion` that
  doesn't match MUST fail with `ConcurrentUpdate` and MUST NOT be retried
  silently. This is cashctl's OCC rule (`ledger.go`).
- A `tx` callback MUST NOT await anything except operations on that `tx`.
  IndexedDB auto-commits on a foreign await, so network calls always happen
  between transactions, never inside one. The journal (§5) is designed
  around this.
- Adapters:
  - `storage-memory` for tests.
  - `storage-indexeddb` for browsers.
  - `storage-sqlite` for Node/Bun: `node:sqlite`, with `better-sqlite3` as
    an optional peer. It uses WAL, `busy_timeout`, `BEGIN IMMEDIATE`
    migrations and 0600 files, as cashctl's `internal/store` does.

**SecretVault.** Encrypts secret fields at rest (§10).

```ts
interface SecretVault {
  seal(plain: Uint8Array): Promise<Sealed>
  open(sealed: Sealed): Promise<Uint8Array>
  locked(): boolean
}
```

- `vault-passphrase`: scrypt (NIP-49 parameters) with XChaCha20-Poly1305.
- `vault-device`: a non-extractable WebCrypto AES-GCM key kept in
  IndexedDB.
- `vault-none`: plaintext. It MUST be chosen explicitly and is meant for
  tests and CLI-style use.

**Signer.** Signs as the user's identity.

```ts
interface Signer {
  readonly pubkey: string       // resolved once; a NIP-07/46 adapter's factory awaits it
  signEvent(e: EventTemplate): Promise<NostrEvent>
  nip44Decrypt(peer: string, ciphertext: string): Promise<string>
}
```

The identity is only needed for claim proofs, item proofs and decrypting
delivered tokens, all of which this interface covers. That makes NIP-07
(`window.nostr`) and NIP-46 (bunker) signers workable. Every other key is
local to the engine and never goes through `Signer`:

- request ephemeral keys
- bill connection secrets (bill proofs)
- cash secrets
- throwaway merge keys
- circle connection keys

A remote signer adds latency per item, and there is no minimum speed. The
session signs items as it packs them and closes an envelope once half of
`not_after`'s window has gone on signing; each envelope gets its own
`not_after` and is sent before the next is built. A single signature that
takes the whole window is refused (`signer_too_slow`), and nothing is sent.

**RelayPool.**

```ts
interface RelayPool {
  subscribe(relays: string[], filter: Filter,
            h: { onEvent(e: SignedEvent): void; onEose(relay: string): void }): () => void
  publish(relay: string, e: SignedEvent): Promise<{ ok: boolean; message?: string }>
}
```

Adapters: `relay-ws` (built in, uses the global `WebSocket`, which Node ≥ 22
has), `relay-nostr-tools` (`SimplePool`), `relay-ndk`. The last two are
optional peer dependencies.

**Lock.** `withLock(name, fn)` serialises money-moving operations per wallet
(§5.4). `lock-weblocks` uses `navigator.locks`; `lock-memory` is per-process.

**SyncChannel.** `post({ walletId, at })` after a commit, and
`subscribe(fn)`: another tab of the same wallet reloads its state on a
notice. `sync-broadcast` uses BroadcastChannel. Notices carry no row and no
secret.

**persist.** `() => Promise<boolean>`, called once at open; the answer is
`state.storagePersisted` (§10).

`openWallet` (the package root) fills these in for a browser: IndexedDB,
Web Locks, BroadcastChannel, `navigator.storage.persist`, and relay-ws.
Outside a browser `storage` must be given.

## 4. Domain model

All amounts are `bigint` millis. Secret-bearing fields use branded types
(`CashSecret`, `PrivKey`, `NwcUri`, `CashNoteString`). These types are never
JSON-serialisable through the public `toJSON` (§10).

| Collection | Key fields | Mirrors |
|---|---|---|
| `identity` | `source` (`local` / `signer`), `pubkey`, `label`, sealed `priv?` | `identity` table |
| `connections` | `name`, sealed `uri`, `kind` (`nwc` / `circle`), `isDefault`, `lastKnownBalance{millis,at}` | `connections` |
| `holdings` | see below | `entries` |
| `activity` | `at`, `action`, structured `detail` (§4.2) | `history` |
| `handoffs` | `kind` (`cash_note` / `gift`), sealed `handoff`, `amount`, `target`, `walletPubkey`, `expiresAt`, `status`, `checkedAt` | `handoffs` |
| `pendingJoins` | `connectionPubkey`, sealed `connectionSecret`, `hubPubkey`, `hubLabel`, `at` | `pending_joins` |
| `settings` | §6.9 | config |
| `meta` | `schemaVersion` (2), `walletId`, `storeFingerprint` | — |
| `pendingCalls` | `requestId`, `method`, `target`, `node`, `relays`, exact `deadline`, `hAtSend`, `device`, `attempts`, `derivedFrom?`, `amount`, `sources`, `authorizer` (sealed `authorizerKey` / `buyerKey` where it is a key), `outputs` (a cash destination's sealed `secret`), `state`, `outcome?`, `lookup?`, `needsUser?` | — |
| `device` (local) | `deviceId`, `storeFingerprint` | — |
| `derivedIds` (local) | `parentCallId`, `deadline`, `keepUntil` | — |
| `hubs` (local) | `hMax` (the largest `max_request_age` seen) | — |

Schema 2 has no migration: a store written by schema 1 is refused on open
(`internal`) before anything is written. Local collections are never
exported or imported. Every call that carries a `request_id` is written
ahead by `prepareCall` (secrets sealed, the row read back and every sealed
field opened and compared before anything is sent), marked sent from the
session's `beforePublish`, and closed by `finishCall` in the transaction
that commits its result; `openCallsFor` lists the calls that lock a
holding. A call records the device that placed it: on another device (a
restored backup, a store whose meta fingerprint no longer matches its
device row) it is foreign and never re-placed.

### 4.1 Holding

```ts
interface Holding {
  id: string                       // opaque, e.g. "h-3f9a"; stable across reactivation
  token: string                    // lowercased; unique
  walletPubkey: string; minterPubkey?: string; relayUrls: string[]
  amount?: bigint; expiresAt?: number; verified: boolean
  status: 'held' | 'redeemed' | 'transferred' | 'consolidated' | 'spent'
  mode: 'pubkey' | 'cash' | 'connection_key'
  protection: 'none' | 'shared' | 'protected'   // cash mode only
  cashSecret?: Sealed<CashSecret>
  connectionKey?: { platform: string; externalId: string; attestationId: string; iaPubkey: string }
  throwawayKey?: Sealed<PrivKey>    // a merge key this bill sits on (§6.2)
  version: number
}
```

Rows are never deleted; only `status` changes. Adding a token that already
exists but is no longer held reactivates the same row with the same ID.
Adding one that is already held is a `conflict`. Both rules come from
`ledger.Add`.

### 4.2 Activity

cashctl's `history.detail` is free text. cashkit stores structured entries
instead, so a UI can render, filter and localise them:

```ts
type Activity =
  | { action: 'receive'; amount: bigint; holdingId: string; mode: Holding['mode'] }
  | { action: 'protect'; holdingId: string }
  | { action: 'redeem'; amount: bigint; feesPaid: bigint; into: string /* connection name or 'invoice' */; holdingIds: string[] }
  | { action: 'send'; amount: bigint; to: TargetDisplay; handoffId?: string; holdingIds: string[]; remainderId?: string }
  | { action: 'consolidate'; amount: bigint; from: string[]; into?: string }
  | { action: 'spent'; holdingId: string }
  | { action: 'join'; circle: string; connection: string }
```

`TargetDisplay` holds only the public, resolved form (npub, NIP-05, or the
literal `cash`). It MUST NOT hold an `nconnection1` string or any secret;
this is cashctl's `auditD_cli_history_secrets` rule.

`wallet.activity()` returns activity rows merged with handoffs into one
time-ordered feed, which is what a wallet's "transactions" screen shows.

## 5. Operation journal

This is the invariant everything else hangs on.

> **Persist, then send.** A secret that will control value after a wire
> call MUST be committed to storage before that call is made. If the commit
> fails, the call MUST NOT be made.

### 5.1 Pending calls

Every call that carries a `request_id` (`cash_transfer`, `cash_consolidate`,
and later `mint_cash`, `cash_order`, `cash_withdraw`) is written ahead as a
`pendingCalls` row before its first byte is sent: its request id, exact
deadline, target, sources, authorizer, and every secret it creates.

| What the call creates | Written ahead as | On success |
|---|---|---|
| a new cash note (a send to cash, a consolidate to cash, protect, back-to-cash) | `outputs[role=new]`, `{ kind: 'cash', secret }` | the handoff `<token>#<secret>`, or the holding's `cashSecret` |
| the remainder of a partial split | `outputs[role=remainder]`: a fresh cash secret for a cash note (its `remainder_commitment`), the source's merge key or the wallet's pubkey otherwise | the remainder holding |
| a bill on a merge key | `outputs[role=new]`, `{ kind: 'throwaway', pubkey, key }` | the holding's `throwawayKey`; it switches to signing |
| a call signed by a merge key | `authorizer`, `{ kind: 'throwaway', authorizerKey }` | — |
| `pendingJoin` row (`create_circle_wallet`) | its own row | deleted in the same tx that adds the connection |

A holding named by an open call (as a source, or as the cash note that
authorizes it) is **locked**: no plan picks it, and naming it is a
`conflict` until the call closes. `holdings()` and `state.holdings` show it
as `unsettled`. Redeem creates no locally generated secret; it commits once,
after the result arrives.

### 5.2 State machine

Each money-moving call follows the same machine:

```
prepare ─► written ahead ─► sent ─┬─► applied ──► result applied + call closed (one tx)
   │            │                 ├─► BAD_REQUEST, tombstone ──► closed, not applied
   │            │                 └─► anything else ──► open (sources locked) ──► settle() looks it up
   │            └─ write-ahead failed ─► aborted (nothing sent)
   └─ validation failed ─► aborted
applied but the result commit failed ─► internal error; the call stays written ahead
  (and the error's recovery text carries any cash notes it created)
```

How Hub answers are classified (cashctl `classifyCashSpendErr`):

- **Definite**: a decodable item error, a "not sent" or no-announcement
  failure, or a pre-send validation sentinel.
- **Indeterminate**: everything else. The error code is `indeterminate`,
  and the caller is told to check `status` before retrying.

### 5.3 Settling

**Pending calls** (`wallet/runner.ts`). A call is run by `executeCall`:
an applied answer is applied and the call closed in one transaction;
`BAD_REQUEST` closes it not applied (`invalid_input`); a tombstone marks
its source spent; a call nothing was sent for closes `not_sent`; any other
answer leaves it open (`sent`, sources locked) and throws with its
`pendingCallId`. `settle()` then looks every open call up by its exact
deadline, signed by its authorizer (a cash one without its secret first):

| lookup | what happens |
|---|---|
| never marked sent | closed `not_sent` |
| `done` | the original result applied, closed `applied` (`recovered` event) |
| `pending` | `retryAfter` kept; `state.nextSettleAt` is the earliest |
| `unknown`, another device's call | `needsUser: 'foreign_device'`, never placed again from here |
| `unknown` after a coded refusal | closed `not_applied`, `needsUser: 'refused'` with the code |
| `unknown`, a kind that asks first (mint, order) | `needsUser: 'confirm_replace'`; `pendingCalls.confirmReplace(id)` |
| `unknown`, otherwise | placed again under the derived id (recorded first), at most 3 attempts (`replace_cap`) |
| `expired` | closed `lookup_expired`; its written-ahead secrets in `unreconciledSecrets` |
| omitted, refused, or `REQUEST_REUSED` | `omissions + 1`, never `unknown`; past deadline + H, `lookup_unanswered` |

`state.pendingCalls` and `pendingCalls.list()` show open calls and closed
ones waiting for the user, without request ids or secrets;
`pendingCalls.close(id)` closes one; `autoSettle()` runs `settle()` at
`nextSettleAt`. Each operation kind registers how it places, finishes and
looks up its calls (`registerCallKind`); sends, splits, protect, moves onto and off a merge key, and consolidations run as `transfer` and `consolidate` calls (`wallet/kinds.ts`).

`wallet.settle()` MUST run on `open`, before every spend plan, and on
demand. `protect()` settles first too.

### 5.4 Concurrency

- **Browser tabs.** Each money-moving operation runs inside
  `lock.withLock('cashkit:<walletId>:spend')`. Reads don't take the lock.
  After a commit, the tab posts on a `BroadcastChannel` so other tabs reload
  their state. OCC stays as the backstop for anything outside the lock.
- **Processes (Node).** OCC on `version`. A `ConcurrentUpdate` reloads and
  fails the operation with `conflict` (retryable), never a silent retry.
- **Kill window.** A tab close, a service-worker termination or SIGKILL can
  land between any two steps. §5.1 guarantees the only loss is time, not
  money. The scenario suite (§11.2) kills the engine at every step boundary
  and checks that `settle()` recovers.
- **Durability.** On first open, browsers SHOULD call
  `navigator.storage.persist()`. `state.storagePersisted` exposes the result
  so the UI can warn about it (§10).

## 6. Wallet API

```ts
import { Wallet } from '@ohstr/cashkit'
const wallet = await Wallet.open({ storage, vault, signer, relays })
```

Every money-moving operation is split in two: **plan, then execute**. A
plan describes everything cashctl would ask the user to confirm:

- auto-consolidation, and the fact that it tells the Hub the bills share an
  owner
- the resolved target
- the fee quote
- expiry mixing

The UI shows the plan, and `execute(plan)` performs it. A plan holds the
`version` of every holding it read; if any changed, `execute` fails with
`conflict`. Callers that don't need a confirmation step use the one-call
form (`wallet.send(...)` is `execute(await planSend(...))`). This replaces
cashctl's interactive prompts and `--yes`; the library itself never
prompts.

### 6.1 Receive

```ts
receive(input: string, o?: { protect?: boolean /* default settings.autoProtect */ }): Promise<ReceiveResult>
type ReceiveResult =
  | { received: true; holding: HoldingView; secured: { status: 'not_applicable' | 'declined' | 'failed' | 'rekeyed'; unresolved?: boolean; likelyWrongSecret?: boolean } }
  | { received: false; reason: 'no_embedded_secret'; report: TokenReport }
```

Flow, from `cash_receive.go`:

1. Split `#`, sniff the input, decode it.
2. A cash token pasted without its secret first gets a probe as the local
   identity, then degrades to a read-only report.
3. A token already held is a `conflict`.
4. `checkClaim`, the caller's own row found from the credential (`ownRow`,
   scope `mine`) and checked with `claimable`:
   - spent → `spent`
   - no match → `invalid_input`
   - a row that is claimed or ended by a cash_withdraw → `spent` (reason
     `claimed` or `withdrawn`); past its expiry → `invalid_input` (reason
     `expired`). Status and redeem quotes read the row the same way;
     `status` reports such a holding with `notClaimable`.
5. Validate the amount against `MaxInt64` and the attested amount.
6. Commit.
7. Protect: rekey to a fresh secret, written ahead as a pending call.

Receive never merges.

### 6.2 Send

```ts
planSend(o: { amount?: bigint; to?: string /* default 'cash' */; holdings?: string[]; ia?: string }): Promise<SendPlan>
send(...same): Promise<SendResult>
interface SendResult {
  sent: bigint; to: TargetDisplay; targetResolved: string
  cashNote?: CashNoteString          // when to = cash: the <token>#<secret> to hand over
  handoffId?: string; remainder?: HoldingView; consolidatedFirst?: boolean
}
```

- An amount with no holdings named uses cash selection (§7.1).
- When the plan has `consolidateFirst`, the send goes through the
  auto-consolidate path: cash notes are moved to a throwaway key, merged,
  then split-sent. The result is the same as
  `transferWithAutoConsolidate` / `mergeThenSend`.
- Targets are sniffed the way cashctl sniffs them: hex, `npub1`, NIP-05,
  `nconnection1` (needs `ia`, or the result is a `usage` error naming it),
  `cash`, `pubkey:` or `connection:`.
- `connection:<platform>:<id>:<ia>` hashes the canonical id on x, discord,
  email and dns and refuses any other platform (`invalid_input`, with a
  hint to paste the account's `nconnection1`); the IA is a hex pubkey, an
  npub or a NIP-05 name. An `nconnection1` key is taken byte for byte, and
  one without a platform is refused.
- Resolved targets always appear in `targetResolved`.

### 6.3 Redeem

```ts
planRedeem(o: { amount?: bigint; holdings?: string[]; all?: boolean;
                into?: string /* connection name */; invoice?: string }): Promise<RedeemPlan>
redeem(...same): Promise<Report<RedeemOutcome>>
```

- The selection rules match cashctl's `cash redeem`:
  - Naming nothing while several holdings are held is a `usage` error.
    This is the one ambiguity that refuses, because value leaves the user's
    control.
  - `amount` means an exact single holding or an exact same-hub subset sum
    (§7.2).
  - `invoice` accepts exactly one holding. For a fixed-amount invoice,
    passing `amount` is an error; for an amount-less invoice, `amount` is
    required.
- Quotes are batched per node (`nodeKey`, the minter whose announcement
  names the inbox) with `statusMany`. Each holding gets one invoice for its
  **net** amount. Every holding on the same node goes in one `redeemMany`,
  which is one relay event.
- A holding with no recoverable minter cannot be spent, and is refused.
- Invoices made through the app's NWC wallet ask for `expiry` 3600.
  `PAYMENT_FAILED` is retried once with a fresh invoice and proof;
  `RATE_LIMITED` is a retryable `conflict` and the bill stays live.
- An unclear outcome (`INTERNAL`, an omission, a timeout) is never resent.
  One `cash_status` read of the holding's own row decides it: unclaimed ⇒
  the bill is live and nothing was paid; a tombstone ⇒ `spent`; claimed (or
  no answer) ⇒ status `redeeming` and `indeterminate` with reason
  `redeem_in_flight`. A `redeeming` holding is in no balance and no plan.
  Every `settle()` re-reads it (`report.redeems`): unclaimed ⇒ `held` again;
  a tombstone ⇒ `spent`; the NWC wallet reporting the invoice settled
  (`lookup_invoice`), or the row still claimed a day past the invoice's
  expiry ⇒ `redeemed`.

### 6.4 Consolidate, protect, status

```ts
consolidate(o?: { holdings?: string[]; to?: string }): Promise<Report<ConsolidateOutcome>>
protect(o?: { holdings?: string[] }): Promise<Report<ProtectOutcome>>
status(o?: { holdings?: string[]; scope?: 'mine' | 'all' }): Promise<Report<StatusOutcome>>
```

- **Consolidate with nothing named** auto-groups holdings by hub group
  (never by minter) and, within it, keeps ordered bills apart from the rest
  and groups by the `min_transfer_millis` last read from `cash_status`; it
  merges every group of two or more. A bill past its expiry or kept out of
  merges (`holdings.setExcludeFromMerge(id, on)`) is never auto-merged.
  Holdings alone in their group are reported in `aloneOnTheirHub`.
- **Naming** ordered and other bills together is `invalid_input` with
  reason `mixed_ordered`, before anything is written.
- **Common ownership.** Every consolidate outcome, and a send plan that
  merges first, carries `disclosesCommonOwnership: true`: the Hub learns
  that the merged bills share an owner. A send that could be covered only
  by merging a bill kept out of merges is `invalid_input` with reason
  `excluded_from_merge`.
- **Handed-out cash notes** are re-checked with `cash_status` over their
  bearer credential, the secret never sent: a claimed row, a row that moved
  to another identity, or a tombstone ⇒ `claimed`; a row past its expiry or
  `EXPIRED` ⇒ `expired`.
- **Cash notes in a consolidate** move to a throwaway key first. The merged
  result is a fresh cash note, or a pubkey holding when the target is self.
- **Protect** re-keys every `shared` holding when nothing is named.
- **Status** reports every holding. A `spent` row records a tombstone.
- **Consolidate to another identity** (`to` naming someone else) leaves a
  gift handoff and no holding row.

### 6.5 Balance

```ts
balance(o?: { refresh?: boolean }): Promise<Balance>
interface Balance {
  total: bigint                                   // wallets + unexpired held cash, as cashctl's
  stranded: bigint                                // the part of total that is a stranded wallet's cached figure
  wallets: { name: string; kind: 'nwc' | 'circle'; balance?: bigint; stranded?: boolean; unreachable?: CashkitError }[]
  holdings: { held: bigint; count: number; expired: bigint; pendingMerge: number }
  outstandingCashNotes: bigint                    // handed out, unclaimed — shown, not counted
}
```

This is `wallet_balance.go`'s logic:

- An auth-class decline that has a cached figure is shown as `stranded`. It
  still counts in `total`, as cashctl's does, and `stranded` says how much.
- Expired holdings are excluded from `total`.

### 6.6 Activity and handoffs

```ts
activity(o?: { refresh?: boolean; includeSecrets?: boolean; limit?: number; before?: number }): Promise<ActivityItem[]>
handoffs(o?: { status?: Handoff['status'][]; includeSecrets?: boolean }): Promise<HandoffView[]>
```

- `refresh` re-checks every unclaimed cash note with its hub (15 s each,
  in parallel), as `refreshHandoffs` does. The status moves to `claimed`,
  `expired` or stays `unclaimed`.
- Without `includeSecrets`, the secret of an unclaimed note is replaced and
  `secretHidden: true` is set. With it, the result is secret-bearing (§10).

### 6.7 Circles

```ts
circles.join(hub: string /* circlehub1… */, terms: { maxAmount; maxReceive; expirySeconds?; budgetRenewal? },
             o?: { name?; makeDefault?; confirmUnverified?; confirmNoRecovery? }): Promise<JoinResult>
circles.list(), circles.client(name), circles.memberRequest(name, action), circles.notify(name, n),
circles.delete(name, confirmDelete), circles.exportConnectionSecret(nameOrJoin), circles.forgetJoin(id)
```

- `hub` is a `circlehub1` string only; a `cashhub1`, `cashorder1` or a URI is
  `connection_invalid`. `connectCircle` runs first: nothing is signed or
  written before its checks pass. Terms over the Hub's reported limits are
  refused locally (`limit_exceeded`, naming the field).
- A Hub without `rotation_delay_secs` cannot move a wallet to a new key:
  `confirmNoRecovery()` must resolve true before anything is signed.
- One wallet per circle, keyed by the Hub pubkey (TLV 0).
- The connection key is generated locally; only its pubkey leaves. The join
  is written ahead as a `pendingJoins` row (its secret and the `circlehub1`
  sealed, `deadline` = proof `created_at` + 300) before it is sent.
- Every refusal but `REQUEST_REUSED` is final for that proof and drops the
  pending join; a retry signs a new proof with a new key. `REQUEST_REUSED`
  or a lost reply leaves it pending: `settle()` looks it up by connection key
  and deadline, signed by the join's key: `done` adds the wallet, `pending`
  waits, `unknown` asks the member (`needsUser: 'join_not_made'`), `expired`
  is shown and never rejoined with that key, `UNAUTHORIZED` is final for the
  lookup, and omissions past deadline + 360 s are `lookup_unanswered`.
- The wallet is stored as kind `circle_wallet`: `walletPubkey`, `relays`, the
  member's sealed `secret`, and the terms its details fixed. No URI is
  built. `lightning(name)` and redeem use it like any Lightning wallet; a
  frozen one attempts no payment.
- Member requests (`rotate`, `freeze`, `unfreeze`) are signed by the join's
  key and returned for the host to submit; a rotate stores the new key
  sealed first. A wallet whose details carry no `rotation_delay_secs` takes
  none (`rotation_not_served`).
- `circles.notify(name, n)` applies a notification: `rotation_pending`
  (`rotation_alert` event), `rotation_cancelled`, `rotation_completed`
  (switches to the stored new key), `wallet_frozen` (`frozen_alert`).
- `circles.delete` refuses above the wallet's dust threshold and asks
  `confirmDelete({ dust })` first.

### 6.7a Orders

```ts
orders.quote(cashorder1, { amountMillis, payment }): Promise<OrderQuote>
orders.place({ connection, amountMillis, payment, to?, ia?, confirmUnverified? }): Promise<OrderView>
orders.refresh(id), orders.list(), orders.get(id), orders.watch(id, { signal?, pollMs?, onUpdate? })
```

- `connectOrder` decodes and verifies the `cashorder1`, checks `get_info`'s
  `pubkey` and `chain` against TLV 4 and 6 on every terms read, asks
  `confirmUnverified` for an unverified string, refuses a connection that
  sells nothing (`not_selling`) or does not list `cash_order` privately, and
  opens the private transport from the announcement of TLV 4.
- `quote` shows the order fee, what to pay, the on-chain confirmations and
  the bill's redeem fee; nothing is written. `place` reads the terms again
  and checks the amount locally (`amount_out_of_range`).
- `to` is `cash` (default: a cash holding; the buyer key is derived from
  the secret), `self` (the wallet identity), or a send target (a gift: no
  holding is made). The request id, a fresh `notify` and the secret or a
  fresh buyer key are written ahead with the `cash_order` call.
- The reply opens the order: the call stays `open_order` and keeps the
  order as last read until it is finished (Lightning `minted` or `expired`;
  on-chain `expired` or `closed`, which may still gain bills). A reply the
  Hub committed but this wallet refuses (an invoice for another amount, an
  address of another chain or network) keeps the order open, flagged
  `invalidReply`, its invoice or address never shown.
- `refresh` reads the order with `cash_lookup` (signed by the buyer key);
  each new bill this wallet keeps becomes a holding marked ordered (once,
  by wallet pubkey), and a tombstoned one marks its holding spent. An order
  past `pay_by` that never progressed and shows no bill ended unpaid, once
  a lookup after `pay_by` was answered.
- `watch` reads the order on each order notice (kind 23189 on `notify`)
  and, for Lightning, every 5 s until `pay_by`, while the app watches.
- A lost reply is settled by lookup; an `unknown` one waits for
  `pendingCalls.confirmReplace` (a new order asks for a new payment).
- Views never carry the buyer key, a secret, `notify` or the request id,
  and carry the warnings `pay_before`, `amount_mints_bill` and, on-chain,
  `late_payment_kept`, `per_output_fee` and `fee_floor`.

### 6.7b On-chain withdrawals

```ts
withdraw.terms(holdingId), withdraw.quote(holdingId, address, { sendBefore? }),
withdraw.send(quoteView, { confirm }), withdraw.refresh(id), withdraw.cancel(id),
withdraw.list(), withdraw.get(id), withdraw.receipt(id), withdraw.signedTx(id), withdraw.watch(id, o)
```

- `terms` reads the Hub's `withdraw` terms and the bill's row in one
  `cash_status`; nothing is written.
- `quote` refuses locally before asking: a malformed, mixed-case or legacy
  address (`address_invalid`, with `malformed`, `mixed_case`,
  `no_witness`, `network` or `script_type_not_paid`), one of this wallet's
  own order addresses (`own_order_address`), a bill an open call holds, a
  cash note still shared (`protect_first`). The answer is checked against
  what was asked (signed by the Hub identity, its tags equal to its fields,
  the bill, slice and address asked about, `sent_by` within `send_before`,
  fee = amount − payout, whole base units, the committed amount, at least
  the redeem fee: `quote_mismatch` otherwise). The view is held in memory
  only: exact payout, fee split, `sentBy`, `holdsUntil`, the Lightning net
  for comparison, `highFee`, `expiringSoon`, privacy warnings
  (`known_amount` with `splitFirst`, `address_reuse`, `near_match`) and
  `unrecoverable` for a cash note.
- `send` needs `confirm(view)` to resolve true, refuses a bill expiring
  within 120 s, and runs `cash_withdraw` as a pending call written ahead
  with the quote, request id, `notify` and, for a cash note, a fresh remint
  secret. A receipt that checks out against the written-ahead call ends the
  bill and keeps the call `open_withdraw`.
- `refresh` reads the payout (its receipt re-checked on every `done`); a
  `tx` is checked against the address and payout (`txCheck`; a mismatch is
  a warning, never a payout failure); `final` closes the call and drops the
  address, receipt and transaction; `cancelled` imports the re-minted bill
  (the whole amount, `origin: 'reminted'`, under the remint secret for a
  cash note) and closes it.
- `cancel` is offered only for a payout still `broadcast` 7 days after
  `sent_by` (`cancel_not_due` before, nothing sent). `signedTx` is offered
  only when the payout is late, signed and its transaction checked; the SDK
  never broadcasts.
- A refusal's `detail` becomes the error's `reason`, with fixed public
  wording; payout states are results, never errors. Views never carry the
  request id, `notify`, the quote, the receipt or secrets.

### 6.7c Cash Zaps

```ts
zaps.send({ to, amountMillis, target?: { e?, a?, k? }, content?, relays }): Promise<ZapSent>
zaps.list({ relays, connectionKeys? }): Promise<ZapView[]>
zaps.claim(event): Promise<HoldingView>
zaps.approveMinter(minter, chain)
```

- `send` reads the recipient's 10522 (a pubkey `p`) and picks a pubkey bill
  on an accepted chain covering the amount, a listed minter first, then the
  longest life. It runs a zap transfer: `zap_target` is the `a` coordinate,
  else the `e` id, and only for a pubkey `p` on an event. Once the bill
  exists (from the reply, or from a lookup after a lost reply) its 9522 is
  built from the bill's signed `issued_at`/`expires_at`, stored with the
  call and published once, to the recipient's 10522 relays and the given
  ones. A Hub that ignored `zap_target`, or a zap on no event, is valid and
  never counted (`countable: false`).
- `verifyCashZap` runs rules 1–8 in order and reports each; `countCashZaps`
  totals only countable zaps (zap-signed, trusted minter, life at least
  `settings.zapMinLifeSeconds` or never ending), once per token `w`, without
  deleted ones.
- `list` shows incoming zaps as `issued`, never received. `claim` needs
  rules 1–6 and 8 (an unlisted minter only once approved), then rule 9: the
  bill's own `cash_status` shows this wallet's slice unclaimed at the zap's
  amount. The bill is kept with its zap fields (its provenance needs them:
  every client for a holding is built with them) and the expiry its status
  reports.
- `approveMinter` trusts a minter for one chain; its network cannot be
  verified from the token.

### 6.7d Cash Pocket

With `WalletDeps.pocket` (`adapters/sync-pocket` over the user's inbox
relays) the wallet keeps a NIP-CP Cash Pocket: kind-9525 entries sealed and
gift-wrapped to the user, each with a fresh wrap key it records.

- **Write ahead.** Before any bill-creating call or withdrawal goes out, its
  `pending` entry (request id, deadline, target, device, amount, every
  secret it generated by role, an order's key or `notify`, a withdrawal's
  address and quote) is stored on enough relays (default 2) and read back;
  failing that, the call is not sent.
- **After the outcome.** An entry for each bill the wallet keeps (a bill
  moved in place rewritten at its next `rev`), then the pending entry
  `done` and its sources `spent`. An order or a withdrawal stays pending
  until it is finished; a withdrawal's entry gains its receipt, and its
  address, quote and receipt are dropped when it closes.
- Every change is a new wrap at the next `rev`; the previous wrap is
  deleted with a kind 5 signed by its own wrap key. The wraps' local
  record (`pocket`) is never exported.
- `pocket.sync()` imports live entries this device does not hold (with
  their secret), writes entries for held bills the pocket lacks, and marks
  bills no longer held `spent`; `pocket.balance()` sums live entries per
  chain; `pocket.entries()` lists resolved entries without secrets.

### 6.7e Discover

```ts
discover.refresh({ relays, follows?, curators?, includeUnreviewed?, chains?, testNetworks? })
discover.list(): DiscoverView
discover.tap(address): Promise<TapView>
discover.order(address, input), discover.join(address, terms, options), discover.recommendPreview(address)
discover.recommend(address, { content, confirm? }), discover.report(nodeOrAddress, { reason, content, confirm? })
discover.withdrawRecommendation(node, { relays?, confirm? })
discover.outbox.list() / cancel(id) / publishDue()
discover.curators.list() / add(pubkey) / remove(pubkey) / setDefaults({ pubkeys, sourceName? }) / publish({ relays? }) / sync({ relays? })
```

- **Fetching** contacts no Hub: first the recommendations and reports of
  the user's follows and curators and the listings and deletions of the
  nodes they name (so a flood cannot push signalled offers out), then
  operators' 11191 and who among the follows follows them, then, only if
  asked, the global request, shown apart as unreviewed.
- **Before showing**, `parseListing` runs steps 1–4 (signature and counts;
  the type and the connection's HRP, no other string decoded; the string
  signed by TLV 4 = `pubkey`, TLV 0 = `d`, TLV 6 = `n`; a held chain on
  mainnet unless test networks are on). A failure is a diagnostic with its
  step, never an offer. `VersionBook` keeps the newest version per address
  (never undercut, 15 minutes of skew, deletions by the node identity, the
  30-day expiry cap).
- **Signals** come only from follows and curators; an operator is shown
  only when verified (the listing's `p` and the operator's newest 11191
  naming the listing). Cards carry sanitized text (look-alike marks,
  bidirectional and zero-width characters stripped, capped by grapheme
  clusters), an identicon until the user taps, and never the connection
  string. Listings of different pubkeys sharing a `d` are never merged.
- **At tap** `get_info` is read over the listed connection's public secret
  and checked: another identity or network hides that version for good,
  the Hub's closed signal hides it until a newer one, anything else keeps
  it as unavailable for now. The terms always come from `get_info`, with a
  banner when a hint differs. `order` and `join` then hand the listed
  string to `orders.place` and `circles.join`.
- **Kept across restarts** (local, never exported): the version book's
  floors (the newest version seen and each deletion), the tap outcomes
  other than "unavailable for now" (tried again), and the events of the
  last refresh (current listings, recommendations, reports, operators'
  offers). `list` shows them as soon as the wallet opens; a new or restored
  device starts empty.
- **Recommending and reporting** are public and signed by the user's
  identity; without one they are refused (`identity_required`), and cashkit
  never makes a key for them. A recommendation is allowed only for an offer
  the user has used, outside the session of the order or join there and a
  day after it (`recommend_not_allowed` otherwise); a report has no such
  rule. `confirm` receives what will be public and may decline. Both are
  queued with a delay drawn from [1 h, 6 h) and signed only when published,
  to the user's write relays (their kind 10002) and the relays of the last
  refresh; `publishDue` runs at open and from `autoSettle`, never early.
  One recommendation per node: a second replaces the first.
  `withdrawRecommendation` publishes the NIP-09 deletion at once and
  cancels a queued one. The outbox lists items without their text.
- **Curators** live in `settings.discover` (backed up). An app may set
  defaults, shown as curated by its name; any edit by the user makes the
  list the user's, and the app's defaults no longer apply. `publish` writes
  the list as the user's NIP-51 set (kind 30000, `d` `cash-discover`, no
  title), its items private (NIP-44 to self) unless `curatorsPrivate` is
  false; `sync` reads the newest copy back. `refresh` ranks by the stored
  curators unless others are passed.

### 6.8 Lightning, connections, identity

- `wallet.lightning(name?)` returns the NIP-47 calls against a registered
  connection: `getInfo`, `getBalance`, `makeInvoice`, `payInvoice`,
  `listTransactions`, `signMessage`.
- `wallet.connections`: `add`, `list`, `remove`, `setDefault`. `add` takes
  a NIP-47 pairing URI (a Lightning wallet) or a Cash Hub's signed
  `cashhub1` string. The string is decoded, verified and checked online
  (`get_info` must name its node and chain) before it is stored, as given
  and sealed; an unverified one only after `confirmUnverified(view)`
  resolved true. A URI given as a Cash Hub is `connection_invalid`. A Cash
  Hub connection is never the default Lightning wallet: `lightning(name)`,
  `setDefault` and redeem refuse it (`usage`).
- `wallet.mint({ hub, amount, to? | recipients, expirySeconds? })` mints over
  a stored Cash Hub connection as one `mint` pending call: `to` is `cash`
  (default; the note comes back as `cashNote`, its secret written ahead),
  `self` (a held bill, `origin: 'minted'`, verified when its minter is the
  connection's node), or any send target (the token comes back as
  `recipientToken`). A lost reply is settled by lookup; an `unknown` lookup
  waits for `pendingCalls.confirmReplace`.
- `wallet.identity`:
  - `get`
  - `generate`
  - `useSigner(signer)`
  - `export()`, which returns an encrypted ncryptsec (NIP-49) of a local
    key.

### 6.9 Settings

| Setting | Default | Meaning |
|---|---|---|
| `defaultConnection` | first added | where `redeem` lands when `into` is omitted |
| `autoProtect` | `true` | rekey cash-mode receipts |
| `allowAutoConsolidate` | `true` | let `send` merge a same-hub subset; the plan still discloses it |

### 6.10 Offline helpers

`decode(input)` and `inspect(input)` live in `@ohstr/cashkit/core`. They
cover tokens, `cashhub1`, `circlehub1`, NWC URIs and npub, return a typed
report, and make no network call. They match cashctl `decode` without
`--check`.

### 6.11 State and events

```ts
wallet.state: WalletState    // snapshot: balance summary, holdings, pendingJoins, pendingCalls,
                             // pendingMerge, storagePersisted, locked
wallet.subscribe(fn: (s: WalletState) => void): () => void
wallet.on('operation', (e: { op: string; phase: 'planned' | 'sent' | 'committed' | 'failed'; id: string }) => void)
```

The events don't depend on any framework. React, Svelte and zustand
bindings wrap `subscribe`. `@ohstr/cashkit/react` is the React one:
`WalletProvider`, `useWalletState(select?)` on `useSyncExternalStore`,
action hooks that track one call's pending/result/error, and query hooks
that re-run on every commit. It sits above `wallet` and never imports an
adapter (lint-enforced), and React is an optional peer.

## 7. Algorithms

### 7.1 Cash selection

Port `internal/ledger/cashselect.go` `SelectForAmount` exactly. Port the
code, not its stale comments.

1. Any held holding of exactly the target amount → full send.
2. Otherwise, the smallest holding larger than the target → split.
3. Otherwise, go through hub groups in sorted key order. In each group, sort
   by amount descending and add greedily until the sum reaches the target.
   The first group that reaches it gives `consolidateFirst`, with
   `split = sum > target`.
4. Otherwise `InsufficientFunds` (`invalid_input`) or `FundsFragmented`
   (`usage`).

Steps 1–2 consider every held holding with a known amount. Step 3 considers
only *groupable* holdings (`GroupableForConsolidation`):

- the amount is known
- the hub group key is non-empty
- the holding is not bound to a connection key
- it is in pubkey mode, or it is a cash note whose secret is known

### 7.2 Exact redeem by amount

1. A live quote per holding; the first exact match on net amount wins.
2. Otherwise, an exact subset-sum on net amount within each hub group, by
   brute force over at most 20 items.
3. Otherwise `invalid_input` or `usage` (fragmented).

### 7.3 Consolidation rounds

The source count per round is `min(announced max_consolidate_sources, what
fits in an envelope)` (`MaxSourcesForEnvelope`). A round the client refuses
before sending as too large (`item_too_large`) is halved, keeping what has
already merged. Each interim result gets the throwaway key and is committed
before the next round.

## 8. Errors and results

```ts
class CashkitError extends Error {
  code: 'usage' | 'invalid_input' | 'not_found' | 'conflict' | 'network'
      | 'auth' | 'indeterminate' | 'exists' | 'spent' | 'internal'
  retryable: boolean        // true only for conflict, network
  input?: string            // redacted (§10)
  nwcCode?: string          // raw NIP-47 code when a wallet returned one
  recovery?: string         // verbatim handoffs; never redacted or truncated
  recoveryHandoffs?: string[]  // the same handoffs, structured
  hint?: string
}
```

- The codes are exactly cashctl's table, so an app and an agent driving
  cashctl branch the same way.
- `exitCode(code)` is exported for CLI-shaped consumers.
- The NWC mapping follows `internal/output/nwc_errors.go`:

  | NWC code | cashkit code |
  |---|---|
  | `BAD_REQUEST` | `invalid_input` |
  | `NOT_FOUND` | `not_found` |
  | `RESTRICTED`, `UNAUTHORIZED`, `EXPIRED` | `auth` |
  | `RATE_LIMITED` | `conflict` |
  | NOT_READY | `network` |
  | WALLET_EXISTS | `exists` |
  | anything else | `internal` |

**Partial success.** An operation over several independent commits
(`redeem`, `consolidate`, `protect`, `status` over several holdings)
returns, and does not throw:

```ts
interface Report<O> { outcomes: (O & { ok: true } | { ok: false; error: CashkitError; holdingIds: string[] })[]; firstError?: CashkitError }
```

The engine never throws after any commit has happened. It throws only for
failures before the first wire call.

**JSON.** `toJSON(result)` produces the shape cashctl prints under `--json`:

- snake_case keys
- bigint amounts written as exact JSON integers
- secrets omitted unless they were requested

This lets cashkit and cashctl share fixtures.

## 9. Observability

- The `logger` port only ever receives records that already went through
  `redact()`.
- There are no `console.*` calls in `core`, `transport`, `client` or
  `wallet`. Lint enforces this, as cashctl's `auditD_cli_output_boundary`
  test does.
- Operation events (§6.11) carry IDs and phases, never secrets.

## 10. Security

- **Secret inventory:**
  - cash secrets
  - pending and destination secrets
  - throwaway keys
  - the local identity key
  - NWC and circle connection URIs
  - pending-join secrets
  - unclaimed cash-note handoffs
  - `recovery` text

  Every item MUST be sealed by the `SecretVault` at rest. They MUST NOT
  appear in `activity`, logs, events, error `input` or `toJSON` unless it
  was explicitly requested.
- **Redaction.** `redact()` is a port of `RedactSecretInput`:
  - A whole value that is `nsec1…` or 64-hex becomes `""`.
  - `cash:`, `pubkey:` and `connection-key:` credentials have their secret
    part blanked.
  - `secret=` in a URI is blanked.
  - `#<64hex>` becomes `#<redacted>`.
  - `cashhub1`, `circlehub1` and `nconnection1` strings become
    `hrp1<redacted>`.
  - The output is sanitised of C0, C1, DEL, U+2028/9 and bidi controls.
- **Recovery.** `recovery` is the one deliberate exception to redaction. It
  appears only when a Hub-side mutation is confirmed and the local commit
  failed. A UI MUST show it in a way that can be copied verbatim.
- **Browser storage eviction.** IndexedDB can be cleared by the user or the
  browser, and an unclaimed cash note or holding secret may exist nowhere
  else. cashkit provides:
  - `navigator.storage.persist()` on open
  - `exportBackup(passphrase)` / `importBackup`, a versioned JSON of every
    collection with secrets sealed under the passphrase
  - `state.backupStale` once value-bearing changes have happened since the
    last export (a fingerprint of the value-bearing rows' ids and versions,
    kept in `meta` at export, so no ordinary commit writes a shared row)

  **Backup format, version 2.** One JSON document, written with the
  row codec (a bigint is `{"$bigint":"<decimal>"}`), so another tool can
  import it:

  ```jsonc
  {
    "format": "cashkit-backup", "version": 2,
    "walletId": "…", "createdAt": 1760870000,          // Unix seconds
    "kdf": { "name": "scrypt", "logN": 16, "r": 8, "p": 1, "salt": "<base64, 16 bytes>" },
    "check": "<sealed 'cashkit backup key check'>",     // tells a wrong passphrase from damage
    "collections": {                                     // every collection of §4, rows as stored
      "holdings": [ { "id": "h-…", "token": "lokicash1…", "amount": {"$bigint":"5000"},
                      "cashSecret": { "sealed": "<base64 nonce‖ciphertext>" }, … } ],
      "handoffs": […], "connections": […], "identity": […], "pendingJoins": […],
      "activity": […], "settings": […], "meta": […], "pendingCalls": […]
    }                                                    // never device, derivedIds or hubs
  }
  ```

  - The key is scrypt over the NFKC passphrase (NIP-49's parameters); each
    secret is XChaCha20-Poly1305 under a fresh 24-byte nonce, with associated
    data `cashkit/backup/v1`.
  - The secret-bearing fields are exactly: holdings `cashSecret` and
    `throwawayKey`; handoffs `handoff`; connections `uri`; identity `priv`;
    pendingJoins `connectionSecret`; pendingCalls `authorizer.authorizerKey`,
    `authorizer.buyerKey`, `outputs[].destination.secret` and
    `outputs[].destination.key`. Each is `{ "sealed": … }` in the file and
    nothing else is secret. A version-1 backup is refused.
  - `importBackup` restores into an empty wallet only (merging two ledgers is
    not a restore), re-seals every secret under the new wallet's vault,
    adopts the backup's `walletId`, then runs `settle()`.
- **XSS.** A device vault protects data at rest and in exports, not against
  script running in the page. Apps MUST ship a strict CSP. The doc for
  `vault-device` says this plainly.
- **NIP-05.** HTTPS only, no redirects, a 256 KiB body cap, a 15 s timeout,
  and the name must map to 64-hex. These are cashctl `credential/nip05.go`'s
  rules. A browser `fetch` cannot refuse redirects for a cross-origin GET in
  every environment, so the adapter uses `redirect: 'error'` and checks the
  final URL.
- **Randomness.** All keys, secrets, nonces and padding decisions come from
  the `Random` port, which defaults to `crypto.getRandomValues`.

## 11. Conformance

### 11.1 Vectors

`tools/export-vectors` is a small Go module that imports nmilat and writes
`vectors/*.json`. `just vectors` regenerates them, and CI fails if they
drift. Coverage:

| File | Source in nmilat |
|---|---|
| `provenance.json` | `nipcash/kat_test.go`, `provenance_test.go` (lokicash/satscash, forgery table) |
| `connection-key.json` | `nipcash/kat_test.go`, `nipcw/connection_key_kat_test.go` |
| `reply-key.json` | `nipcash/transport/auditC_reply_key_kat_test.go` (also NIP-CASH.md §reply key) |
| `canonical-params.json` | `nipcash/transport/canonical_jcs_test.go` (full form, hash, 11 escapes) |
| `tlv.json` | `nipcash/decode_tlv_rules_test.go`, `token_test.go`, `encode_relay_test.go`, `nipcw/circlehub_tlv_rules_test.go` |
| `hub-group.json` | `nipcash/hub_group_test.go` |
| `cash-string.json` | `nipcash/cash_string_test.go` |
| `proof.json` | `nipcash/proof_binding_test.go`, `transport/proof_window_test.go` |
| `padding.json` | `transport/auditB_priv_padding_test.go`, `auditD_privacy_padding_test.go`, `limits_test.go` |
| `envelope.json` | `transport/envelope_test.go`, `response_test.go`, `auditB_duplicate_item_test.go` |
| `nip44.json` | `nip44/auditC_qa_kat_test.go` plus the upstream NIP-44 vectors |
| `private-join.json` | `nipcw/private_join_test.go`, `nipcash/client/batch_circle_join_test.go` |

Vectors with fixed randomness produce byte-identical envelopes, which is
why the Go-compatible escaping in §2.2 is a SHOULD.

Where cashkit is stricter than nmilat, the vectors record the difference:

- **Secret range.** A secp256k1 secret that is zero or ≥ n is refused
  rather than reduced mod n (`connection-key.json` leaves them out).
- **NWC replies.** Only a reply authored and signed by the wallet is
  accepted (§2.3).

Event ids are hashed exactly as nmilat serializes them, including its
escaping of control characters, because the Hub recomputes ids with nmilat
(`nip01.json`). Tags and content are escaped alike.

### 11.2 Engine scenarios

A `FakeHub` test harness implements the private transport in memory. It can
inject failures: drop, delay, omit an item, return an undecodable result,
answer spent, refuse, and crash the engine between steps. The scenarios
port cashctl's audit tests:

- **kill window**: every step boundary of every operation, followed by
  `settle()` (`auditD_cli_killwindow`)
- **write-ahead ordering**: every created secret is in a pending call
  before the wire call; a call that can't be written ahead is not placed; a
  lost reply or a failed result commit leaves the call open, its sources
  locked, until `settle()` applies it (`auditD_cli_writeahead`)
- **recovery text**: intact and paired, never truncated
  (`auditD_cli_recovery_handoff`)
- **no secrets in activity** (`auditD_cli_history_secrets`)
- **OCC**: two writers on the same row conflict, different rows both
  succeed (`auditD_cli_occ_crossprocess`)
- **amount bounds**: `auditC_ledger_amount_invariant`,
  `auditC_sdk_quote_unvalidated`

### 11.3 End-to-end

The same flows run against the isolated Hub stack that cashctl's
`integration/` uses (dev flnd). `test/e2e/wallet.test.ts` creates a
throwaway, self-funded cash_hub through the admin API, as cashctl's
`setUpCashHub` does. It mints a cash bill, and two wallets take it through
receive, status, send-as-cash, receive and redeem-all over the Hub's real
relays. Then it deletes every child wallet and the hub. `test/e2e/hub.test.ts`
is a read-only `cash_status` on a bill you supply. The isolated Hub is not
reachable from GitHub's runners, so these tests run by hand (`just e2e`) rather than in
GitHub CI.

## 12. Tooling

- pnpm, TypeScript `strict` with `exactOptionalPropertyTypes`, target
  ES2022, ESM only.
- `tsup` builds one entry per subpath export, with `sideEffects: false`.
- vitest runs in Node, and in a browser through `@vitest/browser` for the
  IndexedDB, Web Locks and WebSocket adapters.
- oxlint plus dependency-cruiser for the layer rules (§2).
- `just`: `check`, `test`, `vectors`, `e2e`, `build`.
- Runtime dependencies: `@noble/curves`, `@noble/hashes`, `@noble/ciphers`,
  `@scure/base`. NIP-44 is implemented on noble and checked against the
  vectors, so there is no nostr-tools runtime dependency.
- Optional peer dependencies: `nostr-tools`, `@nostr-dev-kit/ndk`,
  `better-sqlite3`.
- Node ≥ 22, for the global `WebSocket` and `node:sqlite`.
- CI and release workflows follow cashctl's (`ci.yml`, `release.yml`, docs
  via docs-kit `pages.yml`). Releases publish to npm with provenance.
- Licence: Unlicense.

## References

- Protocol specs: `ohstr/nips` `NIP-CASH.md`, `NIP-CW.md`
- nmilat:
  - `nipcash/{token,identity,proof,provenance,cash_string,claim}.go`
  - `nipcash/transport/*`
  - `nipcash/client/{batch_session,batch_pack,batch_send,batch_outcome,bill_state,transfer_from_sources,rekey_cash_slice}.go`
  - `nipcw/*`, `nip44`, `nip47`
- cashctl:
  - `cmd/{cash_receive,receive_secure,cash_redeem,redeem_private,cash_transfer,cash_merge,cash_consolidate,cash_writeahead,pending_secret_fallback,save_recovery,spent,handoffs,wallet_balance,wallet_protect,cash_inspect,circle,nwc_errors}.go`
  - `internal/{ledger,store,credential,output,dial}`
