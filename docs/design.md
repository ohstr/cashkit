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
               billState, cashClient, transferFromSources, rekeyCashSlice,
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
  - Decoding MUST apply no length limit and MUST accept a bech32 or a
    bech32m checksum, matching go-flokicoin's `bech32.DecodeNoLimit`.
    Encoding always writes bech32. `@scure/base`'s `bech32.decode` refuses
    bech32m, so `core/bech32.ts` implements the framing itself. An
    all-uppercase string decodes as its lowercase form; a mixed-case one is
    refused (`CoreError` `mixed_case`).
  - Unknown TLV types (4 included) are ignored; entries decode in any order.
  - A duplicate or wrong-length pubkey, secret or identity_required is
    fatal, and so is a token with no usable relay hint.
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
  - Builders: `pubkey`, `connectionKey`, `anyone`, `newCashTarget`, and
    credentials `bySecret`, `bySigning`, `bySigningConnectionKey`.
  - On the wire, a cash target is `hex(sha256(secret))`, hashing the 32
    raw secret bytes (not their hex text).
- **Claim proof.**
  - Kind 23198 with tags `d`, `bolt11_hash`, `new_identity_hash`,
    `amount_millis`, plus `connection_key`/`e` and an embedded NIP-IC
    35522 attestation for connection keys.
  - `new_identity_hash = sha256(type ":" value ":" ia)`.
  - Tokens delivered to the claimant are NIP-44 decrypted with
    ECDH(own priv, new wallet pubkey).
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
- **NIP-44 plaintext length.** 1 to 2^32−1 bytes, with the extended length
  prefix from 65536, as current NIP-44 and nmilat; an empty plaintext is
  refused (`nip44.json`).
- **Units.** Amounts are `bigint` millis everywhere, never `number`. The
  display unit comes from the token's HRP (`lokicash` → loki, `satscash` →
  sat, with 1 unit = 1000 millis).

### 2.2 transport

A port of `nmilat/nipcash/transport`, which carries every bill method
(`cash_status`, `cash_redeem`, `cash_transfer`, `cash_consolidate`).
`mint_cash` and `create_circle_wallet` stay on plain NIP-47, as nmilat's
circle client sends them.

- **Envelope** `{v:1, not_after, nonce, reply_to, items, pad}`. Each item is
  `{id, target, method, params, proof, bill_proof}`. Kinds:
  - 23190 request, 23191 response
  - 23192 item proof, 23193 bill proof
  - 11190 Hub announcement
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
  - The plaintext is padded to a multiple of `pad_bucket_bytes`, measured on
    cashkit's own serialized bytes.
  - cashkit SHOULD escape `<`, `>` and `&` the way Go's `json.Marshal`
    does, so envelopes are byte-identical to nmilat's and vectors can
    compare them directly.
- **Limits.**
  - Defaults: 56 KiB / 32 items / 8 KiB bucket / verify budget 200 / 48
    consolidate sources.
  - An announced bucket is at least 2 KiB, and NIP-44 plaintext is at most
    65535 bytes.
- **Request wrap.**
  - A fresh ephemeral key signs the event: kind 23190, `["p", inbox]`, and a
    randomized `created_at` up to 2 days in the past.
  - The content is NIP-44 v2 under ECDH(ephemeral, inbox). It is not a gift
    wrap.
- **Reply key.**
  - HKDF-Expand only (SHA-256): PRK = the conversation key, info =
    `"nipcash-reply-v1" || reply_to hex`, L = 32.
  - The response (kind 23191, p-tagged `reply_to`) is NIP-44 v2 encrypted
    with that key used directly as the conversation key.
- **Proof freshness** is 5 min in the past and 1 min in the future on
  `created_at`. `not_after` is at most 120 s ahead.
- **Announcement.**
  - Fetch the newest `{kinds:[11190], authors:[hub]}`.
  - Verify the author and the BIP-340 signature.
  - The inbox MUST NOT be the node key.
  - Announced limits are validated.

### 2.3 client

A port of `nmilat/nipcash/client`, `nipcw/client` and the NWC client:

- **`BatchSession(hub, relays)`.**
  - Fetches and refreshes the announcement, keeping the newest by
    `created_at` (rollback guard).
  - Adopts the relays the announcement lists.
  - Packs items greedily into envelopes with a fresh nonce and `reply_to`
    per envelope and `not_after = now + 60s`.
- **Send.**
  - Per relay: subscribe to `{kinds:[23191], #p:[reply_to]}`, wait up to 2 s
    for EOSE, then publish.
  - The first relay to accept wins.
  - Collect replies until `not_after`. Merge chunks by `seq`/`total`; a
    conflicting chunk makes the reply malformed.
- **Per-item `ItemOutcome`.**
  - `state` is `not_served` (the zero value: **unknown**, possibly applied),
    `result` or `error`.
  - `safeToResend()` is true only for a decodable error.
- **`BillState`** is `indeterminate` (the zero value), `available` or
  `spent`. Only an explicit `"spent"` answer produces `spent`; a timeout
  never does.
- **Composite flows.**
  - `transferFromSources`: consolidate into an interim identity, reconnect,
    then split-transfer.
  - `rekeyCashSlice`.
  - Both surface `PartialProgressError { transferred?, consolidated?, cause }`.
- **`NwcClient`**: `getInfo`, `getBalance`, `makeInvoice`, `payInvoice`,
  `listTransactions`, `signMessage`. The scheme comes from the wallet's
  kind 13194 info event: `nip44_v2` when listed, `nip04` when the wallet
  lists only that or nothing. Only a reply authored and signed by
  the wallet is accepted.
- **`CircleClient.createCircleWallet`**: generates the connection key
  locally and sends only `connection_pubkey`.
- **`CircleClient.join(params, { requirePrivate })`**: `chooseTransport`
  then `createCircleWallet` over it (NIP-CW §Private Join, §6.7).
  `openBatchSession(identity, relays)` opens a session from `get_info`'s
  identity instead of a bill, and `createCircleWalletMany` sends joins over
  it. `NwcClient.getInfo` types the `circle_wallet` block, with
  `circle_policy` `'allowlist' | 'follow_set'`.

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
  fallbackRelays?: string[]   // announcement discovery
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
| `meta` | `schemaVersion`, `walletId` | — |

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
  // write-ahead slots (§5)
  pendingCashSecret?: Sealed<CashSecret>
  pendingDestinationCashSecret?: Sealed<CashSecret>
  pendingThrowawayKey?: Sealed<PrivKey>
  throwawayKey?: Sealed<PrivKey>
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

### 5.1 Write-ahead slots

| Slot | Written before | Cleared on definite refusal | Kept on ambiguous result | Promoted on success | cashctl source |
|---|---|---|---|---|---|
| `pendingCashSecret` | rekey of the same bill (protect, back-to-cash) | yes | yes, then reported `unresolved` | becomes `cashSecret`, `protection = protected` | `receive_secure.go` `protectRekeyOnly`, `cash_merge.go` `toCashNotes` |
| `pendingDestinationCashSecret` | any spend whose target is a new cash note | yes (`forgetIfNothingCreated`) | yes, surfaced as an unfinished cash send | written into the handoff / new holding | `cash_writeahead.go` `parkDestinationCashSecret` |
| `pendingThrowawayKey` | moving a cash note onto a merge key | yes, and earlier moves are undone | yes | becomes `throwawayKey`; the holding switches to signing | `cash_merge.go` `moveCashNotesToKey` |
| `pendingJoin` row | `create_circle_wallet` | deleted | kept (`pendingJoins` in state) | deleted in the same tx that adds the connection | `circle.go`, `config/pending_join.go` |

Redeem has no slot because it creates no locally generated secret. It
commits once, after the result arrives.

### 5.2 State machine

Each money-moving call follows the same machine:

```
prepare ─► parked ─► sent ─┬─► applied ──► committed
   │          │            ├─► refused ──► cleared              (definite: decodable error / not sent)
   │          │            └─► unknown ──► indeterminate        (timeout, not_served, incomplete, undecodable)
   │          └─ park commit failed ─► aborted (nothing sent)
   └─ validation failed ─► aborted
committed but final commit failed ─► RecoveryError (recovery text carries the handoffs)
```

How Hub answers are classified (cashctl `classifyCashSpendErr`):

- **Definite**: a decodable item error, a "not sent" or no-announcement
  failure, or a pre-send validation sentinel.
- **Indeterminate**: everything else. The error code is `indeterminate`,
  and the caller is told to check `status` before retrying.

### 5.3 Settling

`wallet.settle()` reconciles leftover slots. The engine MUST run it on
`open`, before every spend, and on demand:

- **`pendingThrowawayKey`.** Probe `checkClaim(bySigning(key))`. On a match,
  promote. Otherwise probe `bySecret(cashSecret)`; on a match, clear. Then
  return any leftover throwaway-key holdings to cash notes (`toCashNotes`).
- **`pendingCashSecret`.** Probe `bySecret(pending)`; on a match, promote it
  (`protection = protected`). Otherwise probe the current secret; on a
  match, clear. Separately, a spend that comes back `NOT_FOUND` is retried
  once with the pending secret, as `pending_secret_fallback.go` and
  `redeem_private.go` `retryWithPendingSecrets` do.
- **`pendingDestinationCashSecret`.** Cleared when the source is still held
  and its Hub still answers for it at the recorded amount; otherwise shown
  in `state.unfinishedCashSends`.

A probe that errors is inconclusive and leaves its slot alone.

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
4. `checkClaim`:
   - spent → `spent`
   - no match → `invalid_input`
5. Validate the amount against `MaxInt64` and the attested amount.
6. Commit.
7. Protect: rekey through `pendingCashSecret`.

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

### 6.4 Consolidate, protect, status

```ts
consolidate(o?: { holdings?: string[]; to?: string }): Promise<Report<ConsolidateOutcome>>
protect(o?: { holdings?: string[] }): Promise<Report<ProtectOutcome>>
status(o?: { holdings?: string[]; scope?: 'mine' | 'all' }): Promise<Report<StatusOutcome>>
```

- **Consolidate with nothing named** auto-groups holdings by hub group and
  merges every group of two or more. Holdings alone on their hub are
  reported in `aloneOnTheirHub`.
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
joinCircle(o: { hub: string /* circlehub1… or NWC URI */; maxAmount: bigint; name?: string; makeDefault?: boolean; requirePrivate?: boolean }): Promise<JoinResult>
```

- `maxAmount` MUST be greater than 0.
- The connection key is generated locally and `pendingJoin` is committed
  before the request goes out.
- The transport is chosen first, as NIP-CW §Finding the Private Transport
  says, and kept for the retry below:
  - `get_info`'s `circle_wallet.identity` is the only source of the node
    identity. When it is present, the Hub's kind-11190 announcement is
    fetched and verified against it (§2.2, §2.3: newest wins,
    never backwards) and the join goes over the private transport without
    asking.
  - The item targets the Hub connection pubkey. Its kind-23192 proof is
    signed by the joining key, with `d` = Hub pubkey and `h` = identity; its
    kind-23193 bill proof is signed with the Hub connection secret. The
    params are the standard request, kind-23199 proof included.
  - `encrypted_details` is decrypted from the Hub connection pubkey on both
    transports, never from the inbox or node key.
  - No identity means the standard transport and no `fallbackReason`. A
    `get_info` that fails, refused or unanswered, fails the join before
    anything is parked or sent.
  - An announcement that can't be found or verified, or a private item that
    fails before it is sent, falls back to the standard transport and sets
    `fallbackReason`. With `requirePrivate` it is a `not_found` error
    instead, and nothing is sent.
  - A private join that was sent never falls back: a missing reply may mean
    it ran.
  - A standard join that fails after a fallback keeps its code, and the
    `CashkitError` carries `fallbackReason` (`fallbackReasonOf(err)` in the
    client), so the member still learns the join was not private.
- A replay-guard error is retried once after 1.1 s.
- An answer of "already exists" is an `exists` error.
- On success the connection is added and the pending join deleted in one
  transaction.
- The result carries `walletPubkey`, `relays`, `connectionPubkey`,
  `expiresAt`, `maxAmount` (granted), `feesPpm`, `budgetRenewal`, `private`
  and, after a fallback, `fallbackReason`. It never carries the connection
  string.

### 6.8 Lightning, connections, identity

- `wallet.lightning(name?)` returns the NIP-47 calls against a registered
  connection: `getInfo`, `getBalance`, `makeInvoice`, `payInvoice`,
  `listTransactions`, `signMessage`.
- `wallet.connections`: `add`, `list`, `remove`, `setDefault`.
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
| `fallbackRelays` | `[]` | extra relays for finding Hub announcements |
| `timeouts` | per op: status 15 s, redeem 30 s/bill (cap 5 min) | cashctl's values |
| `displayUnit` | from HRP | `loki` / `sat` / `millis`, for formatting helpers only |

### 6.10 Offline helpers

`decode(input)` and `inspect(input)` live in `@ohstr/cashkit/core`. They
cover tokens, `cashhub1`, `circlehub1`, NWC URIs and npub, return a typed
report, and make no network call. They match cashctl `decode` without
`--check`.

### 6.11 State and events

```ts
wallet.state: WalletState    // snapshot: balance summary, holdings, pendingJoins, unfinishedCashSends,
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

  **Backup format, version 1.** One JSON document, written with the
  row codec (a bigint is `{"$bigint":"<decimal>"}`), so another tool can
  import it:

  ```jsonc
  {
    "format": "cashkit-backup", "version": 1,
    "walletId": "…", "createdAt": 1760870000,          // Unix seconds
    "kdf": { "name": "scrypt", "logN": 16, "r": 8, "p": 1, "salt": "<base64, 16 bytes>" },
    "check": "<sealed 'cashkit backup key check'>",     // tells a wrong passphrase from damage
    "collections": {                                     // every collection of §4, rows as stored
      "holdings": [ { "id": "h-…", "token": "lokicash1…", "amount": {"$bigint":"5000"},
                      "cashSecret": { "sealed": "<base64 nonce‖ciphertext>" }, … } ],
      "handoffs": […], "connections": […], "identity": […], "pendingJoins": […],
      "activity": […], "settings": […], "meta": […]
    }
  }
  ```

  - The key is scrypt over the NFKC passphrase (NIP-49's parameters); each
    secret is XChaCha20-Poly1305 under a fresh 24-byte nonce, with associated
    data `cashkit/backup/v1`.
  - The secret-bearing fields are exactly: holdings `cashSecret`,
    `pendingCashSecret`, `pendingDestinationCashSecret`,
    `pendingThrowawayKey`, `throwawayKey`; handoffs `handoff`; connections
    `uri`; identity `priv`; pendingJoins `connectionSecret`. Each is
    `{ "sealed": … }` in the file and nothing else is secret.
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
- **write-ahead ordering**: park before the wire call, refuse when the park
  can't be recorded, release without committing, a concurrent re-park
  survives (`auditD_cli_writeahead`)
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
