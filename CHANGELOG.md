# Changelog

## [0.2.0-rc.1]

- Reads and writes the token's signature scheme (TLV 8) and verifies mint
  provenance over the `cash-mint:v1` and `cash-zap:v1` payloads, which sign
  the relay hints. A copy whose provenance fails is never dialled, and a zap
  bill needs its Cash Zap. ([#8](https://github.com/ohstr/cashkit/pull/8))
- Refuses a mixed-case bech32 string; an all-uppercase one still decodes.
  ([#8](https://github.com/ohstr/cashkit/pull/8))
- Decodes and verifies signed `cashhub1`, `cashorder1` and `circlehub1`
  strings (Hub identity, connection signature, chain), and adds the online
  check of `get_info` against them. An unsigned string is refused.
  ([#9](https://github.com/ohstr/cashkit/pull/9))
- Adds `sanitizeText` for a lister's display text.
  ([#9](https://github.com/ohstr/cashkit/pull/9))
- Signs claim proofs with the method (`m`) and, for a consolidate, the
  source-list hash (`s`), and sends a `request_id` on every transfer and
  consolidate.
  ([#10](https://github.com/ohstr/cashkit/pull/10))
- Writes a cash note's split remainder ahead under a fresh secret and sends
  its `remainder_commitment`.
  ([#10](https://github.com/ohstr/cashkit/pull/10))
- Reads a destroyed bill's tombstone (`status`, `reason`) from any bill
  method and reports it as spent; an expiry of 0 now means never.
  ([#10](https://github.com/ohstr/cashkit/pull/10))
- Adds builders and parsers for `mint_cash`, `cash_lookup` and the status
  request, request ids, the redeem fee quote, and `get_info`'s `network`
  and `chain`.
  ([#10](https://github.com/ohstr/cashkit/pull/10))
- Reads the tag-form Hub announcement (`inbox`, `limit`, `r`, `addr`) with
  `max_request_age`, and writes envelopes and reads responses without a
  version field. A Hub without a usable `max_request_age` stays readable.
  ([#11](https://github.com/ohstr/cashkit/pull/11))
- Sends a cash-mode `cash_status` with neither proof nor secret, and checks
  a cash secret against the row's commitment instead.
  ([#11](https://github.com/ohstr/cashkit/pull/11))
- Pads envelopes up to `max_bytes` instead of refusing, counts every signed
  event in the verification budget, and keeps a response chunk's other
  results when one item is answered twice or unknown; errors keep `detail`.
  ([#11](https://github.com/ohstr/cashkit/pull/11))
- Adds proof of work for private requests: NIP-11 minimum, mining with
  `nonce` and `expiration`, and re-mining the same request after a `pow:`
  refusal.
  ([#11](https://github.com/ohstr/cashkit/pull/11))
- Sets each private call's deadline from the Hub's `max_request_age`
  (`deadlineFor`); `notAfterSeconds` is replaced by `replyWaitMs`, which only
  shortens the wait. A Hub without a usable `max_request_age` takes no
  bill-creating call.
  ([#12](https://github.com/ohstr/cashkit/pull/12))
- Adds a write-ahead hook to `BatchSession.send` (`beforePublish`, with a
  20 s margin and `singleEnvelope`) and returns the relays that accepted a
  request.
  ([#12](https://github.com/ohstr/cashkit/pull/12))
- Publishes to the announced relays first, then the bill's hints, and reads
  the announcement from the hints only.
  ([#12](https://github.com/ohstr/cashkit/pull/12))
- Keeps every decided outcome of a malformed or incomplete reply, marks an
  item answered twice `conflicted`, and adds `classifyCall`.
  ([#12](https://github.com/ohstr/cashkit/pull/12))
- Adds `cash_lookup` clients (`lookupMany`, `lookupOne`) signed by the
  original call's authorizer, with the two-step lookup of a cash-authorized
  call.
  ([#13](https://github.com/ohstr/cashkit/pull/13))
- Adds `CashHubClient` for a signed `cashhub1`: the online check on every
  `get_info`, confirmation of an unverified string, `mint` with a
  `request_id` and an `expiration`, `lookupMint`, and a `HubView` for display.
  ([#13](https://github.com/ohstr/cashkit/pull/13))
- NWC calls wait for every relay's subscription before publishing, and
  `get_info` types `pubkey`, `network` and `chain`.
  ([#13](https://github.com/ohstr/cashkit/pull/13))
- Mines private requests to the relays' NIP-11 proof-of-work minimum and
  re-mines the same request after a `pow:` refusal; adds the `relayInfo` and
  `powBudget` options and the `pow_too_hard` error.
  ([#14](https://github.com/ohstr/cashkit/pull/14))
- Relay adapters return a relay's refusal message verbatim and read its
  NIP-11 document.
  ([#14](https://github.com/ohstr/cashkit/pull/14))
- Maps `QUOTA_EXCEEDED` to `conflict`.
  ([#14](https://github.com/ohstr/cashkit/pull/14))
- Removes `transferFromSources`, `rekeyCashSlice`, `reconnect` and
  `PartialProgressError`; `cashTransfer`, `cashConsolidate` and every
  transfer or consolidate item now need the caller's `request_id`.
  ([#15](https://github.com/ohstr/cashkit/pull/15))
- Acts on Hub error codes only: a refusal's message no longer changes what
  the wallet does (the circle-join retry, the cross-Hub and cash-secret
  explanations), and the build fails on code that reads it.
  ([#15](https://github.com/ohstr/cashkit/pull/15))
- Adds `NwcClient.notifications` for a wallet's NIP-47 notifications.
  ([#15](https://github.com/ohstr/cashkit/pull/15))
- Moves the wallet store to schema 2: a schema-1 store is refused on open
  (start a new store), and pending calls, a device id and local derived-id
  and Hub records are added. Backups are version 2 and carry pending calls
  sealed; a version-1 backup is refused.
  ([#16](https://github.com/ohstr/cashkit/pull/16))
- Removes the unused `fallbackRelays` option and the `timeouts` and
  `displayUnit` settings.
  ([#16](https://github.com/ohstr/cashkit/pull/16))
- Settles pending calls by `cash_lookup`: a lost reply is applied, an
  unknown call is placed again under its derived id by the device that
  placed it (or waits for the user), and an expired one keeps its secrets
  in `unreconciledSecrets`.
  ([#17](https://github.com/ohstr/cashkit/pull/17))
- Adds `state.pendingCalls`, `state.nextSettleAt`, `state.unreconciled`,
  `pendingCalls.list`/`close`/`confirmReplace`, `autoSettle` and the
  `pending`, `recovered` and `needs_user` operation events; an error that
  leaves a call open carries its `pendingCallId`.
  ([#17](https://github.com/ohstr/cashkit/pull/17))
- Runs every send, split, protect, merge-key move and consolidate as
  pending calls written ahead with their deadline, request id and every
  secret they create; a lost reply is settled by lookup instead of a probe.
  ([#18](https://github.com/ohstr/cashkit/pull/18))
- A bill in an open call is locked: plans skip it, naming it is a
  `conflict`, and `holdings()` shows it `unsettled`. `BAD_REQUEST` closes
  the call at once and frees the bill, and a tombstone closes it with the
  bill spent; any other code keeps it open until a lookup settles it.
  ([#18](https://github.com/ohstr/cashkit/pull/18))
- Removes the per-holding write-ahead fields (`pendingCashSecret`,
  `pendingDestinationCashSecret`, `pendingRemainderCashSecret`,
  `pendingThrowawayKey`) and `unfinishedCashSends`; `settle()` returns the
  pending-call report. Their secrets now live in the pending call.
  ([#18](https://github.com/ohstr/cashkit/pull/18))
- A result that the Hub applied but that could not be saved leaves its call
  open for `settle()`, and the error's recovery text carries the cash notes
  it created.
  ([#18](https://github.com/ohstr/cashkit/pull/18))
- Adds `wallet.mint`: mints over a stored Cash Hub connection as a pending
  call, to a cash note, to this wallet, or to any send target; a lost reply
  is settled by lookup, and an unknown one waits for confirmation.
  ([#19](https://github.com/ohstr/cashkit/pull/19))
- `connections.add` takes a `cashhub1` string: verified and checked online
  before it is stored as given (an unverified one only after
  `confirmUnverified`); never a URI built from it, and never the default
  Lightning wallet.
  ([#19](https://github.com/ohstr/cashkit/pull/19))
- Errors carry an optional machine-readable `reason` (also in `toJSON`).
  ([#19](https://github.com/ohstr/cashkit/pull/19))
- A redeem whose outcome is unclear is never resent: one status read
  decides it, and a bill the Hub has claimed waits as `redeeming` (in no
  balance or plan) until `settle()` sees it released, gone, or paid.
  `settle()` reports these under `redeems`.
  ([#20](https://github.com/ohstr/cashkit/pull/20))
- Redeem invoices ask for a one-hour expiry, and `PAYMENT_FAILED` is retried
  once with a fresh invoice.
  ([#20](https://github.com/ohstr/cashkit/pull/20))
- Consolidate groups bills by hub group, keeps ordered bills apart and
  groups by the last-read `min_transfer_millis`; it never auto-merges an
  expired bill or one kept out of merges (`holdings.setExcludeFromMerge`).
  Naming ordered and other bills together is refused (`mixed_ordered`).
  ([#21](https://github.com/ohstr/cashkit/pull/21))
- Consolidate outcomes and merging send plans carry
  `disclosesCommonOwnership`; a send coverable only by merging an excluded
  bill is refused (`excluded_from_merge`).
  ([#21](https://github.com/ohstr/cashkit/pull/21))
- Handed-out cash notes are re-checked by `cash_status` without sending the
  secret.
  ([#21](https://github.com/ohstr/cashkit/pull/21))
- Joins a circle with `wallet.circles.join(circlehub1, terms, options)`
  over the private transport only, after `connectCircle` checked the
  string, its `get_info` and the announcement; the join carries
  `max_receive` and a `terms`-bound proof, is written ahead, and a lost
  reply is settled by the join lookup. **Breaking:** `joinCircle`,
  `CircleClient`, the standard-transport join, `requirePrivate`,
  `fallbackReason` and `PrivateJoinUnavailableError` are removed.
  ([#22](https://github.com/ohstr/cashkit/pull/22))
- Stores a Circle Wallet as its fields and the member's own secret, never a
  URI, and adds `CircleWalletClient` (budget, keysend, delete, payment
  preview); `lightning(name)` and redeem use it.
  ([#22](https://github.com/ohstr/cashkit/pull/22))
- Adds member requests, rotation and freeze notifications, wallet deletion
  above dust refused, budget periods, and the full `circle_wallet` terms
  (`accepting`, `fee_reserve`, limits).
  ([#22](https://github.com/ohstr/cashkit/pull/22))
- Adds orders (NIP-CO): `wallet.orders.quote`, `place`, `refresh`, `list`,
  `get` and `watch` over a `cashorder1` Order connection, paid over
  Lightning or on-chain. An order is a `cash_order` pending call that stays
  open until the order is finished; its bills become holdings marked
  ordered, and a gift's go to their recipient.
  ([#23](https://github.com/ohstr/cashkit/pull/23))
- Adds the NIP-CO core: terms, the order fee and confirmation tiers, the
  mint split, the request, the order reply (an invoice must be for exactly
  `pay_millis`, an address of the Hub's chain and network), the buyer key,
  order notices, and `connectOrder`.
  ([#23](https://github.com/ohstr/cashkit/pull/23))
- Adds on-chain withdrawals: `wallet.withdraw.terms`, `quote`, `send`,
  `refresh`, `cancel`, `list`, `get`, `receipt`, `signedTx` and `watch`.
  A quote is checked against what was asked and held in memory; sending
  needs the app's confirmation and runs as a pending call that stays open
  while the payout is followed; a cancelled payout comes back as a
  re-minted holding.
  ([#24](https://github.com/ohstr/cashkit/pull/24))
- Adds witness-address decoding and classification, the payout
  transaction check, the withdraw fee, and the quote, receipt and payout
  codecs with their checks.
  ([#24](https://github.com/ohstr/cashkit/pull/24))
- Adds Cash Zaps (NIP-CZ): `wallet.zaps.send` (a zap transfer whose 9522
  is published once its bill exists, also after a lost reply), `list`,
  `claim` (after rule 9) and `approveMinter`; the core verification rules
  1–8, identity tags, the 10522 and counting.
- A held zap bill keeps its Cash Zap fields, and every call on it uses them
  to find its Hub. Settings gain `trustedMinters` and `zapMinLifeSeconds`.

## [0.1.0-rc.2]

- Updates the README shipped with the package: install from npm, and a
  shorter description of each example.
  ([#4](https://github.com/ohstr/cashkit/pull/4))

## [0.1.0-rc.1]

- Adds `@ohstr/cashkit/core`: cash token, `cashhub1`, `circlehub1` and
  `nconnection1` codecs, hub group, cash string split, mint provenance,
  connection keys, NIP-44 v2 (current plaintext lengths), NIP-04, NIP-49
  `ncryptsec`, `redact`, units and `sniff`.
- Adds NIP-01 events, NIP-19 entities, bolt11 decoding, and NIP-47 pairing
  URIs and request and response events.
- Adds cash targets, credentials, NIP-IC attestations, claim proofs and the
  `cash_redeem`, `cash_transfer`, `cash_consolidate` and `cash_status`
  messages, plus NIP-CW `create_circle_wallet`.
- Adds `@ohstr/cashkit/transport`: NIP-CASH's private transport (envelope,
  params hash, padding, item and bill proofs, request wrap, reply key, Hub
  announcement), byte-compatible with nmilat.
- Adds `@ohstr/cashkit/client`: batch sessions with relay failover, chunked
  replies and per-envelope deadlines, the four batched bill methods, a
  single-bill client with claim checks and the transfer and rekey flows, an
  NWC client that negotiates nip44_v2 or nip04, and a Circle client.
- Adds `@ohstr/cashkit/wallet`: the wallet engine, with plan-then-execute
  receive, protect, send (auto-consolidating), consolidate and redeem,
  status, balance, activity and handoffs, circle joins, connections,
  identity and settings, and cashctl's error codes.
- Adds a write-ahead journal for every secret a call can create, and
  `settle()` to reconcile it after a crash or a lost reply.
- Adds `exportBackup` / `importBackup` and `state.backupStale`.
- Adds `openWallet` with browser defaults, and `state.storagePersisted`.
- Adds the adapters: `storage-memory`, `storage-sqlite` (node:sqlite or a
  compatible driver), `storage-indexeddb`, `vault-none`, `vault-passphrase`,
  `vault-device`, `lock-memory`, `lock-weblocks`, `sync-broadcast`,
  `signer-nip07`, `signer-nip46`, `relay-ws`, `relay-nostr-tools` and
  `relay-ndk`.
- Adds `@ohstr/cashkit/react`: `WalletProvider`, `useWalletState` (with
  selectors), action hooks (`useSend`, `useRedeem`, `useReceive`,
  `useConsolidate`, `useAction`), query hooks (`useBalance`, `useHoldings`,
  `useActivity`, `useHandoffs`, `useConnections`, `useIdentity`, `useQuery`)
  and `useOperationEvents`. React is an optional peer.
- Builds on install (`prepare`), so an app can depend on a pinned commit of
  the repository.
- Tests: conformance vectors exported from nmilat with a drift check, decode
  parity with `cashctl decode --json`, the engine scenario suite, a shared
  Storage contract, a headless Chromium run with a multi-tab scenario, and
  a live end-to-end run on a throwaway cash_hub (`just e2e`).
- Release workflow (npm with provenance, notes from this file) and the docs
  site.
- Adds a private circle join: `joinCircle` uses NIP-CASH's private transport
  when the Hub reports `circle_wallet.identity`, and reports a
  `fallbackReason` when it can't.
  ([#1](https://github.com/ohstr/cashkit/pull/1))
