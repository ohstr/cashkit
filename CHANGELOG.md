# Changelog

## [0.2.0-rc.2]

- Picks, from a scope-all roster that lists claimed history, the caller's
  unclaimed row wherever it is listed (two are refused as ambiguous), else
  its most recently claimed row, instead of the first row that matches. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Refuses a bolt11 invoice carrying two 32-byte payment hash fields, as
  readers disagree on which one counts; a field of another length is still
  skipped. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Refuses the platform name `nostr` (`validPlatformName`): no ConnectionKey,
  nconnection, attestation or `connection:` target is built or read on it, as
  it names a native pubkey. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Refuses a NIP-LSP announcement dated more than 15 minutes ahead (step 4),
  and `LspSeen` no longer counts one as seen, so it cannot hide the node's
  later announcements. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Sends a private-transport envelope on to the next relay, as the same
  envelope, when the relay that took it gives no reply within its share of
  the wait, so a relay the Hub has left no longer holds a call until `not_after`. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Closes a call whose Cash Pocket entry another device made final as
  `closed_elsewhere` (a new `CallOutcome`), not `not_applied`, and reads its
  sources first, so a bill that device spent no longer shows as held. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Reads a lookup `done` whose created bill is already a tombstone as that
  bill gone: a spin-off is no longer taken for a move in place or handed off
  as the source's token, and such a mint closes instead of being looked up again. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Refuses an email user id with a leading `@` (`@alice@example.com`) as not
  canonical, instead of deriving a ConnectionKey no IA attests. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Checks, in `resolveConnection`, that an attestation is current and not
  deleted on the IA's own relays (the write relays of its NIP-65 list, or the
  new `iaRelays` option), never on the claimant's relay hint; with none
  reachable it does not count. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Reads an operator's offer list (kind 11191) from the operator's own NIP-65
  write relays as well as the discovery relays, so an operator that keeps it
  only there is no longer shown as unverified. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Ranks `discover.list()` offers on the signals each card shows, so a
  recommended offer is no longer placed below a newer one with no signal. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Refuses a Hub connection string whose TLV 3 label is not well-formed UTF-8,
  as the spec requires, instead of decoding it with replacement characters. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Sends an NWC request to the next relay hint, as the same event, when the
  relay that took it gives no answer within the wait, instead of giving up
  while a hint is still untried; a request past its `expiration` is not resent. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Keys holdings by the bill's wallet pubkey and stores each token in its
  canonical spelling (new `canonicalToken`), so a bill re-spelled with its
  entries reordered or an unknown TLV added is refused as already held
  instead of being counted twice. `Wallet.open` rewrites stored tokens and
  marks every second held copy an older version stored with the new holding
  status `duplicate`, kept for its secrets but never counted or spent. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Adds the item outcome state `unanswered` for an item an incomplete reply
  (or no reply) left out, and waits for every chunk up to `total` before a
  reply is complete; `not_served` now means only a complete reply's omission. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Refuses every call to a Hub whose newest signed announcement is rejected
  (`hub_unusable`), at `open()` and on refresh, instead of using an older
  announcement and its inbox; a valid newer announcement makes it usable again. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Follows an on-chain payout by lookups as well as notices: `withdraw.watch`
  polls it until `final` or `cancelled`, `settle()` reads every open payout
  (`report.withdrawals`), and `autoSettle()` reads one hourly and at each
  milestone (`state.nextWithdrawReadAt`), so a lost notice no longer leaves a
  re-minted bill unimported. ([#46](https://github.com/ohstr/cashkit/pull/46))
- Sorts canonical params keys by UTF-16 code units, as RFC 8785 does; the
  params hash changes only where keys mix characters above U+FFFF with ones
  from U+E000 to U+FFFF. ([#46](https://github.com/ohstr/cashkit/pull/46))

## [0.2.0-rc.1]

- Adds the holding statuses `expired` and `reclaimed` to the exported
  `HoldingStatus`, and `StatusOutcome.ends`; code that switches on a status
  must accept the new values. ([#44](https://github.com/ohstr/cashkit/pull/44))
- Fixes a bill whose slice its sender removed staying held and counted: a
  `NOT_FOUND` to the holding's own key or cash secret, from any method, now
  ends it `reclaimed`, and a tombstone ends it by its reason. Another
  device's final pocket state is adopted on a matching recheck instead of
  being reported as a conflict. ([#44](https://github.com/ohstr/cashkit/pull/44))
- Places a lost withdrawal again automatically on the device that placed
  it, under the derived id with the same quote, while no call of it was
  refused `quote_expired` or `quote_invalid`; after `REQUEST_REUSED` it
  still asks `confirmWithdrawReplace`. ([#44](https://github.com/ohstr/cashkit/pull/44))
- A presumed-paid redeem is re-read by every `settle()` and goes back to
  held when its row reads unclaimed again. ([#44](https://github.com/ohstr/cashkit/pull/44))
- A cancelled payout whose re-mint was already gone is recorded as
  `remintGone` and told once in the `withdrawCancelled` notice; nothing waits
  for an answer. ([#44](https://github.com/ohstr/cashkit/pull/44))
- `settle()` turns bills a merge left on its one-time key back into cash
  notes (`report.unmerged`); such a bill is still never withdrawn. ([#44](https://github.com/ohstr/cashkit/pull/44))
- A Cash Pocket with `auth` signs in on a pool of its own (`authPool`, or the
  new `RelayPool.isolated()`), never on the shared one; `NostrToolsPool`
  takes a `newPool` option for it. ([#44](https://github.com/ohstr/cashkit/pull/44))
- The pocket sync records the rev another device wrote for a bill held here,
  so this device's spend is written above it. ([#44](https://github.com/ohstr/cashkit/pull/44))
- A queued recommendation or report is published only by the identity that
  queued it (`author`). ([#44](https://github.com/ohstr/cashkit/pull/44))
- `circles.memberRequestFor` stores a rotate's new key, sealed, and
  `circles.recover(hub)` finds it without the secret; it asks the
  `confirmUnverified` handler; a `rotation_cancelled` for another key leaves
  the pending rotation alone; another device's unsent join is looked up once
  nothing can still arrive. ([#44](https://github.com/ohstr/cashkit/pull/44))


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
  ([#25](https://github.com/ohstr/cashkit/pull/25))
- A held zap bill keeps its Cash Zap fields, and every call on it uses them
  to find its Hub. Settings gain `trustedMinters` and `zapMinLifeSeconds`.
  ([#25](https://github.com/ohstr/cashkit/pull/25))
- Adds the Cash Pocket (NIP-CP) behind `WalletDeps.pocket` and the new
  `adapters/sync-pocket`: every bill-creating call and withdrawal is
  written ahead as a gift-wrapped pending entry (read back before the call
  goes out), kept bills get entries, and `wallet.pocket.sync`, `balance`
  and `entries` read it back on any device. Adds NIP-59 seal and wrap, and
  `Signer.nip44Encrypt`.
  ([#26](https://github.com/ohstr/cashkit/pull/26))
- Adds Discover: `wallet.discover.refresh`, `list`, `tap`, `order`, `join`
  and `recommendPreview` over offer listings, ranked by the user's follows
  and curators only, with terms read from the listed connection at tap;
  and the listing core (`parseListing` steps 1–4, `VersionBook`, operators,
  recommendations, reports, curator sets, signals, `checkTap`, fetch
  filters).
  ([#27](https://github.com/ohstr/cashkit/pull/27))
- Adds NIP-LSP announcements (kind 10735): building from an LSP's own LSPS
  answers, the client checks in the NIP's order, newest-only tracking with
  no fallback, and the live check against the node's LSPS answers.
  ([#28](https://github.com/ohstr/cashkit/pull/28))
- The conformance vectors now come from nmilat's own vectors package (37
  files), and every file has a suite; the cases where cashkit still differs
  are listed and skipped.
  ([#29](https://github.com/ohstr/cashkit/pull/29))
- Fixes reading `expires_at` from a mint's lookup result.
  ([#29](https://github.com/ohstr/cashkit/pull/29))
- Adds NIP-IC canonical platform user ids: `canonicalUserId`,
  `canonicalDomain` (UTS #46 ToASCII with the spec's refusals, tables from
  Unicode 15.0.0), `connectionKeyFromTyped` (x, discord, email, dns only)
  and `connectionKeyFromAttested`. They agree with nmilat on its 5000-domain
  corpus. ([#30](https://github.com/ohstr/cashkit/pull/30))
- Credential decoders (tokens, Hub connection strings, `nconnection1`)
  refuse a bech32m checksum; `encodeToken` refuses an HRP that is not
  lowercase. ([#31](https://github.com/ohstr/cashkit/pull/31))
- A relay hint is blank only when it is empty once ASCII whitespace is
  trimmed: a token or Hub connection whose hints are non-ASCII now decodes,
  and such hints are listed in `relays`. ([#31](https://github.com/ohstr/cashkit/pull/31))
- `nconnection1` is strict: a second key or platform, a platform outside
  `[a-z0-9._-]+` and a truncated TLV are refused; the encoder refuses a key
  that is not lowercase hex, a non-ASCII relay and a bad platform name. ([#31](https://github.com/ohstr/cashkit/pull/31))
- `zapPayloadV1` takes the `zap_target` itself and refuses an empty target
  or a recipient or sender that is not 64 lowercase hex (breaking);
  `chainForHrp` matches the HRP in lowercase; `relayHashOf` refuses a hint
  over 255 bytes. ([#31](https://github.com/ohstr/cashkit/pull/31))
- `derivedRequestId` refuses an id that is not a request id; adds
  `requiresRequestId`. ([#31](https://github.com/ohstr/cashkit/pull/31))
- `connectionKeyFromSecret` refuses uppercase hex. ([#31](https://github.com/ohstr/cashkit/pull/31))
- Breaking: `decodeEnvelope` is structural, as nmilat's: items sharing an
  id refuse the envelope and only a malformed item is dropped;
  `servableItems` applies the per-item serving checks. `decodeResponse` is
  now the strict single-event reading; the lenient chunk reading the session
  uses is `decodeResponseChunk`. Responses write `results` last (`[]` for a
  reply of omissions) and pad under the 65535 ceiling. ([#44](https://github.com/ohstr/cashkit/pull/44))
- `servingMethod` classifies a `cash_withdraw` cancel (served as
  `cash_lookup`) and refuses a malformed one; `bearerShapeOK` judges the
  served method. ([#44](https://github.com/ohstr/cashkit/pull/44))
- A proof verifies only with an `expiration` equal to the envelope's
  `not_after`, empty content, hex `d`, `h` and `ph`, and one string in each
  binding tag. ([#44](https://github.com/ohstr/cashkit/pull/44))
- `validateEnvelope` also checks every item's bill proof against the item,
  and refuses an item without one. ([#44](https://github.com/ohstr/cashkit/pull/44))
- Breaking: an announced `max_bytes` above 65535 is kept as announced;
  `effectiveLimits` reads it as 65535, and envelopes are sized against that. ([#44](https://github.com/ohstr/cashkit/pull/44))
- `parsePowRejection` reads the difficulty from any `pow:` refusal naming a
  positive integer (`pow:20`). ([#44](https://github.com/ohstr/cashkit/pull/44))
- `cashLookupParams` refuses a deadline of 0. ([#44](https://github.com/ohstr/cashkit/pull/44))
- A prepared join builds one item only (`claimPreparedJoin`,
  `preparedJoinUsed`). ([#44](https://github.com/ohstr/cashkit/pull/44))
- `parseAttestation` is strict: repeated tags, non-empty content, non-hex
  `d` or `p`, an invalid platform name, a malformed `expiration` and evidence
  that is not version 1 with an `auth_type` (and, for `public_post`, its
  proof fields) are refused. ([#44](https://github.com/ohstr/cashkit/pull/44))
- A `cash_transfer` or `cash_consolidate` reply carrying a secret is
  refused. ([#44](https://github.com/ohstr/cashkit/pull/44))
- Adds `ownRow` (the caller's row, taken from the credential, a widened
  scope-mine answer refused) and `claimable` (claimed, withdrawn or expired).
  ([#33](https://github.com/ohstr/cashkit/pull/33))
- A NIP-IC ConnectionKey now always travels with its IA: targets are built
  with `connectionTarget(ref)` from a `ConnectionKeyRef` made by
  `connectionKeyRefFromTyped` (x, discord, email, dns only),
  `connectionKeyFromAttestation`, `connectionKeyFromNConnection` or
  `connectionKeyRef`. `newConnectionKey`, `connectionKeyTarget` and
  `resolvedConnectionKeyTarget` are removed (breaking). ([#34](https://github.com/ohstr/cashkit/pull/34))
- `parseTarget` hashes a typed `connection:` target only on x, discord,
  email and dns, in canonical form, and refuses any other platform with a
  hint to paste the recipient's `nconnection1`; an `nconnection1` without a
  platform is refused for a send. ([#34](https://github.com/ohstr/cashkit/pull/34))
- Adds NIP-IC connection verification: `resolveConnection` (client) and
  `evaluateConnection`, `parseIdentityConnection` (core), reporting
  `verified`, `unverified` or `spoofed` per the Verification Model. ([#34](https://github.com/ohstr/cashkit/pull/34))
- Claim checks now find the caller's own row from its credential and ask
  whether it can still be spent: `checkClaim(credential)` (the pubkey
  argument is gone) returns `claimable` and `reason`, and receive, status,
  redeem quotes and zap claims treat a claimed, withdrawn or expired row as
  such instead of as missing. New `ownClaim`; `matchClaim`,
  `matchClaimAuto` and `NO_LOCAL_IDENTITY` are removed.
  ([#35](https://github.com/ohstr/cashkit/pull/35))
- `connectionKeyFromAttested` refuses a user id that is not in canonical
  form on a platform that has one (x, discord, email, dns).
  ([#35](https://github.com/ohstr/cashkit/pull/35))
- Orders: terms with a `window` of 0 are refused; `orderFee` refuses a
  payment kind other than `lightning` or `onchain` and an amount whose fee
  overflows a uint64; `parseOrder` takes `lookup` and refuses a direct reply
  whose order is not `open`. A NIP-47 reply's integer written as `1e3` or
  `1.0` is no longer read as an integer.
  ([#32](https://github.com/ohstr/cashkit/pull/32))
- Withdrawals: `withdrawFee` refuses a fee that overflows a uint64;
  `parsePayout` checks every field the state requires or forbids (txid,
  vout and depth from `broadcast` on, `tx` only once signed, the re-minted
  bill always under `cancelled`, fee plus payout equal to the amount); a
  version-0 script type is 20 or 32 bytes; `classifyAddress` with an empty
  HRP accepts any network.
  ([#32](https://github.com/ohstr/cashkit/pull/32))
- Cash Zaps: a 9522 with a NIP-40 `expiration` tag is valid but never
  counted (`CashZapTags.hasExpiration`), where it was refused; rule 7 fails
  when an `e`-only zap does not name the given target's `id`.
  ([#32](https://github.com/ohstr/cashkit/pull/32))
- Listings: a repeated type `t` is refused at step 1; a listing is current
  through its expiry second; `sanitizeText` also drops a U+FE0F right after
  a check mark, treats line breaks next to stripped characters as the input
  has them, and caps nothing when `maxClusters` is 0 or less.
  ([#32](https://github.com/ohstr/cashkit/pull/32))
- Cash Pocket: `validatePocketEntry` checks an entry before it is written
  and `checkPendingEntry` a call's first pending entry (an order keeps its
  notify and its secret or key; a withdrawal its notify, address, quote and
  only a remint secret); `parsePocketEntry` refuses repeated tags, uppercase
  hex, a state without its check time, a 64-hex `mint` and `expires_at` 0;
  `resolveEntries` reports a conflict only when the winning `rev` holds two
  rumors.
  ([#32](https://github.com/ohstr/cashkit/pull/32))
- `budgetPeriodStart` returns undefined for a negative period index.
  ([#32](https://github.com/ohstr/cashkit/pull/32))
- Signers: `Signer.nip44Encrypt` is required (breaking), and NIP-07 and
  NIP-46 adapters implement it. NIP-46 errors are `SignerError`s classified
  by prefix (`denied`, `invalid`, `failed`). New `adapters/signer-unix`
  (Node only): a local signer over a unix socket (NIP-LS), with
  `signerFromUri` for both `bunker://` and `bunker+unix://` addresses,
  attestations and `approvedEventId`; `parseBunkerUri` refuses a unix
  address and points there. ([#36](https://github.com/ohstr/cashkit/pull/36))
- Bills bound to a connection key can be held and spent:
  `receive(token, { attestation })` checks the account's attestation and
  keeps it on the holding; status, redeem, send and on-chain withdrawal
  claim with it, reading the holder's row with `scope: all` (`ownScope`).
  A split's remainder and a cancelled withdrawal's re-mint stay bound to the
  same account. ([#37](https://github.com/ohstr/cashkit/pull/37))
- Circles: `circles.recover(hub, newConnectionSecret)` takes a wallet onto
  the device that holds the key a rotation moved it to (`done`, `pending`
  with `retryAt`, or `not_found`); `connections.add` stores a `circlehub1`
  string (checked online, never joined), and a pending join whose own string
  stays unanswered past its deadline plus 360 s is looked up once through
  another held string of the same circle before it is shown as unanswered;
  `connections.inspect` shows what a `cashhub1`, `cashorder1` or
  `circlehub1` string is, with nothing stored.
  ([#38](https://github.com/ohstr/cashkit/pull/38))
- Adds confirmation requests: the wallet raises typed questions
  (`confirmUnverified`, `confirmMintReplace`, `confirmOrderReplace`,
  `confirmWithdrawReplace`, `confirmNoRecovery`, `confirmDelete`,
  `approveMinter`, `confirmWithdraw`, `confirmRecommend`, `confirmReport`)
  and notices (`rotationAlert`, `walletFrozen`, `lookupExpired`,
  `expiringSoon`, `withdrawLate`, `withdrawCancelled`) through
  `wallet.on('confirm', …)`; with no handler every question is answered
  no. `circles.delete` takes its confirmation optionally, and a zap from an
  untrusted minter can be approved from the claim.
  ([#40](https://github.com/ohstr/cashkit/pull/40))
- Adds React hooks: `useConfirmations`, `usePendingCalls`,
  `useUnreconciled`, `useCircles`, `useCircleWallet`, `useCashZaps`,
  `usePocket`, `useOrders`, `useOrder`, `useWithdrawTerms`,
  `useWithdrawQuote`, `useWithdrawals`, `useWithdrawal`, `useDiscover`,
  `useTap` and `useTestNetworkBanner`.
  ([#40](https://github.com/ohstr/cashkit/pull/40))
- Cash Pocket upkeep: a sync fills a missing `expires_at` from
  `cash_status` and deletes the wraps of final entries after 30 days
  (keeping a closed on-chain order's `done` entry, an unscrubbed
  withdrawal's, and any source of an open call); `settings.pocketNip40`
  (off by default) sets a NIP-40 `expiration` on wraps of entries with an
  expiry; a rewrite after a sync takes the pocket's `rev` and deletes every
  wrap it read for that entry. `PocketSyncReport` gains `pruned` and
  `expiryFilled`.
  ([#41](https://github.com/ohstr/cashkit/pull/41))
- Before a call is placed again under its derived id, the wallet reads its
  Cash Pocket: an entry with the derived id, in any state, only closes the
  old call; an old entry already final closes it without placing; an entry
  the pocket does not show stops the re-placement.
  ([#41](https://github.com/ohstr/cashkit/pull/41))
- `adapters/sync-pocket` finds the user's relays (kind 10050, else NIP-65
  write relays, else the configured ones, plus `ownRelays`) and takes an
  `auth` signer for NIP-42. `RelayPool.setAuth` is new: `relay-ws` answers
  AUTH challenges and retries a request refused `auth-required:` once;
  `relay-nostr-tools` passes it on as `onauth`.
  ([#41](https://github.com/ohstr/cashkit/pull/41))
- `decodeBolt11` also reads an invoice's creation time, expiry and payee
  (the `n` field, else the key its signature recovers to);
  `invoiceExpiresAt`.
  ([#42](https://github.com/ohstr/cashkit/pull/42))
- Redeem: an invoice's amount must be what the Hub will pay, the full
  amount when its payee is the bill's own minter (fee-free, same node),
  else the net amount; any other is refused before sending (reason
  `invoice_amount`). An invoice the app's wallet makes is made again for
  the full amount when its payee is the minter. New `redeemInvoiceMillis`.
  ([#42](https://github.com/ohstr/cashkit/pull/42))
- Consolidate: a set the Hub refused `RESTRICTED` is remembered and not
  planned again.
  ([#42](https://github.com/ohstr/cashkit/pull/42))
- Orders: the view's `payDeadline` is `pay_by` or the invoice's expiry,
  whichever comes first; each bill's own row is read before it is kept (a
  bill for another recipient is never kept, one with an expiry is kept
  without the ordered mark); a confirmed re-placement carries a fresh
  `notify`.
  ([#42](https://github.com/ohstr/cashkit/pull/42))
- Withdrawals: `withdraw.requote` (a new quote listing what changed) and
  `withdraw.recover` (a lost withdrawal found from the bill's
  `withdraw_request_id`, looked up, never placed again).
  ([#42](https://github.com/ohstr/cashkit/pull/42))
- Discover keeps the last refresh, its version floors and the tap outcomes
  across restarts; adds recommending and reporting through a delayed outbox
  signed by the identity (`recommend`, `report`, `withdrawRecommendation`,
  `outbox.*`, published at open and by `autoSettle`), and the user's
  curators (`curators.*`: app defaults, the user's edits, a private NIP-51
  set published and synced). A session now starts on the wallet's clock.
  ([#39](https://github.com/ohstr/cashkit/pull/39))
- Reads a Hub's `NOT_FOUND` to a connection-key holder's `cash_status`, which
  NIP-CASH §Scoping the Roster requires, as "status not readable": the bill
  is received unverified at its attested amount (`statusUnreadable`),
  `status` reports it `unreadable`, `BillState` gains `unreadable` and
  `checkClaim` throws `status_unreadable`; a redeem or withdrawal is refused
  before anything is sent (`usage`/`status_unreadable`), a send still works,
  and `settle()` never settles a redeeming bill on that answer. Adds
  `statusUnreadable`. ([#44](https://github.com/ohstr/cashkit/pull/44))
- Circles: `circles.watch(name)` listens for the wallet's NIP-CW
  notifications and applies each, on the current key and, while a rotation
  this device asked for is pending, on the new key, which alone receives
  `rotation_completed`; it sends the Hub nothing, so it never cancels the
  rotation, and marks a connection moved once a rotation it did not ask for
  passes its `completes_at`. `circles.refresh(name)` asks the Hub over the
  current key whether the wallet is frozen and lifts the local mark after an
  unfreeze, which has no notification; it is refused while this device's
  rotation is pending unless `cancelRotation` is set. ([#44](https://github.com/ohstr/cashkit/pull/44))
- Circles: `circles.memberRequestFor(circlehub1, walletPubkey, action)`
  signs a member request for a wallet this device does not hold, for a
  member who lost the device that did; a rotate returns the new key's
  secret for `circles.recover`. ([#44](https://github.com/ohstr/cashkit/pull/44))

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
