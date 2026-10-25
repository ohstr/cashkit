# Changelog

## [0.2.0-rc.1]

- Reads and writes the token's signature scheme (TLV 8) and verifies mint
  provenance over the `cash-mint:v1` and `cash-zap:v1` payloads, which sign
  the relay hints. A copy whose provenance fails is never dialled, and a zap
  bill needs its Cash Zap. ([#8](https://github.com/ohstr/cashkit/pull/8))
- Refuses a mixed-case bech32 string; an all-uppercase one still decodes.
  ([#8](https://github.com/ohstr/cashkit/pull/8))

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
