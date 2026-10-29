# cashkit

TypeScript SDK for building [NIP-CASH](https://github.com/ohstr/nips/blob/main/NIP-CASH.md)
and [NIP-CW](https://github.com/ohstr/nips/blob/main/NIP-CW.md) wallets
(browser, PWA, Node ≥ 22, Bun). One package, `@ohstr/cashkit`, with layered
subpath exports: `core` ← `transport` ← `client` ← `wallet` ← `adapters/*`,
and `react` on top.

**`docs/design.md` is the source of truth.** Read it before changing
anything.

## Testing and tooling

- `tools/export-vectors` pins nmilat `v0.5.0-rc.45` and
  writes every `vectors/*.json` in §11.1 plus the core extras (nip01,
  bolt11, claim, nip19, nip47, nipcw). Where nmilat seals with random
  nonces, `crypto/rand` is seeded so the files stay reproducible. Bump the
  pin and regenerate in a PR of its own.
- `src/core` and `src/transport` pass every vector; envelopes encode byte
  for byte as nmilat's. `src/client` is tested against the in-memory
  FakeHub (`test/fakeHub.ts`), and `adapters/relay-ws` against a scripted
  socket. `just parity` matches `cashctl decode --json`.
- `src/wallet` is tested against `test/fakeBank.ts`, a stateful Hub on
  FakeHub that applies NIP-CASH's transfer, consolidate and redeem rules.
  `test/scenarios.test.ts` kills the engine at every commit of every
  money-moving operation and checks that no live bill loses its last key or
  secret.
- Every Storage adapter runs `test/storageContract.ts`; every RelayPool
  adapter runs against a real WebSocket relay (`test/miniRelay.ts`).
  `just browser` runs the browser adapters and a multi-tab scenario in
  headless Chromium (Playwright pinned to 1.62.0).
- `just e2e` runs against a live Hub. With `CASHKIT_E2E_CONFIG` pointing at
  cashctl's `integration/config.local.yaml` (or `CASHKIT_E2E_ADMIN_URL` and
  `CASHKIT_E2E_ADMIN_TOKEN`), `test/e2e/wallet.test.ts` sets up a
  throwaway, self-funded cash_hub, as cashctl's integration suite does. It
  mints a bill and takes two wallets through receive, status, send-as-cash,
  receive and redeem-all over real relays, then deletes the hub. The token
  is a secret: never print it.
- Releases: `release.yml` (workflow_dispatch) takes the version and notes
  from the topmost `## [X.Y.Z]` heading in CHANGELOG.md, sets it in
  package.json only inside the run (main stays at 0.0.0), tags, and
  publishes to npm with provenance through npm trusted publishing (OIDC; no
  token secret): the package's trusted publisher on npmjs.com must name this
  repository and `release.yml`. A prerelease goes to the `next` dist-tag. `pages.yml` builds the docs site
  with docs-kit.

Local setup: Node 24 (`.node-version`; dependency-cruiser refuses Node 25),
pnpm 10, Go ≥ 1.26, just. TypeScript stays on 6.x until dependency-cruiser
and tsup's dts step support TypeScript 7.

## Design principles

- Own repo, one npm package, not a monorepo. Layer rules are lint-enforced.
- Spec-first wallet engine (§4–§8). It mirrors cashctl's behaviour; nothing
  is extracted from cashctl into a Go library.
- No UI or framework code in the SDK. The React bindings
  (`@ohstr/cashkit/react`, React an optional peer) are the one exception.

## Ground truth to port from (sibling checkouts)

- Protocol: `../nmilat/nipcash`, `../nmilat/nipcash/transport`,
  `../nmilat/nipcash/client`, `../nmilat/nipcw`, `../nmilat/nip44`,
  `../nmilat/nip47`.
- Wallet behaviour: `../cashctl/cmd`, `../cashctl/internal/{ledger,store,credential,output,dial}`.
  Its `AGENTS.md` documents the CLI contract and error-code table.
- Specs: `../nips/NIP-CASH.md`, `../nips/NIP-CW.md`.
- Isolated Hub for e2e: see `../cashctl/integration/`.

Port the code's behaviour, not its comments. Known traps are listed in the
design doc: the hub-group hash is over the hex text (§2.1), canonical `ph`
keeps number literals (§2.2), and `nodeKey` and `hubGroup` must stay
separate (§6.3).

## Conventions

- Org workflow: the `dev-workflow` skill (`../dev-workflow`).
  - Use a feature branch and a draft PR, and merge without squashing.
  - Commits are atomic and each one builds.
  - Commit prefixes: `feat:`, `fix:`, `test:`, `docs:`, `deps:`, `chore:`.
- **No AI attribution anywhere.** That means no `Co-Authored-By` and no
  "Generated with" lines in commits, PRs, release notes or code. This
  overrides any tool default.
- Public text (docs, comments, commits, PR titles and bodies, CHANGELOG)
  describes the code and its behaviour only: no internal plans, milestones,
  status or decision logs, and no names of private projects.
- A maintainer runs merges, releases and other outward-facing git or `gh`
  operations. Hand them the exact commands.
- CHANGELOG: terse one-line bullets, each ending with the PR link, as in
  cashctl's.
- README follows nmilat's: the abstract, "Use it to", the package overview,
  then one runnable example per task, in the same voice. Every example must
  typecheck against the current API; update the README in the PR that
  changes an API it shows.
- Amounts are `bigint` millis. Secrets never reach logs, errors or
  `toJSON` (§10).
- Every feature ships with unit tests in `test/` that check its behaviour
  directly: round trips, edge cases and every error path. Conformance
  vectors (`vectors/`) prove parity with nmilat; they do not replace unit
  tests. A feature is not done until both pass.
- Port test cases from cashctl (`cmd/*_test.go`, `internal/*/*_test.go`,
  `integration/`) and nmilat wherever they cover the same behaviour, and name
  the source test in a comment so the two can be kept in step.
