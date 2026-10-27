set shell := ["bash", "-euo", "pipefail", "-c"]

# Lint, typecheck and test.
check: lint typecheck test

lint:
    pnpm lint

typecheck:
    pnpm typecheck

test:
    pnpm test

build:
    pnpm build

# The browser adapters in a headless Chromium (Playwright).
browser:
    pnpm test:browser

# Regenerate vectors/*.json from nmilat's vectors package (pinned in
# tools/export-vectors/go.mod). Until nmilat tags the release that ships the
# package, put a go.work next to that go.mod that uses an nmilat checkout.
vectors:
    go -C tools/export-vectors run . -out ../../vectors

# Fail if the committed vectors differ from what nmilat produces.
vectors-check:
    just vectors
    git diff --exit-code -- vectors
    test -z "$(git status --porcelain -- vectors)"

# Regenerate src/core/idnaData.ts from the pinned Unicode 15.0.0 files
# (downloaded, or read from `dir`).
idna-tables dir="":
    node tools/gen-idna-tables.mjs {{dir}}

# Decode parity with `cashctl decode --json`, built from a cashctl checkout.
parity cashctl="../cashctl":
    bin="$(mktemp -d)/cashctl" && \
    GOWORK=off go -C {{cashctl}} build -buildvcs=false -o "$bin" . && \
    CASHCTL_BIN="$bin" pnpm vitest run test/parity

# End-to-end against a live Hub: CASHKIT_E2E_CONFIG (or ADMIN_URL/ADMIN_TOKEN) for the wallet flow, CASHKIT_E2E_BILL for the read-only check (see test/e2e).
e2e:
    pnpm vitest run test/e2e

