# cashkit

[![CI](https://github.com/ohstr/cashkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ohstr/cashkit/actions/workflows/ci.yml)
![Node Version](https://img.shields.io/badge/node-%3E%3D22-brightgreen)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)

cashkit is a TypeScript SDK for building wallets on
[NIP-CASH](https://github.com/ohstr/nips/blob/main/NIP-CASH.md) and
[NIP-CW](https://github.com/ohstr/nips/blob/main/NIP-CW.md): token codecs,
the private transport to a Hub, write-ahead journaling of every secret, and
the wallet rules [`cashctl`](https://github.com/ohstr/cashctl) follows.

Use it to:

- **Build a cash wallet** in a browser, a PWA, Node ≥ 22 or Bun: receive,
  send, consolidate and redeem bills, with cashctl's behaviour and error codes
- **Join a Circle**, privately when the Hub offers it, and use its wallet
  over Nostr Wallet Connect
- **Talk to a Hub directly**, one bill or one batch at a time

A library only: no UI code, apart from the optional React bindings.

## Install

```sh
npm install @ohstr/cashkit   # or: pnpm add / yarn add / bun add
```

Or from the repository at a commit, which builds on install. Use the
`git+https` form, since yarn 1 doesn't build the `github:` shorthand:

```json
"@ohstr/cashkit": "git+https://github.com/ohstr/cashkit.git#<commit>"
```

Runtime dependencies: `@noble/curves`, `@noble/hashes`, `@noble/ciphers` and
`@scure/base`.

## Package overview

One package, in layers; each subpath imports only from the ones before it:

- **`@ohstr/cashkit/core`**: codecs and crypto, no I/O. Cash tokens,
  `cashhub1`/`circlehub1`/`nconnection1`, mint provenance, claim proofs, the
  `cash_*` and `create_circle_wallet` messages, NIP-01, NIP-19, NIP-44 v2,
  NIP-04 (legacy NWC only), NIP-47, NIP-49, bolt11, `sniff` and `redact`
- **`@ohstr/cashkit/transport`**: NIP-CASH's private transport, byte-compatible
  with nmilat
- **`@ohstr/cashkit/client`**: `CashClient` (one bill), `BatchSession` and its
  batch methods, `NwcClient` and `CircleClient`
- **`@ohstr/cashkit/wallet`**: the wallet engine: plan then execute, a
  write-ahead journal, `settle()` and cashctl's error codes (also exported
  from the package root)
- **`@ohstr/cashkit/react`**: a provider and hooks; React is an optional peer
- **`@ohstr/cashkit/adapters/*`**: the ports, made concrete:
  - storage: `storage-indexeddb` (browsers), `storage-sqlite` (Node and Bun,
    on `node:sqlite` or any compatible driver), `storage-memory` (tests)
  - vaults: `vault-passphrase` (scrypt + XChaCha20-Poly1305),
    `vault-device` (a non-extractable WebCrypto key in IndexedDB),
    `vault-none` (plaintext; choose it explicitly)
  - relays: `relay-ws` (the global `WebSocket`), `relay-nostr-tools` and
    `relay-ndk` (bring your own SimplePool or NDK)
  - signers: `signer-nip07` (browser extensions), `signer-nip46` (bunkers)
  - tabs: `lock-weblocks` and `sync-broadcast` (one tab moves money at a
    time, every tab sees the changes); `lock-memory` per process

[`docs/design.md`](docs/design.md) is the specification the code follows.

## Quick start

### Open a wallet in a browser

`openWallet` picks the browser defaults (IndexedDB, Web Locks,
BroadcastChannel, `navigator.storage.persist()`). You choose how secrets are
sealed at rest:

```ts
import { openWallet } from '@ohstr/cashkit'
import { DeviceVault } from '@ohstr/cashkit/adapters/vault-device'

const wallet = await openWallet({ vault: await DeviceVault.open() })

// Bills sent to a pubkey need an identity to claim them.
const me = (await wallet.identity.get()) ?? (await wallet.identity.generate())
console.log('receive at', me.npub)
if (wallet.state.storagePersisted === false) warnTheBrowserMayEvictThis()
```

Opening runs `settle()`, so anything a previous tab left mid-operation is
reconciled first.

### Open a wallet on Node or Bun

Storage, vault and relays are ports you pass in:

```ts
import { Wallet } from '@ohstr/cashkit'
import { RelayWs } from '@ohstr/cashkit/adapters/relay-ws'
import { SqliteStorage } from '@ohstr/cashkit/adapters/storage-sqlite'
import { PassphraseVault } from '@ohstr/cashkit/adapters/vault-passphrase'

// First run: create the vault and keep its (non-secret) params next to the wallet.
const vault = await PassphraseVault.create(passphrase)
await writeFile('vault.json', JSON.stringify(vault.params))
// Later runs: await PassphraseVault.unlock(passphrase, JSON.parse(await readFile('vault.json', 'utf8')))

const wallet = await Wallet.open({
  storage: await SqliteStorage.open({ path: 'wallet.db' }), // WAL, 0600, one writer per file
  vault,
  relays: new RelayWs(),
})
```

While the vault is locked (`vault.lock()`), the wallet reads but won't move
money.

### Sign with an extension or a bunker

Both adapters check every event they get back: signer, content and
signature:

```ts
import { nip07Signer } from '@ohstr/cashkit/adapters/signer-nip07'
import { nip46Signer } from '@ohstr/cashkit/adapters/signer-nip46'

const fromExtension = await nip07Signer() // window.nostr
const fromBunker = await nip46Signer({
  bunker: 'bunker://<remote-signer-pubkey>?relay=wss://relay.example&secret=…',
  relays: new RelayWs(),
  onAuthUrl: (url) => window.open(url), // the bunker asks the user to approve
})

const w = await openWallet({ vault: await DeviceVault.open(), signer: fromBunker })
```

A slow signer, such as a phone bunker, just gets smaller batches.

### Receive a bill

Pass a token for your pubkey or a cash note `<token>#<secret>`. `receive`
checks it with its Hub, then re-keys a cash note under a secret only this
wallet knows:

```ts
const r = await wallet.receive(pasted)
if (!r.received) {
  // A cash token without its secret: a read-only report, nothing stored.
  console.log('ask for the full token#secret; it holds', r.report.attestedAmount, 'millis')
} else {
  console.log('received', r.holding.amount, 'millis, protection:', r.holding.protection)
  if (r.secured.unresolved) console.log('the re-key may have landed; settle() checks')
}
```

### Send: plan, confirm, execute

Every money-moving call has a plan to confirm (merges, target, expiry) and
an execute, which refuses with `conflict` if a holding changed since:

```ts
const plan = await wallet.planSend({ amount: 2_000_000n }) // to: 'cash' by default
if (plan.consolidateFirst) console.log(`merges ${plan.sources.length} bills first`)

const sent = await wallet.executeSend(plan)
console.log('hand this over:', sent.cashNote) // <token>#<secret>, the only copy

// To a person instead: hex, npub, NIP-05, or an nconnection with its IA.
await wallet.send({ amount: 500_000n, to: 'alice@example.com' })
```

`wallet.send(...)` does both in one call.

### Redeem into a Lightning wallet

Add a NWC connection, then redeem. Bills on one node are quoted and
redeemed in one request each:

```ts
await wallet.connections.add('main', 'nostr+walletconnect://…')

const plan = await wallet.planRedeem({ all: true })
console.log(`receive ${plan.totalNet} after ${plan.totalFee} in fees`)

const report = await wallet.executeRedeem(plan)
for (const o of report.outcomes) {
  if (o.ok) console.log(o.holdingId, 'redeemed, preimage', o.preimage)
  else console.log(o.holdingIds, 'failed:', o.error.code, o.error.message)
}
```

`amount` redeems exactly that much net; `invoice` redeems into a given
invoice. Calls over several bills return a `Report` and never throw once
anything has committed.

### Consolidate and protect

```ts
const merged = await wallet.consolidate() // every hub group of two or more bills
console.log(merged.outcomes, 'left alone:', merged.aloneOnTheirHub)

await wallet.protect() // re-key every cash note still shared with its sender
```

### Join a Circle

The connection key is generated locally; the Hub only sees its pubkey. When
the Hub reports `circle_wallet.identity`, the join goes over the private
transport, and a fallback to the shared connection is reported in
`fallbackReason` (`requirePrivate: true` refuses instead):

```ts
const joined = await wallet.joinCircle({ hub: 'circlehub1…', maxAmount: 100_000_000n })
console.log('joined', joined.name, 'wallet', joined.walletPubkey)
if (joined.fallbackReason !== undefined) console.warn('joined without the private transport:', joined.fallbackReason)

const ln = await wallet.lightning(joined.name)
console.log(await ln.getBalance())
```

### Handle errors

Every failure is a `CashkitError` whose `code` is cashctl's:

| code | exit | meaning |
|---|---|---|
| `usage` | 2 | the call itself was wrong |
| `invalid_input` | 3 | a value doesn't parse or validate |
| `not_found` | 4 | no such bill, connection or identity |
| `conflict` | 5 | state moved under you; retry |
| `network` | 6 | couldn't reach a relay or Hub; retry |
| `auth` | 7 | not authorized, or no longer |
| `indeterminate` | 8 | **may have been applied**: check `status()` before retrying |
| `exists` | 9 | already there |
| `spent` | 10 | the bill's value has already moved |
| `internal` | 1 | anything else |

```ts
import { CashkitError } from '@ohstr/cashkit'

try {
  await wallet.send({ amount: 1_000n })
} catch (e) {
  if (!(e instanceof CashkitError)) throw e
  if (e.recovery) showVerbatim(e.recovery) // the Hub moved money we couldn't record
  else if (e.code === 'indeterminate') await wallet.status()
  else if (e.retryable) retryLater()
}
```

`recovery` is the one place a secret appears in an error: set when the Hub
applied a change that couldn't be saved locally. Show it whole.

### Back it up

Clearing site data can delete the only copy of a cash note. `exportBackup`
writes everything as JSON with secrets sealed under a passphrase, and
`state.backupStale` says when it's due:

```ts
if (wallet.state.backupStale) {
  const text = await wallet.exportBackup(backupPassphrase)
  download('cashkit-backup.json', text) // or anywhere the browser cannot evict
}

// On a new device, into an empty wallet:
const restored = await openWallet({ vault: await DeviceVault.open() })
await restored.importBackup(text, backupPassphrase)
```

### Watch state

```ts
const stop = wallet.subscribe((s) => render(s.holdings, s.balance, s.unfinishedCashSends))
wallet.on('operation', (e) => console.log(e.op, e.phase)) // planned, sent, committed, failed
```

State and events never carry secrets. `toJSON(result)` writes cashctl's
`--json` shape.

### Use it from React

`WalletProvider` opens the wallet; `useWalletState` re-renders on every
commit in any tab, and action hooks track `pending`, `result` and `error`:

```tsx
import { openWallet } from '@ohstr/cashkit'
import { DeviceVault } from '@ohstr/cashkit/adapters/vault-device'
import { WalletProvider, useActivity, useSend, useWalletState } from '@ohstr/cashkit/react'

export function App() {
  return (
    <WalletProvider open={async () => openWallet({ vault: await DeviceVault.open() })} fallback={<p>Opening…</p>}>
      <Balance />
      <SendCash />
      <History />
    </WalletProvider>
  )
}

function Balance() {
  const held = useWalletState((s) => s.balance.held)
  return <p>{held.toString()} millis</p>
}

function SendCash() {
  const { plan, execute } = useSend()
  const confirm = async () => {
    const p = await plan.run({ amount: 2_000_000n })
    if (window.confirm(p.consolidateFirst ? 'Merge bills first, then send?' : 'Send?')) await execute.run(p)
  }
  return (
    <>
      <button disabled={execute.pending} onClick={() => void confirm()}>Send as cash</button>
      {execute.result?.cashNote && <code>{execute.result.cashNote}</code>}
      {execute.error && <p>Failed: {execute.error.message}</p>}
    </>
  )
}

function History() {
  const { data } = useActivity({ limit: 20 })
  return <ul>{data?.map((a) => <li key={a.id}>{a.type === 'activity' ? a.action : a.kind}</li>)}</ul>
}
```

### Decode offline

`core` reads every string a user might paste, with no network:

```ts
import { decodeToken, sniff, splitCashString, verifyProvenance } from '@ohstr/cashkit/core'

const { token, cashSecret } = splitCashString(pasted)
if (sniff(token) === 'cash_token') {
  const t = decodeToken(token)
  console.log(t.walletPubkey, t.relays, 'minted by', verifyProvenance(t) ?? 'unknown')
}
```

### Bring your own relay pool

Reuse an existing nostr-tools or NDK pool:

```ts
import { SimplePool } from 'nostr-tools/pool'
import NDK, { NDKEvent, NDKRelaySet } from '@nostr-dev-kit/ndk'
import { NostrToolsPool } from '@ohstr/cashkit/adapters/relay-nostr-tools'
import { NdkPool } from '@ohstr/cashkit/adapters/relay-ndk'

const viaNostrTools = new NostrToolsPool(new SimplePool())
const viaNdk = new NdkPool(ndk, { NDKEvent, NDKRelaySet })
```

### Talk to a Hub directly

`CashClient` speaks for one bill over the private transport and persists
nothing:

```ts
import { bySecret, decodeToken } from '@ohstr/cashkit/core'
import { CashClient } from '@ohstr/cashkit/client'
import { RelayWs } from '@ohstr/cashkit/adapters/relay-ws'

const bill = new CashClient({ relays: new RelayWs() }, decodeToken(token))
const claim = await bill.checkClaim(bySecret(secret), '')
console.log(claim.amountMillis, 'millis, net', claim.netRedeemableMillis)
```

## Development

[`just`](https://github.com/casey/just), pnpm and Node 24 (`.node-version`):

```sh
# lint (oxlint + layer rules) and typecheck
just lint typecheck
# unit, vector and scenario tests
just test
# the browser adapters in headless Chromium
just browser
# lint + typecheck + test
just check
# regenerate vectors/ from nmilat, and fail on drift
just vectors-check
# decode parity with `cashctl decode --json`
just parity
# against a live Hub (see test/e2e)
just e2e
```

## License

[Unlicense](LICENSE): public domain.
