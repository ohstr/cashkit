// A wallet over FakeBank: memory storage, vault-none, a local identity, and
// a fake NWC wallet to redeem into. Test support only.
import { buildPairingURI, finalizeEvent, getPublicKey, nip44, toHex, type NostrEvent } from '../src/core/index.js'
import { MemoryStorage } from '../src/adapters/storage-memory.js'
import { NoneVault } from '../src/adapters/vault-none.js'
import { Wallet } from '../src/wallet/index.js'
import type { Storage, WalletDeps } from '../src/wallet/index.js'
import { FakeBank } from './fakeBank.js'
import { MemoryRelayPool } from './fakeHub.js'
import { fill, invoice } from './helpers.js'

export const HUB_RELAY = 'wss://bank.test'
export const NWC_RELAY = 'wss://nwc.test'

export type NwcHandler = (method: string, params: Record<string, unknown>) => { result?: unknown; error?: { code: string; message: string } } | 'silent'

/** A NIP-47 wallet service on `relay`; default handler pays invoices and reports a balance. */
export class FakeNwcWallet {
  readonly key: Uint8Array
  readonly pubkey: string
  readonly appSecret: Uint8Array
  readonly seen: { method: string; params: Record<string, unknown> }[] = []
  invoiceSeq = 0x50
  balance = 0n
  handler: NwcHandler = (method, params) => {
    if (method === 'make_invoice') return { result: { invoice: invoice(BigInt(params['amount'] as number), this.invoiceSeq++ & 0xff) } }
    if (method === 'get_balance') return { result: { balance: Number(this.balance) } }
    return { error: { code: 'NOT_IMPLEMENTED', message: method } }
  }

  constructor(
    readonly pool: MemoryRelayPool,
    seed = 0x71,
    readonly relay = NWC_RELAY,
  ) {
    this.key = fill(seed, 32)
    this.pubkey = getPublicKey(this.key)
    this.appSecret = fill(seed + 1, 32)
    pool.subscribe([relay], { kinds: [23194], '#p': [this.pubkey] }, {
      onEvent: (e: NostrEvent, r: string) => {
        const ck = nip44.getConversationKey(this.key, e.pubkey)
        const req = JSON.parse(nip44.decrypt(e.content, ck)) as { method: string; params?: Record<string, unknown> }
        this.seen.push({ method: req.method, params: req.params ?? {} })
        const a = this.handler(req.method, req.params ?? {})
        if (a === 'silent') return
        const body = JSON.stringify({ result_type: req.method, ...a })
        const reply = finalizeEvent({ kind: 23195, created_at: e.created_at, tags: [['p', e.pubkey], ['e', e.id], ['encryption', 'nip44_v2']], content: nip44.encrypt(body, ck) }, this.key)
        void pool.publish(r, reply)
      },
      onEose: () => {},
    })
  }

  get uri(): string {
    return buildPairingURI(this.pubkey, [this.relay], toHex(this.appSecret))
  }
}

export interface Harness {
  readonly pool: MemoryRelayPool
  readonly bank: FakeBank
  readonly storage: Storage
  readonly wallet: Wallet
  readonly me: string
  readonly deps: WalletDeps
  /** Opens a second wallet over the same storage (another tab or process). */
  reopen(o?: Partial<WalletDeps>): Promise<Wallet>
}

let counter = 0

export async function harness(o: { storage?: Storage; deps?: Partial<WalletDeps>; identity?: boolean; bank?: FakeBank; pool?: MemoryRelayPool } = {}): Promise<Harness> {
  const pool = o.pool ?? new MemoryRelayPool()
  const bank = o.bank ?? new FakeBank(pool, [HUB_RELAY])
  if (o.bank === undefined) await bank.start()
  const storage = o.storage ?? new MemoryStorage()
  // Deterministic but distinct randomness per harness.
  let n = (++counter) * 0x10000
  const random = (k: number) => {
    const out = new Uint8Array(k)
    for (let i = 0; i < k; i++) out[i] = (n = (n * 1103515245 + 12345) >>> 0) >>> 24
    return out
  }
  const deps: WalletDeps = { storage, vault: new NoneVault(), relays: pool, notAfterSeconds: 2, random, ...o.deps }
  const wallet = await Wallet.open(deps)
  let me = ''
  if (o.identity !== false) me = (await wallet.identity.get())?.pubkey ?? (await wallet.identity.generate()).pubkey
  return { pool, bank, storage, wallet, me, deps, reopen: (x = {}) => Wallet.open({ ...deps, ...x }) }
}
