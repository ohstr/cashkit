// What every wallet operation shares: sealing, credentials, clients, commits
// and events. Internal to the wallet layer.
import { bySecret, bySigning, decodeToken, fromUtf8, localSigner, fromHex, utf8, verifyProvenance, toHex, type Credential, type Signer, type Token } from '../core/index.js'
import { billFor, CashClient, type Bill, type ClientDeps } from '../client/index.js'
import { CashkitError } from './errors.js'
import { conflict } from './ledger.js'
import type { Holding, Sealed, Settings } from './model.js'
import { DEFAULT_SETTINGS } from './model.js'
import { ConcurrentUpdateError, type Lock, type Logger, type StorageTx, type WalletDeps } from './ports.js'

/**
 * `pending`: the call got no decided answer and stays open (looked up by
 * `settle`); `recovered`: a lookup found it applied; `needs_user`: it waits
 * for the user (a confirmation, or an answer that never came).
 */
export type OperationPhase = 'planned' | 'sent' | 'committed' | 'failed' | 'pending' | 'recovered' | 'needs_user' | 'rotation_alert' | 'frozen_alert'
export interface OperationEvent {
  readonly op: string
  readonly phase: OperationPhase
  readonly id: string
  /** The pending call the event is about, when there is one. */
  readonly pendingCallId?: string
}

/** A per-process lock, used when the app passes none. */
class ProcessLock implements Lock {
  private readonly tails = new Map<string, Promise<unknown>>()
  withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const run = (this.tails.get(name) ?? Promise.resolve()).then(fn)
    const tail = run.catch(() => undefined)
    this.tails.set(name, tail)
    void tail.then(() => {
      if (this.tails.get(name) === tail) this.tails.delete(name)
    })
    return run
  }
}

export class Ctx {
  readonly lock: Lock
  readonly clientDeps: ClientDeps
  readonly random: (n: number) => Uint8Array
  walletId = ''
  /** This store's device id: the owner of the calls it places. */
  deviceId = ''
  /** When this wallet object was opened (ms): a session's start. */
  readonly openedAt: number = Date.now()
  /** Set by identity.useSigner or a stored local key. */
  signerOverride: Signer | undefined
  private readonly opListeners = new Set<(e: OperationEvent) => void>()
  private readonly changeListeners = new Set<() => Promise<void> | void>()
  private opSeq = 0

  constructor(readonly deps: WalletDeps) {
    this.lock = deps.lock ?? new ProcessLock()
    this.random = deps.random ?? ((n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)))
    this.clientDeps = {
      relays: deps.relays,
      random: this.random,
      ...(deps.clock !== undefined && { clock: deps.clock }),
      ...(deps.replyWaitMs !== undefined && { replyWaitMs: deps.replyWaitMs }),
      ...(deps.nwcTimeoutMs !== undefined && { nwcTimeoutMs: deps.nwcTimeoutMs }),
    }
    this.signerOverride = deps.signer
  }

  now(): number {
    return (this.deps.clock ?? Date.now)()
  }
  nowSeconds(): number {
    return Math.floor(this.now() / 1000)
  }

  get log(): Logger | undefined {
    return this.deps.logger
  }

  // ---- storage

  read<T>(fn: (t: StorageTx) => Promise<T>): Promise<T> {
    return this.deps.storage.tx('r', fn)
  }

  /**
   * A read-write transaction; a version clash becomes a retryable
   * `conflict`. Resolves once the wallet's state reflects the commit.
   */
  async commit<T>(fn: (t: StorageTx) => Promise<T>): Promise<T> {
    let r: T
    try {
      r = await this.deps.storage.tx('rw', fn)
    } catch (err) {
      if (err instanceof ConcurrentUpdateError) throw conflict(err)
      throw err
    }
    await this.changed()
    return r
  }

  async settings(): Promise<Settings> {
    const row = await this.read((t) => t.get('settings', 'settings'))
    if (row === undefined) return DEFAULT_SETTINGS
    const { id: _id, version: _v, ...s } = row
    return { ...DEFAULT_SETTINGS, ...s }
  }

  // ---- secrets

  requireUnlocked(): void {
    if (this.deps.vault.locked()) throw new CashkitError('auth', 'the wallet vault is locked; unlock it before moving money')
  }
  seal(s: string): Promise<Sealed> {
    return this.deps.vault.seal(utf8(s))
  }
  async open(s: Sealed): Promise<string> {
    return fromUtf8(await this.deps.vault.open(s))
  }
  async openOpt(s: Sealed | undefined): Promise<string | undefined> {
    return s === undefined ? undefined : this.open(s)
  }

  // ---- identity

  async signer(): Promise<Signer | undefined> {
    if (this.signerOverride !== undefined) return this.signerOverride
    const row = await this.read((t) => t.get('identity', 'self'))
    if (row?.source !== 'local' || row.priv === undefined) return undefined
    const s = localSigner(fromHex(await this.open(row.priv), 'identity key'))
    this.signerOverride = s
    return s
  }

  async requireSigner(): Promise<Signer> {
    const s = await this.signer()
    if (s === undefined) {
      throw new CashkitError('not_found', 'no identity is set up: generate one with wallet.identity.generate(), or pass a signer', { hint: 'wallet.identity.generate()' })
    }
    return s
  }

  /** The local identity pubkey, or "" when there is none. */
  async myPubkey(): Promise<string> {
    return (await this.signer())?.pubkey ?? ''
  }

  /**
   * How to authorize a call on a holding (`resolveCredential`): its
   * throwaway merge key, its cash secret, or the identity.
   */
  async credentialFor(h: Holding): Promise<Credential> {
    if (h.throwawayKey !== undefined) return bySigning(localSigner(fromHex(await this.open(h.throwawayKey), 'throwaway key')))
    if (h.mode === 'cash') {
      if (h.cashSecret === undefined) throw new CashkitError('invalid_input', 'this cash-mode holding has no cash secret, so it cannot be spent', { input: h.id })
      return bySecret(await this.open(h.cashSecret))
    }
    if (h.mode === 'connection_key') {
      throw new CashkitError('usage', 'this holding is bound to a connection key; spending it needs that connection-key credential, which this wallet does not hold', { input: h.id })
    }
    return bySigning(await this.requireSigner())
  }

  // ---- clients

  client(token: string | Token): CashClient {
    return new CashClient(this.clientDeps, token)
  }

  /** The client for a holding: a zap bill's provenance needs its Cash Zap fields. */
  clientFor(h: Pick<Holding, 'token' | 'zap'>): CashClient {
    return new CashClient(this.clientDeps, h.token, h.zap)
  }

  // ---- events

  newOpId(op: string): string {
    return `${op}-${++this.opSeq}`
  }
  emit(e: OperationEvent): void {
    for (const l of this.opListeners) l(e)
  }
  onOperation(fn: (e: OperationEvent) => void): () => void {
    this.opListeners.add(fn)
    return () => this.opListeners.delete(fn)
  }
  onChange(fn: () => Promise<void> | void): () => void {
    this.changeListeners.add(fn)
    return () => this.changeListeners.delete(fn)
  }
  /** Something committed here: tell the other tabs, and refresh. */
  async changed(): Promise<void> {
    if (this.walletId !== '') this.deps.sync?.post({ walletId: this.walletId, at: this.now() })
    await Promise.all([...this.changeListeners].map((l) => l()))
  }

  /** Something committed in another tab: refresh only. */
  changedElsewhere(): Promise<void> {
    return Promise.all([...this.changeListeners].map((l) => l())).then(() => undefined)
  }

  /** Runs a money-moving operation under the wallet's spend lock (§5.4). */
  spend<T>(fn: () => Promise<T>): Promise<T> {
    this.requireUnlocked()
    return this.lock.withLock(`cashkit:${this.walletId}:spend`, fn)
  }
}

/** Token facts every holding row carries. */
/** A holding's bill, its zap fields included. */
export const billOf = (h: Pick<Holding, 'token' | 'zap'>): Bill => billFor(decodeToken(h.token), h.zap)

export function tokenFacts(token: string): { tok: Token; minterPubkey?: string; hubGroup: string } {
  const tok = decodeToken(token)
  const minter = verifyProvenance(tok)?.minter
  return { tok, ...(minter !== undefined && { minterPubkey: minter }), hubGroup: tok.hubGroup !== undefined ? toHex(tok.hubGroup) : '' }
}
