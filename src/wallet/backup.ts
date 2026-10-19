// Backups (design §10): a versioned JSON of every collection, every
// secret re-sealed under a passphrase (scrypt with NIP-49's parameters, then
// XChaCha20-Poly1305), so a cleared or evicted store loses nothing. The
// format is documented in docs/design.md §10 so cashctl can import it.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { scrypt } from '@noble/hashes/scrypt.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'
import { toHex, utf8 } from '../core/index.js'
import { decodeRow, encodeRow } from './codec.js'
import type { Ctx } from './context.js'
import { CashkitError } from './errors.js'
import { COLLECTIONS, type Collection, type Rows, type Sealed } from './model.js'

export const BACKUP_FORMAT = 'cashkit-backup'
export const BACKUP_VERSION = 1
const AAD = utf8('cashkit/backup/v1')
const CHECK = 'cashkit backup key check'

/** The secret-bearing fields of each collection: every one is re-sealed, none travels in the clear. */
export const SEALED_FIELDS: Readonly<Partial<Record<Collection, readonly string[]>>> = {
  holdings: ['cashSecret', 'pendingCashSecret', 'pendingDestinationCashSecret', 'pendingThrowawayKey', 'throwawayKey'],
  handoffs: ['handoff'],
  connections: ['uri'],
  identity: ['priv'],
  pendingJoins: ['connectionSecret'],
}

/** Collections that carry value or a way to reach it: what makes a backup stale. */
const VALUE_BEARING: readonly Collection[] = ['holdings', 'handoffs', 'connections', 'identity', 'pendingJoins']

export interface BackupFile {
  readonly format: typeof BACKUP_FORMAT
  readonly version: number
  readonly walletId: string
  /** Unix seconds. */
  readonly createdAt: number
  readonly kdf: { readonly name: 'scrypt'; readonly logN: number; readonly r: 8; readonly p: 1; readonly salt: string }
  /** A known text sealed under the key: tells a wrong passphrase from a damaged file. */
  readonly check: string
  /** Rows as the codec writes them (bigint as {"$bigint": "…"}); secrets as { "sealed": "<base64 nonce‖ciphertext>" }. */
  readonly collections: Partial<Record<Collection, unknown[]>>
}

function deriveKey(passphrase: string, salt: Uint8Array, logN: number): Uint8Array {
  if (!Number.isInteger(logN) || logN < 1 || logN > 22) throw new CashkitError('invalid_input', 'backup: logN out of range')
  return scrypt(utf8(passphrase.normalize('NFKC')), salt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32, maxmem: 2 ** (logN + 11) })
}

function seal(key: Uint8Array, plain: Uint8Array, random: (n: number) => Uint8Array): string {
  const nonce = random(24)
  const ct = xchacha20poly1305(key, nonce, AAD).encrypt(plain)
  const out = new Uint8Array(24 + ct.length)
  out.set(nonce)
  out.set(ct, 24)
  return base64.encode(out)
}

function open(key: Uint8Array, data: string): Uint8Array {
  const raw = base64.decode(data)
  return xchacha20poly1305(key, raw.subarray(0, 24), AAD).decrypt(raw.subarray(24))
}

/** A fingerprint of every value-bearing row's id and version. */
export async function valueFingerprint(ctx: Ctx): Promise<string> {
  const parts: string[] = []
  await ctx.read(async (t) => {
    for (const c of VALUE_BEARING) for (const r of await t.list(c)) parts.push(`${c}/${r.id}/${(r as { version?: number }).version ?? 0}`)
  })
  return parts.length === 0 ? '' : toHex(sha256(utf8(parts.join('\n'))))
}

export async function exportBackup(ctx: Ctx, passphrase: string, o: { logN?: number } = {}): Promise<string> {
  if (passphrase === '') throw new CashkitError('usage', 'a backup needs a passphrase')
  ctx.requireUnlocked()
  const logN = o.logN ?? 16
  const salt = ctx.random(16)
  const key = deriveKey(passphrase, salt, logN)
  const snapshot = await ctx.read(async (t) => {
    const out: Partial<Record<Collection, unknown[]>> = {}
    for (const c of COLLECTIONS) out[c] = await t.list(c)
    return out
  })
  const collections: Partial<Record<Collection, unknown[]>> = {}
  for (const c of COLLECTIONS) {
    const fields = SEALED_FIELDS[c] ?? []
    const rows: unknown[] = []
    for (const r of snapshot[c] ?? []) {
      const row = { ...(r as Record<string, unknown>) }
      for (const f of fields) {
        const v = row[f] as Sealed | undefined
        if (v !== undefined) row[f] = { sealed: seal(key, await ctx.deps.vault.open(v), ctx.random) }
      }
      rows.push(row)
    }
    collections[c] = rows
  }
  const file: BackupFile = {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    walletId: ctx.walletId,
    createdAt: ctx.nowSeconds(),
    kdf: { name: 'scrypt', logN, r: 8, p: 1, salt: base64.encode(salt) },
    check: seal(key, utf8(CHECK), ctx.random),
    collections,
  }
  const text = encodeRow(file)
  // Remember what this backup covers, so state.backupStale can tell when it is behind.
  const fp = await valueFingerprint(ctx)
  await ctx.commit(async (t) => {
    const m = await t.get('meta', 'meta')
    if (m !== undefined) await t.put('meta', { ...m, lastBackupAt: ctx.now(), backupFingerprint: fp, version: m.version + 1 }, m.version)
  })
  return text
}

export interface ImportSummary {
  readonly walletId: string
  readonly holdings: number
  readonly handoffs: number
  readonly connections: number
  readonly identity: boolean
}

/**
 * Restores a backup into an empty wallet: every secret is opened with the
 * passphrase and re-sealed with this wallet's vault, and the wallet takes
 * the backup's id. A wallet that already holds anything is refused
 * (`exists`): merging two ledgers is not a restore.
 */
export async function importBackup(ctx: Ctx, text: string, passphrase: string): Promise<ImportSummary> {
  ctx.requireUnlocked()
  let file: BackupFile
  try {
    file = decodeRow<BackupFile>(text)
  } catch (err) {
    throw new CashkitError('invalid_input', 'this is not a cashkit backup: it is not JSON', { cause: err })
  }
  if (file?.format !== BACKUP_FORMAT) throw new CashkitError('invalid_input', 'this is not a cashkit backup')
  if (file.version > BACKUP_VERSION) throw new CashkitError('usage', `this backup was written by a newer cashkit (version ${file.version}); upgrade to import it`)
  if (file.kdf?.name !== 'scrypt' || typeof file.kdf.salt !== 'string') throw new CashkitError('invalid_input', 'this backup has no usable key parameters')
  const key = deriveKey(passphrase, base64.decode(file.kdf.salt), file.kdf.logN)
  try {
    open(key, file.check)
  } catch {
    throw new CashkitError('auth', 'wrong passphrase for this backup')
  }
  const rows: Partial<Record<Collection, Record<string, unknown>[]>> = {}
  for (const c of COLLECTIONS) {
    const fields = SEALED_FIELDS[c] ?? []
    const out: Record<string, unknown>[] = []
    for (const r of file.collections[c] ?? []) {
      const row = { ...(r as Record<string, unknown>) }
      for (const f of fields) {
        const v = row[f] as { sealed?: string } | undefined
        if (v === undefined) continue
        if (typeof v.sealed !== 'string') throw new CashkitError('invalid_input', `backup: ${c}.${f} is not sealed`)
        let plain: Uint8Array
        try {
          plain = open(key, v.sealed)
        } catch (err) {
          throw new CashkitError('invalid_input', `backup: ${c}.${f} of ${String(row['id'])} is damaged`, { cause: err })
        }
        row[f] = await ctx.deps.vault.seal(plain)
      }
      out.push(row)
    }
    rows[c] = out
  }
  const summary = await ctx.commit(async (t) => {
    for (const c of VALUE_BEARING) {
      if ((await t.list(c)).length > 0) throw new CashkitError('exists', 'this wallet is not empty; restore a backup into a fresh wallet')
    }
    for (const c of COLLECTIONS) {
      if (c === 'meta') continue
      for (const r of rows[c] ?? []) {
        if (c === 'settings') {
          const cur = await t.get('settings', 'settings')
          await t.put('settings', { ...(r as unknown as Rows['settings']), version: (cur?.version ?? 0) + 1 }, cur?.version ?? 0)
        } else if (c === 'activity') {
          const { id: _id, ...rest } = r
          await t.insert('activity', rest as never)
        } else {
          await t.put(c, r as never)
        }
      }
    }
    const m = await t.get('meta', 'meta')
    if (m !== undefined) {
      const { lastBackupAt: _a, backupFingerprint: _f, ...rest } = m
      await t.put('meta', { ...rest, walletId: file.walletId, version: m.version + 1 }, m.version)
    }
    return {
      walletId: file.walletId,
      holdings: (rows.holdings ?? []).length,
      handoffs: (rows.handoffs ?? []).length,
      connections: (rows.connections ?? []).length,
      identity: (rows.identity ?? []).length > 0,
    }
  })
  ctx.walletId = file.walletId
  return summary
}
