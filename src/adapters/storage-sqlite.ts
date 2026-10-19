// A Storage on SQLite (design §3), for Node ≥ 22 and Bun: `node:sqlite` by
// default, or any driver with the same prepare/exec shape (better-sqlite3,
// bun:sqlite) through `open`. Follows cashctl internal/store: WAL, a busy
// timeout, BEGIN IMMEDIATE for writes and migrations, and 0600 files.
//
// Writes go through one connection and one in-process queue; BEGIN
// IMMEDIATE takes SQLite's write lock up front, so two processes on one
// file serialise too, and the per-row version check runs under that lock.
// Reads use a second connection, so they never see a write in progress.
import { chmodSync, closeSync, existsSync, openSync } from 'node:fs'
import { resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { decodeRow, encodeRow } from '../wallet/codec.js'
import type { AppendOnly, Collection, NewRow, Row } from '../wallet/model.js'
import { ConcurrentUpdateError, type Query, type Storage, type StorageTx } from '../wallet/ports.js'

export interface SqliteStatement {
  run(...params: unknown[]): unknown
  get(...params: unknown[]): unknown
  all(...params: unknown[]): unknown[]
}

export interface SqliteDatabase {
  exec(sql: string): void
  prepare(sql: string): SqliteStatement
  close(): void
}

export interface SqliteStorageOptions {
  /** A file path. ':memory:' works but cannot be shared between instances. */
  readonly path: string
  /** Opens a connection; default `new DatabaseSync(path)` from node:sqlite. */
  readonly open?: (path: string) => SqliteDatabase
  /** How long a writer waits for another process's lock. Default 5 s. */
  readonly busyTimeoutMs?: number
}

export const SQLITE_SCHEMA_VERSION = 1

const MIGRATIONS: readonly string[] = [
  `CREATE TABLE cashkit_rows (
     coll TEXT NOT NULL,
     key TEXT NOT NULL,
     seq INTEGER NOT NULL,
     version INTEGER NOT NULL,
     body TEXT NOT NULL,
     PRIMARY KEY (coll, key)
   ) WITHOUT ROWID;
   CREATE INDEX cashkit_rows_order ON cashkit_rows (coll, seq);`,
]

function restrict(path: string): void {
  for (const p of [path, `${path}-wal`, `${path}-shm`]) {
    try {
      if (existsSync(p)) chmodSync(p, 0o600)
    } catch {
      // best-effort: a platform without POSIX modes
    }
  }
}

/**
 * One write queue per file for the whole process. node:sqlite is
 * synchronous: a second instance's BEGIN IMMEDIATE would block the thread
 * that the first instance's open transaction needs to finish, so instances
 * in one process take turns here; other processes wait on SQLite's lock.
 */
const writeQueues = new Map<string, Promise<unknown>>()

function readOnly(): never {
  throw new Error('storage: write in a read-only transaction')
}

interface RowRecord {
  seq: number
  version: number
  body: string
}

export class SqliteStorage implements Storage {
  private closed = false
  private last: Promise<unknown> = Promise.resolve()

  private constructor(
    private readonly writer: SqliteDatabase,
    private readonly reader: SqliteDatabase,
    private readonly queueKey: string,
  ) {}

  /** Opens (creating and migrating when needed) the store at `path`. */
  static async open(o: SqliteStorageOptions): Promise<SqliteStorage> {
    const memory = o.path === ':memory:'
    if (!memory && !existsSync(o.path)) closeSync(openSync(o.path, 'a', 0o600))
    const connect = o.open ?? ((p: string) => new DatabaseSync(p) as unknown as SqliteDatabase)
    const writer = connect(o.path)
    const busy = Math.max(0, Math.trunc(o.busyTimeoutMs ?? 5000))
    writer.exec(`PRAGMA busy_timeout = ${busy}`)
    if (!memory) writer.exec('PRAGMA journal_mode = WAL')
    writer.exec('PRAGMA foreign_keys = ON')
    migrate(writer)
    const reader = memory ? writer : connect(o.path)
    if (reader !== writer) reader.exec(`PRAGMA busy_timeout = ${busy}`)
    if (!memory) restrict(o.path)
    return new SqliteStorage(writer, reader, memory ? `:memory:${Math.random()}` : resolve(o.path))
  }

  async close(): Promise<void> {
    await this.last.catch(() => undefined)
    if (this.closed) return
    this.closed = true
    if (this.reader !== this.writer) this.reader.close()
    this.writer.close()
  }

  tx<T>(mode: 'r' | 'rw', fn: (t: StorageTx) => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new Error('storage: closed'))
    if (mode === 'r') return fn(this.view(this.reader, false))
    const run = (writeQueues.get(this.queueKey) ?? Promise.resolve()).then(async () => {
      this.writer.exec('BEGIN IMMEDIATE')
      try {
        const result = await fn(this.view(this.writer, true))
        this.writer.exec('COMMIT')
        return result
      } catch (err) {
        this.writer.exec('ROLLBACK')
        throw err
      }
    })
    const tail = run.catch(() => undefined)
    writeQueues.set(this.queueKey, tail)
    this.last = tail
    void tail.then(() => {
      if (writeQueues.get(this.queueKey) === tail) writeQueues.delete(this.queueKey)
    })
    return run
  }

  private view(db: SqliteDatabase, writable: boolean): StorageTx {
    const one = (c: Collection, key: string) => db.prepare('SELECT seq, version, body FROM cashkit_rows WHERE coll = ? AND key = ?').get(c, key) as RowRecord | undefined
    const nextSeq = (c: Collection) => (db.prepare('SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM cashkit_rows WHERE coll = ?').get(c) as { n: number }).n
    return {
      get: async <C extends Collection>(c: C, key: string) => {
        const r = one(c, key)
        return r === undefined ? undefined : decodeRow<Row<C>>(r.body)
      },
      list: async <C extends Collection>(c: C, q?: Query<C>) => {
        const rows = (db.prepare('SELECT body FROM cashkit_rows WHERE coll = ? ORDER BY seq').all(c) as { body: string }[]).map((r) => decodeRow<Row<C>>(r.body))
        const where = q?.where as Record<string, unknown> | undefined
        if (where === undefined) return rows
        return rows.filter((r) => Object.entries(where).every(([k, v]) => (r as Record<string, unknown>)[k] === v))
      },
      put: async <C extends Collection>(c: C, row: Row<C>, expectVersion?: number) => {
        if (!writable) readOnly()
        const key = (row as { id: string }).id
        const cur = one(c, key)
        if (expectVersion !== undefined && (cur?.version ?? 0) !== expectVersion) throw new ConcurrentUpdateError(c, key)
        const version = (row as { version?: number }).version ?? 0
        if (cur === undefined) db.prepare('INSERT INTO cashkit_rows (coll, key, seq, version, body) VALUES (?, ?, ?, ?, ?)').run(c, key, nextSeq(c), version, encodeRow(row))
        else db.prepare('UPDATE cashkit_rows SET version = ?, body = ? WHERE coll = ? AND key = ?').run(version, encodeRow(row), c, key)
      },
      insert: async <C extends AppendOnly>(c: C, row: NewRow<C>) => {
        if (!writable) readOnly()
        const seq = nextSeq(c)
        const key = `${c.slice(0, 1)}-${String(seq).padStart(10, '0')}`
        db.prepare('INSERT INTO cashkit_rows (coll, key, seq, version, body) VALUES (?, ?, ?, ?, ?)').run(c, key, seq, 0, encodeRow({ ...row, id: key }))
        return key
      },
      delete: async <C extends Collection>(c: C, key: string) => {
        if (!writable) readOnly()
        db.prepare('DELETE FROM cashkit_rows WHERE coll = ? AND key = ?').run(c, key)
      },
    }
  }
}

/** Brings the schema up to date under the write lock; refuses a newer one. */
function migrate(db: SqliteDatabase): void {
  db.exec('BEGIN IMMEDIATE')
  try {
    const v = (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version
    if (v > SQLITE_SCHEMA_VERSION) throw new Error(`storage: this database was written by a newer cashkit (schema ${v})`)
    for (let i = v; i < MIGRATIONS.length; i++) db.exec(MIGRATIONS[i]!)
    if (v < MIGRATIONS.length) db.exec(`PRAGMA user_version = ${MIGRATIONS.length}`)
    db.exec('COMMIT')
  } catch (err) {
    db.exec('ROLLBACK')
    throw err
  }
}
