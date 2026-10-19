// A Storage on IndexedDB (design §3), for browsers and PWAs. Rows are stored
// with structured clone, so bigint amounts survive as they are.
//
// IndexedDB commits a transaction as soon as nothing is pending on it, so a
// callback that awaits anything but this tx's own operations (a network
// call, a vault seal) finds the transaction gone: the engine never does
// that (§3), and this adapter is where breaking the rule shows.
//
// Readwrite transactions over the same store are serialised by the browser,
// across tabs too, and the per-row version check runs inside the one that
// writes, so it is atomic.
import type { AppendOnly, Collection, NewRow, Row } from '../wallet/model.js'
import { ConcurrentUpdateError, type Query, type Storage, type StorageTx } from '../wallet/ports.js'

export interface IndexedDbStorageOptions {
  /** Database name; one wallet per name. Default "cashkit". */
  readonly name?: string
  /** Default globalThis.indexedDB. */
  readonly indexedDB?: IDBFactory
}

const ROWS = 'rows'
const SEQ = 'seq'
const BY_COLL = 'byColl'

interface Record_ {
  coll: string
  key: string
  seq: number
  version: number
  row: unknown
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.addEventListener('success', () => resolve(r.result))
    r.addEventListener('error', () => reject(r.error ?? new Error('indexeddb: request failed')))
  })
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.addEventListener('complete', () => resolve())
    tx.addEventListener('abort', () => reject(tx.error ?? new Error('indexeddb: transaction aborted')))
    tx.addEventListener('error', () => reject(tx.error ?? new Error('indexeddb: transaction failed')))
  })
}

function readOnly(): never {
  throw new Error('storage: write in a read-only transaction')
}

export class IndexedDbStorage implements Storage {
  private constructor(private readonly db: IDBDatabase) {}

  static async open(o: IndexedDbStorageOptions = {}): Promise<IndexedDbStorage> {
    const factory = o.indexedDB ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB
    if (factory === undefined) throw new Error('storage-indexeddb: no indexedDB in this environment')
    const open = factory.open(o.name ?? 'cashkit', 1)
    open.addEventListener('upgradeneeded', () => {
      const db = open.result
      if (!db.objectStoreNames.contains(ROWS)) db.createObjectStore(ROWS, { keyPath: ['coll', 'key'] }).createIndex(BY_COLL, 'coll')
      if (!db.objectStoreNames.contains(SEQ)) db.createObjectStore(SEQ, { keyPath: 'coll' })
    })
    const db = await req(open)
    // Another tab upgrading the schema: let it, rather than block it.
    db.addEventListener('versionchange', () => db.close())
    return new IndexedDbStorage(db)
  }

  close(): void {
    this.db.close()
  }

  async tx<T>(mode: 'r' | 'rw', fn: (t: StorageTx) => Promise<T>): Promise<T> {
    const tx = this.db.transaction([ROWS, SEQ], mode === 'rw' ? 'readwrite' : 'readonly')
    const finished = done(tx)
    let result: T
    try {
      result = await fn(this.view(tx, mode === 'rw'))
    } catch (err) {
      try {
        tx.abort()
      } catch {
        // already finished
      }
      await finished.catch(() => undefined)
      throw err
    }
    await finished
    return result
  }

  private view(tx: IDBTransaction, writable: boolean): StorageTx {
    const rows = tx.objectStore(ROWS)
    const seqs = tx.objectStore(SEQ)
    const nextSeq = async (c: string): Promise<number> => {
      const cur = (await req(seqs.get(c))) as { coll: string; n: number } | undefined
      const n = (cur?.n ?? 0) + 1
      await req(seqs.put({ coll: c, n }))
      return n
    }
    return {
      get: async <C extends Collection>(c: C, key: string) => {
        const r = (await req(rows.get([c, key]))) as Record_ | undefined
        return r === undefined ? undefined : (r.row as Row<C>)
      },
      list: async <C extends Collection>(c: C, q?: Query<C>) => {
        // By plain key, not a key range: no IDBKeyRange global is needed.
        const all = (await req(rows.index(BY_COLL).getAll(c))) as Record_[]
        // oxlint-disable-next-line unicorn/no-array-sort -- sorts the fresh result array
        const out = all.sort((a, b) => a.seq - b.seq).map((r) => r.row as Row<C>)
        const where = q?.where as Record<string, unknown> | undefined
        if (where === undefined) return out
        return out.filter((r) => Object.entries(where).every(([k, v]) => (r as Record<string, unknown>)[k] === v))
      },
      put: async <C extends Collection>(c: C, row: Row<C>, expectVersion?: number) => {
        if (!writable) readOnly()
        const key = (row as { id: string }).id
        const cur = (await req(rows.get([c, key]))) as Record_ | undefined
        if (expectVersion !== undefined && (cur?.version ?? 0) !== expectVersion) throw new ConcurrentUpdateError(c, key)
        const seq = cur?.seq ?? (await nextSeq(c))
        await req(rows.put({ coll: c, key, seq, version: (row as { version?: number }).version ?? 0, row } satisfies Record_))
      },
      insert: async <C extends AppendOnly>(c: C, row: NewRow<C>) => {
        if (!writable) readOnly()
        const seq = await nextSeq(c)
        const key = `${c.slice(0, 1)}-${String(seq).padStart(10, '0')}`
        await req(rows.put({ coll: c, key, seq, version: 0, row: { ...row, id: key } } satisfies Record_))
        return key
      },
      delete: async <C extends Collection>(c: C, key: string) => {
        if (!writable) readOnly()
        await req(rows.delete([c, key]))
      },
    }
  }
}
