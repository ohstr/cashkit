// An in-memory Storage (design §3), for tests and short-lived processes.
// Read-write transactions run one at a time; each stages its writes and
// applies them only if its callback resolves, so a throw rolls back.
import { ConcurrentUpdateError, type Query, type Storage, type StorageTx } from '../wallet/ports.js'
import type { AppendOnly, Collection, NewRow, Row } from '../wallet/model.js'

type Table = Map<string, unknown>
type Staged = Map<Collection, Map<string, unknown>>

const clone = <T>(v: T): T => structuredClone(v)

function matches(row: Record<string, unknown>, where: Record<string, unknown> | undefined): boolean {
  if (where === undefined) return true
  return Object.entries(where).every(([k, v]) => row[k] === v)
}

export class MemoryStorage implements Storage {
  private readonly tables = new Map<Collection, Table>()
  private queue: Promise<unknown> = Promise.resolve()
  private seq = 0

  private table(c: Collection): Table {
    let t = this.tables.get(c)
    if (t === undefined) {
      t = new Map()
      this.tables.set(c, t)
    }
    return t
  }

  tx<T>(mode: 'r' | 'rw', fn: (t: StorageTx) => Promise<T>): Promise<T> {
    if (mode === 'r') return fn(this.view(undefined))
    const run = this.queue.then(async () => {
      const staged: Staged = new Map()
      const result = await fn(this.view(staged))
      // Commit: every write, or none of them.
      for (const [c, writes] of staged) {
        const t = this.table(c)
        for (const [k, v] of writes) {
          if (v === undefined) t.delete(k)
          else t.set(k, v)
        }
      }
      return result
    })
    this.queue = run.catch(() => undefined)
    return run
  }

  private view(staged: Staged | undefined): StorageTx {
    const read = (c: Collection, key: string): unknown => {
      const s = staged?.get(c)
      if (s?.has(key)) return s.get(key)
      return this.table(c).get(key)
    }
    const write = (c: Collection, key: string, v: unknown) => {
      if (staged === undefined) throw new Error('storage: write in a read-only transaction')
      let s = staged.get(c)
      if (s === undefined) {
        s = new Map()
        staged.set(c, s)
      }
      s.set(key, v)
    }
    return {
      get: async <C extends Collection>(c: C, key: string) => {
        const v = read(c, key)
        return v === undefined ? undefined : (clone(v) as Row<C>)
      },
      list: async <C extends Collection>(c: C, q?: Query<C>) => {
        const keys = new Set(this.table(c).keys())
        for (const k of staged?.get(c)?.keys() ?? []) keys.add(k)
        const out: Row<C>[] = []
        for (const k of keys) {
          const v = read(c, k) as Record<string, unknown> | undefined
          if (v !== undefined && matches(v, q?.where as Record<string, unknown> | undefined)) out.push(clone(v) as Row<C>)
        }
        return out
      },
      put: async <C extends Collection>(c: C, row: Row<C>, expectVersion?: number) => {
        const key = (row as { id: string }).id
        if (expectVersion !== undefined) {
          const cur = read(c, key) as { version?: number } | undefined
          if ((cur?.version ?? 0) !== expectVersion) throw new ConcurrentUpdateError(c, key)
        }
        write(c, key, clone(row))
      },
      insert: async <C extends AppendOnly>(c: C, row: NewRow<C>) => {
        const key = `${c.slice(0, 1)}-${String(++this.seq).padStart(10, '0')}`
        write(c, key, clone({ ...row, id: key }))
        return key
      },
      delete: async <C extends Collection>(c: C, key: string) => {
        write(c, key, undefined)
      },
    }
  }
}
