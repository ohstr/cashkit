// A per-process Lock (design §5.4): one holder per name at a time, FIFO.
import type { Lock } from '../wallet/ports.js'

export class MemoryLock implements Lock {
  private readonly tails = new Map<string, Promise<unknown>>()

  withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(name) ?? Promise.resolve()
    const run = prev.then(fn)
    const tail = run.catch(() => undefined)
    this.tails.set(name, tail)
    void tail.then(() => {
      if (this.tails.get(name) === tail) this.tails.delete(name)
    })
    return run
  }
}
