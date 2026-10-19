// A Lock on the Web Locks API (design §5.4): one holder per name across
// every tab and worker of this origin, so two tabs never move money at once.
// The browser releases a lock whose holder closes, so a crashed tab cannot
// wedge the others.
import type { Lock } from '../wallet/ports.js'

/** The slice of navigator.locks this needs. */
export interface LockManagerLike {
  request<T>(name: string, options: { mode: 'exclusive' }, callback: () => Promise<T>): Promise<T>
}

export class WebLocksLock implements Lock {
  private readonly locks: LockManagerLike

  constructor(locks?: LockManagerLike) {
    const found = locks ?? (globalThis as { navigator?: { locks?: LockManagerLike } }).navigator?.locks
    if (found === undefined) throw new Error('lock-weblocks: no navigator.locks in this environment')
    this.locks = found
  }

  /** Whether this environment has Web Locks. */
  static available(): boolean {
    return typeof (globalThis as { navigator?: { locks?: { request?: unknown } } }).navigator?.locks?.request === 'function'
  }

  withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    return this.locks.request(name, { mode: 'exclusive' }, fn)
  }
}
