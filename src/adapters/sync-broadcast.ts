// A SyncChannel on BroadcastChannel (design §5.4): after a commit a tab
// says so, and every other tab of the same wallet reloads its state. The
// message carries the wallet id and a time, never a row or a secret.
import type { SyncChannel, SyncMessage } from '../wallet/ports.js'

export class BroadcastSync implements SyncChannel {
  private readonly channel: BroadcastChannel

  constructor(name = 'cashkit') {
    if (typeof BroadcastChannel === 'undefined') throw new Error('sync-broadcast: no BroadcastChannel in this environment')
    this.channel = new BroadcastChannel(name)
  }

  static available(): boolean {
    return typeof BroadcastChannel !== 'undefined'
  }

  post(msg: SyncMessage): void {
    // oxlint-disable-next-line unicorn/require-post-message-target-origin -- BroadcastChannel.postMessage takes no target origin
    this.channel.postMessage(msg)
  }

  subscribe(fn: (msg: SyncMessage) => void): () => void {
    const listener = (e: MessageEvent) => {
      const m = e.data as Partial<SyncMessage> | null
      if (m !== null && typeof m === 'object' && typeof m.walletId === 'string' && typeof m.at === 'number') fn({ walletId: m.walletId, at: m.at })
    }
    this.channel.addEventListener('message', listener)
    return () => this.channel.removeEventListener('message', listener)
  }

  close(): void {
    this.channel.close()
  }
}
