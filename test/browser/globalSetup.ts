// Runs in Node before the browser run: starts the mini relay the browser's
// own WebSocket talks to, and hands its URL to the tests.
import type { TestProject } from 'vitest/node'
import { MiniRelay } from '../miniRelay.js'

declare module 'vitest' {
  export interface ProvidedContext {
    relayUrl: string
  }
}

export default async function setup(project: TestProject) {
  const relay = await MiniRelay.start()
  project.provide('relayUrl', relay.url)
  return () => relay.stop()
}
