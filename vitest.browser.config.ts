// The browser run (design §12): IndexedDB, Web Locks, BroadcastChannel,
// WebCrypto and WebSocket as a real Chromium provides them. `just browser`.
import { playwright } from '@vitest/browser-playwright'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/browser/**/*.browser.test.ts'],
    globalSetup: ['test/browser/globalSetup.ts'],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }],
    },
  },
})
