import { defineConfig, devices } from '@playwright/test'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const authFile = resolve(root, '.build/acceptance/playwright-auth.json')
const hasCredentials = Boolean(
  process.env.EASYPI_E2E_USERNAME && process.env.EASYPI_E2E_PASSWORD,
)
const channel = process.env.EASYPI_E2E_CHANNEL || undefined

export default defineConfig({
  testDir: '.',
  outputDir: resolve(root, '.build/acceptance/playwright-artifacts'),
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: resolve(root, '.build/acceptance/playwright-report'), open: 'never' }],
  ],
  use: {
    ...devices['Desktop Chrome'],
    baseURL: process.env.EASYPI_BASE_URL || 'http://127.0.0.1:5173',
    channel,
    ignoreHTTPSErrors: process.env.EASYPI_E2E_INSECURE === '1',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'off',
  },
  projects: [
    {
      name: 'public',
      testMatch: /public\.spec\.ts/,
    },
    {
      name: 'auth-setup',
      testMatch: /auth\.setup\.ts/,
    },
    {
      name: 'authenticated',
      testMatch: /(?:authenticated|control-inventory)\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'safe-interactions',
      testMatch: /safe-interactions\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'data-lifecycle',
      testMatch: /user-lifecycle\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'cloud-lifecycle',
      testMatch: /picloud-lifecycle\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'files-lifecycle',
      testMatch: /files-lifecycle\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'agent-live',
      testMatch: /agent-live\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'network-observe',
      testMatch: /network-observe\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'operations-live',
      testMatch: /operations-live\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'marketplace-help',
      testMatch: /marketplace-help\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'backup-live',
      testMatch: /backup(?:-restore)?-live\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
    {
      name: 'dns-rewrite-live',
      testMatch: /dns-rewrite-live\.spec\.ts/,
      dependencies: ['auth-setup'],
      use: hasCredentials ? { storageState: authFile } : {},
    },
  ],
})
