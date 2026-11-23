import { expect, test } from '@playwright/test'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

const cases = [
  {
    route: '/network',
    buttons: ['LAN Scanner', 'Port Scanner', 'Speed Test', 'Traffic Graph', 'Active Connections', 'ARP Scanner', 'Port Alerts'],
  },
  {
    route: '/cloud',
    buttons: ['My Files', 'Recent', 'Trash', 'Telegram Bot', 'Photos', 'Videos', 'Documents', 'Music', 'Encrypted Files', 'Refresh Cloud'],
  },
  {
    route: '/guard',
    buttons: ['Dashboard', 'Ad/Tracker AI', 'New Domains', 'Shadow Mode', 'AI Engine', 'Parental Controls', 'Schedules', 'Devices', 'Ad Blocking', 'Lists', 'Firewall', 'Query Log', 'Security Monitor', 'Statistics', 'DNS Settings', 'Advanced'],
  },
  {
    route: '/notifications',
    buttons: ['Refresh', 'All', 'Needs attention', 'Jobs', 'Security', 'Watchdog', 'Push'],
  },
  {
    route: '/devices',
    buttons: ['Cameras', 'Recordings'],
  },
  {
    route: '/settings',
    buttons: ['Light', 'Dark', 'System', 'General', 'Notifications', 'Security', 'User'],
  },
  {
    route: '/help',
    buttons: ['Getting Started', 'FAQ', 'Troubleshooting', 'Tutorials', 'Contact Support'],
  },
] as const

const applicationHost = new URL(
  process.env.EASYPI_BASE_URL || 'http://127.0.0.1:5173',
).hostname

test('safe tabs, filters and refresh controls work', async ({ page }) => {
  test.setTimeout(90_000)
  const failures: string[] = []
  let location = '<startup>'
  page.setDefaultNavigationTimeout(15_000)
  page.on('pageerror', (error) => failures.push(`${location}: page error: ${error.message}`))
  page.on('response', (response) => {
    const url = new URL(response.url())
    if (url.hostname === applicationHost && response.status() >= 500) {
      failures.push(`${location}: ${response.status()} ${url.pathname}`)
    }
  })

  for (const scenario of cases) {
    await page.goto(scenario.route, { waitUntil: 'domcontentloaded', timeout: 15_000 })
    await expect(page).not.toHaveURL(/\/login(?:[/?#]|$)/)
    for (const name of scenario.buttons) {
      location = `${scenario.route} -> ${name}`
      await test.step(location, async () => {
        const button = page.getByRole('button', { name: new RegExp(`^${name}`) }).first()
        try {
          await expect(button).toBeVisible({ timeout: 1_500 })
          await button.click({ timeout: 3_000 })
          await page.waitForTimeout(250)
        } catch (error) {
          failures.push(`${location}: ${error instanceof Error ? error.message : String(error)}`)
        }
      })
    }
  }

  expect(failures).toEqual([])
})
