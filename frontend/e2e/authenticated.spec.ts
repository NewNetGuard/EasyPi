import { expect, test } from '@playwright/test'
import { authenticatedRoutes } from './routes'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

const applicationHost = new URL(
  process.env.EASYPI_BASE_URL || 'http://127.0.0.1:5173',
).hostname

test('all authenticated pages open without browser or server errors', async ({ page }) => {
  const failures: string[] = []
  let currentRoute = '<startup>'
  page.setDefaultNavigationTimeout(15_000)
  page.on('pageerror', (error) => failures.push(`${currentRoute}: page error: ${error.message}`))
  page.on('response', (response) => {
    const url = new URL(response.url())
    if (url.hostname === applicationHost && response.status() >= 500) {
      failures.push(`${currentRoute}: ${response.status()} ${url.pathname}`)
    }
  })

  for (const route of authenticatedRoutes) {
    currentRoute = route
    await test.step(route, async () => {
      try {
        await page.goto(route, { waitUntil: 'domcontentloaded', timeout: 15_000 })
        await expect(page).not.toHaveURL(/\/login(?:[/?#]|$)/)
        await expect(page.locator('main').first()).toBeVisible()
        await page.waitForTimeout(500)
      } catch (error) {
        failures.push(`${route}: ${error instanceof Error ? error.message : String(error)}`)
      }
    })
  }

  expect(failures).toEqual([])
})
