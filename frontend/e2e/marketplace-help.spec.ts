import { expect, test } from '@playwright/test'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

test('Marketplace is an honest read-only preview', async ({ page }) => {
  const marketplaceRequests: string[] = []
  page.on('request', (request) => {
    if (new URL(request.url()).pathname.startsWith('/api/v1/marketplace')) {
      marketplaceRequests.push(request.url())
    }
  })

  await page.goto('/marketplace')
  await expect(page.getByRole('heading', { name: 'Marketplace' })).toBeVisible()
  await expect(page.getByText('Marketplace is intentionally read-only right now.')).toBeVisible()
  await expect(page.getByText('Advanced Monitoring')).toBeVisible()
  await expect(page.getByText(/^4\.8$/)).toHaveCount(0)
  await expect(page.getByText(/^1234$/)).toHaveCount(0)

  const packageButtons = page.getByRole('button', { name: /Not Yet Installable|Planned For Later/ })
  await expect(packageButtons).toHaveCount(5)
  for (const button of await packageButtons.all()) {
    await expect(button).toBeDisabled()
  }

  await page.getByPlaceholder('Search planned packages...').fill('backup')
  await expect(page.getByText('Auto Backup to Cloud')).toBeVisible()
  await expect(page.getByText('Discord Notifications')).toHaveCount(0)
  expect(marketplaceRequests).toEqual([])
})

test('Help navigation is bounded, private, and honest about support', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('easypi-help-metrics', JSON.stringify({ state: { lastError: { message: 'SECRET' } } }))
  })
  await page.goto('/help')

  await expect(page.getByRole('heading', { name: 'Help & Support' })).toBeVisible()
  await expect(page.getByText('Common failure references')).toBeVisible()
  await expect(page.getByText(/These ERR_\* labels are Help search references/)).toBeVisible()
  await expect(page.getByText('Web support form is not connected yet')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Submit' })).toHaveCount(0)
  expect(await page.evaluate(() => localStorage.getItem('easypi-help-metrics'))).toBeNull()

  const search = page.getByPlaceholder(/Search for help/)
  await search.fill('x'.repeat(200))
  await expect(search).toHaveValue('x'.repeat(96))

  const github = page.getByRole('link', { name: /Contact/ })
  await expect(github).toHaveAttribute('href', 'https://github.com/NewNetGuard/EasyPi/issues')
  await expect(github).toHaveAttribute('rel', 'noopener noreferrer')

  await page.getByRole('button', { name: 'FAQ' }).click()
  await expect(page.locator('#faq')).toBeInViewport()
})
