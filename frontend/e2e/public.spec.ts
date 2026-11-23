import { expect, test } from '@playwright/test'

test('login UI loads and registration status is reachable', async ({ page }) => {
  const serverErrors: string[] = []
  page.on('pageerror', (error) => serverErrors.push(`page error: ${error.message}`))
  page.on('response', (response) => {
    if (response.status() >= 500) {
      serverErrors.push(`${response.status()} ${response.url()}`)
    }
  })

  await page.goto('/login')
  await expect(page.getByPlaceholder('Enter username')).toBeVisible()
  await expect(page.getByPlaceholder(/Enter password|Create a strong password/)).toBeVisible()
  await expect.poll(() => serverErrors).toEqual([])
})

test('protected page redirects an anonymous browser to login', async ({ page }) => {
  await page.goto('/dashboard')
  await expect(page).toHaveURL(/\/login(?:[/?#]|$)/)
})
