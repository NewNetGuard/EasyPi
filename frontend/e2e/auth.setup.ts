import { expect, test as setup } from '@playwright/test'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const authFile = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../.build/acceptance/playwright-auth.json',
)
const hasCredentials = Boolean(
  process.env.EASYPI_E2E_USERNAME && process.env.EASYPI_E2E_PASSWORD,
)

setup.skip(!hasCredentials, 'test administrator credentials were not supplied')

setup('authenticate test administrator', async ({ page }) => {
  const username = process.env.EASYPI_E2E_USERNAME
  const password = process.env.EASYPI_E2E_PASSWORD
  if (!username || !password) throw new Error('missing test credentials')

  await page.goto('/login')
  await page.getByPlaceholder('Enter username').fill(username)
  await page.getByPlaceholder(/Enter password|Create a strong password/).fill(password)
  await page.locator('button[type="submit"]').click()

  const totp = process.env.EASYPI_E2E_TOTP
  const totpInput = page.getByPlaceholder('000000')
  if (await totpInput.isVisible().catch(() => false)) {
    if (!totp) {
      throw new Error('This account requires EASYPI_E2E_TOTP')
    }
    await totpInput.fill(totp)
    await page.locator('button[type="submit"]').click()
  }

  await expect(page).toHaveURL(/\/dashboard(?:[/?#]|$)/)
  await page.context().storageState({ path: authFile })
})
