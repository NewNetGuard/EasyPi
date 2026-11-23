import { expect, test, type Page } from '@playwright/test'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

const isUsersRequest = (url: string) => new URL(url).pathname === '/api/v1/users'

async function loadUsers(page: Page): Promise<void> {
  const loaded = page.waitForResponse(
    (response) => response.request().method() === 'GET' && isUsersRequest(response.url()),
  )
  await page.goto('/users', { waitUntil: 'domcontentloaded' })
  expect((await loaded).ok()).toBe(true)
}

async function deleteRow(page: Page, row: ReturnType<Page['locator']>): Promise<void> {
  await row.getByTitle('Delete').click()
  const dialog = page.getByRole('heading', { name: 'Delete User' }).locator('..').locator('..')
  const deleted = page.waitForResponse(
    (response) => response.request().method() === 'DELETE'
      && new URL(response.url()).pathname.startsWith('/api/v1/users/'),
  )
  const refreshed = page.waitForResponse(
    (response) => response.request().method() === 'GET' && isUsersRequest(response.url()),
  )
  await dialog.getByRole('button', { name: 'Delete', exact: true }).click()
  expect((await deleted).ok()).toBe(true)
  expect((await refreshed).ok()).toBe(true)
}

test('temporary user can be created and removed', async ({ page }) => {
  test.setTimeout(60_000)
  const username = `e2e_${Date.now().toString(36)}`
  const password = `E2e!${Date.now()}Aa`

  const removeTestUsers = async () => {
    await loadUsers(page)
    let staleRows = page.locator('tbody tr').filter({ hasText: 'e2e_' })
    while (await staleRows.count()) {
      await deleteRow(page, staleRows.first())
      staleRows = page.locator('tbody tr').filter({ hasText: 'e2e_' })
    }
  }

  try {
    await removeTestUsers()
    await page.getByRole('button', { name: 'Add User' }).click()
    await page.getByPlaceholder('Enter username').fill(username)
    await page.getByPlaceholder('Enter email (optional)').fill(`${username}@invalid.example`)
    await page.getByPlaceholder('Enter password').fill(password)
    const created = page.waitForResponse(
      (response) => response.request().method() === 'POST' && isUsersRequest(response.url()),
    )
    const refreshed = page.waitForResponse(
      (response) => response.request().method() === 'GET' && isUsersRequest(response.url()),
    )
    await page.getByRole('heading', { name: 'Create User' }).locator('..').locator('..')
      .getByRole('button', { name: 'Create', exact: true }).click()
    expect((await created).status()).toBe(201)
    expect((await refreshed).ok()).toBe(true)

    const row = page.locator('tbody tr').filter({ hasText: username })
    await expect(row).toBeVisible()
    await expect(row).toContainText('User')
    await expect(row).toContainText('Active')
    await deleteRow(page, row)
    await expect(page.locator('tbody tr').filter({ hasText: username })).toHaveCount(0)
  } finally {
    await removeTestUsers()
  }
})
