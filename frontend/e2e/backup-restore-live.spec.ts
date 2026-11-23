import { expect, test, type APIRequestContext, type Page } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { basename } from 'node:path'

test.use({ trace: 'off' })
test.skip(
  process.env.EASYPI_E2E_DESTRUCTIVE !== '1'
    || !process.env.EASYPI_E2E_USERNAME
    || !process.env.EASYPI_E2E_PASSWORD,
  'explicit destructive-test opt-in and administrator credentials are required',
)

const expectedDatabaseKind = String(process.env.EASYPI_E2E_DATABASE || 'sqlite').trim().toLowerCase()
const databaseLabel = expectedDatabaseKind === 'postgresql' ? 'PostgreSQL' : 'SQLite'

type UrlBuilder = (path: string) => string
type MutationHeaders = { 'X-CSRF-Token': string }

async function getMutationHeaders(
  api: APIRequestContext,
  url: UrlBuilder,
): Promise<MutationHeaders> {
  let csrfResponse = await api.get(url('/api/v1/auth/csrf'))
  if (csrfResponse.status() === 401) {
    const login = await api.post(url('/api/v1/auth/login'), {
      data: {
        username: process.env.EASYPI_E2E_USERNAME,
        password: process.env.EASYPI_E2E_PASSWORD,
      },
    })
    expect(login.status()).toBe(200)
    csrfResponse = await api.get(url('/api/v1/auth/csrf'))
  }
  expect(csrfResponse.status()).toBe(200)
  return { 'X-CSRF-Token': String((await csrfResponse.json()).csrf_token) }
}

async function assertExpectedDatabase(api: APIRequestContext, url: UrlBuilder) {
  expect(
    ['sqlite', 'postgresql'],
    'EASYPI_E2E_DATABASE must be either sqlite or postgresql',
  ).toContain(expectedDatabaseKind)
  const response = await api.get(url('/api/v1/health'), {
    params: { include_system: false, include_optional: false },
  })
  expect(response.status()).toBe(200)
  const payload = await response.json() as {
    services?: Array<{ name?: string, status?: string, details?: { type?: string } }>
  }
  const database = payload.services?.find(service => service.name === 'database')
  expect(database, 'detailed health response did not contain the database service').toBeDefined()
  expect(database?.status).toBe('healthy')
  expect(database?.details?.type).toBe(expectedDatabaseKind)
}

async function cleanupArtifacts(
  api: APIRequestContext,
  url: UrlBuilder,
  page: Page,
  backupId: number | null,
  username: string,
) {
  let lastError: unknown = null
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const headers = await getMutationHeaders(api, url)
      const usersResponse = await api.get(url('/api/v1/users'))
      expect(usersResponse.status()).toBe(200)
      for (const user of await usersResponse.json() as Array<{ id: number, username: string }>) {
        if (user.username === username) {
          const deleted = await api.delete(url(`/api/v1/users/${user.id}`), { headers })
          expect([200, 404]).toContain(deleted.status())
        }
      }
      if (backupId !== null) {
        const deleted = await api.delete(url(`/api/v1/backup/${backupId}`), { headers })
        expect([200, 404]).toContain(deleted.status())
      }
      return
    } catch (error) {
      lastError = error
      await page.waitForTimeout(1000)
    }
  }
  throw lastError
}

test(`${databaseLabel} config restore through Backup UI restores the database`, async ({ page }) => {
  test.setTimeout(300_000)
  await page.goto('/backup')

  const origin = new URL(page.url()).origin
  const url = (path: string) => new URL(path, origin).toString()
  const api = page.context().request
  await assertExpectedDatabase(api, url)
  const headers = await getMutationHeaders(api, url)
  const usersResponse = await api.get(url('/api/v1/users'))
  expect(usersResponse.status()).toBe(200)
  for (const user of await usersResponse.json() as Array<{ id: number, username: string }>) {
    if (user.username.startsWith('e2e_restore_')) {
      const deleted = await api.delete(url(`/api/v1/users/${user.id}`), { headers })
      expect(deleted.status()).toBe(200)
    }
  }
  const name = `E2E ${databaseLabel} Restore ${Date.now()}`
  const username = `e2e_restore_${Date.now().toString(36)}`
  const password = `E2e!${Date.now()}Aa`
  let backupId: number | null = null

  try {
    await page.getByRole('combobox').selectOption('config')
    await page.getByPlaceholder('Example: Pre-upgrade backup').fill(name)
    const createResponsePromise = page.waitForResponse(response =>
      response.request().method() === 'POST'
        && response.url() === url('/api/v1/backup/create'))
    await page.getByRole('button', { name: 'Start Backup' }).click()
    const createResponse = await createResponsePromise
    expect(createResponse.status()).toBe(200)
    backupId = Number((await createResponse.json()).id)
    expect(Number.isInteger(backupId) && backupId > 0).toBe(true)

    const row = page.getByRole('row').filter({ hasText: name })
    await expect(row).toContainText('Completed', { timeout: 120_000 })

    await page.goto('/users')
    await page.getByRole('button', { name: 'Add User' }).click()
    await page.getByPlaceholder('Enter username').fill(username)
    await page.getByPlaceholder('Enter email (optional)').fill(`${username}@invalid.example`)
    await page.getByPlaceholder('Enter password').fill(password)
    await page.getByRole('heading', { name: 'Create User' }).locator('..').locator('..')
      .getByRole('button', { name: 'Create', exact: true }).click()
    await expect(page.locator('tbody tr').filter({ hasText: username })).toBeVisible()

    const priorStatusResponse = await api.get(url('/api/v1/backup/restore-status'))
    const priorStatus = priorStatusResponse.status() === 200
      ? await priorStatusResponse.json() as { updated_at?: string | null }
      : { updated_at: null }
    await page.goto('/backup')
    const restoreRow = page.getByRole('row').filter({ hasText: name })
    await expect(restoreRow).toContainText('Completed')
    await restoreRow.getByRole('button', { name: 'Restore' }).click()
    await expect(page.getByRole('heading', { name: 'Restore Backup', exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Restore', exact: true }).last().click()

    let restoreStatus = ''
    for (let attempt = 0; attempt < 180; attempt += 1) {
      try {
        const response = await api.get(url('/api/v1/backup/restore-status'), { timeout: 5000 })
        if (response.status() === 401) {
          await getMutationHeaders(api, url)
          continue
        }
        if (response.status() === 200) {
          const result = await response.json() as { status?: string, updated_at?: string | null }
          if (result.updated_at && result.updated_at !== priorStatus.updated_at) {
            restoreStatus = String(result.status || '')
            if (restoreStatus === 'success' || restoreStatus.startsWith('failed')) break
          }
        }
      } catch {
        // The backend is deliberately restarted during restore.
      }
      await page.waitForTimeout(1000)
    }
    expect(restoreStatus).toBe('success')

    await assertExpectedDatabase(api, url)
    await page.goto('/users')
    await expect(page.locator('tbody tr').filter({ hasText: username })).toHaveCount(0)
  } finally {
    await cleanupArtifacts(api, url, page, backupId, username)
  }
})

test('restore health failure rolls back through Backup UI', async ({ page }) => {
  test.skip(!process.env.EASYPI_E2E_FAILURE_ARCHIVE, 'health-failure archive was not supplied')
  test.setTimeout(360_000)
  const archivePath = String(process.env.EASYPI_E2E_FAILURE_ARCHIVE)
  const archiveName = String(process.env.EASYPI_E2E_FAILURE_ARCHIVE_NAME || basename(archivePath))
  const currentPassword = String(process.env.EASYPI_E2E_PASSWORD)
  const username = `e2e_restore_${Date.now().toString(36)}`
  const password = `E2e!${Date.now()}Aa`

  await page.goto('/backup')
  const origin = new URL(page.url()).origin
  const url = (path: string) => new URL(path, origin).toString()
  const api = page.context().request
  await assertExpectedDatabase(api, url)
  let importedId: number | null = null

  try {
    const headers = await getMutationHeaders(api, url)
    const imported = await api.post(url('/api/v1/backup/import'), {
      headers,
      multipart: {
        current_password: currentPassword,
        archive: {
          name: archiveName,
          mimeType: 'application/octet-stream',
          buffer: await readFile(archivePath),
        },
      },
    })
    expect(imported.status()).toBe(200)
    importedId = Number((await imported.json()).id)
    expect(Number.isInteger(importedId) && importedId > 0).toBe(true)

    await page.goto('/users')
    await page.getByRole('button', { name: 'Add User' }).click()
    await page.getByPlaceholder('Enter username').fill(username)
    await page.getByPlaceholder('Enter email (optional)').fill(`${username}@invalid.example`)
    await page.getByPlaceholder('Enter password').fill(password)
    await page.getByRole('heading', { name: 'Create User' }).locator('..').locator('..')
      .getByRole('button', { name: 'Create', exact: true }).click()
    await expect(page.locator('tbody tr').filter({ hasText: username })).toBeVisible()

    const priorStatusResponse = await api.get(url('/api/v1/backup/restore-status'))
    const priorStatus = priorStatusResponse.status() === 200
      ? await priorStatusResponse.json() as { updated_at?: string | null }
      : { updated_at: null }
    await page.goto('/backup')
    const row = page.getByRole('row').filter({ hasText: `Imported ${archiveName}` })
    await expect(row).toContainText('Completed')
    await row.getByRole('button', { name: 'Restore' }).click()
    await expect(page.getByRole('heading', { name: 'Restore Backup', exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Restore', exact: true }).last().click()

    let restoreStatus = ''
    for (let attempt = 0; attempt < 240; attempt += 1) {
      try {
        const response = await api.get(url('/api/v1/backup/restore-status'), { timeout: 5000 })
        if (response.status() === 401) {
          await getMutationHeaders(api, url)
        } else if (response.status() === 200) {
          const result = await response.json() as { status?: string, updated_at?: string | null }
          if (result.updated_at && result.updated_at !== priorStatus.updated_at) {
            restoreStatus = String(result.status || '')
            if (restoreStatus === 'success' || restoreStatus.startsWith('failed')) break
          }
        }
      } catch {
        // Restore and rollback restart the backend.
      }
      await page.waitForTimeout(1000)
    }
    expect(restoreStatus).toBe('failed-rolled-back')

    await assertExpectedDatabase(api, url)
    await page.goto('/users')
    const restoredUser = page.locator('tbody tr').filter({ hasText: username })
    await expect(restoredUser).toBeVisible()
  } finally {
    await cleanupArtifacts(api, url, page, importedId, username)
  }
})
