import { expect, test } from '@playwright/test'

test.use({ trace: 'off' })
test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

test('encrypted config backup, recovery export and malformed import work live', async ({ page }) => {
  test.setTimeout(180_000)
  const currentPassword = process.env.EASYPI_E2E_PASSWORD
  if (!currentPassword) throw new Error('missing test administrator password')

  await page.goto('/backup')
  const origin = new URL(page.url()).origin
  const url = (path: string) => new URL(path, origin).toString()
  const api = page.context().request
  const csrfResponse = await api.get(url('/api/v1/auth/csrf'))
  expect(csrfResponse.status()).toBe(200)
  const headers = { 'X-CSRF-Token': String((await csrfResponse.json()).csrf_token) }
  const name = `E2E config ${Date.now()}`
  let backupId: number | null = null

  try {
    const created = await api.post(url('/api/v1/backup/create'), {
      headers,
      data: { type: 'config', name },
    })
    expect(created.status()).toBe(200)
    backupId = Number((await created.json()).id)

    let completed: { status?: string, error_message?: string | null } | null = null
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const status = await api.get(url(`/api/v1/backup/status/${backupId}`))
      expect(status.status()).toBe(200)
      completed = await status.json()
      if (completed?.status !== 'running') break
      await page.waitForTimeout(500)
    }
    expect(completed?.status, completed?.error_message || 'backup did not complete').toBe('completed')

    const listed = await api.get(url('/api/v1/backup/list'))
    expect(listed.status()).toBe(200)
    expect((await listed.json()).some((item: { id: number, name: string }) =>
      item.id === backupId && item.name === name)).toBe(true)

    const downloaded = await api.get(url(`/api/v1/backup/download/${backupId}`))
    expect(downloaded.status()).toBe(200)
    expect(downloaded.headers()['content-type']).toContain('application/octet-stream')
    expect(downloaded.headers()['content-disposition']).toContain('.epibak')
    expect(downloaded.headers()['x-content-type-options']).toContain('nosniff')
    expect((await downloaded.body()).subarray(0, 9).toString()).toBe('EASYPIBK1')

    const recoveryPassphrase = `E2E-Recovery-${Date.now()}-Only`
    const recovery = await api.post(url('/api/v1/backup/recovery-key/export'), {
      headers,
      data: {
        current_password: currentPassword,
        package_passphrase: recoveryPassphrase,
      },
    })
    expect(recovery.status()).toBe(200)
    expect(recovery.headers()['cache-control']).toContain('no-store')
    expect((await recovery.body()).subarray(0, 10).toString()).toBe('EASYPIKEY1')

    const malformed = await api.post(url('/api/v1/backup/import'), {
      headers,
      multipart: {
        current_password: currentPassword,
        archive: {
          name: 'config-2026-09-06-23-00.epibak',
          mimeType: 'application/octet-stream',
          buffer: Buffer.from('EASYPIBK1-invalid'),
        },
      },
    })
    expect(malformed.status()).toBe(400)
  } finally {
    if (backupId !== null) {
      const removed = await api.delete(url(`/api/v1/backup/${backupId}`), { headers })
      expect([200, 404]).toContain(removed.status())
    }
  }
})
