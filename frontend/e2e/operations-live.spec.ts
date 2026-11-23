import { expect, test, type APIRequestContext, type BrowserContext } from '@playwright/test'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

const apiUrl = (origin: string, path: string) => new URL(path, origin).toString()

async function csrfHeaders(api: APIRequestContext, origin: string) {
  const response = await api.get(apiUrl(origin, '/api/v1/auth/csrf'))
  expect(response.ok()).toBe(true)
  return { 'X-CSRF-Token': String((await response.json()).csrf_token) }
}

test('terminal PTY, jobs, notification preferences and user boundaries work live', async ({ page, browser }) => {
  test.setTimeout(90_000)
  await page.goto('/dashboard')
  const origin = new URL(page.url()).origin
  const api = page.context().request
  const headers = await csrfHeaders(api, origin)
  const username = `e2e_ops_${Date.now().toString(36)}`
  const password = `E2e!Ops${Date.now()}Aa`
  let userId: number | null = null
  let userContext: BrowserContext | null = null

  const originalPreferencesResponse = await api.get(apiUrl(origin, '/api/v1/notifications/preferences'))
  expect(originalPreferencesResponse.status()).toBe(200)
  const originalPreferences = await originalPreferencesResponse.json()
  const preferencePayload = {
    enabled: originalPreferences.enabled,
    email: originalPreferences.email || null,
    alert_types: originalPreferences.alert_types,
    min_priority: originalPreferences.min_priority,
    max_emails_per_hour: originalPreferences.max_emails_per_hour,
    max_emails_per_day: originalPreferences.max_emails_per_day,
    digest_mode: originalPreferences.digest_mode,
    digest_interval_hours: originalPreferences.digest_interval_hours,
    quiet_hours_enabled: originalPreferences.quiet_hours_enabled,
    quiet_hours_start: originalPreferences.quiet_hours_start,
    quiet_hours_end: originalPreferences.quiet_hours_end,
  }

  try {
    const changedPreferences = await api.put(apiUrl(origin, '/api/v1/notifications/preferences'), {
      headers,
      data: { ...preferencePayload, quiet_hours_enabled: !preferencePayload.quiet_hours_enabled },
    })
    expect(changedPreferences.status()).toBe(200)
    expect((await changedPreferences.json()).quiet_hours_enabled).toBe(!preferencePayload.quiet_hours_enabled)

    const restoredPreferences = await api.put(apiUrl(origin, '/api/v1/notifications/preferences'), {
      headers,
      data: preferencePayload,
    })
    expect(restoredPreferences.status()).toBe(200)
    expect((await restoredPreferences.json()).quiet_hours_enabled).toBe(preferencePayload.quiet_hours_enabled)

    const jobsBefore = await api.get(apiUrl(origin, '/api/v1/jobs?limit=20'))
    expect(jobsBefore.status()).toBe(200)
    const jobsPayload = await jobsBefore.json()
    expect(Array.isArray(jobsPayload.jobs)).toBe(true)
    expect(jobsPayload.summary.total).toBe(jobsPayload.jobs.length)
    for (const job of jobsPayload.jobs) {
      expect(job).not.toHaveProperty('args')
      expect(job).not.toHaveProperty('script')
      expect(job).not.toHaveProperty('log_tail')
    }

    await page.goto('/settings?tab=notifications', { waitUntil: 'domcontentloaded' })
    await expect(page.getByText('Email alerts', { exact: true })).toBeVisible()
    await expect(page.getByText('SMTP server', { exact: true })).toBeVisible()
    await expect(page.getByText('Browser Push Notifications', { exact: true })).toBeVisible()

    let terminalWebSocketUrl = ''
    page.on('websocket', (socket) => {
      if (new URL(socket.url()).pathname === '/ws/terminal') terminalWebSocketUrl = socket.url()
    })

    await page.goto('/terminal', { waitUntil: 'domcontentloaded' })
    const terminalRows = page.locator('.xterm-rows')
    await expect(terminalRows).toContainText('EasyPi Terminal', { timeout: 20_000 })
    await page.locator('.xterm-helper-textarea').focus()
    await page.keyboard.type("printf '__EASYPI_TERMINAL_PASS__\\n'")
    await page.keyboard.press('Enter')
    await expect(terminalRows).toContainText('__EASYPI_TERMINAL_PASS__', { timeout: 10_000 })
    await page.setViewportSize({ width: 1180, height: 760 })
    await page.waitForTimeout(300)
    await expect(page.getByText('Connection Error')).toHaveCount(0)
    expect(new URL(terminalWebSocketUrl).search).toBe('')

    const jobsAfter = await api.get(apiUrl(origin, '/api/v1/jobs?limit=40'))
    expect(jobsAfter.status()).toBe(200)
    expect((await jobsAfter.json()).jobs.some((job: { title?: string }) =>
      String(job.title || '').includes('Terminal'))).toBe(true)

    const created = await api.post(apiUrl(origin, '/api/v1/users'), {
      headers,
      data: {
        username,
        email: `${username}@invalid.example`,
        password,
        role: 'user',
      },
    })
    expect(created.status()).toBe(201)
    userId = Number((await created.json()).id)

    userContext = await browser.newContext({ ignoreHTTPSErrors: true })
    const userApi = userContext.request
    const login = await userApi.post(apiUrl(origin, '/api/v1/auth/login'), {
      data: { username, password },
    })
    expect(login.status()).toBe(200)
    const userHeaders = await csrfHeaders(userApi, origin)

    expect((await userApi.get(apiUrl(origin, '/api/v1/notifications/preferences'))).status()).toBe(200)
    expect((await userApi.get(apiUrl(origin, '/api/v1/jobs'))).status()).toBe(403)
    expect((await userApi.get(apiUrl(origin, '/api/v1/notifications/smtp/config'))).status()).toBe(403)
    expect((await userApi.post(apiUrl(origin, '/api/v1/auth/terminal-ws-token'), {
      headers: userHeaders,
    })).status()).toBe(403)
  } finally {
    await userContext?.close()
    if (userId !== null) {
      const removed = await api.delete(apiUrl(origin, `/api/v1/users/${userId}`), { headers })
      expect([200, 404]).toContain(removed.status())
    }
    const restore = await api.put(apiUrl(origin, '/api/v1/notifications/preferences'), {
      headers,
      data: preferencePayload,
    })
    expect(restore.status()).toBe(200)
  }
})
