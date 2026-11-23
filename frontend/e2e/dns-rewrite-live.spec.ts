import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { expect, test } from '@playwright/test'

const run = promisify(execFile)
test.skip(
  !process.env.EASYPI_E2E_USERNAME
    || !process.env.EASYPI_E2E_PASSWORD
    || !process.env.EASYPI_E2E_SSH_TARGET,
  'test administrator credentials and SSH target were not supplied',
)

test('DNS rewrite reaches the real resolver and is removed cleanly', async ({ page }) => {
  test.setTimeout(60_000)
  const sshTarget = process.env.EASYPI_E2E_SSH_TARGET
  if (!sshTarget) throw new Error('missing SSH target')
  await page.goto('/guard')
  const origin = new URL(page.url()).origin
  const url = (path: string) => new URL(path, origin).toString()
  const api = page.context().request
  const csrfResponse = await api.get(url('/api/v1/auth/csrf'))
  expect(csrfResponse.status()).toBe(200)
  const headers = { 'X-CSRF-Token': String((await csrfResponse.json()).csrf_token) }
  const domain = `e2e-${Date.now().toString(36)}.invalid`
  let ruleId: string | null = null

  const resolve = async () => {
    const result = await run('ssh', [
      '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', sshTarget,
      `dig @127.0.0.1 ${domain} A +time=2 +tries=1 +short`,
    ], { timeout: 15_000 })
    return result.stdout.trim()
  }

  try {
    const created = await api.post(url('/api/v1/dns/rewrites'), {
      headers,
      data: {
        domain,
        answer: '203.0.113.77',
        rewrite_type: 'A',
        comment: 'EasyPi acceptance test',
        priority: 900,
        enabled: true,
      },
    })
    expect(created.status()).toBe(201)
    ruleId = String((await created.json()).id)

    const matched = await api.post(url('/api/v1/dns/rewrites/test'), {
      headers,
      data: { domain },
    })
    expect(matched.status()).toBe(200)
    expect(await matched.json()).toMatchObject({
      matched: true,
      rewritten_answer: '203.0.113.77',
      rewrite_type: 'A',
    })
    await expect.poll(resolve, { timeout: 5_000 }).toBe('203.0.113.77')

    const updated = await api.put(url(`/api/v1/dns/rewrites/${ruleId}`), {
      headers,
      data: { answer: '203.0.113.78' },
    })
    expect(updated.status()).toBe(200)
    expect((await updated.json()).answer).toBe('203.0.113.78')
    await expect.poll(resolve, { timeout: 5_000 }).toBe('203.0.113.78')
  } finally {
    if (ruleId !== null) {
      const removed = await api.delete(url(`/api/v1/dns/rewrites/${ruleId}`), { headers })
      expect([200, 404]).toContain(removed.status())
    }
  }

  await expect.poll(resolve, { timeout: 5_000 }).not.toBe('203.0.113.78')
})
