import { expect, test } from '@playwright/test'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

test('Files lifecycle enforces active-content and path boundaries', async ({ page }) => {
  test.setTimeout(60_000)
  await page.goto('/files')
  const origin = new URL(page.url()).origin
  const apiUrl = (path: string) => new URL(path, origin).toString()
  const api = page.context().request
  const suffix = Date.now().toString(36)
  const folderPath = `/opt/EasyPi/data/e2e_files_${suffix}`
  const textPath = `${folderPath}/note_${suffix}.txt`
  const svgPath = `${folderPath}/active_${suffix}.svg`
  const pngPath = `${folderPath}/pixel_${suffix}.png`
  const textBody = `EasyPi acceptance ${suffix}`
  let folderCreated = false

  const csrfResponse = await api.get(apiUrl('/api/v1/auth/csrf'))
  expect(csrfResponse.ok()).toBe(true)
  const csrf = (await csrfResponse.json()).csrf_token as string
  const mutationHeaders = { 'X-CSRF-Token': csrf }

  try {
    const folder = await api.post(apiUrl('/api/v1/files/create-folder'), {
      headers: mutationHeaders,
      data: { path: folderPath },
    })
    expect(folder.status()).toBe(200)
    folderCreated = true

    const created = await api.post(apiUrl('/api/v1/files/create-file'), {
      headers: mutationHeaders,
      data: { path: textPath },
    })
    expect(created.status()).toBe(200)

    const written = await api.post(apiUrl('/api/v1/files/write'), {
      headers: mutationHeaders,
      data: { path: textPath, content: textBody },
    })
    expect(written.status()).toBe(200)

    const read = await api.get(apiUrl('/api/v1/files/read'), { params: { path: textPath } })
    expect(read.status()).toBe(200)
    expect((await read.json()).content).toBe(textBody)

    const listed = await api.get(apiUrl('/api/v1/files/list'), { params: { path: folderPath } })
    expect(listed.status()).toBe(200)
    expect(await listed.json()).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: textPath, type: 'file' }),
    ]))

    const searched = await api.get(apiUrl('/api/v1/files/search'), {
      params: { query: suffix, path: folderPath },
    })
    expect(searched.status()).toBe(200)
    expect(await searched.json()).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: textPath }),
    ]))

    const svg = await api.post(apiUrl('/api/v1/files/upload'), {
      headers: mutationHeaders,
      multipart: {
        path: svgPath,
        file: {
          name: `active_${suffix}.svg`,
          mimeType: 'image/svg+xml',
          buffer: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
        },
      },
    })
    expect(svg.status()).toBe(200)
    const svgPreview = await api.get(apiUrl('/api/v1/files/image'), { params: { path: svgPath } })
    expect(svgPreview.status()).toBe(400)

    const png = await api.post(apiUrl('/api/v1/files/upload'), {
      headers: mutationHeaders,
      multipart: {
        path: pngPath,
        file: {
          name: `pixel_${suffix}.png`,
          mimeType: 'image/png',
          buffer: Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
            'base64',
          ),
        },
      },
    })
    expect(png.status()).toBe(200)
    const pngPreview = await api.get(apiUrl('/api/v1/files/image'), { params: { path: pngPath } })
    expect(pngPreview.status()).toBe(200)
    expect(pngPreview.headers()['content-type']).toContain('image/png')
    expect(pngPreview.headers()['x-content-type-options']).toContain('nosniff')
    expect(pngPreview.headers()['content-security-policy']).toContain('sandbox')

    for (const blockedPath of ['/opt/EasyPi/.env', '/etc/passwd']) {
      const blocked = await api.get(apiUrl('/api/v1/files/read'), { params: { path: blockedPath } })
      expect(blocked.status()).toBe(403)
    }
  } finally {
    if (folderCreated) {
      const removed = await api.delete(apiUrl('/api/v1/files/delete'), {
        headers: mutationHeaders,
        data: { path: folderPath },
      })
      expect([200, 404]).toContain(removed.status())
    }
  }
})
