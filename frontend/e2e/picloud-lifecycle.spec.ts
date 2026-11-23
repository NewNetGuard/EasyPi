import { expect, test } from '@playwright/test'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

const encodedId = (value: string) => value.split('/').map(encodeURIComponent).join('/')

test('PiCloud active-content lifecycle stays downloadable and cleans up', async ({ page, request }) => {
  test.setTimeout(60_000)
  await page.goto('/picloud')
  const origin = new URL(page.url()).origin
  const apiUrl = (path: string) => new URL(path, origin).toString()
  const api = page.context().request
  const suffix = Date.now().toString(36)
  const folderPath = `/e2e_${suffix}`
  const payloads = [
    {
      name: `active_${suffix}.html`,
      mimeType: 'text/html',
      body: '<!doctype html><script>document.body.dataset.executed="yes"</script>',
      thumbnailStatus: 200,
    },
    {
      name: `active_${suffix}.svg`,
      mimeType: 'image/svg+xml',
      body: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
      thumbnailStatus: 404,
    },
  ]
  const fileIds: string[] = []
  const shareIds: string[] = []
  let folderId: string | null = null

  const csrfResponse = await api.get(apiUrl('/api/v1/auth/csrf'))
  expect(csrfResponse.ok()).toBe(true)
  const csrf = (await csrfResponse.json()).csrf_token as string
  const mutationHeaders = { 'X-CSRF-Token': csrf }

  const remove = async (url: string, params?: Record<string, string | boolean>) => {
    const response = await api.delete(apiUrl(url), { headers: mutationHeaders, params })
    expect([200, 404]).toContain(response.status())
  }

  try {
    const folder = await api.post(apiUrl('/api/v1/picloud/folder'), {
      headers: mutationHeaders,
      params: { path: folderPath },
    })
    expect(folder.status()).toBe(200)
    folderId = (await folder.json()).id as string

    for (const payload of payloads) {
      const uploaded = await api.post(apiUrl('/api/v1/picloud/upload'), {
        headers: mutationHeaders,
        multipart: {
          path: folderPath,
          auto_sort: 'false',
          files: {
            name: payload.name,
            mimeType: payload.mimeType,
            buffer: Buffer.from(payload.body),
          },
        },
      })
      expect(uploaded.status()).toBe(200)
      const data = await uploaded.json()
      const fileId = data.uploaded[0].id as string
      fileIds.push(fileId)

      const downloaded = await api.get(apiUrl(`/api/v1/picloud/file/${encodedId(fileId)}/download`))
      expect(downloaded.status()).toBe(200)
      expect(downloaded.headers()['content-type']).toContain('application/octet-stream')
      expect(downloaded.headers()['content-disposition']).toContain('attachment')
      expect(downloaded.headers()['x-content-type-options']).toContain('nosniff')
      expect(downloaded.headers()['content-security-policy']).toContain('sandbox')
      expect(await downloaded.text()).toBe(payload.body)

      const thumbnail = await api.get(apiUrl(`/api/v1/picloud/thumbnail/${encodedId(fileId)}`))
      expect(thumbnail.status()).toBe(payload.thumbnailStatus)
      if (payload.thumbnailStatus === 200) {
        expect(thumbnail.headers()['content-type']).toContain('image/jpeg')
        expect(thumbnail.headers()['x-content-type-options']).toContain('nosniff')
        expect(thumbnail.headers()['content-security-policy']).toContain('sandbox')
      }
    }

    const publicShare = await api.post(apiUrl('/api/v1/picloud/share'), {
      headers: mutationHeaders,
      data: { file_id: fileIds[0], hours: 1 },
    })
    expect(publicShare.status()).toBe(200)
    const publicShareData = await publicShare.json()
    shareIds.push(publicShareData.id)
    const publicPath = new URL(publicShareData.url, process.env.EASYPI_BASE_URL).pathname
    const publicDownload = await request.get(apiUrl(publicPath))
    expect(publicDownload.status()).toBe(200)
    expect(publicDownload.headers()['content-disposition']).toContain('attachment')
    expect(publicDownload.headers()['x-content-type-options']).toContain('nosniff')

    const protectedShare = await api.post(apiUrl('/api/v1/picloud/share'), {
      headers: mutationHeaders,
      data: { file_id: fileIds[1], hours: 1, password: 'E2eShare!123' },
    })
    expect(protectedShare.status()).toBe(200)
    const protectedShareData = await protectedShare.json()
    shareIds.push(protectedShareData.id)
    const protectedToken = new URL(
      protectedShareData.url,
      process.env.EASYPI_BASE_URL,
    ).pathname.split('/').pop()
    const publicCsrfResponse = await request.get(apiUrl('/api/v1/auth/csrf'))
    expect(publicCsrfResponse.ok()).toBe(true)
    const publicCsrf = (await publicCsrfResponse.json()).csrf_token as string
    const protectedDownload = await request.post(apiUrl(`/api/v1/picloud/share-access/${protectedToken}`), {
      headers: { 'X-CSRF-Token': publicCsrf },
      data: { password: 'E2eShare!123' },
    })
    expect(protectedDownload.status()).toBe(200)
    expect(protectedDownload.headers()['content-disposition']).toContain('attachment')
    expect(protectedDownload.headers()['x-content-type-options']).toContain('nosniff')
  } finally {
    for (const shareId of shareIds) {
      await remove(`/api/v1/picloud/share/${encodeURIComponent(shareId)}`)
    }
    for (const fileId of fileIds) {
      await remove('/api/v1/picloud/file', { file_id: fileId, permanent: true })
    }
    if (folderId) {
      await remove('/api/v1/picloud/file', { file_id: folderId })
      const trashResponse = await api.get(apiUrl('/api/v1/picloud/trash'))
      expect(trashResponse.ok()).toBe(true)
      const trash = await trashResponse.json() as Array<{ id: string; original: string }>
      const item = trash.find((entry) => `/${entry.original.replace(/^\/+/, '')}` === folderPath)
      if (item) await remove(`/api/v1/picloud/trash/${encodeURIComponent(item.id)}`)
    }
  }
})
