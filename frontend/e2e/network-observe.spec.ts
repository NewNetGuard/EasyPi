import { expect, test } from '@playwright/test'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

test('network, Guard, PRISM and Chameleon expose consistent live state', async ({ page }) => {
  test.setTimeout(90_000)
  await page.goto('/network')
  const origin = new URL(page.url()).origin
  const apiUrl = (path: string) => new URL(path, origin).toString()
  const api = page.context().request

  const csrfResponse = await api.get(apiUrl('/api/v1/auth/csrf'))
  expect(csrfResponse.ok()).toBe(true)
  const csrf = (await csrfResponse.json()).csrf_token as string
  const mutationHeaders = { 'X-CSRF-Token': csrf }

  const getJson = async (path: string, params?: Record<string, string | number | boolean>) => {
    const response = await api.get(apiUrl(path), { params })
    expect(response.status(), `${path}: ${await response.text()}`).toBe(200)
    return response.json()
  }

  const networkInfo = await getJson('/api/network-toolkit/network-info')
  expect(networkInfo).toEqual(expect.objectContaining({ success: expect.any(Boolean) }))
  const info = networkInfo.data ?? {}
  expect(info.localIp).toMatch(/^\d{1,3}(?:\.\d{1,3}){3}$/)
  expect(info.gateway).toMatch(/^\d{1,3}(?:\.\d{1,3}){3}$/)
  expect(info.interface).toEqual(expect.any(String))

  const [traffic, trafficStats, arp, gateway, gatewayVerify] = await Promise.all([
    getJson('/api/network-toolkit/traffic', { duration: 10 }),
    getJson('/api/network-toolkit/traffic/stats'),
    getJson('/api/network-toolkit/arp-scan'),
    getJson('/api/network-toolkit/gateway-mode/status'),
    getJson('/api/network-toolkit/gateway-mode/verify'),
  ])
  for (const result of [traffic, trafficStats, arp]) {
    expect(result).toEqual(expect.objectContaining({ success: expect.any(Boolean) }))
  }

  const connectionsResponse = await api.post(apiUrl('/api/network-toolkit/connections'), {
    headers: mutationHeaders,
    data: {},
  })
  expect(connectionsResponse.status()).toBe(200)
  const connections = await connectionsResponse.json()
  expect(connections).toEqual(expect.objectContaining({ success: expect.any(Boolean) }))

  const dns = await getJson('/api/network/dns', { domain: 'example.com' })
  expect(dns).toEqual(expect.objectContaining({ domain: 'example.com' }))
  expect(dns.addresses ?? dns.records ?? []).not.toHaveLength(0)

  const ping = await getJson('/api/network/ping', { target: info.gateway })
  expect(ping).toEqual(expect.objectContaining({ target: info.gateway }))

  const [guardStatus, guardDashboard, guardStats, guardMetrics, shadowSettings, shadowStats] = await Promise.all([
    getJson('/api/v1/netprotection/status/full'),
    getJson('/api/v1/netprotection/dashboard'),
    getJson('/api/v1/netprotection/stats', { period: '24h' }),
    getJson('/api/v1/netprotection/metrics'),
    getJson('/api/v1/netprotection/settings/shadow-mode'),
    getJson('/api/v1/netprotection/shadow/stats'),
  ])
  expect(guardStatus.running ?? guardStatus.service_status === 'active').toBe(true)
  expect(shadowSettings).toEqual(expect.objectContaining({ success: true, data: expect.any(Object) }))
  expect(shadowStats).toEqual(expect.objectContaining({ success: true, data: expect.any(Object) }))

  const prism = await getJson('/api/v1/network-activity/queries/prism', { limit: 50 })
  expect(prism.data).toEqual(expect.any(Array))
  for (const row of prism.data) {
    expect(row.queryType).toMatch(/^(TLS|QUIC)$/)
    expect(row.source).toBe('prism')
  }

  const stealth = await getJson('/api/v1/netprotection/stealth/status')
  expect(stealth).toEqual(expect.objectContaining({
    configured: expect.any(Boolean),
    enabled: expect.any(Boolean),
    running: expect.any(Boolean),
    connected: expect.any(Boolean),
    has_psk: expect.any(Boolean),
  }))
  if (!stealth.configured) {
    expect(stealth).toEqual(expect.objectContaining({
      enabled: false,
      running: false,
      connected: false,
      has_psk: false,
    }))
  }
  if (stealth.configured) expect(stealth.has_psk).toBe(true)
  if (stealth.enabled) expect(stealth.configured).toBe(true)
  if (stealth.running) {
    expect(stealth.configured).toBe(true)
    expect(stealth.enabled).toBe(true)
  }
  if (stealth.connected) {
    expect(stealth.configured).toBe(true)
    expect(stealth.enabled).toBe(true)
    expect(stealth.running).toBe(true)
    expect(stealth.has_psk).toBe(true)
  }
  const stealthJson = JSON.stringify(stealth)
  expect(stealthJson).not.toMatch(/"(?:psk|password|private_key|ssh_key)"\s*:/i)

  console.log(`NETWORK_EVIDENCE=${JSON.stringify({
    local_ip: info.localIp,
    gateway: info.gateway,
    interface: info.interface,
    gateway_enabled: gateway.enabled ?? gateway.configured ?? null,
    gateway_effective: gatewayVerify.effective ?? gatewayVerify.success ?? null,
    guard_running: guardStatus.running ?? null,
    queries: guardStats.totalQueries ?? guardDashboard.totalQueries ?? null,
    blocked: guardStats.blocked ?? guardDashboard.blocked ?? null,
    guard_uptime: guardMetrics.uptime_seconds ?? null,
    shadow_enabled: shadowSettings.data?.enabled ?? null,
    shadow_observed: shadowStats.data?.active_count ?? shadowStats.data?.observing ?? null,
    prism_rows: prism.data.length,
    chameleon_connected: stealth.connected,
    chameleon_sent: stealth.bytes_sent,
    chameleon_received: stealth.bytes_recv,
    active_connections: connections.data?.length ?? null,
  })}`)
})
