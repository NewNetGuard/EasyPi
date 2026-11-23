import api from './client'

export interface MobilePairing {
  pairing_code: string
  expires_at: string
  tailscale_exit_node: string | null
  certificate_sha256: string | null
  server_url: string | null
}

export interface MobileLinkSettings {
  enabled: boolean
  public_url: string | null
}

export interface MobileLinkAgentStatus {
  configured: boolean
  enabled: boolean
  active: boolean
  installation_id: string | null
  relay_address: string | null
  server_name: string | null
}

export type MobileLinkRelayAuthMethod = 'password' | 'key'

export interface MobileLinkRelayCredentials {
  host: string
  ssh_port: number
  ssh_user: string
  auth_method: MobileLinkRelayAuthMethod
  ssh_password?: string
  ssh_key?: string
}

export interface MobileLinkRelayStatus {
  configured: boolean
  installed: boolean
  enabled: boolean
  active: boolean
  host: string | null
  ssh_port: number
  ssh_user: string
  credential_configured: boolean
  credential_type: MobileLinkRelayAuthMethod | null
  credential_protection: string | null
  host_key_trusted: boolean
  domain: string | null
  agent_port: number
  mobile_port: number
  last_checked_at: string | null
  last_error: string | null
}

export interface MobileLinkRelayHostKey {
  host: string
  port: number
  algorithm: string
  fingerprint: string
  public_key: string
  trust_status: 'unknown' | 'trusted' | 'changed'
}

export interface MobileDevice {
  id: string
  name: string
  is_active: boolean
  created_at: string
  last_seen_at: string
  revoked_at: string | null
}

export async function startMobilePairing(): Promise<MobilePairing> {
  const { data } = await api.post<MobilePairing>('/mobile/pairing/start')
  return data
}

export async function listMobileDevices(): Promise<MobileDevice[]> {
  const { data } = await api.get<MobileDevice[]>('/mobile/devices')
  return data
}

export async function deleteMobileDevice(deviceId: string): Promise<void> {
  await api.delete(`/mobile/devices/${encodeURIComponent(deviceId)}`)
}

export async function getMobileLinkSettings(): Promise<MobileLinkSettings> {
  const { data } = await api.get<MobileLinkSettings>('/mobile/link/settings')
  return data
}

export async function saveMobileLinkSettings(settings: MobileLinkSettings): Promise<MobileLinkSettings> {
  const { data } = await api.put<MobileLinkSettings>('/mobile/link/settings', settings)
  return data
}

export async function getMobileLinkAgentStatus(): Promise<MobileLinkAgentStatus> {
  const { data } = await api.get<MobileLinkAgentStatus>('/mobile/link/agent')
  return data
}

export async function configureMobileLinkAgent(relayAddress: string, serverName: string): Promise<MobileLinkAgentStatus> {
  const { data } = await api.put<MobileLinkAgentStatus>('/mobile/link/agent', {
    relay_address: relayAddress,
    server_name: serverName,
  })
  return data
}

export async function manageMobileLinkAgent(action: 'enable' | 'disable' | 'rotate-secret'): Promise<MobileLinkAgentStatus> {
  const { data } = await api.post<MobileLinkAgentStatus>(`/mobile/link/agent/${action}`)
  return data
}

export async function getMobileLinkRelayStatus(): Promise<MobileLinkRelayStatus> {
  const { data } = await api.get<MobileLinkRelayStatus>('/mobile/link/relay/status')
  return data
}

export async function inspectMobileLinkRelayHostKey(host: string, sshPort: number): Promise<MobileLinkRelayHostKey> {
  const { data } = await api.post<MobileLinkRelayHostKey>('/mobile/link/relay/host-key', { host, ssh_port: sshPort })
  return data
}

export async function trustMobileLinkRelayHostKey(host: string, sshPort: number, fingerprint: string): Promise<MobileLinkRelayHostKey> {
  const { data } = await api.post<MobileLinkRelayHostKey>('/mobile/link/relay/trust-host-key', { host, ssh_port: sshPort, fingerprint })
  return data
}

export async function checkMobileLinkRelayConnection(credentials: MobileLinkRelayCredentials): Promise<{
  success: boolean
  message: string
  os: string
  credential_configured: boolean
  credential_type: MobileLinkRelayAuthMethod | null
  credential_protection: string | null
}> {
  const { data } = await api.post('/mobile/link/relay/check', credentials)
  return data
}

export async function deployMobileLinkRelay(payload: MobileLinkRelayCredentials & {
  domain: string
  agent_port: number
  mobile_port: number
}): Promise<MobileLinkRelayStatus> {
  const { data } = await api.post<MobileLinkRelayStatus>('/mobile/link/relay/deploy', payload)
  return data
}

export async function manageMobileLinkRelay(
  action: 'check-status' | 'restart' | 'disable' | 'uninstall',
  credentials: MobileLinkRelayCredentials,
): Promise<MobileLinkRelayStatus> {
  const { data } = await api.post<MobileLinkRelayStatus>(`/mobile/link/relay/${action}`, credentials)
  return data
}
