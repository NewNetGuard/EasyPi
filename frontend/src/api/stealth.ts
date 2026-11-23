import api from './client'
import type { VpnDevice } from './vpn'

export interface StealthStatus {
  success?: boolean
  // tunnel
  running: boolean
  connected: boolean
  scope: 'all' | 'selected'
  devices: number
  killswitch: boolean
  dns_protected: boolean
  quic_blocked: boolean
  fingerprint: string
  behavior: string
  shield: string
  bytes_sent: number
  bytes_recv: number
  server: string
  // client settings
  configured: boolean
  server_address: string
  transport: string
  cert_mode: string
  shield_preset: string
  reality_public: string
  has_psk: boolean
  doh_domain: string
  buffer_size: number
  reconnect_interval: number
  block_quic: boolean
  fingerprint_mode: 'auto' | 'mobile' | 'desktop'
  enabled: boolean
  device_list: VpnDevice[]
  online_targets: number | null
  // server SSH
  ssh_host: string
  ssh_user: string
  ssh_port: number
  has_password: boolean
  ssh_key_installed: boolean
  ssh_key_verified: boolean
  ssh_key_fingerprint: string
  credential_protection: string
  remote_path: string
  acme_terms_accepted: boolean
  ip_shield_deployed: boolean
  domain: string
  domain_tls_deployed: boolean
  shield_migration_required: boolean
  ssh_host_key_trusted: boolean
  ssh_host_key_fingerprint: string
  runtime_log: string
  error?: string
  warning?: string
  failure_code?: string
  health_error?: string
  failed_at?: string
  health_title?: string
  health_hint?: string
}

export interface DeployResult {
  success: boolean
  log: string
  error?: string
  active?: boolean
  needs_trust?: boolean
  fingerprint?: string
  key_type?: string
  busy?: boolean
  host_key_trusted?: boolean
  credentials_ready?: boolean
}

export const getStealthStatus = async (): Promise<StealthStatus> => {
  const { data } = await api.get('/netprotection/stealth/status'); return data
}
export const saveStealthClient = async (body: Record<string, unknown>): Promise<StealthStatus> => {
  const { data } = await api.post('/netprotection/stealth/client', body); return data
}
export const generatePsk = async (): Promise<{ psk_key: string }> => {
  const { data } = await api.post('/netprotection/stealth/generate/psk'); return data
}
export const generateReality = async (): Promise<{ reality_public: string }> => {
  const { data } = await api.post('/netprotection/stealth/generate/reality'); return data
}
export const enableStealth = async (confirmRoutingConflict = false): Promise<StealthStatus> => {
  const { data } = await api.post('/netprotection/stealth/enable', {
    confirm_routing_conflict: confirmRoutingConflict,
  }); return data
}
export const disableStealth = async (): Promise<StealthStatus> => {
  const { data } = await api.post('/netprotection/stealth/disable'); return data
}
export const setStealthTargets = async (
  scope: 'all' | 'selected', devices: VpnDevice[], confirmRoutingConflict = false,
): Promise<StealthStatus> => {
  const { data } = await api.post('/netprotection/stealth/targets', {
    scope,
    devices,
    confirm_routing_conflict: confirmRoutingConflict,
  }); return data
}
export const resetStealthProfile = async (): Promise<{ success: boolean }> => {
  const { data } = await api.post('/netprotection/stealth/reset-profile'); return data
}
export const deleteStealthConfig = async (): Promise<{ success: boolean }> => {
  const { data } = await api.delete('/netprotection/stealth/config'); return data
}
export const saveStealthServer = async (body: {
  host: string; user: string; port: number; password?: string; remote_path: string; acme_terms_accepted: boolean
  domain: string
}): Promise<StealthStatus> => {
  const { data } = await api.post('/netprotection/stealth/server', body); return data
}
export const checkStealthSsh = async (): Promise<DeployResult> => {
  const { data } = await api.post('/netprotection/stealth/server/check'); return data
}
export const trustStealthSshHostKey = async (fingerprint: string): Promise<DeployResult> => {
  const { data } = await api.post('/netprotection/stealth/server/trust-host-key', { fingerprint }); return data
}
export const deployStealthServer = async (): Promise<DeployResult> => {
  // A first deployment may install packages and issue the IP certificate.
  // Keep this operation bounded, but do not let the shared 30-second timeout
  // report a failure while the authenticated deployment continues on the VPS.
  const { data } = await api.post(
    '/netprotection/stealth/server/deploy', undefined, { timeout: 900_000 },
  ); return data
}
export const configureStealthDomainTls = async (): Promise<DeployResult> => {
  // HTTP-01 validation and certificate migration may take more than the shared
  // 30-second API timeout. Keep this single operation bounded at 10 min.
  const { data } = await api.post(
    '/netprotection/stealth/server/domain-tls', undefined, { timeout: 600_000 },
  ); return data
}
export const removeStealthDomainTls = async (): Promise<DeployResult> => {
  const { data } = await api.delete(
    '/netprotection/stealth/server/domain-tls', { timeout: 300_000 },
  ); return data
}
export const stopStealthServer = async (): Promise<DeployResult> => {
  const { data } = await api.post('/netprotection/stealth/server/stop'); return data
}
export const uninstallStealthServer = async (): Promise<DeployResult> => {
  const { data } = await api.post('/netprotection/stealth/server/uninstall'); return data
}
export const fetchStealthServerLogs = async (): Promise<DeployResult> => {
  const { data } = await api.post('/netprotection/stealth/server/logs'); return data
}
