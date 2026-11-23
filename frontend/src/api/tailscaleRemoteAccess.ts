/**
 * Tailscale Remote Access API Client
 * 
 * Simple API for ON/OFF control of remote VPN access.
 * No configuration required from the UI - all settings are handled server-side.
 */

import axios from 'axios'
import { getApiBaseUrl } from '../utils/apiBase'
import { getCsrfHeaders } from '../utils/csrf'
import { refreshAuthSession } from './authSession'

// Get backend URL dynamically
const getApiBase = () => `${getApiBaseUrl()}/api/remote/tailscale`

// Create axios instance with cookies auth
const api = axios.create({
  timeout: 30000,
  withCredentials: true,  // Send httpOnly cookies
})

// Add CSRF token to mutating requests
api.interceptors.request.use(async (config) => {
  if (config.method && ['post', 'put', 'patch', 'delete'].includes(config.method.toLowerCase())) {
    const csrfHeaders = await getCsrfHeaders()
    for (const [key, value] of Object.entries(csrfHeaders)) {
      config.headers[key] = value
    }
  }
  return config
})

// Response interceptor - handle 401 with automatic retry
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config
    
    // Handle 401 - try to refresh token via cookie
    if (error.response?.status === 401 && !originalRequest?._retry) {
      originalRequest._retry = true
      
      try {
        await refreshAuthSession()
        
        // Retry original request with fresh cookies
        return axios({
          ...originalRequest,
          withCredentials: true,
        })
      } catch {
        // Refresh failed - user needs to login again
        return Promise.reject(error)
      }
    }
    
    return Promise.reject(error)
  }
)

// Types

export interface TailscaleStatus {
  enabled: boolean
  tailscale_running: boolean
  lan_cidr: string | null
  tailscale_ips: string[]
  advertised_routes: string[]
  exit_node_advertised: boolean
  hostname: string | null
  tailnet: string | null
  backend_state: string | null
  last_error: string | null
  last_enabled_at: string | null
  taildrop_importer_active: boolean
  taildrop_device_eligible: boolean
  taildrop_error: string | null
  taildrop_free_bytes: number | null
  taildrop_reserve_bytes: number | null
}

export interface ErrorDetail {
  message: string
  code: string
  details?: string
}

export interface EnableResponse {
  success: boolean
  pending?: boolean
  lan_cidr?: string
  details?: string
  status?: TailscaleStatus
  error?: ErrorDetail
}

export interface DisableResponse {
  success: boolean
  details?: string
  status?: TailscaleStatus
  error?: ErrorDetail
}

export interface ConfigResponse {
  has_authkey: boolean
  interface: string
}

export interface SaveAuthkeyResponse {
  success: boolean
  error?: ErrorDetail
}

export interface InstallStatusResponse {
  installed: boolean
  version: string | null
  installing: boolean
}

export interface InstallResponse {
  success: boolean
  message: string
  version: string | null
  error?: ErrorDetail
}

export interface UninstallResponse {
  success: boolean
  message: string
  error?: ErrorDetail
}

export type RelayAuthMethod = 'password' | 'key'

export interface RelayCredentials {
  host: string
  ssh_port: number
  ssh_user: string
  auth_method: RelayAuthMethod
  ssh_password?: string
  ssh_key?: string
}

export interface RelayDeployRequest extends RelayCredentials {
  relay_name: string
  relay_port: number
  public_endpoint?: string
  auth_key?: string
}

export interface RelayStatus {
  configured: boolean
  installed: boolean
  enabled: boolean
  daemon_active: boolean
  listening: boolean
  managed_install: boolean
  firewall_managed: boolean
  isolation_active: boolean
  relay_tagged: boolean
  shields_up: boolean
  host: string | null
  ssh_port: number
  ssh_user: string
  credential_configured: boolean
  credential_type: RelayAuthMethod | null
  credential_protection: string | null
  host_key_trusted: boolean
  relay_name: string
  relay_port: number
  public_endpoint: string | null
  tailscale_ip: string | null
  tailscale_version: string | null
  policy_grant: string | null
  policy_required: boolean
  last_checked_at: string | null
  last_error: string | null
}

export interface RelayHostKey {
  host: string
  port: number
  key_type: string
  fingerprint: string
  bits: number
  trust_status: 'unknown' | 'trusted' | 'changed'
  trusted_fingerprint?: string
}

// API Functions

/**
 * Enable remote VPN access.
 * No parameters needed - server handles all configuration automatically.
 */
export async function enableRemoteAccess(): Promise<EnableResponse> {
  const response = await api.post<EnableResponse>(`${getApiBase()}/enable`)
  return response.data
}

/**
 * Disable remote VPN access.
 */
export async function disableRemoteAccess(): Promise<DisableResponse> {
  const response = await api.post<DisableResponse>(`${getApiBase()}/disable`)
  return response.data
}

/**
 * Get current status of remote VPN access.
 */
export async function getRemoteAccessStatus(): Promise<TailscaleStatus> {
  const response = await api.get<TailscaleStatus>(`${getApiBase()}/status`)
  return response.data
}

/**
 * Get current config (check if authkey is configured).
 */
export async function getConfig(): Promise<ConfigResponse> {
  const response = await api.get<ConfigResponse>(`${getApiBase()}/config`)
  return response.data
}

/**
 * Save auth key to server config.
 */
export async function saveAuthkey(authkey: string): Promise<SaveAuthkeyResponse> {
  const response = await api.post<SaveAuthkeyResponse>(`${getApiBase()}/config`, { authkey })
  return response.data
}

/**
 * Check if Tailscale is installed on the system.
 */
export async function getInstallStatus(): Promise<InstallStatusResponse> {
  const response = await api.get<InstallStatusResponse>(`${getApiBase()}/install-status`)
  return response.data
}

/**
 * Install Tailscale on the system.
 */
export async function installTailscale(): Promise<InstallResponse> {
  const response = await api.post<InstallResponse>(`${getApiBase()}/install`, {}, { timeout: 300000 }) // 5 min timeout
  return response.data
}

/**
 * Uninstall Tailscale from the system.
 */
export async function uninstallTailscale(): Promise<UninstallResponse> {
  const response = await api.post<UninstallResponse>(`${getApiBase()}/uninstall`, {}, { timeout: 300000 })
  return response.data
}

const getRelayBase = () => `${getApiBase()}/relay`

export async function getRelayStatus(): Promise<RelayStatus> {
  const response = await api.get<RelayStatus>(`${getRelayBase()}/status`)
  return response.data
}

export async function inspectRelayHostKey(host: string, sshPort: number): Promise<RelayHostKey> {
  const response = await api.post<RelayHostKey>(`${getRelayBase()}/host-key`, {
    host,
    ssh_port: sshPort,
  })
  return response.data
}

export async function trustRelayHostKey(
  host: string,
  sshPort: number,
  fingerprint: string,
): Promise<RelayHostKey> {
  const response = await api.post<RelayHostKey>(`${getRelayBase()}/trust-host-key`, {
    host,
    ssh_port: sshPort,
    fingerprint,
  })
  return response.data
}

export async function checkRelayConnection(credentials: RelayCredentials): Promise<{
  success: boolean
  message: string
  os: string
  credential_configured: boolean
  credential_type: RelayAuthMethod | null
  credential_protection: string | null
}> {
  const response = await api.post(`${getRelayBase()}/check`, credentials, { timeout: 60000 })
  return response.data
}

export async function deployRelay(request: RelayDeployRequest): Promise<RelayStatus> {
  const response = await api.post<RelayStatus>(`${getRelayBase()}/deploy`, request, { timeout: 420000 })
  return response.data
}

export async function manageRelay(
  action: 'check-status' | 'restart' | 'disable' | 'uninstall',
  credentials: RelayCredentials,
): Promise<RelayStatus> {
  const response = await api.post<RelayStatus>(`${getRelayBase()}/${action}`, credentials, { timeout: 420000 })
  return response.data
}
