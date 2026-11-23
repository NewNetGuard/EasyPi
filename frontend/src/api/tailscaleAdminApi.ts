/**
 * Tailscale Admin API Client
 * 
 * API for managing Tailscale settings via Admin API:
 * - DNS settings (set NetProtection as global nameserver)
 * - Device management (approve routes, enable exit node)
 */

import axios from 'axios'
import { getApiBaseUrl } from '../utils/apiBase'
import { getCsrfHeaders } from '../utils/csrf'

const getApiBase = () => `${getApiBaseUrl()}/api/remote/tailscale/admin`

const api = axios.create({
  timeout: 30000,
  withCredentials: true,
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

// Types

export interface CredentialsStatus {
  configured: boolean
  tailnet: string | null
  has_api_key: boolean
}

export interface DNSConfig {
  nameservers: string[]
  magic_dns: boolean
  override_local_dns: boolean
  search_paths: string[]
}

export interface Device {
  id: string
  name: string
  hostname: string
  user: string
  tailscale_ips: string[]
  advertised_routes: string[]
  enabled_routes: string[]
  is_exit_node: boolean
  is_exit_node_enabled: boolean
  last_seen: string | null
  os: string | null
}

export interface SetDNSRequest {
  nameservers: string[]
  override_local_dns?: boolean
  magic_dns?: boolean
}

// API Functions

/**
 * Get API credentials status
 */
export async function getCredentialsStatus(): Promise<CredentialsStatus> {
  const response = await api.get<CredentialsStatus>(`${getApiBase()}/credentials`)
  return response.data
}

/**
 * Set API credentials
 */
export async function setCredentials(apiKey: string, tailnet: string): Promise<{ success: boolean; message: string; warning?: string }> {
  const response = await api.post(`${getApiBase()}/credentials`, {
    api_key: apiKey,
    tailnet: tailnet,
  })
  return response.data
}

/**
 * Delete API credentials
 */
export async function deleteCredentials(): Promise<{ success: boolean }> {
  const response = await api.delete(`${getApiBase()}/credentials`)
  return response.data
}

/**
 * Get current DNS settings
 */
export async function getDNSSettings(): Promise<DNSConfig> {
  const response = await api.get<DNSConfig>(`${getApiBase()}/dns`)
  return response.data
}

/**
 * Set DNS settings
 */
export async function setDNSSettings(request: SetDNSRequest): Promise<{ success: boolean }> {
  const response = await api.post(`${getApiBase()}/dns`, request)
  return response.data
}

/**
 * Quick setup: Configure NetProtection DNS for all Tailscale clients
 * This is the preferred method for EasyPi DNS protection
 */
export async function setupNetProtectionDNS(netprotectionTailscaleIp?: string): Promise<{ 
  success: boolean
  nameservers: string[]
  override_local_dns: boolean
  magic_dns: boolean
  message?: string
}> {
  const response = await api.post(`${getApiBase()}/dns/setup-netprotection`, {
    netprotection_tailscale_ip: netprotectionTailscaleIp || null,
  })
  return response.data
}

/**
 * List all devices in tailnet
 */
export async function listDevices(): Promise<Device[]> {
  const response = await api.get<Device[]>(`${getApiBase()}/devices`)
  return response.data
}

/**
 * Approve routes for a device
 */
export async function approveRoutes(deviceId: string, routes: string[]): Promise<{ success: boolean }> {
  const response = await api.post(`${getApiBase()}/devices/${deviceId}/routes`, { routes })
  return response.data
}

/**
 * Enable/disable exit node for a device
 */
export async function setExitNode(deviceId: string, enable: boolean): Promise<{ success: boolean }> {
  const response = await api.post(`${getApiBase()}/devices/${deviceId}/exit-node`, { enable })
  return response.data
}

/**
 * Auto-approve all pending routes
 */
export async function autoApproveRoutes(): Promise<{ 
  success: boolean
  approved: Array<{ device: string; routes_approved: string[] }>
}> {
  const response = await api.post(`${getApiBase()}/devices/auto-approve-routes`)
  return response.data
}



