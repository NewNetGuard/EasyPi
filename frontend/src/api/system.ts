import axios from 'axios'
import { getApiBaseUrl } from '../utils/apiBase'
import { getCsrfHeaders } from '../utils/csrf'

const systemApi = axios.create({
  baseURL: `${getApiBaseUrl()}/api/system`,
  timeout: 60_000,
  withCredentials: true,
})

// Add CSRF token interceptor
systemApi.interceptors.request.use(async (config) => {
  if (config.method && ['post', 'put', 'patch', 'delete'].includes(config.method.toLowerCase())) {
    const csrfHeaders = await getCsrfHeaders()
    for (const [key, value] of Object.entries(csrfHeaders)) {
      config.headers[key] = value
    }
  }
  return config
})

export interface PermissionStatus {
  current_user: string
  in_easypi_group: boolean
  group_exists: boolean
  sudo_configured: boolean
  needs_relogin: boolean
  permissions_ok: boolean
  is_development: boolean
}

export interface SetupPermissionsResponse {
  success: boolean
  message: string
  needs_relogin: boolean
  username: string
}

export interface SystemUser {
  username: string
  uid: number
  home: string
  in_easypi_group: boolean
}

export interface SystemInfo {
  hostname: string
  os: string
  kernel: string
  uptime: string
  current_user: string
  easypi_installed: boolean
}

export type SystemUpdateMode = 'archive' | 'url'

export interface SystemUpdateRequest {
  mode: SystemUpdateMode
  archive_path?: string
  url?: string
  // Detached release signature: a URL (url mode) or a server file path (archive
  // mode). Required — the updater rejects anything not signed by the release key.
  signature?: string
  sha256?: string
  run_install?: boolean
  delete_obsolete?: boolean
  dry_run?: boolean
  restart_services?: boolean
}

export interface SystemUpdateResponse {
  success: boolean
  status: 'running' | 'success' | 'failed'
  message: string
  command: string
  mode: SystemUpdateMode
  job_id?: string | null
  exit_code: number | null
  started_at: string
  finished_at: string | null
  stdout: string
  stderr: string
}

export interface SystemUpdateStatusResponse {
  success: boolean
  status: 'running' | 'success' | 'failed'
  message: string
  job_id: string
  exit_code: number | null
  stdout: string
  stderr: string
}

// Get current permission status
export const getPermissionsStatus = async (): Promise<PermissionStatus> => {
  const response = await systemApi.get('/permissions/status')
  return response.data
}

// Set up permissions for a user
export const setupPermissions = async (username?: string): Promise<SetupPermissionsResponse> => {
  // Use empty object if username is undefined to ensure JSON body is sent
  const response = await systemApi.post('/permissions/setup', { username: username || null })
  return response.data
}

// List system users
export const listSystemUsers = async (): Promise<{ users: SystemUser[] }> => {
  const response = await systemApi.get('/users')
  return response.data
}

// Add user to easypi group
export const addUserToGroup = async (username: string): Promise<{
  success: boolean
  message: string
  needs_relogin: boolean
}> => {
  const response = await systemApi.post(`/users/${username}/add-to-group`)
  return response.data
}

// Get system information
export const getSystemInfo = async (): Promise<SystemInfo> => {
  const response = await systemApi.get('/info')
  return response.data
}

export const runSystemUpdate = async (payload: SystemUpdateRequest): Promise<SystemUpdateResponse> => {
  const response = await systemApi.post('/update/run', payload)
  return response.data
}

export const getSystemUpdateStatus = async (jobId: string): Promise<SystemUpdateStatusResponse> => {
  const response = await systemApi.get(`/update/status/${encodeURIComponent(jobId)}`)
  return response.data
}

export const restartSystemServices = async (): Promise<{
  success: boolean
  message: string
  logs: string
  exit_code: number
}> => {
  const response = await systemApi.post('/update/restart-services')
  return response.data
}

// --- DNS for the EasyPi device itself (via systemApi so CSRF is attached) ---
export interface SystemDnsStatus {
  current_dns: string[]
  connection_name: string | null
  ignore_dhcp_dns: boolean
  is_development: boolean
  gateway?: string | null
}

export const getSystemDnsStatus = async (): Promise<SystemDnsStatus> => {
  const response = await systemApi.get('/dns/status')
  return response.data
}

export const configureSystemDns = async (payload: {
  primary_dns: string
  secondary_dns?: string
  ignore_dhcp_dns: boolean
}): Promise<{ success: boolean; message: string; connection?: string }> => {
  const response = await systemApi.post('/dns/configure', payload)
  return response.data
}

export const resetSystemDns = async (): Promise<{ success: boolean; message: string; connection?: string }> => {
  const response = await systemApi.post('/dns/reset')
  return response.data
}

export default systemApi
