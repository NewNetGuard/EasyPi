import api from './client'

export interface VpnDevice {
  mac: string
  name?: string
  ip?: string | null
}

export interface OutboundVpnStatus {
  success?: boolean
  configured: boolean
  running: boolean
  engine: 'wireguard' | 'openvpn' | 'outline' | string
  scope: 'all' | 'selected'
  devices: number
  device_list: VpnDevice[]
  online_targets: number | null
  endpoint: string
  endpoint_host: string
  address: string
  transport_protocol?: string
  transport_port?: number | null
  transport_warning?: string
  latest_handshake: number
  rx_bytes: number
  tx_bytes: number
  killswitch: boolean
  error?: string
  requires_credentials?: boolean
  credentials_configured?: boolean
}

export interface CachedDevice {
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  is_router: boolean
  is_online?: boolean
  source?: 'managed' | 'managed+scan' | string
}

export const getCachedDevices = async (): Promise<CachedDevice[]> => {
  try {
    const res = await fetch('/api/network-toolkit/cached-devices', { credentials: 'include' })
    if (!res.ok) return []
    const data = await res.json()
    return (data.devices || []).filter((d: CachedDevice) => d.mac && !d.is_router)
  } catch {
    return []
  }
}

export const setVpnTargets = async (
  scope: 'all' | 'selected',
  devices: VpnDevice[],
  confirmRoutingConflict = false,
): Promise<OutboundVpnStatus> => {
  const { data } = await api.post('/netprotection/vpn/targets', {
    scope,
    devices,
    confirm_routing_conflict: confirmRoutingConflict,
  })
  return data
}

export const getVpnStatus = async (): Promise<OutboundVpnStatus> => {
  const { data } = await api.get('/netprotection/vpn/status')
  return data
}

export const importVpnConfig = async (
  config: string,
): Promise<{ success: boolean; engine: string; endpoint: string; endpoint_host: string; address: string; transport_protocol?: string; transport_port?: number | null; transport_warning?: string; requires_credentials?: boolean; credentials_configured?: boolean }> => {
  const { data } = await api.post('/netprotection/vpn/import', { config })
  return data
}

export const saveOpenVpnCredentials = async (
  username: string,
  password: string,
): Promise<{ success: boolean; credentials_configured: boolean; credential_protection?: string }> => {
  const { data } = await api.post('/netprotection/vpn/credentials', { username, password })
  return data
}

export const deleteOpenVpnCredentials = async (): Promise<{ success: boolean; credentials_configured: boolean }> => {
  const { data } = await api.delete('/netprotection/vpn/credentials')
  return data
}

export const enableVpn = async (confirmRoutingConflict = false): Promise<OutboundVpnStatus> => {
  const { data } = await api.post('/netprotection/vpn/enable', {
    confirm_routing_conflict: confirmRoutingConflict,
  })
  return data
}

export const disableVpn = async (): Promise<OutboundVpnStatus> => {
  const { data } = await api.post('/netprotection/vpn/disable')
  return data
}

export const deleteVpnConfig = async (): Promise<{ success: boolean }> => {
  const { data } = await api.delete('/netprotection/vpn/config')
  return data
}
