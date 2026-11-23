import api from './client'
import { getDevices as getNetProtectionDevices } from './netProtectionApi'
import { normalizeNetProtectionDevices } from './guardSecurityMappers'
import type { Device } from '../types/security'

export type UnknownDeviceStatus = 'pending' | 'blocked'

export interface UnknownDevice {
  id: string
  mac: string
  ip: string
  hostname?: string | null
  vendor?: string | null
  sources: string[]
  status: UnknownDeviceStatus
  first_seen: string
  last_seen: string
  decided_at?: string | null
  managed_device?: boolean
  managed_name?: string | null
  managed_profile?: DeviceAccessProfile['id'] | null
  identity_candidate?: {
    identity_state?: 'possible_mac_change'
    device_id: string
    name: string
    current_mac: string
    confidence: number
    action: 'review' | 'auto_rebind'
    automatic: boolean
    evidence: string[]
    evidence_groups: string[]
    conflicts: string[]
  } | null
}

export interface DeviceAccessProfile {
  id: 'strict' | 'balanced' | 'kids' | 'minimal'
  name: string
  description: string
}

export interface UnknownDeviceQuarantine {
  enabled: boolean
  pending: UnknownDevice[]
  blocked: UnknownDevice[]
  access_profiles: DeviceAccessProfile[]
  identity_assurance: 'observed_mac_ip_pair'
  spoof_resistant: false
}

export const getDevices = async (): Promise<Device[]> => {
  try {
    const data = await getNetProtectionDevices()
    return normalizeNetProtectionDevices(data)
  } catch {
    return []
  }
}

export const addDevice = async (device: Partial<Device>) => {
  const { data } = await api.post('/netprotection/devices', device)
  return data
}

export const deleteDevice = async (id: string) => {
  const { data } = await api.delete(`/netprotection/devices/${id}`)
  return data
}

export const getUnknownDeviceQuarantine = async (): Promise<UnknownDeviceQuarantine> => {
  const { data } = await api.get('/netprotection/devices/quarantine')
  return data
}

export const blockUnknownDevice = async (id: string) => {
  const { data } = await api.post(`/netprotection/devices/quarantine/${encodeURIComponent(id)}/block`)
  return data
}

export const allowUnknownDevice = async (
  id: string,
  approval: { name: string; access_profile: DeviceAccessProfile['id'] },
) => {
  const { data } = await api.post(
    `/netprotection/devices/quarantine/${encodeURIComponent(id)}/allow`,
    approval,
  )
  return data
}

export const replaceUnknownDeviceIdentity = async (id: string, targetDeviceId: string) => {
  const { data } = await api.post(
    `/netprotection/devices/quarantine/${encodeURIComponent(id)}/replace-identity`,
    { target_device_id: targetDeviceId },
  )
  return data
}
