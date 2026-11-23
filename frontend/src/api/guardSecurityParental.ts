import api, { securityApi } from './client'
import type { ParentalProfile } from '../types/security'

export interface ParentalClient {
  id: string
  name: string
  record_name?: string
  ip: string
  mac: string | null
  ids: string[]
  parental_managed: boolean
  parental_enabled: boolean
  safesearch_enabled: boolean
  safebrowsing_enabled: boolean
  filtering_enabled: boolean
  shield_profile?: 'strict' | 'balanced' | 'kids' | 'minimal' | null
  blocked_services: string[]
  use_global_settings: boolean
  fail_closed?: boolean
  dns_last_seen?: string | null
  dns_query_count?: number | null
  dns_blocked_count?: number | null
}

export interface FailClosedDevice {
  ip: string
  name: string
  id?: string | null
  domain?: string | null
  triggered_at?: string | null
  groups?: string[]
  tor_bridge?: boolean
  group_label?: string | null
}

export interface FailClosedStatus {
  count: number
  devices: FailClosedDevice[]
}

export interface BypassDevice {
  ip: string
  name: string
  id?: string | null
  bypass_mode: 'warn' | 'quarantine' | 'log_only' | string
  quarantine: boolean
  leak?: boolean
  domain?: string | null
  triggered_at?: string | null
  groups?: string[]
  tor_bridge?: boolean
  group_label?: string | null
  source_hint?: string | null
  has_alert?: boolean
}

export interface BypassStatus {
  count: number
  devices: BypassDevice[]
}

export interface BypassBlockedDevice {
  ip: string
  name: string
  total: number
  channels: Record<string, number>
}

export interface BypassBlockedStatus {
  count: number
  total_blocked: number
  devices: BypassBlockedDevice[]
}

export interface BypassHistoryDevice {
  ip: string
  name: string
  total: number
  channels: Record<string, number>
  first_seen: string | null
  last_seen: string | null
  last_domain: string | null
}

export interface BypassHistoryStatus {
  count: number
  total_all: number
  devices: BypassHistoryDevice[]
}

export type WhatsAppBlockMode = 'balanced' | 'aggressive'

export interface WhatsAppBlockModeStatus {
  success: boolean
  mode: WhatsAppBlockMode
}

export const getParentalClients = async (): Promise<ParentalClient[]> => {
  const { data } = await securityApi.get('/parental/clients')
  return data || []
}

export const addParentalClient = async (client: Partial<ParentalClient>) => {
  const { data } = await securityApi.post('/parental/client', client)
  return data
}

export const updateParentalClient = async (name: string, client: Partial<ParentalClient>) => {
  const { data } = await securityApi.put(`/parental/client/${encodeURIComponent(name)}`, client)
  return data
}

export const deleteParentalClient = async (name: string) => {
  const { data } = await securityApi.delete(`/parental/client/${encodeURIComponent(name)}`)
  return data
}

export const restoreParentalClientInternet = async (name: string) => {
  const { data } = await securityApi.post(`/parental/client/${encodeURIComponent(name)}/restore-internet`)
  return data
}

export const getBlockedServicesList = async (): Promise<string[]> => {
  const { data } = await securityApi.get('/parental/blocked-services')
  return data
}

export const getFailClosedStatus = async (): Promise<FailClosedStatus> => {
  const { data } = await securityApi.get('/parental/fail-closed')
  return data || { count: 0, devices: [] }
}

export const restoreFailClosedInternetByIp = async (ip: string) => {
  const { data } = await securityApi.post(`/parental/fail-closed/${encodeURIComponent(ip)}/restore`)
  return data
}

export const getBypassStatus = async (): Promise<BypassStatus> => {
  const { data } = await securityApi.get('/parental/bypass')
  return data || { count: 0, devices: [] }
}

export const getBypassBlocked = async (): Promise<BypassBlockedStatus> => {
  const { data } = await securityApi.get('/parental/bypass-blocked')
  return data || { count: 0, total_blocked: 0, devices: [] }
}

export const getBypassHistory = async (): Promise<BypassHistoryStatus> => {
  const { data } = await securityApi.get('/parental/bypass-history')
  return data || { count: 0, total_all: 0, devices: [] }
}

export const clearBypassHistory = async () => {
  const { data } = await securityApi.post('/parental/bypass-history/clear')
  return data
}

export const setBypassModeByIp = async (
  ip: string,
  mode: 'warn' | 'quarantine' | 'log_only',
  quarantineNow: boolean = false,
) => {
  const { data } = await securityApi.post(`/parental/bypass/${encodeURIComponent(ip)}/mode`, {
    mode,
    quarantine_now: quarantineNow,
  })
  return data
}

export const acknowledgeBypassAlertByIp = async (ip: string) => {
  const { data } = await securityApi.post(`/parental/bypass/${encodeURIComponent(ip)}/ack`)
  return data
}

export const getWhatsAppBlockMode = async (): Promise<WhatsAppBlockModeStatus> => {
  const { data } = await securityApi.get('/parental/whatsapp-block-mode')
  const mode = String(data?.mode || 'balanced').toLowerCase() === 'aggressive' ? 'aggressive' : 'balanced'
  return {
    success: Boolean(data?.success ?? true),
    mode,
  }
}

export const setWhatsAppBlockMode = async (mode: WhatsAppBlockMode) => {
  const { data } = await securityApi.put('/parental/whatsapp-block-mode', { mode })
  return data
}

export const getParentalProfiles = async (): Promise<ParentalProfile[]> => {
  try {
    const { data } = await api.get('/dns/profiles')
    return data || []
  } catch {
    return []
  }
}

export const createParentalProfile = async (profile: Partial<ParentalProfile>) => {
  const { data } = await api.post('/dns/profiles', profile)
  return data
}

export const deleteParentalProfile = async (id: string) => {
  const { data } = await api.delete(`/dns/profiles/${id}`)
  return data
}

export const getParentalStatus = async () => {
  const { data } = await securityApi.get('/parental/status')
  return data
}

export const toggleParental = async (enabled: boolean) => {
  const { data } = await securityApi.post('/parental/toggle', { enabled })
  return data
}

export const toggleSafeSearch = async (enabled: boolean) => {
  const { data } = await securityApi.post('/parental/safesearch', { enabled })
  return data
}
