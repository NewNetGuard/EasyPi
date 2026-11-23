import { securityApi } from './client'
import type { BannedIP, Threat } from '../types/security'

export const getThreats = async (): Promise<Threat[]> => {
  try {
    const { data } = await securityApi.get('/threats')
    return data || []
  } catch {
    return []
  }
}

export const banIP = async (ip: string, reason: string, type?: string, permanent: boolean = false) => {
  const { data } = await securityApi.post('/threat/ban', { ip, reason, type, permanent })
  return data
}

export const unbanIP = async (ip: string, type?: string) => {
  const { data } = await securityApi.post('/threat/unban', { ip, type })
  return data
}

export const getBannedIPs = async (): Promise<BannedIP[]> => {
  try {
    const { data } = await securityApi.get('/banned-ips')
    return data || []
  } catch {
    return []
  }
}

export const clearThreats = async () => {
  const { data } = await securityApi.post('/threats/clear')
  return data
}

export interface MonitoringStatus {
  enabled: boolean
  ssh_threshold: number
  auto_ban: boolean
  threats_count: number
  uptime?: string | null
}

export const getMonitoringStatus = async (): Promise<MonitoringStatus> => {
  const { data } = await securityApi.get('/monitoring/status')
  return data
}

export const startMonitoring = async () => {
  const { data } = await securityApi.post('/monitoring/start')
  return data
}

export const stopMonitoring = async () => {
  const { data } = await securityApi.post('/monitoring/stop')
  return data
}

export const updateMonitoringSettings = async (settings: { ssh_threshold?: number; auto_ban?: boolean }) => {
  const { data } = await securityApi.post('/monitoring/settings', settings)
  return data
}

export interface DNSRewrite {
  id: string
  domain: string
  answer: string
}

export const getDNSRewrites = async (): Promise<DNSRewrite[]> => {
  try {
    const { data } = await securityApi.get('/dns/rewrites')
    return (data || []).map((r: any) => ({
      id: r.id || `${r.domain}-${r.answer}`,
      domain: r.domain || r.pattern,
      answer: r.answer || r.target,
    }))
  } catch {
    return []
  }
}

export const addDNSRewrite = async (domain: string, answer: string) => {
  const { data } = await securityApi.post('/dns/rewrite', { domain, answer })
  return data
}

export const deleteDNSRewrite = async (domain: string, answer: string) => {
  const { data } = await securityApi.delete('/dns/rewrite', { params: { domain, answer } })
  return data
}

export const clearDNSCache = async () => {
  const { data } = await securityApi.post('/dns/cache/clear')
  return data
}

export const testUpstreamDNS = async (servers: string[]) => {
  const { data } = await securityApi.post('/dns/test-upstream', { servers })
  return data
}

export const resetStatistics = async () => {
  const { data } = await securityApi.post('/stats/reset')
  return data
}

export const resetAllSettings = async () => {
  const { data } = await securityApi.post('/reset-settings')
  return data
}
