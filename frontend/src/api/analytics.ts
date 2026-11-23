import api from './client'

export interface ThreatCategory { key: string; label: string; count: number }
export interface AnalyticsDevice {
  client_id: string
  name: string
  ip: string
  requests: number
  blocked: number
  blockRate: number
}
export interface Analytics {
  period: string
  threatCategories: ThreatCategory[]
  devices: AnalyticsDevice[]
  insights: string[]
  comparison: { queriesChangePct?: number | null; blockedChangePct?: number | null }
  peakHour?: string | null
}
export interface DomainCount { domain: string; count: number; hosts?: number }
export interface DeviceDetail {
  recent: { domain: string; count: number }[]
  visited?: { sites: DomainCount[]; trackers: DomainCount[]; background: DomainCount[] }
  topQueried: { domain: string; count: number }[]
  topBlocked: { domain: string; count: number }[]
  categories: ThreatCategory[]
}

export const getAnalytics = async (period: string): Promise<Analytics> => {
  const { data } = await api.get('/netprotection/analytics', { params: { period } })
  return data
}

export const getDeviceDetail = async (clientId: string, period: string, search?: string): Promise<DeviceDetail> => {
  const { data } = await api.get('/netprotection/analytics/device', {
    params: { client_id: clientId, period, ...(search ? { search } : {}) },
  })
  return data
}
