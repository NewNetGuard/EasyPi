import {
  getNetProtectionDashboard,
  getNetProtectionFullStatus,
  getNetProtectionStats,
} from './netProtectionApi'
import type { SecurityDashboard } from '../types/security'

export const getDashboard = async (): Promise<SecurityDashboard & { configured: boolean }> => {
  try {
    const [statusRes, statsRes, dashRes] = await Promise.all([
      getNetProtectionFullStatus().catch(() => null),
      getNetProtectionStats('24h').catch(() => null),
      getNetProtectionDashboard().catch(() => null),
    ])

    const status: any = statusRes
    const stats: any = statsRes
    const dashboard: any = dashRes

    if (!status?.running && !status?.service_status) {
      return {
        configured: false,
        protectionStatus: { enabled: false, disabledUntil: null },
        totalQueries: 0,
        blockedToday: 0,
        blockPercentage: 0,
        activeBlocklists: 0,
        blockedDomains: 0,
        activeThreats: 0,
        topBlocked: [],
      }
    }

    const totalQueries = dashboard?.totalQueries || stats?.totalQueries || 0
    const blocked = dashboard?.blockedToday || stats?.blocked || 0
    const blockPercentage = dashboard?.blockPercentage || stats?.blockRate ||
      (totalQueries > 0 ? Math.round((blocked / totalQueries) * 100 * 10) / 10 : 0)

    return {
      configured: true,
      protectionStatus: {
        enabled: dashboard?.protectionStatus?.enabled ?? status?.running ?? status?.service_status === 'active',
        disabledUntil: dashboard?.protectionStatus?.disabledUntil || null,
      },
      totalQueries,
      blockedToday: blocked,
      blockPercentage,
      activeBlocklists: dashboard?.activeBlocklists || 1,
      blockedDomains: dashboard?.blockedDomains || 0,
      activeThreats: dashboard?.activeThreats || 0,
      topBlocked: (dashboard?.topBlocked || stats?.topBlocked || []).slice(0, 5).map((item: any, index: number) => ({
        domain: typeof item === 'string' ? item : (Array.isArray(item) ? item[0] : item.domain) || `domain-${index}`,
        hits: typeof item === 'object' && !Array.isArray(item) ? item.hits || item.count || 0 : (Array.isArray(item) ? item[1] : 0),
      })),
    }
  } catch (error) {
    console.error('Failed to get NetProtection dashboard:', error)
    return {
      configured: false,
      protectionStatus: { enabled: false, disabledUntil: null },
      totalQueries: 0,
      blockedToday: 0,
      blockPercentage: 0,
      activeBlocklists: 0,
      blockedDomains: 0,
      activeThreats: 0,
      topBlocked: [],
    }
  }
}

export const getStats = async (period: '24h' | '7d' = '24h'): Promise<any> => {
  try {
    return await getNetProtectionStats(period)
  } catch {
    const hours = period === '24h' ? 24 : period === '7d' ? 7 : 30
    return {
      totalQueries: 0,
      blocked: 0,
      blockRate: 0,
      queryTrend: Array.from({ length: hours }, (_, i) => ({
        time: period === '24h' ? `${i}:00` : `Day ${i + 1}`,
        queries: 0,
      })),
      blockTrend: Array.from({ length: hours }, (_, i) => ({
        time: period === '24h' ? `${i}:00` : `Day ${i + 1}`,
        blocked: 0,
        allowed: 0,
      })),
      topBlocked: [],
      topClients: [],
      topQueried: [],
      avgResponseTime: null,
    }
  }
}

export const getTopBlocked = async (limit: number = 10) => {
  const stats = await getNetProtectionStats('24h')
  return (stats?.topBlocked || []).slice(0, limit)
}

export interface ProfileInfo {
  version: string
  running: boolean
  protection_enabled: boolean
  dns_addresses: string[]
  upstream_dns: string[]
  total_queries: number
  blocked_queries: number
  blocklist_count: number
}

export const getProfileInfo = async (): Promise<ProfileInfo> => {
  try {
    const [status, stats]: [any, any] = await Promise.all([
      getNetProtectionFullStatus(),
      getNetProtectionStats('24h').catch(() => ({} as any)),
    ])

    return {
      version: status?.version || '1.0.0',
      running: status?.running || status?.service_status === 'active',
      protection_enabled: status?.protection_enabled ?? true,
      dns_addresses: status?.dns_addresses || ['0.0.0.0:53'],
      upstream_dns: status?.upstream_dns || ['https://dns.quad9.net/dns-query'],
      total_queries: stats?.totalQueries || 0,
      blocked_queries: stats?.blocked || 0,
      blocklist_count: stats?.blocklist_size || 0,
    }
  } catch {
    return {
      version: '1.0.0',
      running: false,
      protection_enabled: false,
      dns_addresses: [],
      upstream_dns: [],
      total_queries: 0,
      blocked_queries: 0,
      blocklist_count: 0,
    }
  }
}
