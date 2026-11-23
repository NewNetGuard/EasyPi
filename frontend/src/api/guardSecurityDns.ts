import {
  clearQueryLog as clearNetProtectionQueryLog,
  disableProtection as disableNetProtection,
  enableProtection as enableNetProtection,
  getNetProtectionConfig,
  getNetProtectionFullStatus,
  getVerdicts,
  updateNetProtectionConfig,
} from './netProtectionApi'
import { normalizeVerdictsToDnsQueries } from './guardSecurityMappers'
import type { DNSQuery, QueryLogFilters } from '../types/security'

export const enableProtection = async () => {
  return await enableNetProtection()
}

export const disableProtection = async (duration?: number) => {
  void duration
  return await disableNetProtection()
}

export const getQueryLog = async (filters?: QueryLogFilters, limit: number = 100): Promise<DNSQuery[]> => {
  try {
    const data = await getVerdicts({
      limit,
      search: filters?.search,
      verdict_type: filters?.status === 'blocked' ? 'deny' : filters?.status === 'allowed' ? 'allow' : undefined,
    })
    return normalizeVerdictsToDnsQueries(data)
  } catch {
    return []
  }
}

export const clearQueryLog = async () => {
  return await clearNetProtectionQueryLog(0)
}

export const getDNSConfig = async (): Promise<any> => {
  try {
    const [data, status]: [any, any] = await Promise.all([
      getNetProtectionConfig(),
      getNetProtectionFullStatus().catch(() => ({})),
    ])

    return {
      upstreamServers: (data?.upstream_dns || status?.upstream_dns || ['https://dns.quad9.net/dns-query']).map((s: string, i: number) => ({
        id: `upstream-${i}`,
        name: s.includes('quad9') ? 'Quad9 DoH' : s.includes('cloudflare') || s.includes('1.1.1.1') ? 'Cloudflare' : `Upstream ${i + 1}`,
        address: s,
        enabled: true,
      })),
      bootstrapDns: status?.bootstrap_dns || ['9.9.9.9', '1.1.1.1'],
      ratelimit: data?.rate_limit || 0,
      blockingMode: data?.block_response || 'null_ip',
      blockingIpv4: '0.0.0.0',
      blockingIpv6: '::',
      enableDNSSEC: data?.dnssec ?? false,
      enableCache: true,
      cacheTTL: data?.cache_ttl || 300,
      cacheSize: data?.cache_size || 10000,
    }
  } catch {
    return {
      upstreamServers: [{ id: 'upstream-0', name: 'Quad9 DoH', address: 'https://dns.quad9.net/dns-query', enabled: true }],
      bootstrapDns: ['9.9.9.9'],
      ratelimit: 0,
      blockingMode: 'null_ip',
      blockingIpv4: '0.0.0.0',
      blockingIpv6: '::',
      enableDNSSEC: false,
      enableCache: true,
      cacheTTL: 300,
      cacheSize: 10000,
    }
  }
}

export const updateDNSConfig = async (config: any) => {
  return await updateNetProtectionConfig({
    upstream_dns: config.upstreamServers?.map((s: any) => s.address) || config.upstream_dns,
    cache_size: config.cacheSize || config.cache_size,
    cache_ttl: config.cacheTTL || config.cache_ttl,
    dnssec: config.enableDNSSEC || config.dnssec,
  } as any)
}
