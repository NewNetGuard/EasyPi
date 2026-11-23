import type { Blocklist, DNSQuery, Device, DomainEntry } from '../types/security'

interface DomainWithMeta {
  domain: string
  addedAt?: string
  hits?: number
  type?: string
  comment?: string
}

export const normalizeBlocklists = (sources: any[]): Blocklist[] =>
  (sources || []).map((source: any) => ({
    id: source.id || source.name,
    name: source.name,
    url: source.url,
    enabled: source.enabled ?? true,
    lastUpdated: source.added_at || new Date().toISOString(),
    domainsCount: source.domain_count || source.rules_count || 0,
    category: source.license ? `verified:${source.license}` : 'custom',
    updateStatus: source.last_error ? 'error' : 'success',
  }))

export const normalizeDomainEntries = (
  domainsInput: Array<string | DomainWithMeta>,
  prefix: 'wl' | 'bl',
): DomainEntry[] =>
  (domainsInput || []).map((item, index) => {
    if (typeof item === 'string') {
      return {
        id: `${prefix}-${index}`,
        domain: item,
        type: 'exact',
        enabled: true,
        comment: '',
        addedAt: new Date().toISOString(),
        hits: 0,
      }
    }

    return {
      id: `${prefix}-${index}`,
      domain: item.domain,
      type: (item.type || 'exact') as 'exact' | 'wildcard' | 'regex',
      enabled: true,
      comment: item.comment || '',
      addedAt: item.addedAt || new Date().toISOString(),
      hits: item.hits || 0,
    }
  })

export const normalizeVerdictsToDnsQueries = (verdictsInput: any): DNSQuery[] => {
  const verdicts = verdictsInput?.data || verdictsInput || []

  return verdicts.map((v: any) => ({
    id: v.id || v.flow_id,
    timestamp: v.time || v.timestamp || v.ts,
    domain: v.domain || v.question,
    queryType: v.query_type || v.type || v.qtype || 'A',
    // Prefer a human-readable client (resolved IP/name) over the privacy hash (client_id).
    client: v.client_name || v.client_ip || v.client,
    // flow_log stores status as 'blocked' | 'upstream' and verdict as deny/allow/observe.
    // The UI only knows allowed/blocked, so collapse every non-blocked verdict to 'allowed'
    // (otherwise 'upstream' renders unstyled and the Allowed stat/filter stay empty).
    status: (v.status === 'blocked' || v.verdict === 'deny' || v.blocked) ? 'blocked' : 'allowed',
    answer: v.response || v.answer,
    responseTime: v.latency_ms || v.response_time_ms,
    cached: v.cached || false,
    reason: v.evidence || v.reason || v.block_reason,
    source: v.block_source || undefined,
    sourceKey: v.block_source_key || undefined,
  }))
}

export const normalizeNetProtectionDevices = (devices: any[]): Device[] =>
  (devices || []).map((device: any) => ({
    id: device.id,
    name: device.name || device.hostname || device.id,
    ip: device.ip_address || device.ipAddress || '',
    mac: device.mac_address || device.macAddress || '',
    type: device.device_type || device.type || 'unknown',
    online: true,
    lastSeen: device.last_seen || new Date().toISOString(),
    profileId: device.shield_profile || device.profileId || undefined,
  }))
