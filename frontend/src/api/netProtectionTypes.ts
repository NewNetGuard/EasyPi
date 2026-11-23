export type VerdictType = 'allow' | 'deny' | 'redirect' | 'observe';
export type MatcherKind = 'exact' | 'wildcard' | 'regex' | 'blocklist' | 'ip' | 'asn';
export type ShieldProfileId = 'strict' | 'balanced' | 'kids' | 'minimal' | 'custom';

export interface NetProtectionStatus {
  running: boolean;
  protection_enabled: boolean;
  version: string;
  dns_port: number;
  dns_addresses: string[];
  upstream_dns: string[];
  bootstrap_dns: string[];
  available: boolean;
}

export interface NetProtectionConfig {
  protection_enabled: boolean;
  safe_search: boolean;
  parental_control: boolean;
  cache_size: number;
  cache_ttl: number;
  block_response: string;
  upstream_dns: string[];
  shield_profile: ShieldProfileId;
}

export interface Evidence {
  source: string;
  signal: string;
  confidence?: number;
  timestamp?: string;
}

export interface Verdict {
  id?: number;
  flow_id: string;
  domain: string;
  verdict: VerdictType;
  confidence: number;
  evidence: Evidence[];
  client_id?: string;
  client_ip?: string;
  client_name?: string;
  time: string;
  response_time_ms?: number;
  query_type?: string;
  status?: string;
  cached?: boolean;
  device_id?: string | null;
  matcher_id?: string | null;
  evidence_summary?: string;
  block_source?: string;
  block_source_key?: string;
}

export interface VerdictListResponse {
  data: Verdict[];
  oldest: string | null;
  total: number;
}

export interface Matcher {
  id: string;
  name: string;
  kind: MatcherKind;
  pattern?: string;
  url?: string;
  action: VerdictType;
  priority: number;
  enabled: boolean;
  rules_count: number;
  tags: string[];
  last_updated?: string;
  created_at?: string;
}

export interface ShieldProfile {
  id: ShieldProfileId;
  name: string;
  description: string;
  icon: string;
  blocks: string[];
  safe_search?: boolean;
}

export interface ShieldProfilesResponse {
  profiles: ShieldProfile[];
  current: ShieldProfileId;
}

export interface Device {
  id: string;
  name: string;
  hostname?: string;
  mac_address?: string;
  ip_address?: string;
  device_type: string;
  shield_profile: ShieldProfileId;
  enabled: boolean;
  last_seen?: string;
  queries_today?: number;
  blocked_today?: number;
}

export interface DashboardStats {
  configured: boolean;
  protectionStatus: {
    enabled: boolean;
    disabledUntil: string | null;
  };
  totalQueries: number;
  blockedToday: number;
  blockPercentage: number;
  activeBlocklists: number;
  blockedDomains: number;
  activeThreats: number;
  topBlocked: Array<{ domain: string; hits: number }>;
  cacheHitRate?: number;
  avgResponseTime?: number;
}

export interface ThreatStats {
  total_threats: number;
  confirmed: number;
  quarantine: number;
  by_category: Record<string, number>;
  by_type?: {
    malware?: number;
    phishing?: number;
    ads?: number;
    trackers?: number;
  };
  recent_blocks?: Array<{
    domain: string;
    threat_type?: string;
    blocked_at?: string;
  }>;
}

export interface BlocklistInfo {
  exists: boolean;
  path?: string;
  domain_count: number;
  generated?: string;
  last_updated?: string;
  format?: string;
  file_size_kb?: number;
  sources_breakdown?: Record<string, number>;
  expiring_soon?: number;
  warning?: string;
}

export interface QueryLogStats {
  total_logged: number;
  total_flushed: number;
  buffer_size: number;
  pending_flush: number;
  storage_total: number;
  storage_today: number;
  blocked_total: number;
  blocked_today: number;
  retention_days: number;
}
