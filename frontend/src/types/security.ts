// Guard Security Types

export type ProtectionStatusType = 'active' | 'disabled' | 'partial' | 'temp-disabled'
export type ThreatLevel = 'low' | 'medium' | 'high' | 'critical'
export type ThreatType = 'brute-force' | 'port-scan' | 'malware' | 'ddos' | 'suspicious'
export type QueryStatus = 'allowed' | 'blocked' | 'forwarded'
export type DomainType = 'exact' | 'regex' | 'wildcard'
export type FirewallAction = 'ALLOW' | 'DENY' | 'LIMIT' | 'REJECT'
export type Protocol = 'tcp' | 'udp' | 'icmp' | 'all'

export interface ProtectionStatus {
  enabled: boolean
  disabledUntil: string | null
}

// Dashboard
export interface SecurityDashboard {
  configured?: boolean  // Whether NetProtection is configured
  error?: string       // Error message if not configured
  protectionStatus: ProtectionStatus
  totalQueries: number
  blockedToday: number
  blockPercentage: number
  activeBlocklists: number
  blockedDomains: number
  activeThreats: number
  topBlocked: Array<{ domain: string; hits: number }>
}

export interface SecurityStats {
  queryTrend: Array<{ time: string; queries: number }>
  blockTrend: Array<{ time: string; blocked: number; allowed: number }>
}

// Ad Blocking
export interface BlockCategory {
  id: string
  name: string
  icon: string
  enabled: boolean
  description: string
  domainsCount: number
}

export interface Blocklist {
  id: string
  name: string
  url: string
  enabled: boolean
  lastUpdated: string
  domainsCount: number
  category: string
  updateStatus: 'idle' | 'updating' | 'success' | 'error'
}

export interface BlockingConfig {
  enabled: boolean
  categories: string[]
  customBlocklists: string[]
  updateInterval: number // hours
}

// White/Black Lists
export interface DomainEntry {
  id: string
  domain: string
  type: DomainType
  enabled: boolean
  comment?: string
  hits: number
  addedAt: string
  addedBy?: string
}

export interface ListStats {
  whitelistCount: number
  blacklistCount: number
  totalHits: number
}

// Firewall
export interface FirewallRule {
  id: string
  name: string
  priority: number
  action: FirewallAction
  source: string
  destination?: string
  port?: number | string
  protocol: Protocol
  enabled: boolean
  comment?: string
  hits: number
  createdAt: string
}

export interface PortForward {
  id: string
  externalPort: number
  internalIp: string
  internalPort: number
  protocol: Protocol
  enabled: boolean
  comment?: string
}

export interface FirewallStats {
  rulesCount: number
  activeRules: number
  blockedPackets: number
  allowedPackets: number
}

// Query Log
export interface DNSQuery {
  id: string
  timestamp: string
  client: string
  clientName?: string
  domain: string
  queryType: string
  status: QueryStatus
  responseTime?: number
  blocklist?: string
  reason?: string
  source?: string
  sourceKey?: string
}

export interface QueryLogFilters {
  status?: QueryStatus
  client?: string
  search?: string
  startTime?: string
  endTime?: string
}

// Parental Controls
export interface ParentalProfile {
  id: string
  name: string
  devices: string[]
  blockedCategories: string[]
  allowedDomains: string[]
  blockedDomains: string[]
  schedules: Array<{
    day: string
    startTime: string
    endTime: string
    enabled: boolean
  }>
  safeSearch: boolean
  youtubeRestricted: boolean
  enabled: boolean
  // IP-based app blocking (for apps that bypass DNS)
  blockedApps?: BlockedApp[]
}

// Apps that can be blocked via IP (bypass DNS)
export type BlockableAppName =
  | 'telegram'
  | 'whatsapp'
  | 'signal'
  | 'tor'
  | 'messenger'
  | 'snapchat'
  | 'wechat'
  | 'viber'
  | 'imessage'
  | 'discord'
  | 'line'

export interface BlockedApp {
  name: BlockableAppName
  displayName: string
  description: string
  enabled: boolean
}

export interface BlockableApp {
  name: BlockableAppName
  displayName: string
  description: string
  ipCount: number
  asnCount: number
  hasDnsBlocking: boolean
}

export interface Device {
  id: string
  name: string
  ip: string
  mac: string
  type: 'phone' | 'tablet' | 'laptop' | 'desktop' | 'tv' | 'iot' | 'unknown'
  profileId?: string
  online: boolean
  lastSeen: string
  // Parental control settings
  parental?: boolean
  safesearch?: boolean
  blockedServices?: string[]
  // IP-based app blocking (Telegram, WhatsApp, Signal, Tor)
  blockedApps?: BlockableAppName[]
}

// Security Monitor
export interface Threat {
  id: string
  type: ThreatType
  severity: ThreatLevel
  sourceIp: string
  sourceCountry?: string
  target?: string
  description: string
  timestamp: string
  status: 'active' | 'resolved' | 'ignored'
  details: Record<string, any>
}

export interface BannedIP {
  id?: string
  ip: string
  type?: string
  reason: string
  bannedAt: string
  expiresAt?: string
  permanent: boolean
  source?: 'manual' | 'fail2ban' | 'auto'
}

export interface SecurityEvent {
  id: string
  type: string
  severity: ThreatLevel
  message: string
  timestamp: string
  details?: Record<string, any>
}

// Statistics
export interface TopDomain {
  domain: string
  count: number
  percentage: number
}

export interface TopClient {
  client: string
  clientName?: string
  queries: number
  blocked: number
  percentage: number
}

export interface QueryStats {
  timestamp: string
  count: number
}

export interface QueryTypeStats {
  A: number
  AAAA: number
  CNAME: number
  MX: number
  TXT: number
  other: number
}

export interface SecurityStats {
  period: '24h' | '7d'
  totalQueries: number
  blockedQueries: number
  allowedQueries: number
  uniqueClients: number
  topBlocked: TopDomain[]
  topAllowed: TopDomain[]
  topClients: TopClient[]
  queryTypes: QueryTypeStats
  queriesOverTime: QueryStats[]
  blockingEffectiveness: number
  bandwidthSaved: number // MB
  threatsBlocked: number
  // Additional optional fields
  blocked?: number
  blockRate?: number
}

// DNS Settings
export interface DNSServer {
  id: string
  name: string
  address: string
  port?: number
  enabled: boolean
  responseTime?: number
}

export interface DNSRecord {
  id: string
  domain: string
  type: 'A' | 'AAAA' | 'CNAME' | 'MX'
  value: string
  enabled: boolean
}

export interface DNSConfig {
  upstreamServers: DNSServer[]
  enableDNSSEC: boolean
  enableCache: boolean
  cacheTTL: number
  conditionalForwarding: boolean
  localDomain?: string
  routerIP?: string
  customRecords: DNSRecord[]
  // Additional optional fields
  dnssec?: boolean
  ipv6?: boolean
  logQueries?: boolean
}

// Settings
export interface NotificationSettings {
  enabled: boolean
  email?: string
  webhook?: string
  events: {
    threatsDetected: boolean
    highBlockRate: boolean
    serviceDown: boolean
    updateAvailable: boolean
  }
}

export interface AdvancedSettings {
  apiToken?: string
  logRetentionDays: number
  updateBlocklistsHour: number
  performanceTuning: {
    cacheSize: number
    maxConnections: number
    queryTimeout: number
  }
  notifications: NotificationSettings
}

// WebSocket Events
export interface WSMessage {
  type: 'query' | 'threat' | 'stats' | 'status' | 'event'
  data: any
  timestamp: string
}

export interface RealtimeQuery extends DNSQuery {}

export interface RealtimeStats {
  currentQPS: number // Queries Per Second
  activeConnections: number
  cacheHitRate: number
}



