// Network Toolkit Types - Complete

// Tool IDs
export type ToolId = 
  | 'lan-scanner'
  | 'port-scanner'
  | 'speed-test'
  | 'network-map'
  | 'traffic-graph'
  | 'active-connections'
  | 'arp-scanner'
  | 'open-ports-alert'

// Common Types
export type ScanSpeed = 'fast' | 'normal' | 'deep'
export type ScanType = 'tcp-syn' | 'tcp-connect' | 'udp'
export type PortStatus = 'open' | 'closed' | 'filtered'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type DeviceStatus = 'online' | 'offline' | 'limited'
export type ConnectionState = 'ESTABLISHED' | 'LISTENING' | 'TIME_WAIT' | 'CLOSE_WAIT' | 'SYN_SENT' | 'SYN_RECEIVED'
export type LayoutType = 'radial' | 'hierarchical' | 'force-directed' | 'grid'
export type DeviceType =
  | 'computer'
  | 'phone'
  | 'printer'
  | 'router'
  | 'tv'
  | 'console'
  | 'pi'
  | 'nas'
  | 'sbc'
  | 'iot'
  | 'smart-tv'
  | 'smart-speaker'
  | 'network'
  | 'gaming'
  | 'apple'
  | 'google'
  | 'virtual'
  | 'camera'
  | 'tablet'
  | 'server'
  | 'media'
  | 'unknown'
export type ExportFormat = 'json' | 'csv' | 'xml'

// LAN Scanner
export interface LANDevice {
  id: string
  ip: string
  mac: string
  vendor: string
  hostname: string
  customName?: string
  status: DeviceStatus
  lastSeen: string
  ports?: number[]
  deviceType?: DeviceType
  dhcpVendorClass?: string
  identitySources?: string[]
  identityConfidence?: number
  interfaces?: Array<{ name: string; ip: string; mac: string }>
  isLocalDevice?: boolean
}

export interface LANScanConfig {
  networkRange: string
  scanSpeed: ScanSpeed
  detectVendor: boolean
  resolveHostnames: boolean
  portDiscovery: boolean
}

export interface LANScanResult {
  devices: LANDevice[]
  scanTime: number
  networkRange: string
  timestamp: string
}

// Port Scanner
export interface PortInfo {
  port: number
  protocol: 'TCP' | 'UDP'
  status: PortStatus
  service: string
  riskLevel: RiskLevel
  description: string
  version?: string
}

export interface PortScanConfig {
  targetHost: string
  portRange: string
  scanType: ScanType
  timeout: number
}

export interface PortScanResult {
  host: string
  ports: PortInfo[]
  scanTime: number
  timestamp: string
  openCount: number
  closedCount: number
  filteredCount: number
}

// Speed Test
export interface SpeedTestServer {
  id: string
  name: string
  location: string
  country: string
  distance: number
}

export interface SpeedTestConfig {
  serverId?: string
  testDownload: boolean
  testUpload: boolean
  testPing: boolean
  testJitter: boolean
}

export interface SpeedTestResult {
  download: number // Mbps
  upload: number // Mbps
  ping: number // ms
  jitter: number // ms
  server: SpeedTestServer
  timestamp: string
  isp?: string
  ipAddress?: string
}

export interface SpeedTestProgress {
  phase: 'download' | 'upload' | 'ping' | 'complete'
  progress: number
  currentSpeed: number
}

// Network Map
export interface NetworkNode {
  id: string
  label: string
  ip: string
  mac?: string
  type: DeviceType
  status: DeviceStatus
  x?: number
  y?: number
}

export interface NetworkEdge {
  from: string
  to: string
  bandwidth?: number
  latency?: number
  traffic?: number
}

export interface NetworkMapData {
  nodes: NetworkNode[]
  edges: NetworkEdge[]
  layout: LayoutType
}

export interface NetworkMapConfig {
  layoutType: LayoutType
  showIPs: boolean
  showNames: boolean
  showSpeed: boolean
  showTraffic: boolean
}

// Traffic Graph
export interface TrafficData {
  timestamp: string
  download: number // KB/s
  upload: number // KB/s
}

export interface TrafficStats {
  currentDownload: number
  currentUpload: number
  totalReceived: number
  totalSent: number
  peakDownload: number
  peakUpload: number
}

export type TrafficInterval = '1min' | '5min' | '15min' | '1hour'

// Active Connections
export interface ActiveConnection {
  id: string
  localAddress: string
  localPort: number
  remoteAddress: string | null
  remotePort: number | null
  protocol: 'TCP' | 'UDP'
  state: ConnectionState
  processName?: string
  pid?: number
}

export interface ConnectionFilters {
  protocol?: 'TCP' | 'UDP'
  state?: ConnectionState
  process?: string
  search?: string
}

// ARP Scanner
export interface ARPEntry {
  id: string
  ip: string
  mac: string
  vendor: string
  interface: string
  type: 'dynamic' | 'static'
  state?: string  // REACHABLE, STALE, DELAY, etc.
  isNew?: boolean
}

export interface ARPScanResult {
  entries: ARPEntry[]
  timestamp: string
}

// Open Ports Alert
export interface PortAlert {
  id: string
  port: number
  service: string
  protocol: 'TCP' | 'UDP'
  riskLevel: RiskLevel
  description: string
  recommendation: string
  isMonitored: boolean
  lastDetected: string
}

export interface PortAlertConfig {
  enabled: boolean
  monitoredPorts: number[]
  checkInterval: number // minutes
  notifyOnNew: boolean
}

// Tool Configuration
export interface ToolConfig {
  id: ToolId
  name: string
  icon: string
  description: string
  enabled: boolean
  badge?: number
}

// API Response Types
export interface NetworkApiResponse<T> {
  success: boolean
  data?: T
  error?: string
  timestamp: string
}

export interface ScanProgress {
  status: 'idle' | 'running' | 'completed' | 'error'
  progress: number
  message?: string
  currentStep?: string
}

// Legacy Types (for backward compatibility)
export interface NetworkHost {
  ip: string
  mac?: string | null
  vendor?: string | null
  hostname?: string | null
  device_type?: string | null
  type_confidence?: number | null
  status: 'online'
}

export interface HostScanResponse {
  network: string
  hosts: NetworkHost[]
}

export type PortScanMode = 'quick' | 'full' | 'deep'

export interface PortScanResponse {
  target: string
  mode: PortScanMode
  ports: PortInfo[]
}

export interface PingResponse {
  target: string
  online: boolean
  raw_output: string
}

export interface DnsLookupResponse {
  domain: string
  addresses: string[]
  raw_output: string
}

export interface SpeedtestResponse {
  ping_ms: number | null
  download_mbps: number | null
  upload_mbps: number | null
}

export type NetworkResult =
  | { type: 'hosts'; data: HostScanResponse }
  | { type: 'ports'; data: PortScanResponse }
  | { type: 'ping'; data: PingResponse }
  | { type: 'dns'; data: DnsLookupResponse }
  | { type: 'speedtest'; data: SpeedtestResponse }

// Network Activity / Traffic Monitoring Types (NetProtection Integration)
export interface NetworkDevice {
  id: string;
  name: string;
  ip: string;
  client_id?: string;
  identityResolved?: boolean;
  mac?: string;
  hostname?: string;
  vendor?: string;
  lastSeen: string;
  status: 'online' | 'offline';
  requestsCount: number;
  blockedCount: number;
  allowedCount: number;
}

export interface DNSQuery {
  id: string;
  timestamp: string;
  device: string;
  deviceName: string;
  domain: string;
  queryType: string; // A, AAAA, CNAME, etc
  status: 'allowed' | 'blocked' | 'filtered';
  reason?: string; // Block reason if blocked
  responseTime?: number; // ms
  answer?: string[]; // IP addresses or CNAME results
}

export interface PrismActivity {
  id: string;
  timestamp: string;
  domain: string;
  queryType: 'TLS' | 'QUIC';
  status: 'observed';
  source: 'prism';
  reason?: string;
  client_ip: string;
}

export interface PrismActivityResponse {
  data: PrismActivity[];
  total: number;
}

export interface DeviceTraffic {
  device: string;
  deviceName: string;
  totalQueries: number;
  blockedQueries: number;
  allowedQueries: number;
  topDomains: DomainStats[];
  topBlockedDomains: DomainStats[];
  recentQueries: DNSQuery[];
  queryHistory: QueryHistoryPoint[];
}

export interface DomainStats {
  domain: string;
  count: number;
  blocked: number;
  allowed: number;
  percentage: number;
}

export interface QueryHistoryPoint {
  timestamp: string;
  total: number;
  blocked: number;
  allowed: number;
}

export interface NetworkActivityStats {
  totalDevices: number;
  activeDevices: number;
  totalQueries: number;
  blockedQueries: number;
  allowedQueries: number;
  blockRate: number;
  topDevice: string;
  topDomain: string;
}

export interface NetProtectionStatus {
  running: boolean;
  protectionEnabled: boolean;
  version: string;
  uptime?: number;
  dnsPort: number;
  httpPort: number;
}
