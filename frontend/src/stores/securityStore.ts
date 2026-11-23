import { create } from 'zustand'
import type {
  SecurityDashboard,
  ProtectionStatus,
  Blocklist,
  BlockCategory,
  DomainEntry,
  FirewallRule,
  PortForward,
  DNSQuery,
  QueryLogFilters,
  ParentalProfile,
  Device,
  Threat,
  BannedIP,
  SecurityStats,
  DNSConfig,
  AdvancedSettings,
  RealtimeQuery,
} from '../types/security'

interface SecurityState {
  // Dashboard
  dashboard: SecurityDashboard | null
  protectionStatus: ProtectionStatus
  realtimeQueries: RealtimeQuery[]
  
  // Ad Blocking
  blocklists: Blocklist[]
  blockCategories: BlockCategory[]
  blockingEnabled: boolean
  
  // Lists
  whitelist: DomainEntry[]
  blacklist: DomainEntry[]
  
  // Firewall
  firewallRules: FirewallRule[]
  portForwards: PortForward[]
  firewallEnabled: boolean
  
  // Query Log
  queryLog: DNSQuery[]
  queryFilters: QueryLogFilters
  
  // Parental Controls
  parentalProfiles: ParentalProfile[]
  devices: Device[]
  
  // Security Monitor
  threats: Threat[]
  bannedIPs: BannedIP[]
  
  // Statistics
  stats: SecurityStats | null
  
  // DNS Settings
  dnsConfig: DNSConfig | null
  
  // Advanced Settings
  advancedSettings: AdvancedSettings | null
  
  // Actions
  setDashboard: (dashboard: SecurityDashboard) => void
  setProtectionStatus: (status: ProtectionStatus) => void
  addRealtimeQuery: (query: RealtimeQuery) => void
  clearRealtimeQueries: () => void
  
  setBlocklists: (blocklists: Blocklist[]) => void
  updateBlocklist: (id: string, updates: Partial<Blocklist>) => void
  
  setBlockCategories: (categories: BlockCategory[]) => void
  toggleBlockCategory: (id: string) => void
  
  setWhitelist: (list: DomainEntry[]) => void
  setBlacklist: (list: DomainEntry[]) => void
  addToWhitelist: (entry: DomainEntry) => void
  addToBlacklist: (entry: DomainEntry) => void
  removeFromWhitelist: (id: string) => void
  removeFromBlacklist: (id: string) => void
  
  setFirewallRules: (rules: FirewallRule[]) => void
  addFirewallRule: (rule: FirewallRule) => void
  removeFirewallRule: (id: string) => void
  toggleFirewallRule: (id: string) => void
  
  setPortForwards: (forwards: PortForward[]) => void
  
  setQueryLog: (queries: DNSQuery[]) => void
  setQueryFilters: (filters: QueryLogFilters) => void
  addQuery: (query: DNSQuery) => void
  
  setParentalProfiles: (profiles: ParentalProfile[]) => void
  addParentalProfile: (profile: ParentalProfile) => void
  updateParentalProfile: (id: string, updates: Partial<ParentalProfile>) => void
  removeParentalProfile: (id: string) => void
  
  setDevices: (devices: Device[]) => void
  assignDeviceProfile: (deviceId: string, profileId: string) => void
  
  setThreats: (threats: Threat[]) => void
  addThreat: (threat: Threat) => void
  updateThreat: (id: string, updates: Partial<Threat>) => void
  
  setBannedIPs: (ips: BannedIP[]) => void
  addBannedIP: (ip: BannedIP) => void
  removeBannedIP: (ip: string) => void
  
  setStats: (stats: SecurityStats) => void
  setDNSConfig: (config: DNSConfig) => void
  setAdvancedSettings: (settings: AdvancedSettings) => void
  
  toggleBlocking: () => void
  toggleFirewall: () => void
}

export const useSecurityStore = create<SecurityState>((set) => ({
  // Initial State
  dashboard: null,
  protectionStatus: { enabled: true, disabledUntil: null },
  realtimeQueries: [],
  
  blocklists: [],
  blockCategories: [],
  blockingEnabled: true,
  
  whitelist: [],
  blacklist: [],
  
  firewallRules: [],
  portForwards: [],
  firewallEnabled: true,
  
  queryLog: [],
  queryFilters: {},
  
  parentalProfiles: [],
  devices: [],
  
  threats: [],
  bannedIPs: [],
  
  stats: null,
  dnsConfig: null,
  advancedSettings: null,
  
  // Actions
  setDashboard: (dashboard) => set({ dashboard }),
  setProtectionStatus: (status) => set({ protectionStatus: status }),
  
  addRealtimeQuery: (query) => set((state) => ({
    realtimeQueries: [query, ...state.realtimeQueries].slice(0, 100)
  })),
  
  clearRealtimeQueries: () => set({ realtimeQueries: [] }),
  
  setBlocklists: (blocklists) => set({ blocklists }),
  updateBlocklist: (id, updates) => set((state) => ({
    blocklists: state.blocklists.map(bl => 
      bl.id === id ? { ...bl, ...updates } : bl
    )
  })),
  
  setBlockCategories: (categories) => set({ blockCategories: categories }),
  toggleBlockCategory: (id) => set((state) => ({
    blockCategories: state.blockCategories.map(cat =>
      cat.id === id ? { ...cat, enabled: !cat.enabled } : cat
    )
  })),
  
  setWhitelist: (list) => set({ whitelist: list }),
  setBlacklist: (list) => set({ blacklist: list }),
  
  addToWhitelist: (entry) => set((state) => ({
    whitelist: [entry, ...state.whitelist]
  })),
  
  addToBlacklist: (entry) => set((state) => ({
    blacklist: [entry, ...state.blacklist]
  })),
  
  removeFromWhitelist: (id) => set((state) => ({
    whitelist: state.whitelist.filter(e => e.id !== id)
  })),
  
  removeFromBlacklist: (id) => set((state) => ({
    blacklist: state.blacklist.filter(e => e.id !== id)
  })),
  
  setFirewallRules: (rules) => set({ firewallRules: rules }),
  
  addFirewallRule: (rule) => set((state) => ({
    firewallRules: [rule, ...state.firewallRules]
  })),
  
  removeFirewallRule: (id) => set((state) => ({
    firewallRules: state.firewallRules.filter(r => r.id !== id)
  })),
  
  toggleFirewallRule: (id) => set((state) => ({
    firewallRules: state.firewallRules.map(rule =>
      rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
    )
  })),
  
  setPortForwards: (forwards) => set({ portForwards: forwards }),
  
  setQueryLog: (queries) => set({ queryLog: queries }),
  setQueryFilters: (filters) => set({ queryFilters: filters }),
  
  addQuery: (query) => set((state) => ({
    queryLog: [query, ...state.queryLog].slice(0, 1000)
  })),
  
  setParentalProfiles: (profiles) => set({ parentalProfiles: profiles }),
  
  addParentalProfile: (profile) => set((state) => ({
    parentalProfiles: [...state.parentalProfiles, profile]
  })),
  
  updateParentalProfile: (id, updates) => set((state) => ({
    parentalProfiles: state.parentalProfiles.map(p =>
      p.id === id ? { ...p, ...updates } : p
    )
  })),
  
  removeParentalProfile: (id) => set((state) => ({
    parentalProfiles: state.parentalProfiles.filter(p => p.id !== id)
  })),
  
  setDevices: (devices) => set({ devices }),
  
  assignDeviceProfile: (deviceId, profileId) => set((state) => ({
    devices: state.devices.map(d =>
      d.id === deviceId ? { ...d, profileId } : d
    )
  })),
  
  setThreats: (threats) => set({ threats }),
  
  addThreat: (threat) => set((state) => ({
    threats: [threat, ...state.threats]
  })),
  
  updateThreat: (id, updates) => set((state) => ({
    threats: state.threats.map(t =>
      t.id === id ? { ...t, ...updates } : t
    )
  })),
  
  setBannedIPs: (ips) => set({ bannedIPs: ips }),
  
  addBannedIP: (ip) => set((state) => ({
    bannedIPs: [ip, ...state.bannedIPs]
  })),
  
  removeBannedIP: (ip) => set((state) => ({
    bannedIPs: state.bannedIPs.filter(b => b.ip !== ip)
  })),
  
  setStats: (stats) => set({ stats }),
  setDNSConfig: (config) => set({ dnsConfig: config }),
  setAdvancedSettings: (settings) => set({ advancedSettings: settings }),
  
  toggleBlocking: () => set((state) => ({
    blockingEnabled: !state.blockingEnabled
  })),
  
  toggleFirewall: () => set((state) => ({
    firewallEnabled: !state.firewallEnabled
  })),
}))
