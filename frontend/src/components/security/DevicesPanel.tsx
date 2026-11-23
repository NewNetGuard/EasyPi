/**
 * Devices Panel - Device Baseline + Per-device Rules
 * 
 * Features:
 * - List all devices on network
 * - Per-device blocking rules
 * - Anomaly detection (baseline behavior)
 * - Device activity history
 * 
 * © 2025 EasyPi Project
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useLocation, useNavigate } from 'react-router-dom'
import {
  Monitor,
  Smartphone,
  Laptop,
  Tv,
  Wifi,
  AlertTriangle,
  Shield,
  Ban,
  Check,
  Clock,
  Activity,
  TrendingUp,
  TrendingDown,
  Search,
  Filter,
  MoreVertical,
  Settings,
  Eye,
  X,
  ChevronDown,
  ChevronUp,
  Zap,
  Globe,
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import api, { securityApi } from '../../api/client'

interface Device {
  id: string
  name: string
  mac: string
  ip: string
  vendor?: string
  type: 'computer' | 'phone' | 'tablet' | 'tv' | 'iot' | 'unknown'
  first_seen: string
  last_seen: string
  is_online: boolean
  profile_id?: string
  profile_name?: string
  // Baseline stats
  baseline?: {
    avg_queries_per_hour: number
    peak_hour: number
    top_domains: string[]
    unusual_activity: boolean
    anomaly_score: number
  }
  // Today's stats
  today?: {
    total_queries: number
    blocked_queries: number
    unique_domains: number
    last_query?: string
  }
  // Rules
  rules?: DeviceRule[]
}

interface DeviceRule {
  id: string
  type: 'block' | 'allow'
  target: string
  target_type: 'domain' | 'category'
  enabled: boolean
}

interface BrowsingActivityEntry {
  id: string
  timestamp: string
  domain: string
  host: string
  source: 'dns' | 'tls' | 'dns+tls'
  trafficClass: 'site' | 'service'
  status: 'connected'
}

interface BrowsingActivityResponse {
  device: string
  deviceIdentity: string
  historySince: string
  activity: BrowsingActivityEntry[]
  total: number
  scope: string
}

interface DeviceGroup {
  type: string
  devices: Device[]
}

// Device type icons
const DEVICE_ICONS: Record<string, any> = {
  computer: Laptop,
  phone: Smartphone,
  tablet: Smartphone,
  tv: Tv,
  iot: Wifi,
  unknown: Monitor,
}

// A device counts as "online" if it made a DNS query within this window.
const ONLINE_WINDOW_MS = 15 * 60 * 1000

// API calls
const fetchDevices = async (): Promise<{ devices: Device[] }> => {
  try {
    // Per-device activity (today stats + the real online signal via lastSeen).
    const activityMap = new Map<string, any>()
    let activityAvailable = false
    try {
      const { data } = await api.get('/network-activity/devices')
      activityAvailable = true
      for (const d of data?.devices || []) {
        if (d?.ip) activityMap.set(d.ip, d)
      }
    } catch {
      // Network activity may be unavailable
    }

    // Per-device behavior baseline / anomaly, keyed by IP (merged into the list
    // below so anomalies show on the primary path, not only in a fallback).
    const baselineByIp = new Map<string, any>()
    try {
      const { data } = await api.get('/netprotection/devices/baseline')
      const items = data?.data?.items || data?.items || data || []
      for (const b of items) {
        const ip = b.ip || b.baseline?.ip
        if (ip) baselineByIp.set(ip, b)
      }
    } catch {
      // No baseline data yet
    }

    const now = Date.now()
    const isRecent = (ts?: string): boolean => {
      if (!ts) return false
      const t = new Date(ts).getTime()
      return !isNaN(t) && now - t < ONLINE_WINDOW_MS
    }

    const mapBaseline = (b: any): Device['baseline'] | undefined => {
      if (!b) return undefined
      const bl = b.baseline || {}
      const rawScore = b.anomaly_score ?? bl.anomaly_score ?? 0
      const score = Math.round((rawScore <= 1 ? rawScore * 100 : rawScore))
      const hasData =
        bl.queries_per_hour != null ||
        bl.avg_queries_per_hour != null ||
        bl.peak_hour != null ||
        (bl.top_domains && bl.top_domains.length) ||
        rawScore > 0
      if (!hasData) return undefined
      return {
        avg_queries_per_hour: bl.queries_per_hour || bl.avg_queries_per_hour || 0,
        peak_hour: typeof bl.peak_hour === 'number' ? bl.peak_hour : -1,
        top_domains: bl.top_domains || [],
        unusual_activity: score >= 50,
        anomaly_score: score,
      }
    }

    // Enrich a device with real online status, today stats and baseline.
    const enrich = (device: Device): Device => {
      const activity = activityMap.get(device.ip)
      if (activity) {
        device.today = {
          total_queries: activity.requestsCount || 0,
          blocked_queries: activity.blockedCount || 0,
          unique_domains: device.today?.unique_domains || 0,
          last_query: device.today?.last_query,
        }
        if (activity.lastSeen) device.last_seen = activity.lastSeen
      }
      // Real online = recent DNS activity. If the activity feed is entirely
      // unavailable we can't tell, so don't mark everything offline.
      const presentOnLan = device.is_online === true
      device.is_online = presentOnLan || (activityAvailable ? isRecent(device.last_seen) : true)

      const baseline = mapBaseline(baselineByIp.get(device.ip))
      if (baseline) device.baseline = baseline
      const b = baselineByIp.get(device.ip)
      if (b?.first_seen && !device.first_seen) device.first_seen = b.first_seen
      return device
    }

    // First try to get cached devices from LAN scan (most reliable source)
    const cachedResponse = await fetch('/api/network-toolkit/cached-devices', {
      credentials: 'include'
    })

    if (cachedResponse.ok) {
      const cachedData = await cachedResponse.json()
      const cachedDevices = cachedData?.devices || []
      const scanTime = cachedData?.last_scan_time || ''

      if (cachedDevices.length > 0) {
        return {
          devices: cachedDevices
            .filter((d: any) => !d.is_router) // Exclude router
            .map((d: any): Device => ({
              id: d.mac || d.ip || String(Math.random()),
              name: d.hostname && d.hostname !== d.ip ? d.hostname : (d.vendor ? `${d.vendor} Device` : 'Unknown Device'),
              mac: d.mac || '',
              ip: d.ip || '',
              vendor: d.vendor,
              type: detectDeviceType(d.hostname || '', d.vendor),
              first_seen: d.first_seen || '',
              last_seen: d.last_seen || scanTime || '',
              is_online: d.is_online === true,
              baseline: undefined,
              today: {
                total_queries: 0,
                blocked_queries: 0,
                unique_domains: 0,
              },
            }))
            .map(enrich),
        }
      }
    }

    // Fallback: try baseline endpoint
    try {
      const { data } = await api.get('/netprotection/devices/baseline')
      const items = data?.data?.items || data?.items || data || []

      if (items.length > 0) {
        return {
          devices: items.map((d: any): Device => ({
            id: d.id || d.mac || String(Math.random()),
            name: d.name || d.hostname || 'Unknown Device',
            mac: d.mac || '',
            ip: d.ip || '',
            vendor: d.vendor,
            type: d.type || 'unknown',
            first_seen: d.first_seen || '',
            last_seen: d.baseline?.last_seen || d.last_seen || '',
            is_online: false,
            baseline: mapBaseline(d),
            today: d.today || {
              total_queries: d.queries_today || 0,
              blocked_queries: d.blocked_today || 0,
              unique_domains: d.unique_domains || 0,
            },
          }))
          .map(enrich),
        }
      }
    } catch {
      // baseline endpoint may not exist or be empty
    }

    // Fallback: try parental clients endpoint (always has configured clients)
    try {
      const clientsResponse = await fetch('/api/v1/netprotection/parental/clients?include_all=true', {
        credentials: 'include'
      })
      if (clientsResponse.ok) {
        const clientsData = await clientsResponse.json()
        const clients = clientsData?.clients || clientsData || []

        if (clients.length > 0) {
          return {
            devices: clients.map((c: any): Device => {
              const ip = c.ids?.[0] || c.ip || ''
              return {
                id: c.name || ip,
                name: c.name || 'Unknown Device',
                mac: c.mac || '',
                ip: ip,
                vendor: undefined,
                type: 'unknown' as const,
                first_seen: c.created_at || '',
                last_seen: c.updated_at || '',
                is_online: false,
                profile_id: c.profile_id,
                profile_name: c.profile_name,
                baseline: undefined,
                today: {
                  total_queries: 0,
                  blocked_queries: 0,
                  unique_domains: 0,
                },
                rules: c.blocked_services?.map((s: string) => ({
                  id: s,
                  type: 'block' as const,
                  target: s,
                  target_type: 'category' as const,
                  enabled: true,
                })) || [],
              }
            }).map(enrich),
          }
        }
      }
    } catch {
      // parental clients endpoint may fail
    }

    // Return empty
    return { devices: [] }
  } catch {
    // Return empty array instead of mock data
    return { devices: [] }
  }
}

const fetchBrowsingActivity = async (
  deviceIp: string,
  deviceMac: string,
  refresh = false,
): Promise<BrowsingActivityResponse> => {
  const { data } = await api.get(
    `/network-activity/devices/${encodeURIComponent(deviceIp)}/browsing`,
    { params: { mac: deviceMac, limit: 200, refresh } },
  )
  return data
}

// Detect device type based on vendor or name
const detectDeviceType = (name: string, vendor?: string): Device['type'] => {
  const n = (name || '').toLowerCase()
  const v = (vendor || '').toLowerCase()
  
  if (n.includes('iphone') || n.includes('android') || n.includes('pixel') || n.includes('galaxy')) return 'phone'
  if (n.includes('ipad') || n.includes('tablet')) return 'tablet'
  if (n.includes('tv') || n.includes('roku') || n.includes('chromecast') || n.includes('fire stick')) return 'tv'
  if (n.includes('macbook') || n.includes('laptop') || n.includes('desktop') || n.includes('pc')) return 'computer'
  if (v.includes('apple')) return n.includes('watch') ? 'iot' : 'computer'
  if (v.includes('samsung') && n.includes('tv')) return 'tv'
  if (n.includes('camera') || n.includes('thermostat') || n.includes('alexa') || n.includes('echo')) return 'iot'
  
  return 'unknown'
}

export default function DevicesPanel() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const location = useLocation()
  const [searchQuery, setSearchQuery] = useState('')
  const [filterType, setFilterType] = useState<string>('all')
  const [filterStatus, setFilterStatus] = useState<'all' | 'online' | 'offline' | 'anomaly'>('all')
  const [expandedDevice, setExpandedDevice] = useState<string | null>(null)
  const [dismissedAnomalies, setDismissedAnomalies] = useState<Set<string>>(new Set())
  const [browsingDevice, setBrowsingDevice] = useState<Device | null>(null)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['devices'],
    queryFn: fetchDevices,
    refetchInterval: 30000,
  })

  const devices = data?.devices || []

  const {
    data: browsingData,
    isLoading: browsingLoading,
    isError: browsingError,
  } = useQuery({
    queryKey: [
      'device-browsing-activity',
      browsingDevice?.ip,
      browsingDevice?.mac,
    ],
    queryFn: () => fetchBrowsingActivity(
      browsingDevice!.ip,
      browsingDevice!.mac,
    ),
    enabled: !!browsingDevice?.ip,
    refetchInterval: browsingDevice ? 15000 : false,
    retry: 1,
  })

  const isAnomalous = (d: Device) => !!d.baseline?.unusual_activity && !dismissedAnomalies.has(d.id)
  const handleDismissAnomaly = (id: string) =>
    setDismissedAnomalies((prev) => new Set(prev).add(id))

  const addRuleMutation = useMutation({
    mutationFn: async ({ ip, type, domain }: { ip: string; type: 'block' | 'allow'; domain: string }) => {
      const { data } = await securityApi.post(`/devices/${encodeURIComponent(ip)}/rules`, { type, domain })
      return data
    },
  })

  const handleAddRule = async (device: Device, type: 'block' | 'allow') => {
    if (!device.ip) {
      toast.error('Device IP is missing')
      return
    }
    const promptText = type === 'block' ? 'Enter domain to block for this device:' : 'Enter domain to allow for this device:'
    const domain = window.prompt(promptText)
    if (!domain) return
    try {
      await addRuleMutation.mutateAsync({ ip: device.ip, type, domain })
      queryClient.invalidateQueries({ queryKey: ['device-rules', device.ip] })
      toast.success(`${type === 'block' ? 'Blocked' : 'Allowed'} ${domain} for ${device.name}`)
    } catch {
      toast.error('Failed to update device rule')
    }
  }

  const handleViewLog = (device: Device) => {
    if (!device.ip || !device.mac) {
      toast.error('A verified device IP and MAC are required')
      return
    }
    setBrowsingDevice(device)
  }

  const handleRefreshBrowsing = async () => {
    if (!browsingDevice?.ip) return
    try {
      const refreshed = await fetchBrowsingActivity(
        browsingDevice.ip,
        browsingDevice.mac,
        true,
      )
      queryClient.setQueryData(
        [
          'device-browsing-activity',
          browsingDevice.ip,
          browsingDevice.mac,
        ],
        refreshed,
      )
    } catch {
      toast.error('Could not refresh browsing activity')
    }
  }

  const handleAddSchedule = (device: Device) => {
    const params = new URLSearchParams(location.search)
    params.set('tab', 'schedules')
    if (device.ip) params.set('device', device.ip)
    navigate(`${location.pathname}?${params.toString()}`)
  }

  // Filter devices
  const filteredDevices = devices.filter(device => {
    // Search filter
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      if (!device.name.toLowerCase().includes(q) && 
          !device.ip.includes(q) && 
          !device.mac.toLowerCase().includes(q) &&
          !(device.vendor?.toLowerCase().includes(q))) {
        return false
      }
    }
    
    // Type filter
    if (filterType !== 'all' && device.type !== filterType) {
      return false
    }
    
    // Status filter
    if (filterStatus === 'online' && !device.is_online) return false
    if (filterStatus === 'offline' && device.is_online) return false
    if (filterStatus === 'anomaly' && !isAnomalous(device)) return false
    
    return true
  })

  // Group by type
  const deviceGroups: DeviceGroup[] = []
  const types = [...new Set(filteredDevices.map(d => d.type))]
  types.forEach(type => {
    deviceGroups.push({
      type,
      devices: filteredDevices.filter(d => d.type === type),
    })
  })

  // Stats
  const onlineCount = devices.filter(d => d.is_online).length
  const anomalyCount = devices.filter(isAnomalous).length
  const totalQueries = devices.reduce((sum, d) => sum + (d.today?.total_queries || 0), 0)
  const blockedQueries = devices.reduce((sum, d) => sum + (d.today?.blocked_queries || 0), 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 sm:gap-4">
          <Monitor className="w-10 h-10 sm:w-16 sm:h-16 text-blue-600 dark:text-blue-400" />
          <div>
            <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">
              Devices
            </h2>
            <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
              Monitor and control network devices
            </p>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
        <StatCard
          icon={<Wifi className="w-5 h-5 text-green-500" />}
          label="Online"
          value={`${onlineCount}/${devices.length}`}
          onClick={() => setFilterStatus('online')}
          active={filterStatus === 'online'}
        />
        <StatCard
          icon={<AlertTriangle className="w-5 h-5 text-orange-500" />}
          label="Anomalies"
          value={anomalyCount}
          onClick={() => setFilterStatus('anomaly')}
          active={filterStatus === 'anomaly'}
          highlight={anomalyCount > 0}
        />
        <StatCard
          icon={<Activity className="w-5 h-5 text-blue-500" />}
          label="Queries Today"
          value={totalQueries.toLocaleString()}
        />
        <StatCard
          icon={<Ban className="w-5 h-5 text-red-500" />}
          label="Blocked"
          value={blockedQueries.toLocaleString()}
        />
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-2 sm:gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search devices..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm"
          />
        </div>
        
        <div className="flex gap-2">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="flex-1 sm:flex-none px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm"
          >
            <option value="all">All Types</option>
            <option value="computer">Computers</option>
            <option value="phone">Phones</option>
            <option value="tablet">Tablets</option>
            <option value="tv">TVs</option>
            <option value="iot">IoT</option>
            <option value="unknown">Unknown</option>
          </select>

          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as any)}
            className="flex-1 sm:flex-none px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm"
          >
            <option value="all">All Status</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="anomaly">Anomalies</option>
          </select>
        </div>
      </div>

      {/* Device List */}
      <div className="space-y-6">
        {isLoading ? (
          <div className="text-center py-12 text-gray-500">Loading devices...</div>
        ) : filteredDevices.length === 0 ? (
          <div className="text-center py-12">
            <Monitor className="w-12 h-12 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">No devices found</p>
          </div>
        ) : (
          filteredDevices.map((device) => (
            <DeviceCard
              key={device.id}
              device={device}
              anomalous={isAnomalous(device)}
              expanded={expandedDevice === device.id}
              onToggle={() => setExpandedDevice(
                expandedDevice === device.id ? null : device.id
              )}
              onAddRule={handleAddRule}
              onAddSchedule={handleAddSchedule}
              onViewLog={handleViewLog}
              onDismissAnomaly={handleDismissAnomaly}
            />
          ))
        )}
      </div>

      {browsingDevice && (
        <BrowsingActivityModal
          device={browsingDevice}
          entries={browsingData?.activity || []}
          loading={browsingLoading}
          error={browsingError}
          onRefresh={() => void handleRefreshBrowsing()}
          onClose={() => setBrowsingDevice(null)}
        />
      )}

    </div>
  )
}

// Stat Card Component
function StatCard({ icon, label, value, onClick, active, highlight }: {
  icon: React.ReactNode
  label: string
  value: string | number
  onClick?: () => void
  active?: boolean
  highlight?: boolean
}) {
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      className={`p-3 sm:p-4 rounded-xl border-2 transition-all text-left ${
        active
          ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
          : highlight
            ? 'border-orange-300 bg-orange-50 dark:bg-orange-900/20 dark:border-orange-700'
            : 'border-transparent bg-white dark:bg-gray-800'
      } ${onClick ? 'cursor-pointer hover:shadow-md' : ''}`}
    >
      <div className="flex items-center gap-2 sm:gap-3 mb-1 sm:mb-2">
        {icon}
        <span className="text-xs sm:text-sm text-gray-500">{label}</span>
      </div>
      <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
    </button>
  )
}

// Device Card Component
function DeviceCard({ device, anomalous, expanded, onToggle, onAddRule, onAddSchedule, onViewLog, onDismissAnomaly }: {
  device: Device
  anomalous: boolean
  expanded: boolean
  onToggle: () => void
  onAddRule: (device: Device, type: 'block' | 'allow') => void
  onAddSchedule: (device: Device) => void
  onViewLog: (device: Device) => void
  onDismissAnomaly: (id: string) => void
}) {
  const Icon = DEVICE_ICONS[device.type] || Monitor
  const hasAnomaly = anomalous
  const anomalyScore = device.baseline?.anomaly_score || 0
  const queryClient = useQueryClient()

  // Existing per-device rules (fetched only while the card is expanded).
  const { data: deviceRules } = useQuery({
    queryKey: ['device-rules', device.ip],
    queryFn: async () => {
      const { data } = await securityApi.get(`/devices/${encodeURIComponent(device.ip)}/rules`)
      return (data?.rules || []) as { type: 'block' | 'allow'; domain: string }[]
    },
    enabled: expanded && !!device.ip,
  })

  const removeRuleMutation = useMutation({
    mutationFn: async (rule: { type: 'block' | 'allow'; domain: string }) => {
      await securityApi.delete(`/devices/${encodeURIComponent(device.ip)}/rules`, { data: rule })
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['device-rules', device.ip] }),
  })

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl border ${
      hasAnomaly
        ? 'border-orange-300 dark:border-orange-700'
        : 'border-gray-200 dark:border-gray-700'
    } overflow-hidden`}>
      {/* Header */}
      <div
        className="p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50"
        onClick={onToggle}
      >
        <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className={`p-3 rounded-xl ${
                      device.is_online
                ? 'bg-green-100 dark:bg-green-900/30'
                : 'bg-gray-100 dark:bg-gray-700'
            }`}>
              <Icon className={`w-6 h-6 ${
                device.is_online ? 'text-green-600' : 'text-gray-400'
              }`} />
            </div>
            
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="font-semibold text-gray-900 dark:text-white">
                          {device.name}
                        </h4>
                        <span className={`w-2 h-2 rounded-full ${
                          device.is_online ? 'bg-green-500' : 'bg-gray-400'
                        }`} />
                {hasAnomaly && (
                  <span className="px-2 py-0.5 text-xs font-medium bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded-full">
                    Anomaly Detected
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3 text-sm text-gray-500 mt-1">
                <span>{device.ip}</span>
                <span>•</span>
                <span>{device.mac}</span>
                {device.vendor && (
                  <>
                    <span>•</span>
                    <span>{device.vendor}</span>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Today's stats */}
            {device.today && (
              <div className="text-right">
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {device.today.total_queries.toLocaleString()} queries
                </div>
                <div className="text-xs text-gray-500">
                  {device.today.blocked_queries} blocked
                </div>
              </div>
            )}
            
            {/* Anomaly score */}
            {device.baseline && (
              <div className={`px-3 py-1.5 rounded-lg ${
                anomalyScore >= 50
                  ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                  : anomalyScore >= 25
                    ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
                    : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
              }`}>
                <div className="text-xs font-medium">Risk Score</div>
                <div className="text-lg font-bold">{anomalyScore}</div>
              </div>
            )}
            
            {expanded ? (
              <ChevronUp className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            )}
          </div>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="border-t border-gray-100 dark:border-gray-700 p-4 bg-gray-50 dark:bg-gray-800/50">
          <div className="grid grid-cols-2 gap-6">
            {/* Baseline Info */}
            {device.baseline && (
              <div>
                <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                  Behavior Baseline
                </h5>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Avg queries/hour</span>
                    <span className="font-medium text-gray-900 dark:text-white">
                      {device.baseline.avg_queries_per_hour}
                    </span>
                  </div>
                  {device.baseline.peak_hour >= 0 && (
                    <div className="flex justify-between">
                      <span className="text-gray-500">Peak activity</span>
                      <span className="font-medium text-gray-900 dark:text-white">
                        {device.baseline.peak_hour}:00
                      </span>
                    </div>
                  )}
                  <div>
                    <span className="text-gray-500">Top domains:</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {device.baseline.top_domains.map(domain => (
                        <span
                          key={domain}
                          className="px-2 py-0.5 text-xs bg-gray-200 dark:bg-gray-700 rounded"
                        >
                          {domain}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Anomaly Details */}
            {hasAnomaly && (
              <div>
                <h5 className="text-sm font-semibold text-orange-600 dark:text-orange-400 mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Anomaly Details
                </h5>
                <div className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg text-sm">
                  <p className="text-orange-800 dark:text-orange-300">
                    This device is showing unusual behavior compared to its baseline.
                    Consider reviewing its recent activity.
                  </p>
                  <div className="mt-2 flex gap-2">
                    <button
                      onClick={() => onViewLog(device)}
                      className="px-3 py-1 text-xs font-medium bg-orange-600 text-white rounded hover:bg-orange-700"
                    >
                      View Query Log
                    </button>
                    <button
                      onClick={() => onDismissAnomaly(device.id)}
                      className="px-3 py-1 text-xs font-medium text-orange-600 border border-orange-600 rounded hover:bg-orange-50"
                    >
                      Dismiss Alert
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Device Rules */}
            <div className="col-span-2">
              <h5 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                Device-Specific Rules
              </h5>
              {deviceRules && deviceRules.length > 0 && (
                <div className="mb-3 flex flex-wrap gap-2">
                  {deviceRules.map((r) => (
                    <span
                      key={`${r.type}-${r.domain}`}
                      className={`inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full ${
                        r.type === 'block'
                          ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                          : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                      }`}
                    >
                      {r.type === 'block' ? <Ban className="w-3 h-3" /> : <Check className="w-3 h-3" />}
                      <span className="font-mono">{r.domain}</span>
                      <button
                        onClick={() => removeRuleMutation.mutate(r)}
                        disabled={removeRuleMutation.isPending}
                        className="ml-1 hover:opacity-70"
                        title="Remove rule"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              )}
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => onAddRule(device, 'block')}
                  className="flex items-center gap-2 px-3 py-2 text-sm border border-dashed border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  <Ban className="w-4 h-4 text-red-500" />
                  Block domain...
                </button>
                <button
                  onClick={() => onAddRule(device, 'allow')}
                  className="flex items-center gap-2 px-3 py-2 text-sm border border-dashed border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  <Check className="w-4 h-4 text-green-500" />
                  Allow domain...
                </button>
                <button
                  onClick={() => onAddSchedule(device)}
                  className="flex items-center gap-2 px-3 py-2 text-sm border border-dashed border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  <Clock className="w-4 h-4 text-purple-500" />
                  Add schedule...
                </button>
                <button
                  onClick={() => onViewLog(device)}
                  className="flex items-center gap-2 px-3 py-2 text-sm border border-dashed border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  <Eye className="w-4 h-4 text-blue-500" />
                  View Query Log
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function BrowsingActivityModal({ device, entries, loading, error, onRefresh, onClose }: {
  device: Device
  entries: BrowsingActivityEntry[]
  loading: boolean
  error: boolean
  onRefresh: () => void
  onClose: () => void
}) {
  const [trafficTab, setTrafficTab] = useState<'site' | 'service'>('site')
  const sourceLabel = (source: BrowsingActivityEntry['source']) => {
    if (source === 'dns+tls') return 'DNS + TLS'
    return source === 'tls' ? 'TLS' : 'DNS'
  }

  const sites = entries.filter((entry) => entry.trafficClass === 'site')
  const services = entries.filter((entry) => entry.trafficClass === 'service')
  const visibleEntries = trafficTab === 'site' ? sites : services

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp)
    return Number.isNaN(date.getTime())
      ? 'Unknown'
      : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-3 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="browsing-activity-title"
    >
      <div className="flex max-h-[88vh] w-full max-w-5xl flex-col overflow-hidden rounded-xl bg-white shadow-2xl dark:bg-gray-800">
        <div className="flex items-start justify-between gap-4 border-b border-gray-200 p-4 dark:border-gray-700 sm:p-5">
          <div>
            <h3 id="browsing-activity-title" className="text-lg font-semibold text-gray-900 dark:text-white">
              Domain Connections - {device.name}
            </h3>
            <p className="mt-1 font-mono text-sm text-gray-500 dark:text-gray-400">
              {device.ip}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onRefresh}
              className="rounded-lg border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-700"
            >
              Refresh
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-2 text-gray-500 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
              aria-label="Close browsing activity"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <div className="border-b border-blue-100 bg-blue-50 px-4 py-3 text-sm text-blue-800 dark:border-blue-900/50 dark:bg-blue-950/30 dark:text-blue-200 sm:px-5">
          Domains contacted by this device • Observed through DNS, TLS, or both
          <span className="mt-1 block text-xs opacity-80">
            Exact hosts are shown; HTTPS paths and page contents are not inspected.
          </span>
        </div>

        <div className="flex gap-1 border-b border-gray-200 px-4 pt-2 dark:border-gray-700 sm:px-5">
          <button
            type="button"
            onClick={() => setTrafficTab('site')}
            className={`border-b-2 px-3 py-2 text-sm font-medium ${
              trafficTab === 'site'
                ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
            }`}
          >
            Sites ({sites.length})
          </button>
          <button
            type="button"
            onClick={() => setTrafficTab('service')}
            className={`border-b-2 px-3 py-2 text-sm font-medium ${
              trafficTab === 'service'
                ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
            }`}
          >
            Service traffic ({services.length})
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-auto p-4 sm:p-5">
          {loading && entries.length === 0 ? (
            <div className="py-12 text-center text-gray-500">Loading domain connections...</div>
          ) : error && entries.length === 0 ? (
            <div className="py-12 text-center">
              <p className="text-red-600 dark:text-red-400">Could not load domain connections.</p>
              <button
                type="button"
                onClick={onRefresh}
                className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
              >
                Try again
              </button>
            </div>
          ) : entries.length === 0 ? (
            <div className="py-12 text-center">
              <Globe className="mx-auto mb-3 h-10 w-10 text-gray-300" />
              <p className="font-medium text-gray-700 dark:text-gray-200">No domain connections recorded</p>
              <p className="mt-1 text-sm text-gray-500">No DNS or TLS hostname has been observed for this device yet.</p>
            </div>
          ) : visibleEntries.length === 0 ? (
            <div className="py-12 text-center text-gray-500">
              No {trafficTab === 'site' ? 'site connections' : 'service traffic'} recorded in this period.
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
              <table className="w-full text-left text-sm">
                <thead className="bg-gray-50 text-xs uppercase text-gray-500 dark:bg-gray-900/40 dark:text-gray-400">
                  <tr>
                    <th className="px-4 py-3 font-medium">Time</th>
                    <th className="px-4 py-3 font-medium">Domain</th>
                    <th className="hidden px-4 py-3 font-medium md:table-cell">Exact host</th>
                    <th className="px-4 py-3 font-medium">Observed via</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {visibleEntries.map((entry) => (
                    <tr key={entry.id} className="text-gray-700 dark:text-gray-200">
                      <td className="whitespace-nowrap px-4 py-3 text-gray-500 dark:text-gray-400">
                        {formatTime(entry.timestamp)}
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-semibold text-gray-900 dark:text-white">{entry.domain}</div>
                        <div className="mt-1 text-xs text-gray-500 md:hidden">{entry.host}</div>
                      </td>
                      <td className="hidden px-4 py-3 font-mono text-xs text-gray-500 dark:text-gray-400 md:table-cell">
                        {entry.host}
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded bg-gray-100 px-2 py-1 text-xs font-medium text-gray-600 dark:bg-gray-700 dark:text-gray-300">
                          {sourceLabel(entry.source)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="border-t border-gray-200 px-4 py-3 text-xs text-gray-500 dark:border-gray-700 dark:text-gray-400 sm:px-5">
          Updates every 15 seconds • Last 200 observations per tab • DNS and TLS hostnames only
        </div>
      </div>
    </div>
  )
}
