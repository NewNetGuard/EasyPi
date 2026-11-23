/**
 * Schedules Panel - Policy Engine + Time Limits
 * 
 * Features:
 * - Time-based blocking rules (block YouTube after 10pm)
 * - Day-of-week schedules (no gaming on school days)
 * - Per-profile schedules
 * - Visual weekly calendar
 * 
 * © 2025 EasyPi Project
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Calendar,
  Clock,
  Plus,
  Trash2,
  Edit2,
  Save,
  X,
  Sun,
  Moon,
  Monitor,
  Gamepad2,
  Youtube,
  Globe,
  Users,
  AlertCircle,
  Play,
  Pause,
  Wifi,
  Router,
  Smartphone,
  Laptop,
  Tv,
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import api from '../../api/client'
import { getCsrfHeaders } from '../../utils/csrf'

interface Schedule {
  id: string
  name: string
  enabled: boolean
  profile_id?: string
  profile_name?: string
  device_ips?: string[]   // legacy fallback for schedules created before MAC binding
  device_macs?: string[]  // durable device identity
  rules: ScheduleRule[]
  created_at: string
}

interface ScheduleRule {
  id: string
  type: 'block' | 'allow'
  target: string // domain, category, or 'all'
  target_type: 'domain' | 'category' | 'all'
  days: number[] // 0=Sunday, 1=Monday, etc.
  start_time: string // HH:MM
  end_time: string // HH:MM
}

interface Profile {
  id: string
  name: string
  icon?: string
}

interface CachedDevice {
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  device_type: string | null
  is_router: boolean
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const DAYS_FULL = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

const CATEGORIES = [
  { id: 'social', name: 'Social Media', icon: Users },
  { id: 'gaming', name: 'Gaming', icon: Gamepad2 },
  { id: 'streaming', name: 'Streaming', icon: Youtube },
  { id: 'adult', name: 'Adult Content', icon: AlertCircle },
  { id: 'all', name: 'All Internet', icon: Globe },
]

// API calls
const fetchSchedules = async (): Promise<{ schedules: Schedule[] }> => {
  try {
    const { data } = await api.get('/netprotection/schedules')
    return { schedules: data?.data || [] }
  } catch {
    return { schedules: [] }
  }
}

const fetchProfiles = async (): Promise<{ profiles: Profile[] }> => {
  try {
    const { data } = await api.get('/dns/profiles')
    return data
  } catch {
    return { profiles: [] }
  }
}

const fetchEnforcement = async (): Promise<{ mode: string; gateway_enforcement: boolean; ip_forward: boolean }> => {
  try {
    const { data } = await api.get('/netprotection/schedules/enforcement-status')
    return data
  } catch {
    return { mode: 'unknown', gateway_enforcement: false, ip_forward: false }
  }
}

const fetchCachedDevices = async (): Promise<{ devices: CachedDevice[], gateway_ip: string | null }> => {
  try {
    const response = await fetch('/api/network-toolkit/cached-devices', { credentials: 'include' })
    if (!response.ok) {
      return { devices: [], gateway_ip: null }
    }
    const data = await response.json()
    return { devices: data.devices || [], gateway_ip: data.gateway_ip }
  } catch {
    return { devices: [], gateway_ip: null }
  }
}

export default function SchedulesPanel() {
  const queryClient = useQueryClient()
  const [isCreating, setIsCreating] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [newSchedule, setNewSchedule] = useState<Partial<Schedule>>({
    name: '',
    enabled: true,
    rules: [],
    device_ips: [],
  })
  const [editSchedule, setEditSchedule] = useState<Partial<Schedule>>({
    name: '',
    enabled: true,
    rules: [],
    device_ips: [],
  })
  const [newRule, setNewRule] = useState<Partial<ScheduleRule>>({
    type: 'block',
    target: 'social',
    target_type: 'category',
    days: [1, 2, 3, 4, 5], // Weekdays
    start_time: '21:00',
    end_time: '07:00',
  })
  const [editRule, setEditRule] = useState<Partial<ScheduleRule>>({
    type: 'block',
    target: 'social',
    target_type: 'category',
    days: [1, 2, 3, 4, 5],
    start_time: '21:00',
    end_time: '07:00',
  })

  const { data: schedulesData, isLoading } = useQuery({
    queryKey: ['schedules'],
    queryFn: fetchSchedules,
  })

  const { data: profilesData } = useQuery({
    queryKey: ['profiles'],
    queryFn: fetchProfiles,
  })

  const { data: devicesData } = useQuery({
    queryKey: ['cachedDevices'],
    queryFn: fetchCachedDevices,
  })

  const { data: enforcement } = useQuery({
    queryKey: ['scheduleEnforcement'],
    queryFn: fetchEnforcement,
  })

  const createMutation = useMutation({
    mutationFn: async (schedule: Partial<Schedule>) => {
      const { data } = await api.post('/netprotection/schedules', schedule)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      toast.success('Schedule created')
      setIsCreating(false)
      setNewSchedule({ name: '', enabled: true, rules: [], device_ips: [] })
    },
    onError: () => toast.error('Failed to create schedule'),
  })

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      const { data } = await api.post(`/netprotection/schedules/${id}/toggle?enabled=${enabled}`)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/netprotection/schedules/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      toast.success('Schedule deleted')
    },
  })

  const updateMutation = useMutation({
    mutationFn: async ({ id, schedule }: { id: string; schedule: Partial<Schedule> }) => {
      const { data } = await api.put(`/netprotection/schedules/${id}`, schedule)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      toast.success('Schedule updated')
      setEditingId(null)
      setEditSchedule({ name: '', enabled: true, rules: [] })
    },
    onError: () => toast.error('Failed to update schedule'),
  })

  // Start editing a schedule
  const startEditing = (schedule: Schedule) => {
    const selectedMacs = schedule.device_macs?.length
      ? schedule.device_macs.map(mac => mac.toLowerCase())
      : (schedule.device_ips || [])
          .map(ip => cachedDevices.find(device => device.ip === ip)?.mac?.toLowerCase())
          .filter((mac): mac is string => Boolean(mac))
    const selectedIps = selectedMacs
      .map(mac => cachedDevices.find(device => device.mac?.toLowerCase() === mac)?.ip)
      .filter((ip): ip is string => Boolean(ip))
    setEditingId(schedule.id)
    setEditSchedule({
      name: schedule.name,
      enabled: schedule.enabled,
      profile_id: schedule.profile_id,
      device_ips: selectedIps,
      device_macs: selectedMacs,
      rules: [...schedule.rules],
    })
  }

  const addRuleToNew = () => {
    if (!newRule.target || !newRule.start_time || !newRule.end_time) return
    
    setNewSchedule(prev => ({
      ...prev,
      rules: [
        ...(prev.rules || []),
        {
          id: crypto.randomUUID(),
          type: newRule.type || 'block',
          target: newRule.target || 'social',
          target_type: newRule.target_type || 'category',
          days: newRule.days || [1, 2, 3, 4, 5],
          start_time: newRule.start_time || '21:00',
          end_time: newRule.end_time || '07:00',
        },
      ],
    }))
    
    // Reset for next rule
    setNewRule({
      type: 'block',
      target: 'social',
      target_type: 'category',
      days: [1, 2, 3, 4, 5],
      start_time: '21:00',
      end_time: '07:00',
    })
  }

  const removeRule = (ruleId: string) => {
    setNewSchedule(prev => ({
      ...prev,
      rules: prev.rules?.filter(r => r.id !== ruleId) || [],
    }))
  }

  // Edit mode functions
  const addRuleToEdit = () => {
    if (!editRule.target || !editRule.start_time || !editRule.end_time) return
    
    setEditSchedule(prev => ({
      ...prev,
      rules: [
        ...(prev.rules || []),
        {
          id: crypto.randomUUID(),
          type: editRule.type || 'block',
          target: editRule.target || 'social',
          target_type: editRule.target_type || 'category',
          days: editRule.days || [1, 2, 3, 4, 5],
          start_time: editRule.start_time || '21:00',
          end_time: editRule.end_time || '07:00',
        },
      ],
    }))
    
    // Reset for next rule
    setEditRule({
      type: 'block',
      target: 'social',
      target_type: 'category',
      days: [1, 2, 3, 4, 5],
      start_time: '21:00',
      end_time: '07:00',
    })
  }

  const removeEditRule = (ruleId: string) => {
    setEditSchedule(prev => ({
      ...prev,
      rules: prev.rules?.filter(r => r.id !== ruleId) || [],
    }))
  }

  const toggleEditDay = (day: number) => {
    setEditRule(prev => {
      const days = prev.days || []
      if (days.includes(day)) {
        return { ...prev, days: days.filter(d => d !== day) }
      } else {
        return { ...prev, days: [...days, day].sort() }
      }
    })
  }

  const toggleDay = (day: number) => {
    setNewRule(prev => {
      const days = prev.days || []
      if (days.includes(day)) {
        return { ...prev, days: days.filter(d => d !== day) }
      } else {
        return { ...prev, days: [...days, day].sort() }
      }
    })
  }

  const schedules = schedulesData?.schedules || []
  const profiles = profilesData?.profiles || []
  const cachedDevices = devicesData?.devices || []
  const gatewayIp = devicesData?.gateway_ip

  // Helper to get device icon based on type
  const getDeviceIcon = (device: CachedDevice) => {
    if (device.is_router) return Router
    const type = device.device_type?.toLowerCase() || ''
    if (type.includes('phone') || type.includes('mobile')) return Smartphone
    if (type.includes('laptop') || type.includes('computer')) return Laptop
    if (type.includes('tv') || type.includes('smart')) return Tv
    return Monitor
  }

  // Helper to get device display name
  const getDeviceName = (device: CachedDevice) => {
    if (device.hostname && device.hostname !== device.ip) {
      return device.hostname
    }
    if (device.vendor) {
      return `${device.vendor} (${device.ip})`
    }
    return device.ip
  }

  // MAC is authoritative; IP is a current display snapshot only.
  const toggleDevice = (device: CachedDevice, forEdit: boolean = false) => {
    const mac = device.mac?.toLowerCase()
    if (!mac) return
    const target = forEdit ? editSchedule : newSchedule
    const setTarget = forEdit ? setEditSchedule : setNewSchedule
    const macs = (target.device_macs || []).map(value => value.toLowerCase())
    const nextMacs = macs.includes(mac) ? macs.filter(value => value !== mac) : [...macs, mac]
    const nextIps = nextMacs
      .map(value => cachedDevices.find(item => item.mac?.toLowerCase() === value)?.ip)
      .filter((value): value is string => Boolean(value))
    setTarget({ ...target, device_ips: nextIps, device_macs: nextMacs })
  }

  // Get CSRF token from cookie
  // Clear device cache on server
  const clearDeviceCache = async () => {
    try {
      const headers = await getCsrfHeaders()
      
      const response = await fetch('/api/network-toolkit/cached-devices', {
        method: 'DELETE',
        credentials: 'include',
        headers,
      })
      if (response.ok) {
        queryClient.invalidateQueries({ queryKey: ['cachedDevices'] })
        toast.success('Device cache cleared')
      } else {
        toast.error('Failed to clear cache')
      }
    } catch {
      toast.error('Failed to clear cache')
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 sm:gap-4">
            <Calendar className="w-10 h-10 sm:w-16 sm:h-16 text-purple-600 dark:text-purple-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">
                Schedules & Time Limits
              </h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Control internet access by time and day
              </p>
            </div>
          </div>
          
          <button
            onClick={() => setIsCreating(true)}
            className="flex items-center justify-center gap-2 px-3 sm:px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors text-sm w-full sm:w-auto"
          >
            <Plus className="w-4 h-4" />
            New Schedule
          </button>
        </div>
      </div>

      {/* Warn ONLY when blocking is bypassable (auto-detected: this box is NOT acting
          as the network gateway). When it IS the gateway, no banner — nothing to say. */}
      {enforcement && enforcement.mode !== 'unknown' && !enforcement.gateway_enforcement && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2.5 text-sm dark:border-amber-800 dark:bg-amber-900/20">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-500" />
          <span className="text-amber-800 dark:text-amber-300">
            <b>Blocks are bypassable right now</b> — this box isn&apos;t acting as your network&apos;s
            gateway, so schedules only block via DNS. A device can get around them by changing its
            DNS or using a VPN. To make blocking unbypassable, set this box as the network gateway.
          </span>
        </div>
      )}

      {/* Quick Templates */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4">
        <QuickTemplate
          icon={<Moon className="w-5 h-5" />}
          title="Bedtime Mode"
          description="Block all internet 10pm - 7am"
          onClick={() => {
            setNewSchedule({
              name: 'Bedtime Mode',
              enabled: true,
              device_ips: [],
              device_macs: [],
              rules: [{
                id: crypto.randomUUID(),
                type: 'block',
                target: 'all',
                target_type: 'all',
                days: [0, 1, 2, 3, 4, 5, 6],
                start_time: '22:00',
                end_time: '07:00',
              }],
            })
            setIsCreating(true)
          }}
        />
        <QuickTemplate
          icon={<Gamepad2 className="w-5 h-5" />}
          title="No Gaming Weekdays"
          description="Block gaming sites Mon-Fri"
          onClick={() => {
            setNewSchedule({
              name: 'No Gaming Weekdays',
              enabled: true,
              device_ips: [],
              device_macs: [],
              rules: [{
                id: crypto.randomUUID(),
                type: 'block',
                target: 'gaming',
                target_type: 'category',
                days: [1, 2, 3, 4, 5],
                start_time: '00:00',
                end_time: '23:59',
              }],
            })
            setIsCreating(true)
          }}
        />
        <QuickTemplate
          icon={<Youtube className="w-5 h-5" />}
          title="Homework Time"
          description="Block social & streaming 4-8pm"
          onClick={() => {
            setNewSchedule({
              name: 'Homework Time',
              enabled: true,
              device_ips: [],
              device_macs: [],
              rules: [
                {
                  id: crypto.randomUUID(),
                  type: 'block',
                  target: 'social',
                  target_type: 'category',
                  days: [1, 2, 3, 4, 5],
                  start_time: '16:00',
                  end_time: '20:00',
                },
                {
                  id: crypto.randomUUID(),
                  type: 'block',
                  target: 'streaming',
                  target_type: 'category',
                  days: [1, 2, 3, 4, 5],
                  start_time: '16:00',
                  end_time: '20:00',
                },
              ],
            })
            setIsCreating(true)
          }}
        />
      </div>

      {/* Create New Schedule Modal */}
      {isCreating && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 p-4 sm:p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white">
              Create Schedule
            </h3>
            <button
              onClick={() => {
                setIsCreating(false)
                setNewSchedule({ name: '', enabled: true, rules: [] })
              }}
              className="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="space-y-4">
            {/* Schedule Name */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Schedule Name
              </label>
              <input
                type="text"
                value={newSchedule.name || ''}
                onChange={(e) => setNewSchedule({ ...newSchedule, name: e.target.value })}
                placeholder="e.g., Kids Bedtime"
                className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              />
            </div>

            {/* Device Selection from LAN Scanner */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Apply to Devices
                </label>
                {cachedDevices.length > 0 && (
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        const sel = cachedDevices.filter(d => !d.is_router && d.mac)
                        setNewSchedule({ ...newSchedule, device_ips: sel.map(d => d.ip), device_macs: sel.map(d => d.mac!.toLowerCase()) })
                      }}
                      className="text-xs text-purple-600 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300"
                    >
                      Select All
                    </button>
                    <span className="text-gray-300 dark:text-gray-600">|</span>
                    <button
                      type="button"
                      onClick={() => setNewSchedule({ ...newSchedule, device_ips: [], device_macs: [] })}
                      className="text-xs text-gray-600 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                    >
                      Unselect
                    </button>
                    <span className="text-gray-300 dark:text-gray-600">|</span>
                    <button
                      type="button"
                      onClick={clearDeviceCache}
                      className="text-xs text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                    >
                      Clear Cache
                    </button>
                  </div>
                )}
              </div>
              
              {cachedDevices.length === 0 ? (
                <div className="p-4 bg-amber-50 dark:bg-amber-900/20 rounded-lg border border-amber-200 dark:border-amber-800">
                  <div className="flex items-center gap-2 text-amber-700 dark:text-amber-400">
                    <Wifi className="w-5 h-5" />
                    <span className="font-medium">No devices found</span>
                  </div>
                  <p className="mt-1 text-sm text-amber-600 dark:text-amber-500">
                    Allow a device in Guard Security or run a LAN Scan in Network Toolkit.
                  </p>
                </div>
              ) : (
                <div className="border border-gray-200 dark:border-gray-600 rounded-lg overflow-hidden">
                  {/* Selected devices count banner */}
                  <div className="px-3 py-2 bg-purple-50 dark:bg-purple-900/20 border-b border-gray-200 dark:border-gray-600">
                    <span className="text-sm font-medium text-purple-700 dark:text-purple-400">
                      {(newSchedule.device_macs?.length || 0) === 0
                        ? '🌐 No devices selected - applies to ALL devices'
                        : `✓ ${newSchedule.device_macs?.length} device(s) selected`}
                    </span>
                  </div>
                  
                  <div className="space-y-0 max-h-48 overflow-y-auto p-2">
                    {/* Selected devices first */}
                    {cachedDevices
                      .filter(d => !d.is_router && Boolean(d.mac) && (newSchedule.device_macs || []).includes(d.mac!.toLowerCase()))
                      .map(device => {
                        const DeviceIcon = getDeviceIcon(device)
                        return (
                          <label
                            key={device.mac || device.ip}
                            className="flex items-center gap-3 p-2 rounded-lg cursor-pointer bg-purple-100 dark:bg-purple-900/30 border border-purple-300 dark:border-purple-700 mb-1"
                          >
                            <input
                              type="checkbox"
                              checked={true}
                              onChange={() => toggleDevice(device)}
                              className="w-4 h-4 text-purple-600 rounded border-gray-300 focus:ring-purple-500"
                            />
                            <DeviceIcon className="w-5 h-5 text-purple-600" />
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-gray-900 dark:text-white truncate">
                                {getDeviceName(device)}
                              </div>
                              <div className="text-xs text-gray-500 dark:text-gray-400">
                                {device.ip} {device.mac ? `• ${device.mac}` : ''}
                              </div>
                            </div>
                          </label>
                        )
                      })}
                    
                    {/* Separator if there are selected devices */}
                    {(newSchedule.device_macs?.length || 0) > 0 && cachedDevices.filter(d => !d.is_router && Boolean(d.mac) && !(newSchedule.device_macs || []).includes(d.mac!.toLowerCase())).length > 0 && (
                      <div className="border-t border-gray-200 dark:border-gray-600 my-2" />
                    )}
                    
                    {/* Unselected devices */}
                    {cachedDevices
                      .filter(d => !d.is_router && Boolean(d.mac) && !(newSchedule.device_macs || []).includes(d.mac!.toLowerCase()))
                      .map(device => {
                        const DeviceIcon = getDeviceIcon(device)
                        return (
                          <label
                            key={device.mac || device.ip}
                            className="flex items-center gap-3 p-2 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50 border border-transparent"
                          >
                            <input
                              type="checkbox"
                              checked={false}
                              onChange={() => toggleDevice(device)}
                              className="w-4 h-4 text-purple-600 rounded border-gray-300 focus:ring-purple-500"
                            />
                            <DeviceIcon className="w-5 h-5 text-gray-400" />
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-gray-900 dark:text-white truncate">
                                {getDeviceName(device)}
                              </div>
                              <div className="text-xs text-gray-500 dark:text-gray-400">
                                {device.ip} {device.mac ? `• ${device.mac}` : ''}
                              </div>
                            </div>
                          </label>
                        )
                      })}
                  </div>
                </div>
              )}
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Devices are matched by their MAC — the rule sticks even if their IP changes.
                {gatewayIp ? ` Router (${gatewayIp}) is excluded.` : ''}
              </p>
            </div>

            {/* Rules */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Rules
              </label>
              
              {/* Existing rules */}
              <div className="space-y-2 mb-4">
                {(newSchedule.rules || []).map((rule) => (
                  <div
                    key={rule.id}
                    className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-xs font-medium rounded ${
                        rule.type === 'block' 
                          ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                          : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                      }`}>
                        {rule.type.toUpperCase()}
                      </span>
                      <span className="text-sm text-gray-900 dark:text-white">
                        {CATEGORIES.find(c => c.id === rule.target)?.name || rule.target}
                      </span>
                      <span className="text-sm text-gray-500">
                        {rule.days.map(d => DAYS[d]).join(', ')}
                      </span>
                      <span className="text-sm text-gray-500">
                        {rule.start_time} - {rule.end_time}
                      </span>
                    </div>
                    <button
                      onClick={() => removeRule(rule.id)}
                      className="p-1 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>

              {/* Add new rule */}
              <div className="p-3 sm:p-4 border border-dashed border-gray-300 dark:border-gray-600 rounded-lg space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-3">
                  {/* Action */}
                  <div>
                    <label className="block text-xs text-gray-500 mb-1">Action</label>
                    <select
                      value={newRule.type}
                      onChange={(e) => setNewRule({ ...newRule, type: e.target.value as 'block' | 'allow' })}
                      className="w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                    >
                      <option value="block">Block</option>
                    </select>
                  </div>
                  
                  {/* Target */}
                  <div>
                    <label className="block text-xs text-gray-500 mb-1">What</label>
                    <select
                      value={newRule.target}
                      onChange={(e) => setNewRule({ ...newRule, target: e.target.value, target_type: 'category' })}
                      className="w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                    >
                      {CATEGORIES.map(c => (
                        <option key={c.id} value={c.id}>{c.name}</option>
                      ))}
                    </select>
                  </div>
                  
                  {/* Time */}
                  <div className="flex gap-2">
                    <div className="flex-1">
                      <label className="block text-xs text-gray-500 mb-1">From</label>
                      <input
                        type="time"
                        value={newRule.start_time}
                        onChange={(e) => setNewRule({ ...newRule, start_time: e.target.value })}
                        className="w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                      />
                    </div>
                    <div className="flex-1">
                      <label className="block text-xs text-gray-500 mb-1">To</label>
                      <input
                        type="time"
                        value={newRule.end_time}
                        onChange={(e) => setNewRule({ ...newRule, end_time: e.target.value })}
                        className="w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                      />
                    </div>
                  </div>
                </div>

                {/* Days */}
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Days</label>
                  <div className="flex flex-wrap gap-1">
                    {DAYS.map((day, idx) => (
                      <button
                        key={day}
                        onClick={() => toggleDay(idx)}
                        className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded transition-colors ${
                          newRule.days?.includes(idx)
                            ? 'bg-purple-600 text-white'
                            : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600'
                        }`}
                      >
                        {day}
                      </button>
                    ))}
                  </div>
                </div>

                <button
                  onClick={addRuleToNew}
                  className="w-full py-2 text-sm font-medium text-purple-600 hover:bg-purple-50 dark:hover:bg-purple-900/20 rounded-lg transition-colors"
                >
                  + Add Rule
                </button>
              </div>
            </div>

            {/* Save Button */}
            <div className="flex justify-end gap-3 pt-4">
              <button
                onClick={() => {
                  setIsCreating(false)
                  setNewSchedule({ name: '', enabled: true, rules: [] })
                }}
                className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
              >
                Cancel
              </button>
              <button
                onClick={() => createMutation.mutate(newSchedule)}
                disabled={!newSchedule.name || !newSchedule.rules?.length}
                className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Save className="w-4 h-4" />
                Create Schedule
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Schedule Modal */}
      {editingId && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Edit Schedule
            </h3>
            <button
              onClick={() => {
                setEditingId(null)
                setEditSchedule({ name: '', enabled: true, rules: [] })
              }}
              className="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="space-y-4">
            {/* Schedule Name */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Schedule Name
              </label>
              <input
                type="text"
                value={editSchedule.name || ''}
                onChange={(e) => setEditSchedule({ ...editSchedule, name: e.target.value })}
                placeholder="e.g., Kids Bedtime"
                className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>

            {/* Device Selection from LAN Scanner */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Apply to Devices
                </label>
                {cachedDevices.length > 0 && (
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        const sel = cachedDevices.filter(d => !d.is_router && d.mac)
                        setEditSchedule({ ...editSchedule, device_ips: sel.map(d => d.ip), device_macs: sel.map(d => d.mac!.toLowerCase()) })
                      }}
                      className="text-xs text-purple-600 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300"
                    >
                      Select All
                    </button>
                    <span className="text-gray-300 dark:text-gray-600">|</span>
                    <button
                      type="button"
                      onClick={() => setEditSchedule({ ...editSchedule, device_ips: [], device_macs: [] })}
                      className="text-xs text-gray-600 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                    >
                      Unselect
                    </button>
                    <span className="text-gray-300 dark:text-gray-600">|</span>
                    <button
                      type="button"
                      onClick={clearDeviceCache}
                      className="text-xs text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                    >
                      Clear Cache
                    </button>
                  </div>
                )}
              </div>
              
              {cachedDevices.length === 0 ? (
                <div className="p-4 bg-amber-50 dark:bg-amber-900/20 rounded-lg border border-amber-200 dark:border-amber-800">
                  <div className="flex items-center gap-2 text-amber-700 dark:text-amber-400">
                    <Wifi className="w-5 h-5" />
                    <span className="font-medium">No devices found</span>
                  </div>
                  <p className="mt-1 text-sm text-amber-600 dark:text-amber-500">
                    Allow a device in Guard Security or run a LAN Scan in Network Toolkit.
                  </p>
                </div>
              ) : (
                <div className="border border-gray-200 dark:border-gray-600 rounded-lg overflow-hidden">
                  {/* Selected devices count banner */}
                  <div className="px-3 py-2 bg-purple-50 dark:bg-purple-900/20 border-b border-gray-200 dark:border-gray-600">
                    <span className="text-sm font-medium text-purple-700 dark:text-purple-400">
                      {(editSchedule.device_macs?.length || 0) === 0
                        ? '🌐 No devices selected - applies to ALL devices'
                        : `✓ ${editSchedule.device_macs?.length} device(s) selected`}
                    </span>
                  </div>
                  
                  <div className="space-y-0 max-h-48 overflow-y-auto p-2">
                    {/* Selected devices first */}
                    {cachedDevices
                      .filter(d => !d.is_router && Boolean(d.mac) && (editSchedule.device_macs || []).includes(d.mac!.toLowerCase()))
                      .map(device => {
                        const DeviceIcon = getDeviceIcon(device)
                        return (
                          <label
                            key={device.mac || device.ip}
                            className="flex items-center gap-3 p-2 rounded-lg cursor-pointer bg-purple-100 dark:bg-purple-900/30 border border-purple-300 dark:border-purple-700 mb-1"
                          >
                            <input
                              type="checkbox"
                              checked={true}
                              onChange={() => toggleDevice(device, true)}
                              className="w-4 h-4 text-purple-600 rounded border-gray-300 focus:ring-purple-500"
                            />
                            <DeviceIcon className="w-5 h-5 text-purple-600" />
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-gray-900 dark:text-white truncate">
                                {getDeviceName(device)}
                              </div>
                              <div className="text-xs text-gray-500 dark:text-gray-400">
                                {device.ip} {device.mac ? `• ${device.mac}` : ''}
                              </div>
                            </div>
                          </label>
                        )
                      })}
                    
                    {/* Separator if there are selected devices */}
                    {(editSchedule.device_macs?.length || 0) > 0 && cachedDevices.filter(d => !d.is_router && Boolean(d.mac) && !(editSchedule.device_macs || []).includes(d.mac!.toLowerCase())).length > 0 && (
                      <div className="border-t border-gray-200 dark:border-gray-600 my-2" />
                    )}
                    
                    {/* Unselected devices */}
                    {cachedDevices
                      .filter(d => !d.is_router && Boolean(d.mac) && !(editSchedule.device_macs || []).includes(d.mac!.toLowerCase()))
                      .map(device => {
                        const DeviceIcon = getDeviceIcon(device)
                        return (
                          <label
                            key={device.mac || device.ip}
                            className="flex items-center gap-3 p-2 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50 border border-transparent"
                          >
                            <input
                              type="checkbox"
                              checked={false}
                              onChange={() => toggleDevice(device, true)}
                              className="w-4 h-4 text-purple-600 rounded border-gray-300 focus:ring-purple-500"
                            />
                            <DeviceIcon className="w-5 h-5 text-gray-400" />
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-gray-900 dark:text-white truncate">
                                {getDeviceName(device)}
                              </div>
                              <div className="text-xs text-gray-500 dark:text-gray-400">
                                {device.ip} {device.mac ? `• ${device.mac}` : ''}
                              </div>
                            </div>
                          </label>
                        )
                      })}
                  </div>
                </div>
              )}
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Devices are matched by their MAC — the rule sticks even if their IP changes.
                {gatewayIp ? ` Router (${gatewayIp}) is excluded.` : ''}
              </p>
            </div>

            {/* Rules */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Rules
              </label>
              
              {/* Existing rules - editable */}
              <div className="space-y-3 mb-4">
                {(editSchedule.rules || []).map((rule, ruleIndex) => (
                  <div
                    key={rule.id}
                    className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 text-xs font-medium rounded ${
                          rule.type === 'block' 
                            ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                            : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                        }`}>
                          {rule.type.toUpperCase()}
                        </span>
                        <span className="text-sm font-medium text-gray-900 dark:text-white">
                          {CATEGORIES.find(c => c.id === rule.target)?.name || rule.target}
                        </span>
                      </div>
                      <button
                        onClick={() => removeEditRule(rule.id)}
                        className="p-1 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                        title="Delete rule"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                    
                    {/* Editable time */}
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2">
                        <label className="text-xs text-gray-500">From:</label>
                        <input
                          type="time"
                          value={rule.start_time}
                          onChange={(e) => {
                            const updatedRules = [...(editSchedule.rules || [])]
                            updatedRules[ruleIndex] = { ...rule, start_time: e.target.value }
                            setEditSchedule({ ...editSchedule, rules: updatedRules })
                          }}
                          className="px-2 py-1 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800"
                        />
                      </div>
                      <div className="flex items-center gap-2">
                        <label className="text-xs text-gray-500">To:</label>
                        <input
                          type="time"
                          value={rule.end_time}
                          onChange={(e) => {
                            const updatedRules = [...(editSchedule.rules || [])]
                            updatedRules[ruleIndex] = { ...rule, end_time: e.target.value }
                            setEditSchedule({ ...editSchedule, rules: updatedRules })
                          }}
                          className="px-2 py-1 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800"
                        />
                      </div>
                    </div>
                    
                    {/* Editable days */}
                    <div className="flex gap-1">
                      {DAYS.map((day, idx) => (
                        <button
                          key={day}
                          onClick={() => {
                            const updatedRules = [...(editSchedule.rules || [])]
                            const currentDays = rule.days || []
                            const newDays = currentDays.includes(idx)
                              ? currentDays.filter(d => d !== idx)
                              : [...currentDays, idx].sort()
                            updatedRules[ruleIndex] = { ...rule, days: newDays }
                            setEditSchedule({ ...editSchedule, rules: updatedRules })
                          }}
                          className={`px-2 py-1 text-xs font-medium rounded transition-colors ${
                            rule.days?.includes(idx)
                              ? 'bg-purple-600 text-white'
                              : 'bg-gray-200 dark:bg-gray-600 text-gray-500 dark:text-gray-400 hover:bg-gray-300 dark:hover:bg-gray-500'
                          }`}
                        >
                          {day}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>

              {/* Add new rule */}
              <div className="p-4 border border-dashed border-gray-300 dark:border-gray-600 rounded-lg space-y-3">
                <div className="grid grid-cols-3 gap-3">
                  {/* Action */}
                  <div>
                    <label className="block text-xs text-gray-500 mb-1">Action</label>
                    <select
                      value={editRule.type}
                      onChange={(e) => setEditRule({ ...editRule, type: e.target.value as 'block' | 'allow' })}
                      className="w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                    >
                      <option value="block">Block</option>
                    </select>
                  </div>
                  
                  {/* Target */}
                  <div>
                    <label className="block text-xs text-gray-500 mb-1">What</label>
                    <select
                      value={editRule.target}
                      onChange={(e) => setEditRule({ ...editRule, target: e.target.value, target_type: 'category' })}
                      className="w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                    >
                      {CATEGORIES.map(c => (
                        <option key={c.id} value={c.id}>{c.name}</option>
                      ))}
                    </select>
                  </div>
                  
                  {/* Time */}
                  <div className="flex gap-2">
                    <div className="flex-1">
                      <label className="block text-xs text-gray-500 mb-1">From</label>
                      <input
                        type="time"
                        value={editRule.start_time}
                        onChange={(e) => setEditRule({ ...editRule, start_time: e.target.value })}
                        className="w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                      />
                    </div>
                    <div className="flex-1">
                      <label className="block text-xs text-gray-500 mb-1">To</label>
                      <input
                        type="time"
                        value={editRule.end_time}
                        onChange={(e) => setEditRule({ ...editRule, end_time: e.target.value })}
                        className="w-full px-2 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                      />
                    </div>
                  </div>
                </div>

                {/* Days */}
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Days</label>
                  <div className="flex gap-1">
                    {DAYS.map((day, idx) => (
                      <button
                        key={day}
                        onClick={() => toggleEditDay(idx)}
                        className={`px-3 py-1.5 text-sm font-medium rounded transition-colors ${
                          editRule.days?.includes(idx)
                            ? 'bg-purple-600 text-white'
                            : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600'
                        }`}
                      >
                        {day}
                      </button>
                    ))}
                  </div>
                </div>

                <button
                  onClick={addRuleToEdit}
                  className="w-full py-2 text-sm font-medium text-purple-600 hover:bg-purple-50 dark:hover:bg-purple-900/20 rounded-lg transition-colors"
                >
                  + Add Rule
                </button>
              </div>
            </div>

            {/* Save Button */}
            <div className="flex justify-end gap-3 pt-4">
              <button
                onClick={() => {
                  setEditingId(null)
                  setEditSchedule({ name: '', enabled: true, rules: [] })
                }}
                className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
              >
                Cancel
              </button>
              <button
                onClick={() => updateMutation.mutate({ id: editingId, schedule: editSchedule })}
                disabled={!editSchedule.name || !editSchedule.rules?.length || updateMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Save className="w-4 h-4" />
                {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Schedules List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="text-center py-12 text-gray-500">Loading schedules...</div>
        ) : schedules.length === 0 ? (
          <div className="text-center py-12">
            <Calendar className="w-12 h-12 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">No schedules configured</p>
            <p className="text-sm text-gray-400 mt-1">
              Create a schedule to control internet access by time
            </p>
          </div>
        ) : (
          schedules.map((schedule) => (
            <ScheduleCard
              key={schedule.id}
              schedule={schedule}
              onToggle={(enabled) => toggleMutation.mutate({ id: schedule.id, enabled })}
              onDelete={() => deleteMutation.mutate(schedule.id)}
              onEdit={() => startEditing(schedule)}
              cachedDevices={cachedDevices}
            />
          ))
        )}
      </div>

      {/* Weekly Overview */}
      {schedules.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Weekly Overview
          </h3>
          <WeeklyCalendar schedules={schedules.filter(s => s.enabled)} />
        </div>
      )}
    </div>
  )
}

// Quick Template Component
function QuickTemplate({ icon, title, description, onClick }: {
  icon: React.ReactNode
  title: string
  description: string
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="p-4 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 hover:border-purple-300 dark:hover:border-purple-700 hover:shadow-md transition-all text-left"
    >
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2 rounded-lg bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400">
          {icon}
        </div>
        <span className="font-medium text-gray-900 dark:text-white">{title}</span>
      </div>
      <p className="text-sm text-gray-500">{description}</p>
    </button>
  )
}

// Schedule Card Component
function ScheduleCard({ schedule, onToggle, onDelete, onEdit, cachedDevices }: {
  schedule: Schedule
  onToggle: (enabled: boolean) => void
  onDelete: () => void
  onEdit: () => void
  cachedDevices?: CachedDevice[]
}) {
  // Get device names for display
  const getDeviceDisplayNames = () => {
    if (schedule.device_macs && schedule.device_macs.length > 0) {
      return schedule.device_macs.map(mac => {
        const device = cachedDevices?.find(d => d.mac?.toLowerCase() === mac.toLowerCase())
        if (device?.hostname && device.hostname !== device.ip) return device.hostname
        if (device?.vendor) return `${device.vendor.split(' ')[0]}`
        return mac
      })
    }
    if (!schedule.device_ips || schedule.device_ips.length === 0) return null
    return schedule.device_ips.map(ip => {
      const device = cachedDevices?.find(d => d.ip === ip)
      if (device?.hostname && device.hostname !== ip) return device.hostname
      if (device?.vendor) return `${device.vendor.split(' ')[0]}`
      return ip
    })
  }

  const deviceNames = getDeviceDisplayNames()

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl border ${
      schedule.enabled 
        ? 'border-purple-200 dark:border-purple-800' 
        : 'border-gray-200 dark:border-gray-700 opacity-60'
    } p-4`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <button
            onClick={() => onToggle(!schedule.enabled)}
            className={`p-2 rounded-lg transition-colors ${
              schedule.enabled
                ? 'bg-green-100 dark:bg-green-900/30 text-green-600 hover:bg-red-100 hover:text-red-600 dark:hover:bg-red-900/30 dark:hover:text-red-400'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-400 hover:bg-green-100 hover:text-green-600 dark:hover:bg-green-900/30 dark:hover:text-green-400'
            }`}
            title={schedule.enabled ? 'Click to disable' : 'Click to enable'}
          >
            {schedule.enabled ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5" />}
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="font-medium text-gray-900 dark:text-white">{schedule.name}</h4>
              <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${
                schedule.enabled 
                  ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                  : 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'
              }`}>
                {schedule.enabled ? 'Active' : 'Disabled'}
              </span>
            </div>
            {deviceNames && deviceNames.length > 0 ? (
              <div className="flex flex-wrap items-center gap-1 mt-1">
                <span className="text-xs text-gray-500">Devices:</span>
                {deviceNames.slice(0, 3).map((name, idx) => (
                  <span key={idx} className="px-1.5 py-0.5 text-xs bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 rounded">
                    {name}
                  </span>
                ))}
                {deviceNames.length > 3 && (
                  <span className="text-xs text-gray-500">+{deviceNames.length - 3} more</span>
                )}
              </div>
            ) : schedule.profile_name ? (
              <span className="text-xs text-gray-500">Profile: {schedule.profile_name}</span>
            ) : (
              <span className="text-xs text-purple-600 dark:text-purple-400 font-medium">🌐 All devices</span>
            )}
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          <button
            onClick={onEdit}
            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
          >
            <Edit2 className="w-4 h-4" />
          </button>
          <button
            onClick={onDelete}
            className="p-2 text-red-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Rules */}
      <div className="space-y-2">
        {schedule.rules.map((rule) => (
          <div
            key={rule.id}
            className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400"
          >
            <span className={`w-2 h-2 rounded-full ${
              rule.type === 'block' ? 'bg-red-500' : 'bg-green-500'
            }`} />
            <span className="font-medium">
              {rule.type === 'block' ? 'Block' : 'Allow'}
            </span>
            <span>{CATEGORIES.find(c => c.id === rule.target)?.name || rule.target}</span>
            <span className="text-gray-400">•</span>
            <span>{rule.days.map(d => DAYS[d]).join(', ')}</span>
            <span className="text-gray-400">•</span>
            <span>{rule.start_time} - {rule.end_time}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// Weekly Calendar Component
function WeeklyCalendar({ schedules }: { schedules: Schedule[] }) {
  const hours = Array.from({ length: 24 }, (_, i) => i)
  
  // Build time blocks for each day
  const getBlocksForDay = (dayIndex: number) => {
    const blocks: Array<{
      start: number
      end: number
      type: 'block' | 'allow'
      target: string
    }> = []
    
    schedules.forEach(schedule => {
      schedule.rules.forEach(rule => {
        if (rule.days.includes(dayIndex)) {
          const startHour = parseInt(rule.start_time.split(':')[0])
          const endHour = parseInt(rule.end_time.split(':')[0]) || 24
          blocks.push({
            start: startHour,
            end: endHour > startHour ? endHour : 24,
            type: rule.type,
            target: rule.target,
          })
          // Handle overnight blocks
          if (endHour < startHour) {
            blocks.push({
              start: 0,
              end: endHour,
              type: rule.type,
              target: rule.target,
            })
          }
        }
      })
    })
    
    return blocks
  }

  return (
    <div className="overflow-x-auto">
      <div className="min-w-[600px]">
        {/* Header */}
        <div className="grid grid-cols-8 gap-1 mb-2">
          <div className="text-xs text-gray-500 text-right pr-2">Time</div>
          {DAYS_FULL.map((day, idx) => (
            <div key={day} className="text-xs font-medium text-gray-700 dark:text-gray-300 text-center">
              {DAYS[idx]}
            </div>
          ))}
        </div>
        
        {/* Time grid */}
        <div className="grid grid-cols-8 gap-1">
          {/* Time labels */}
          <div className="space-y-0">
            {[0, 6, 12, 18].map(hour => (
              <div key={hour} className="h-6 text-xs text-gray-400 text-right pr-2">
                {hour.toString().padStart(2, '0')}:00
              </div>
            ))}
          </div>
          
          {/* Day columns */}
          {DAYS.map((_, dayIdx) => {
            const blocks = getBlocksForDay(dayIdx)
            return (
              <div
                key={dayIdx}
                className="relative h-24 bg-gray-100 dark:bg-gray-700 rounded overflow-hidden"
              >
                {blocks.map((block, idx) => (
                  <div
                    key={idx}
                    className={`absolute left-0 right-0 ${
                      block.type === 'block' 
                        ? 'bg-red-400/60 dark:bg-red-600/40' 
                        : 'bg-green-400/60 dark:bg-green-600/40'
                    }`}
                    style={{
                      top: `${(block.start / 24) * 100}%`,
                      height: `${((block.end - block.start) / 24) * 100}%`,
                    }}
                    title={`${block.type} ${block.target} ${block.start}:00-${block.end}:00`}
                  />
                ))}
              </div>
            )
          })}
        </div>
        
        {/* Legend */}
        <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded bg-red-400/60" />
            <span>Blocked</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded bg-green-400/60" />
            <span>Allowed</span>
          </div>
        </div>
      </div>
    </div>
  )
}
