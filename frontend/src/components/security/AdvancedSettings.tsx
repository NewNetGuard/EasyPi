import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { 
  Bell, Trash2, Save, RefreshCw,
  Server, Shield, Activity, CheckCircle, AlertTriangle, Loader2,
  RotateCcw, HardDrive, Zap, Globe, Wifi, WifiOff, ShieldCheck, ShieldOff, Settings
} from 'lucide-react'
import { 
  getProfileInfo, 
  resetStatistics, 
  clearQueryLog, 
  resetAllSettings,
  clearDNSCache 
} from '../../api/guardSecurity'
import api from '../../api/client'
import { toast } from 'react-hot-toast'

export default function AdvancedSettings() {
  const queryClient = useQueryClient()
  const [showResetConfirm, setShowResetConfirm] = useState(false)
  const [showFactoryConfirm, setShowFactoryConfirm] = useState(false)
  
  // Fail-Safe (DNS watchdog): auto-restarts the resolver if it stops responding.
  const [failSafeSettings, setFailSafeSettings] = useState({
    enabled: true,
    timeout_seconds: 5,
    auto_recover: true,
  })

  // IPv6: real read-only status of this device. (Toggles can't affect a box that
  // isn't the IPv6 gateway, so this just reports the true state + guidance.)
  const { data: ipv6Status } = useQuery({
    queryKey: ['netprotection-ipv6-status'],
    queryFn: async () => {
      const { data } = await api.get('/netprotection/settings/ipv6/status')
      return data?.data
    },
    staleTime: 60000,
  })

  const { data: unknownDeviceSettings } = useQuery({
    queryKey: ['netprotection-unknown-device-settings'],
    queryFn: async () => {
      const { data } = await api.get('/netprotection/settings/unknown-devices')
      return data?.data as {
        mode?: 'block' | 'default'
        identity_assurance?: 'observed_mac_ip_pair'
        spoof_resistant?: boolean
        requires_trusted_lan?: boolean
      }
    },
  })

  const saveUnknownDeviceMutation = useMutation({
    mutationFn: async (mode: 'block' | 'default') => {
      const { data } = await api.put('/netprotection/settings/unknown-devices', { mode })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['netprotection-unknown-device-settings'] })
      toast.success('Unknown-device policy saved')
    },
    onError: () => toast.error('Failed to save unknown-device policy'),
  })

  // Fetch Fail-Safe settings (also carries live state: is_active, restart_count, last_restart_at)
  const { data: failSafeData } = useQuery({
    queryKey: ['netprotection-failsafe-settings'],
    queryFn: async () => {
      const { data } = await api.get('/netprotection/settings/failsafe')
      return data?.data
    },
    staleTime: 30000,
    refetchInterval: 30000,
  })

  useEffect(() => {
    if (failSafeData) {
      setFailSafeSettings({
        enabled: failSafeData.enabled ?? true,
        timeout_seconds: failSafeData.timeout_seconds ?? 5,
        auto_recover: failSafeData.auto_recover ?? true,
      })
    }
  }, [failSafeData])

  const saveFailSafeMutation = useMutation({
    mutationFn: async (settings: typeof failSafeSettings) => {
      const { data } = await api.put('/netprotection/settings/failsafe', settings)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['netprotection-failsafe-settings'] })
      toast.success('Fail-Safe settings saved')
    },
    onError: () => toast.error('Failed to save Fail-Safe settings'),
  })
  
  // Profile info
  const { data: profile, isLoading: profileLoading, refetch: refetchProfile } = useQuery({
    queryKey: ['netprotection-profile'],
    queryFn: getProfileInfo,
    staleTime: 30000,
  })

  // Mutations
  const resetStatsMutation = useMutation({
    mutationFn: resetStatistics,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['netprotection-profile'] })
      queryClient.invalidateQueries({ queryKey: ['netprotection-stats'] })
    }
  })

  const clearLogMutation = useMutation({
    mutationFn: clearQueryLog,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['query-log'] })
    }
  })

  const clearCacheMutation = useMutation({
    mutationFn: clearDNSCache,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dns-config'] })
    }
  })

  const resetAllMutation = useMutation({
    mutationFn: resetAllSettings,
    onSuccess: () => {
      queryClient.invalidateQueries()
      setShowResetConfirm(false)
      setShowFactoryConfirm(false)
    }
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 sm:gap-4">
          <Settings className="w-10 h-10 sm:w-16 sm:h-16 text-gray-600 dark:text-gray-400" />
          <div>
            <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">Advanced Settings</h2>
            <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
              System information, backups, and maintenance tools
            </p>
          </div>
        </div>
      </div>

      {/* System Info Card */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2 sm:gap-3">
            <Server className="w-5 h-5 sm:w-6 sm:h-6 text-blue-500" />
            <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white">NetProtection Status</h3>
          </div>
          <button
            onClick={() => refetchProfile()}
            className="p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${profileLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
        
        {profileLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
          </div>
        ) : profile ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
            <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 sm:p-4">
              <div className="flex items-center gap-2 mb-2">
                <Zap className="w-4 h-4 text-green-500" />
                <span className="text-xs text-gray-500 dark:text-gray-400">Status</span>
              </div>
              <div className={`text-base sm:text-lg font-semibold ${profile.running ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                {profile.running ? 'Running' : 'Stopped'}
              </div>
            </div>
            <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="w-4 h-4 text-blue-500" />
                <span className="text-xs text-gray-500 dark:text-gray-400">Protection</span>
              </div>
              <div className={`text-lg font-semibold ${profile.protection_enabled ? 'text-green-600 dark:text-green-400' : 'text-yellow-600 dark:text-yellow-400'}`}>
                {profile.protection_enabled ? 'Enabled' : 'Disabled'}
              </div>
            </div>
            <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="w-4 h-4 text-purple-500" />
                <span className="text-xs text-gray-500 dark:text-gray-400">Total Queries</span>
              </div>
              <div className="text-lg font-semibold text-gray-900 dark:text-white">
                {profile.total_queries?.toLocaleString() || 0}
              </div>
            </div>
            <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <HardDrive className="w-4 h-4 text-orange-500" />
                <span className="text-xs text-gray-500 dark:text-gray-400">Blocked</span>
              </div>
              <div className="text-lg font-semibold text-red-600 dark:text-red-400">
                {profile.blocked_queries?.toLocaleString() || 0}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center text-gray-500 dark:text-gray-400 py-4">
            Unable to load system info
          </div>
        )}
        
        {profile && (
          <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
            <div className="flex flex-wrap gap-4 text-sm">
              <div>
                <span className="text-gray-500 dark:text-gray-400">Version: </span>
                <span className="text-gray-900 dark:text-white font-mono">{profile.version}</span>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">Blocklists: </span>
                <span className="text-gray-900 dark:text-white">{profile.blocklist_count}</span>
              </div>
              {profile.dns_addresses?.length > 0 && (
                <div>
                  <span className="text-gray-500 dark:text-gray-400">DNS: </span>
                  <span className="text-gray-900 dark:text-white font-mono">{profile.dns_addresses.join(', ')}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Notifications */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Bell className="w-6 h-6 text-yellow-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Notifications</h3>
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Email, SMTP, push, digest, quiet-hour, and Telegram controls are managed together in Settings.
        </p>
        <Link
          to="/settings?tab=notifications"
          className="mt-4 inline-flex items-center rounded-lg bg-yellow-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-yellow-600"
        >
          Open Notification Settings
        </Link>
      </div>

      {/* IPv6 Status */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Globe className="w-6 h-6 text-purple-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">IPv6 Status</h3>
        </div>
        <div className="space-y-4">
          <div className={`flex items-center gap-3 p-4 rounded-lg ${ipv6Status?.protected ? 'bg-green-50 dark:bg-green-900/20' : 'bg-yellow-50 dark:bg-yellow-900/20'}`}>
            {ipv6Status?.protected ? (
              <ShieldCheck className="w-6 h-6 text-green-600 dark:text-green-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-6 h-6 text-yellow-600 dark:text-yellow-400 shrink-0" />
            )}
            <div>
              <div className="text-sm font-semibold text-gray-900 dark:text-white">
                {ipv6Status?.protected
                  ? (ipv6Status?.has_global_ipv6
                    ? 'IPv6 is active — runtime guard enabled'
                    : 'No IPv6 on this device — protected')
                  : 'IPv6 is active on this device'}
              </div>
              <div className="text-xs text-gray-600 dark:text-gray-400 mt-0.5">
                {ipv6Status?.protected
                  ? (ipv6Status?.guard_active
                    ? 'Client-originated IPv6 forwarding is blocked and continuously rechecked.'
                    : 'Devices cannot slip past DNS filtering over IPv6.')
                  : 'Devices may reach IPv6 DNS servers directly, bypassing filtering.'}
              </div>
            </div>
          </div>

          <div className="p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
            <p className="text-sm text-purple-800 dark:text-purple-300">
              <strong>How it works:</strong> EasyPi filters DNS over IPv4. The most reliable way to prevent
              IPv6 DNS leaks is to keep IPv6 disabled on your router (recommended). Full IPv6 filtering would
              require EasyPi to also be your network's IPv6 gateway.
            </p>
          </div>
        </div>
      </div>

      {/* Unknown device admission */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-6 h-6 text-orange-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Unknown Devices (LAN admission)</h3>
        </div>
        <div className="flex items-start justify-between gap-6">
          <div>
            <p className="text-sm text-gray-700 dark:text-gray-300">
              Block DNS and forwarding until a device matches an enabled MAC and IP/network binding for the same identity.
            </p>
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
              New and upgraded installations fail closed. Turning this off deliberately restores permissive Default-profile behavior.
            </p>
            <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">
              Security boundary: this is best-effort admission on a trusted LAN. A hostile device on the same network can clone both an approved MAC and IP address. Spoof-resistant admission requires 802.1X/WPA-Enterprise or a per-device cryptographic tunnel.
            </p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer shrink-0">
            <input
              type="checkbox"
              checked={unknownDeviceSettings?.mode === 'block'}
              disabled={!unknownDeviceSettings || saveUnknownDeviceMutation.isPending}
              onChange={(event) => saveUnknownDeviceMutation.mutate(event.target.checked ? 'block' : 'default')}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-orange-300 dark:peer-focus:ring-orange-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-600" />
          </label>
        </div>
      </div>

      {/* Fail-Safe (DNS watchdog) */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <ShieldCheck className="w-6 h-6 text-green-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Fail-Safe (DNS Watchdog)</h3>
        </div>
        <div className="space-y-4">
          {failSafeData && (
            <div className={`flex items-center gap-3 p-3 rounded-lg ${failSafeData.is_active ? 'bg-yellow-50 dark:bg-yellow-900/20' : 'bg-green-50 dark:bg-green-900/20'}`}>
              {failSafeData.is_active ? (
                <AlertTriangle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 shrink-0" />
              ) : (
                <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 shrink-0" />
              )}
              <div className="text-xs text-gray-700 dark:text-gray-300">
                {failSafeData.is_active
                  ? 'Recovering — the DNS service was just restarted.'
                  : 'DNS service is responding normally.'}
                {typeof failSafeData.restart_count === 'number' && failSafeData.restart_count > 0 && (
                  <span className="ml-1 text-gray-500 dark:text-gray-400">Auto-restarts so far: {failSafeData.restart_count}.</span>
                )}
              </div>
            </div>
          )}

          <div className="flex items-center justify-between py-2">
            <div>
              <div className="text-sm font-medium text-gray-900 dark:text-white">Enable Fail-Safe</div>
              <div className="text-xs text-gray-500 dark:text-gray-400">Watch the DNS service and act if it stops responding</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={failSafeSettings.enabled}
                onChange={(e) => setFailSafeSettings(prev => ({ ...prev, enabled: e.target.checked }))}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-green-300 dark:peer-focus:ring-green-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
            </label>
          </div>

          <div className={`flex items-center justify-between py-2 ${failSafeSettings.enabled ? '' : 'opacity-50 pointer-events-none'}`}>
            <div>
              <div className="text-sm font-medium text-gray-900 dark:text-white">Auto-Restart</div>
              <div className="text-xs text-gray-500 dark:text-gray-400">Automatically restart the DNS service when it stops responding</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={failSafeSettings.auto_recover}
                onChange={(e) => setFailSafeSettings(prev => ({ ...prev, auto_recover: e.target.checked }))}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-green-300 dark:peer-focus:ring-green-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
            </label>
          </div>

          <div className={`pt-2 ${failSafeSettings.enabled ? '' : 'opacity-50 pointer-events-none'}`}>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Health-check timeout (seconds)
            </label>
            <input
              type="number"
              min="1"
              max="30"
              value={failSafeSettings.timeout_seconds}
              onChange={(e) => setFailSafeSettings(prev => ({ ...prev, timeout_seconds: parseInt(e.target.value) || 5 }))}
              className="w-32 px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
            />
          </div>

          <div className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
            <div className="flex items-start gap-2">
              <ShieldCheck className="w-5 h-5 text-green-600 mt-0.5 shrink-0" />
              <p className="text-xs text-green-700 dark:text-green-400">
                Every 30 seconds EasyPi checks that the DNS service answers. If it stops responding, EasyPi
                restarts it automatically (a few seconds) and notifies you — your filtering stays on the whole time.
              </p>
            </div>
          </div>

          <div className="pt-2 flex justify-end">
            <button
              onClick={() => saveFailSafeMutation.mutate(failSafeSettings)}
              disabled={saveFailSafeMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg transition-colors"
            >
              {saveFailSafeMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              Save Fail-Safe Settings
            </button>
          </div>
        </div>
      </div>

      {/* Maintenance Tools */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <RotateCcw className="w-6 h-6 text-orange-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Maintenance</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button 
            onClick={() => clearCacheMutation.mutate()}
            disabled={clearCacheMutation.isPending}
            className="flex items-center justify-center gap-2 px-4 py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 text-white rounded-lg transition-colors"
          >
            {clearCacheMutation.isPending ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : clearCacheMutation.isSuccess ? (
              <CheckCircle className="w-5 h-5" />
            ) : (
              <RefreshCw className="w-5 h-5" />
            )}
            <span>Clear DNS Cache</span>
          </button>
          <button 
            onClick={() => resetStatsMutation.mutate()}
            disabled={resetStatsMutation.isPending}
            className="flex items-center justify-center gap-2 px-4 py-3 bg-purple-500 hover:bg-purple-600 disabled:opacity-50 text-white rounded-lg transition-colors"
          >
            {resetStatsMutation.isPending ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : resetStatsMutation.isSuccess ? (
              <CheckCircle className="w-5 h-5" />
            ) : (
              <Activity className="w-5 h-5" />
            )}
            <span>Reset Statistics</span>
          </button>
          <button 
            onClick={() => clearLogMutation.mutate()}
            disabled={clearLogMutation.isPending}
            className="flex items-center justify-center gap-2 px-4 py-3 bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white rounded-lg transition-colors"
          >
            {clearLogMutation.isPending ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : clearLogMutation.isSuccess ? (
              <CheckCircle className="w-5 h-5" />
            ) : (
              <Trash2 className="w-5 h-5" />
            )}
            <span>Clear Query Log</span>
          </button>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="bg-red-50 dark:bg-red-900/20 border-2 border-red-200 dark:border-red-800 rounded-lg p-6">
        <div className="flex items-center gap-3 mb-4">
          <AlertTriangle className="w-6 h-6 text-red-500" />
          <h3 className="text-lg font-semibold text-red-900 dark:text-red-100">Danger Zone</h3>
        </div>
        
        {!showResetConfirm && !showFactoryConfirm ? (
          <div className="space-y-3">
            <button 
              onClick={() => setShowResetConfirm(true)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Reset All Settings
            </button>
            <p className="text-xs text-red-700 dark:text-red-300 text-center">
              This will reset statistics, clear query log, and clear DNS cache
            </p>
          </div>
        ) : (
          <div className="bg-red-100 dark:bg-red-900/40 rounded-lg p-4">
            <p className="text-sm text-red-800 dark:text-red-200 mb-4">
              Are you sure? This action cannot be undone. All statistics will be cleared.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => resetAllMutation.mutate()}
                disabled={resetAllMutation.isPending}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg transition-colors"
              >
                {resetAllMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Trash2 className="w-4 h-4" />
                )}
                Yes, Reset Everything
              </button>
              <button
                onClick={() => {
                  setShowResetConfirm(false)
                  setShowFactoryConfirm(false)
                }}
                className="flex-1 px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

    </div>
  )
}
