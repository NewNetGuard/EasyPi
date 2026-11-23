import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Shield, Ban, TrendingUp, Play, Square, Settings, ShieldAlert, Trash2 } from 'lucide-react'
import type { Threat, BannedIP, ThreatLevel } from '../../types/security'
import { getThreats, getBannedIPs, banIP, unbanIP, getMonitoringStatus, startMonitoring, stopMonitoring, updateMonitoringSettings, clearThreats } from '../../api/guardSecurity'

export default function SecurityMonitor() {
  const [activeTab, setActiveTab] = useState<'threats' | 'banned'>('threats')
  const [showSettings, setShowSettings] = useState(false)
  const queryClient = useQueryClient()

  // Monitoring status
  const { data: monitoringStatus } = useQuery({
    queryKey: ['monitoring-status'],
    queryFn: getMonitoringStatus,
    refetchInterval: 5000,
  })

  const { data: threatsData, isLoading: threatsLoading } = useQuery({
    queryKey: ['security-threats'],
    queryFn: getThreats,
    refetchInterval: 10000,
  })

  const { data: bannedData, isLoading: bannedLoading } = useQuery({
    queryKey: ['security-banned'],
    queryFn: getBannedIPs,
    refetchInterval: 15000,
  })

  // Map backend response to frontend Threat type
  const threats: Threat[] = Array.isArray(threatsData) 
    ? threatsData.map((t: any) => {
        return {
          id: t.id || `${t.ip}_${t.type}`,
          type: t.type,
          severity: t.severity,
          sourceIp: t.ip || t.sourceIp,  // Backend uses 'ip', frontend expects 'sourceIp'
          description: t.description,
          timestamp: t.last_seen || t.timestamp,
          status: t.blocked ? 'resolved' : 'active',
          details: { count: t.count, first_seen: t.first_seen }
        }
      })
    : []
  const banned: BannedIP[] = Array.isArray(bannedData) ? bannedData : []

  // Monitoring mutations
  const startMutation = useMutation({
    mutationFn: startMonitoring,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['monitoring-status'] }),
  })

  const stopMutation = useMutation({
    mutationFn: stopMonitoring,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['monitoring-status'] }),
  })

  const settingsMutation = useMutation({
    mutationFn: updateMonitoringSettings,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['monitoring-status'] }),
  })

  const banMutation = useMutation({
    mutationFn: ({ ip, type, reason }: { ip: string; type: string; reason: string }) => {
      return banIP(ip, reason, type, true)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-banned'] })
      queryClient.invalidateQueries({ queryKey: ['security-threats'] })
    },
    onError: (error) => {
      console.error('❌ Ban error:', error)
    },
  })

  const unbanMutation = useMutation({
    mutationFn: ({ ip, type }: { ip: string; type?: string }) => unbanIP(ip, type),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-banned'] })
      queryClient.invalidateQueries({ queryKey: ['security-threats'] })
    },
  })

  const clearThreatsMutation = useMutation({
    mutationFn: clearThreats,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['security-threats'] }),
  })

  const getLevelColor = (level: ThreatLevel) => {
    switch (level) {
      case 'critical':
        return 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 border-red-500'
      case 'high':
        return 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 border-orange-500'
      case 'medium':
        return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300 border-yellow-500'
      case 'low':
        return 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-blue-500'
    }
  }

  const getTypeIcon = (type: Threat['type'] | string) => {
    const typeStr = String(type).toLowerCase().replace(/_/g, '-')
    switch (typeStr) {
      case 'brute-force':
      case 'brute_force':
        return '🔐'
      case 'port-scan':
      case 'port_scan':
        return '🔍'
      case 'ddos':
        return '💥'
      case 'malware':
        return '🦠'
      case 'suspicious':
      default:
        return '⚠️'
    }
  }

  const renderThreats = () => (
    <div className="space-y-4">
      {threats.length > 0 && (
        <div className="flex justify-end">
          <button
            onClick={() => {
              if (window.confirm('Clear all non-banned threat records? Banned IPs are kept.')) {
                clearThreatsMutation.mutate()
              }
            }}
            disabled={clearThreatsMutation.isPending}
            className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition-colors disabled:opacity-50"
            title="Clear the threat list (does not remove bans)"
          >
            <Trash2 className="w-4 h-4" />
            Clear
          </button>
        </div>
      )}
      {threatsLoading && <div className="text-sm text-gray-500">Waiting for threats...</div>}
      {!threatsLoading && threats.length === 0 && (
        <div className="text-sm text-gray-500">No threats detected.</div>
      )}
      {threats.map((threat) => (
        <div
          key={threat.id}
          className={`bg-white dark:bg-gray-800 rounded-lg p-6 border-l-4 ${getLevelColor(threat.severity)}`}
        >
          <div className="flex items-start justify-between">
            <div className="flex items-start gap-4">
              <div className="text-4xl">{getTypeIcon(threat.type)}</div>
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white capitalize">
                    {threat.type.replace('-', ' ')}
                  </h3>
                  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getLevelColor(threat.severity)}`}>
                    {threat.severity}
                  </span>
                  {threat.status === 'active' && (
                    <span className="px-2 py-1 text-xs bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-full">
                      Active
                    </span>
                  )}
                </div>
                <div className="space-y-1 text-sm text-gray-600 dark:text-gray-400">
                  <div>IP: <span className="font-mono text-gray-900 dark:text-white">{threat.sourceIp || (threat as any).ip || 'Unknown'}</span></div>
                  <div>Attempts: <span className="font-semibold">{(threat as any).attempts || (threat as any).count || (threat as any).details?.attempts || 'N/A'}</span></div>
                  <div>Details: {threat.description}</div>
                  <div className="text-xs">
                    Last seen: {new Date(threat.timestamp || (threat as any).last_seen || (threat as any).lastSeen).toLocaleString()}
                  </div>
                </div>
              </div>
            </div>
            <button
              onClick={() => banMutation.mutate({
                ip: threat.sourceIp || (threat as any).ip,
                type: threat.type,
                reason: threat.description || 'Manual ban'
              })}
              disabled={banMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors text-sm disabled:opacity-50"
            >
              <Ban className="w-4 h-4" />
              Ban IP
            </button>
          </div>
        </div>
      ))}
    </div>
  )

  const renderBanned = () => (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
      <table className="w-full">
        <thead className="bg-gray-50 dark:bg-gray-900">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">IP Address</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Reason</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Banned At</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Expires</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Attack Type</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
          {bannedLoading && (
            <tr><td colSpan={6} className="px-6 py-4 text-sm text-gray-500">Loading banned IPs...</td></tr>
          )}
          {!bannedLoading && banned.length === 0 && (
            <tr><td colSpan={6} className="px-6 py-4 text-sm text-gray-500">No banned IPs.</td></tr>
          )}
          {banned.map((ban) => (
            <tr key={ban.id || `${ban.ip}_${(ban as any).type}`} className="hover:bg-gray-50 dark:hover:bg-gray-900/50">
              <td className="px-6 py-4">
                <span className="text-sm font-mono font-medium text-gray-900 dark:text-white">{ban.ip}</span>
              </td>
              <td className="px-6 py-4">
                <span className="text-sm text-gray-600 dark:text-gray-400">{ban.reason}</span>
              </td>
              <td className="px-6 py-4">
                <span className="text-xs text-gray-600 dark:text-gray-400">
                  {new Date(ban.bannedAt).toLocaleString()}
                </span>
              </td>
              <td className="px-6 py-4">
                <span className="text-xs text-gray-600 dark:text-gray-400">
                  {ban.expiresAt ? new Date(ban.expiresAt).toLocaleString() : 'Never'}
                </span>
              </td>
              <td className="px-6 py-4">
                <span className="px-2 py-1 text-xs font-medium rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300">
                  {((ban as any).type || 'unknown').replace(/_/g, ' ')}
                </span>
              </td>
              <td className="px-6 py-4">
                <button
                  onClick={() => unbanMutation.mutate({ ip: ban.ip, type: (ban as any).type })}
                  disabled={unbanMutation.isPending}
                  className="px-3 py-1 text-sm text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-500/10 rounded-lg transition-colors disabled:opacity-50"
                >
                  Unban
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 sm:gap-4">
            <ShieldAlert className="w-10 h-10 sm:w-16 sm:h-16 text-orange-600 dark:text-orange-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">Security Monitor</h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Real-time threat detection and IP banning
              </p>
            </div>
          </div>
          {/* Monitoring Toggle */}
          <div className="flex items-center gap-2 sm:gap-3 flex-wrap">
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
              title="Settings"
            >
              <Settings className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${monitoringStatus?.enabled ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
              <span className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 hidden sm:inline">
                {monitoringStatus?.enabled ? 'Monitoring Active' : 'Monitoring Stopped'}
              </span>
            </div>
            <button
              onClick={() => monitoringStatus?.enabled ? stopMutation.mutate() : startMutation.mutate()}
              disabled={startMutation.isPending || stopMutation.isPending}
              className={`flex items-center gap-2 px-3 sm:px-4 py-2 rounded-lg font-medium transition-colors text-sm ${
                monitoringStatus?.enabled
                  ? 'bg-red-500 hover:bg-red-600 text-white'
                  : 'bg-green-500 hover:bg-green-600 text-white'
              } disabled:opacity-50`}
            >
              {monitoringStatus?.enabled ? (
                <>
                  <Square className="w-4 h-4" />
                  <span className="hidden sm:inline">Stop</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span className="hidden sm:inline">Start</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4">Monitoring Settings</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                SSH Failure Threshold
              </label>
              <input
                type="number"
                min="1"
                max="100"
                value={monitoringStatus?.ssh_threshold || 5}
                onChange={(e) => settingsMutation.mutate({ ssh_threshold: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              />
              <p className="text-xs text-gray-500 mt-1">Number of failed attempts before threat detection</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Auto-Ban
              </label>
              <button
                onClick={() => settingsMutation.mutate({ auto_ban: !monitoringStatus?.auto_ban })}
                className={`w-full sm:w-auto px-3 sm:px-4 py-2 rounded-lg font-medium transition-colors text-sm ${
                  monitoringStatus?.auto_ban
                    ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
                }`}
              >
                {monitoringStatus?.auto_ban ? 'Enabled (Auto-ban attackers)' : 'Disabled'}
              </button>
              <p className="text-xs text-gray-500 mt-1">Automatically ban IPs that exceed threshold</p>
            </div>
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2 sm:gap-3">
            <AlertTriangle className="w-6 h-6 sm:w-8 sm:h-8 text-red-500" />
            <div>
              <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Active Threats</div>
              <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{threats.length}</div>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2 sm:gap-3">
            <Ban className="w-6 h-6 sm:w-8 sm:h-8 text-orange-500" />
            <div>
              <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Banned IPs</div>
              <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{banned.length}</div>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2 sm:gap-3">
            <Shield className="w-6 h-6 sm:w-8 sm:h-8 text-green-500" />
            <div>
              <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Threats Detected</div>
              <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{monitoringStatus?.threats_count || 0}</div>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2 sm:gap-3">
            <TrendingUp className="w-6 h-6 sm:w-8 sm:h-8 text-blue-500" />
            <div>
              <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">SSH Threshold</div>
              <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{monitoringStatus?.ssh_threshold || 5}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 sm:gap-2 border-b border-gray-200 dark:border-gray-700">
        {(['threats', 'banned'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 sm:px-6 py-2 sm:py-3 font-medium transition-colors border-b-2 capitalize text-sm sm:text-base ${
              activeTab === tab
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Content */}
      {activeTab === 'threats' && renderThreats()}
      {activeTab === 'banned' && renderBanned()}
    </div>
  )
}
