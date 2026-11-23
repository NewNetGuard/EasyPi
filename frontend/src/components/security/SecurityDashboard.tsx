import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Shield, ShieldAlert, ShieldCheck, Activity, Settings, Plug } from 'lucide-react'
import { useSecurityStore } from '../../stores/securityStore'
import { getDashboard, getStats } from '../../api/guardSecurity'
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

export default function SecurityDashboard() {
  const { dashboard, setDashboard } = useSecurityStore()

  const { data: dashboardData, error: dashboardError, isLoading } = useQuery({
    queryKey: ['security-dashboard'],
    queryFn: getDashboard,
    refetchInterval: 5000,
    retry: 2,
  })

  const { data: statsData } = useQuery({
    queryKey: ['security-stats', '24h'],
    queryFn: () => getStats('24h'),
    refetchInterval: 30000,
  })

  useEffect(() => {
    if (dashboardData?.configured) {
      setDashboard(dashboardData)
    }
  }, [dashboardData, setDashboard])

  // Show setup message if not configured
  if (dashboardData && !dashboardData.configured) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="bg-gray-800 rounded-xl p-8 border border-gray-700 max-w-lg w-full text-center space-y-4">
          <div className="w-16 h-16 bg-yellow-500/20 rounded-full flex items-center justify-center mx-auto">
            <Settings className="w-8 h-8 text-yellow-400" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">Guard Security Not Configured</h2>
            <p className="text-gray-400">
              NetProtection DNS service is not running. Start it from the setup page.
            </p>
          </div>
          <Link
            to="/setup"
            className="inline-flex items-center gap-2 px-6 py-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
          >
            <Plug className="w-5 h-5" />
            Go to Setup
          </Link>
        </div>
      </div>
    )
  }

  if (dashboardError && !dashboard) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="w-full max-w-lg space-y-3 rounded-xl border border-red-200 bg-red-50 p-8 text-center dark:border-red-900/60 dark:bg-red-950/30">
          <ShieldAlert className="mx-auto h-10 w-10 text-red-600 dark:text-red-300" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Live security status unavailable</h2>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            EasyPi could not load NetProtection status. It will retry automatically; no protection state is being inferred.
          </p>
        </div>
      </div>
    )
  }

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
      </div>
    )
  }

  // Zero-valued fallback keeps an incomplete response honest; it never claims
  // protection is active without a positive backend status.
  const displayDashboard = dashboardData || dashboard || {
    protectionStatus: { enabled: false, disabledUntil: null },
    totalQueries: 0,
    blockedToday: 0,
    blockPercentage: 0,
    activeBlocklists: 0,
    blockedDomains: 0,
    activeThreats: 0,
    topBlocked: [],
  }

  const displayStats = statsData || {
    queryTrend: Array.from({ length: 24 }, (_, i) => ({
      time: `${i}:00`,
      queries: 0,
    })),
    blockTrend: Array.from({ length: 24 }, (_, i) => ({
      time: `${i}:00`,
      blocked: 0,
      allowed: 0,
    })),
  }

  const statusColor = displayDashboard.protectionStatus?.enabled ? 'text-green-500' : 'text-red-500'
  const StatusIcon = displayDashboard.protectionStatus?.enabled ? ShieldCheck : ShieldAlert

  return (
    <div className="space-y-6">
      {/* Protection Status */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 sm:gap-4">
            <StatusIcon className={`w-10 h-10 sm:w-16 sm:h-16 ${statusColor}`} />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">
                {displayDashboard.protectionStatus?.enabled ? 'Protection Active' : 'Protection Disabled'}
              </h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                {displayDashboard.protectionStatus?.enabled
                  ? 'Your network is protected'
                  : 'Enable protection to start blocking threats'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Queries Today"
          value={(displayDashboard.totalQueries || 0).toLocaleString()}
          icon={Activity}
          color="text-blue-500"
        />
        <StatCard
          label="Blocked Today"
          value={(displayDashboard.blockedToday || 0).toLocaleString()}
          icon={ShieldCheck}
          color="text-red-500"
          subtitle={`${displayDashboard.blockPercentage || 0}% blocked`}
        />
        <StatCard
          label="Active Blocklists"
          value={(displayDashboard.activeBlocklists || 0).toString()}
          icon={Shield}
          color="text-purple-500"
          subtitle={`${(displayDashboard.blockedDomains || 0).toLocaleString()} domains`}
        />
        <StatCard
          label="Active Threats"
          value={(displayDashboard.activeThreats || 0).toString()}
          icon={ShieldAlert}
          color="text-orange-500"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4">Query Trend (24h)</h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={displayStats.queryTrend}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" stroke="#9CA3AF" />
              <YAxis stroke="#9CA3AF" />
              <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
              <Area type="monotone" dataKey="queries" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4">Blocked vs Allowed</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={displayStats.blockTrend}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" stroke="#9CA3AF" />
              <YAxis stroke="#9CA3AF" />
              <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
              <Line type="monotone" dataKey="blocked" stroke="#EF4444" strokeWidth={2} />
              <Line type="monotone" dataKey="allowed" stroke="#10B981" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top Blocked */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-6 border border-gray-200 dark:border-gray-700">
        <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4">Top Blocked Domains</h3>
        <div className="space-y-2 sm:space-y-3">
          {(displayDashboard.topBlocked || []).length > 0 ? (
            displayDashboard.topBlocked.map((item, index) => {
              // Sanitize domain - only allow valid domain characters
              const safeDomain = typeof item.domain === 'string' 
                ? item.domain.replace(/[^a-zA-Z0-9.\-_]/g, '').slice(0, 253)
                : 'unknown'
              const safeHits = typeof item.hits === 'number' ? item.hits : 0
              
              return (
                <div key={index} className="flex flex-col sm:flex-row sm:items-center sm:justify-between py-2 sm:py-2 border-b border-gray-200 dark:border-gray-700 last:border-0 gap-2">
                  <div className="flex items-center gap-2 sm:gap-3 min-w-0">
                    <span className="text-xs sm:text-sm font-mono text-gray-600 dark:text-gray-400 flex-shrink-0">#{index + 1}</span>
                    <span className="text-xs sm:text-sm text-gray-900 dark:text-white font-medium font-mono truncate">{safeDomain}</span>
                  </div>
                  <div className="flex items-center gap-2 sm:gap-4 pl-6 sm:pl-0">
                    <span className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 flex-shrink-0">{safeHits.toLocaleString()} hits</span>
                    <div className="w-20 sm:w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div className="bg-red-500 h-2 rounded-full" style={{ width: `${Math.min((safeHits / (displayDashboard.topBlocked?.[0]?.hits || 1)) * 100, 100)}%` }} />
                    </div>
                  </div>
                </div>
              )
            })
          ) : (
            <p className="text-sm sm:text-base text-gray-400 text-center py-4">No blocked domains yet</p>
          )}
        </div>
      </div>
    </div>
  )
}

interface StatCardProps {
  label: string
  value: string
  icon: React.ComponentType<{ className?: string }>
  color: string
  subtitle?: string
}

function StatCard({ label, value, icon: Icon, color, subtitle }: StatCardProps) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">{label}</p>
          <p className="text-xl sm:text-3xl font-bold text-gray-900 dark:text-white mt-1 sm:mt-2">{value}</p>
          {subtitle && <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">{subtitle}</p>}
        </div>
        <Icon className={`w-6 h-6 sm:w-8 sm:h-8 ${color}`} />
      </div>
    </div>
  )
}
