import { useState } from 'react'
import { Target, TrendingDown, Activity, AlertCircle, CheckCircle, XCircle, Info, Zap, RefreshCw } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import api from '../../api/client'

interface AdTrackerStats {
  total_analyzed: number
  ads_detected: number
  trackers_detected: number
  blocked_today: number
  blocked_this_week: number
  top_blocked: Array<{
    domain: string
    count: number
    reasons: string[]
    confidence: number
  }>
  detection_methods: {
    ad_keywords: number
    high_entropy: number
    tracking_subdomain: number
    known_ad_network: number
    known_tracker: number
  }
  bandwidth_saved_mb: number
  false_positive_rate: number
}

interface RecentDetection {
  domain: string
  timestamp: string
  score: number
  verdict: 'blocked' | 'observed' | 'allowed'
  reasons: string[]
  confidence: number
  indicators: Record<string, number>
}

export default function AdTrackerPanel() {
  const [timeRange, setTimeRange] = useState<'today' | 'week'>('today')
  const [autoRefresh, setAutoRefresh] = useState(true)

  // Fetch stats
  const { data: stats, isLoading, refetch } = useQuery<AdTrackerStats>({
    queryKey: ['adTrackerStats', timeRange],
    queryFn: async () => {
      const { data } = await api.get('/dns/heuristics/ad-tracker/stats', {
        params: { range: timeRange }
      })
      return data.data
    },
    refetchInterval: autoRefresh ? 10000 : false,
  })

  // Fetch recent detections
  const { data: recent } = useQuery<RecentDetection[]>({
    queryKey: ['adTrackerRecent'],
    queryFn: async () => {
      const { data } = await api.get('/dns/heuristics/ad-tracker/recent', {
        params: { limit: 20 }
      })
      return data.data
    },
    refetchInterval: autoRefresh ? 5000 : false,
  })

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'blocked': return 'text-red-600 bg-red-100 dark:bg-red-900/30 dark:text-red-400'
      case 'observed': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/30 dark:text-yellow-400'
      case 'allowed': return 'text-green-600 bg-green-100 dark:bg-green-900/30 dark:text-green-400'
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-700 dark:text-gray-400'
    }
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'text-red-600'
    if (confidence >= 0.6) return 'text-orange-600'
    if (confidence >= 0.4) return 'text-yellow-600'
    return 'text-gray-600'
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 sm:gap-4">
            <Target className="w-10 h-10 sm:w-16 sm:h-16 text-purple-500" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">
                Ad & Tracker Detection
              </h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Behavioral analysis without blocklists
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`p-2 rounded-lg ${
                autoRefresh 
                  ? 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400' 
                  : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
              }`}
            >
              <RefreshCw className={`w-5 h-5 ${autoRefresh ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* How it works */}
      <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-xl p-4">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-purple-500 mt-0.5" />
          <div>
            <h4 className="font-medium text-purple-900 dark:text-purple-100">Behavioral Detection</h4>
            <p className="text-sm text-purple-700 dark:text-purple-300 mt-1">
              Detects ads and trackers using behavioral patterns: high entropy domains, tracking pixels, 
              cookie syncing, third-party floods, and ad-related keywords — <strong>no blocklists needed</strong>.
            </p>
          </div>
        </div>
      </div>

      {/* Time Range Selector */}
      <div className="flex gap-2">
        {(['today', 'week'] as const).map((range) => (
          <button
            key={range}
            onClick={() => setTimeRange(range)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              timeRange === range
                ? 'bg-purple-500 text-white'
                : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
            }`}
          >
            {range === 'today' ? 'Today' : 'This Week'}
          </button>
        ))}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard
          label="Ads Detected"
          value={stats?.ads_detected || 0}
          icon={Target}
          color="purple"
        />
        <StatCard
          label="Trackers Detected"
          value={stats?.trackers_detected || 0}
          icon={Activity}
          color="orange"
        />
        <StatCard
          label="Blocked Today"
          value={stats?.blocked_today || 0}
          icon={XCircle}
          color="red"
        />
        <StatCard
          label="Bandwidth Saved"
          value={`${stats?.bandwidth_saved_mb || 0} MB`}
          icon={TrendingDown}
          color="green"
        />
      </div>

      {/* Detection Methods */}
      {stats?.detection_methods && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Detection Methods
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
            <MethodCard label="Ad Keywords" count={stats.detection_methods.ad_keywords} />
            <MethodCard label="High Entropy" count={stats.detection_methods.high_entropy} />
            <MethodCard label="Tracking Subdomain" count={stats.detection_methods.tracking_subdomain} />
            <MethodCard label="Known Ad Network" count={stats.detection_methods.known_ad_network} />
            <MethodCard label="Known Tracker" count={stats.detection_methods.known_tracker} />
            <MethodCard 
              label="False Positive Rate" 
              count={`${((stats.false_positive_rate || 0) * 100).toFixed(1)}%`} 
            />
          </div>
        </div>
      )}

      {/* Top Blocked Domains */}
      {stats?.top_blocked && stats.top_blocked.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Top Blocked Domains
          </h3>
          <div className="space-y-2">
            {stats.top_blocked.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
              >
                <div className="flex-1 min-w-0">
                  <code className="text-sm font-mono text-gray-900 dark:text-white block truncate">
                    {item.domain}
                  </code>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {item.reasons.slice(0, 2).map((reason, i) => (
                      <span
                        key={i}
                        className="text-xs text-gray-600 dark:text-gray-400 bg-gray-200 dark:bg-gray-600 px-2 py-0.5 rounded"
                      >
                        {reason}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-3 ml-3">
                  <span className={`text-sm font-medium ${getConfidenceColor(item.confidence)}`}>
                    {(item.confidence * 100).toFixed(0)}%
                  </span>
                  <span className="text-lg font-bold text-gray-900 dark:text-white">
                    {item.count}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Detections */}
      {recent && recent.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Recent Detections (Live)
          </h3>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {recent.map((detection, idx) => (
              <div
                key={idx}
                className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg border-l-4"
                style={{
                  borderLeftColor: 
                    detection.verdict === 'blocked' ? '#ef4444' :
                    detection.verdict === 'observed' ? '#f59e0b' : '#10b981'
                }}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <code className="text-sm font-mono text-gray-900 dark:text-white truncate">
                        {detection.domain}
                      </code>
                      <span className={`px-2 py-0.5 text-xs font-medium rounded ${getVerdictColor(detection.verdict)}`}>
                        {detection.verdict.toUpperCase()}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {detection.reasons.slice(0, 3).map((reason, i) => (
                        <span
                          key={i}
                          className="text-xs text-gray-600 dark:text-gray-400"
                        >
                          • {reason}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <div className={`text-sm font-medium ${getConfidenceColor(detection.confidence)}`}>
                      {(detection.confidence * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-gray-500">
                      Score: {detection.score}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color }: { 
  label: string
  value: number | string
  icon: any
  color: 'purple' | 'orange' | 'red' | 'green'
}) {
  const colorClasses = {
    purple: 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400',
    orange: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400',
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center mb-3 ${colorClasses[color]}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
      <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">{label}</div>
    </div>
  )
}

function MethodCard({ label, count }: { label: string; count: number | string }) {
  return (
    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
      <div className="text-lg font-bold text-gray-900 dark:text-white">{count}</div>
      <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">{label}</div>
    </div>
  )
}
