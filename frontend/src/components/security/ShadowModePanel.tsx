/**
 * Shadow Mode Panel
 * 
 * Shows domains that would be blocked, with:
 * - Explainable reasons (WHY it would be blocked)
 * - Confidence scores
 * - Action buttons: Approve, Block, Allow for device
 * 
 * This is what makes EasyPi different from NetProtection/Pi-hole
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Eye,
  Shield,
  Ban,
  Check,
  X,
  Clock,
  AlertTriangle,
  Brain,
  Fingerprint,
  Globe,
  TrendingUp,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Filter,
  Monitor,
  Zap,
  Info,
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import api from '../../api/client'

interface ShadowDomain {
  domain: string
  score: number
  first_seen: string
  last_seen: string
  hit_count: number
  signals: Record<string, number>
  status: 'observing' | 'blocked' | 'approved' | 'auto_blocked'
  client_ips?: string[]
  categories?: string[]
}

interface SignalExplanation {
  signal: string
  score: number
  explanation: string
  icon: any
  color: string
}

// Signal explanations for users
const SIGNAL_EXPLANATIONS: Record<string, { icon: any; color: string; explain: (score: number) => string }> = {
  dga: {
    icon: Fingerprint,
    color: 'red',
    explain: (s) => `Domain looks algorithmically generated (DGA score: ${s}). Malware often uses random-looking domains.`,
  },
  entropy: {
    icon: Brain,
    color: 'orange', 
    explain: (s) => `High randomness in domain name (entropy: ${s}). Legitimate domains are usually readable.`,
  },
  homoglyph: {
    icon: AlertTriangle,
    color: 'red',
    explain: (s) => `Looks like brand impersonation (score: ${s}). May use lookalike characters (g00gle, paypa1).`,
  },
  first_seen: {
    icon: Clock,
    color: 'yellow',
    explain: (s) => `Very new domain, first seen recently. New domains are higher risk until established.`,
  },
  beaconing: {
    icon: TrendingUp,
    color: 'orange',
    explain: (s) => `Regular repeated requests detected. This pattern is common in malware communications.`,
  },
  reputation: {
    icon: Shield,
    color: 'purple',
    explain: (s) => `Low reputation score (${s}). Based on threat intelligence feeds.`,
  },
  length: {
    icon: Globe,
    color: 'blue',
    explain: (s) => `Unusually long domain name. Most legitimate domains are shorter and memorable.`,
  },
  subdomain_depth: {
    icon: Globe,
    color: 'blue',
    explain: (s) => `Many subdomain levels. Deep subdomains can indicate tracking or malicious activity.`,
  },
  other: {
    icon: Info,
    color: 'gray',
    explain: (s) => `Additional suspicious signal detected (score: ${s}).`,
  },
}

// Fetch shadow domains from shadow mode database
const fetchShadowDomains = async (status: string) => {
  try {
    // Get shadow domains for the active tab (backend routes by status)
    const response = await api.get('/netprotection/shadow/domains', {
      params: { limit: 100, status }
    })
    
    // API returns { success: true, data: [...], total: N }
    const apiData = response.data
    const domainsArray = apiData?.data || []
    
    // Transform to component format
    // Status mapping: observed/auto_blocked -> auto_blocked, promoted -> blocked, dismissed -> approved
    const domains = domainsArray.map((d: any) => {
      // Map backend action -> UI status. A 'promoted' domain splits into user-blocked
      // vs auto-blocked by WHO promoted it (action_by 'auto' = Shadow Mode itself).
      const rawAction = String(d.action || d.status || 'observed').toLowerCase()
      const by = String(d.action_by || d.reviewed_by || '').toLowerCase()
      let status: ShadowDomain['status']
      if (rawAction === 'promoted') status = by === 'auto' ? 'auto_blocked' : 'blocked'
      else if (rawAction === 'auto_blocked') status = 'auto_blocked'
      else if (rawAction === 'dismissed') status = 'approved'
      else status = 'observing' // observed / pending / null → review queue

      return {
        domain: d.domain,
        score: d.max_score || d.score || d.avg_score || 50,
        first_seen: d.first_seen || d.first_observed,
        last_seen: d.last_seen || d.last_observed,
        hit_count: d.hit_count || 1,
        signals: d.signals || {},
        status,
        client_ips: d.client_ips || [],
        categories: d.categories || [],
      }
    })
    
    // Get stats from separate endpoint
    let stats = { observing: 0, blocked: 0, approved: 0, auto_blocked: 0 }
    try {
      const statsRes = await api.get('/netprotection/shadow/stats')
      const statsData = statsRes.data?.data || {}
      stats = {
        observing: statsData.observing || statsData.total_observed || 0,
        blocked: statsData.blocked || 0,
        approved: statsData.approved || 0,
        auto_blocked: statsData.auto_blocked || 0,
      }
    } catch {
      // Calculate from domains if stats endpoint fails
      stats = {
        observing: domains.length,
        blocked: domains.filter((d: any) => d.status === 'blocked').length,
        approved: domains.filter((d: any) => d.status === 'approved').length,
        auto_blocked: domains.filter((d: any) => d.status === 'auto_blocked').length,
      }
    }
    
    return { domains, stats }
  } catch {
    return { domains: [], stats: { observing: 0, blocked: 0, approved: 0, auto_blocked: 0 } }
  }
}

// Take action on domain
const shadowAction = async ({ domain, action, reason }: { domain: string; action: string; reason?: string }) => {
  // Use shadow domain action endpoint
  const { data } = await api.post(`/netprotection/shadow/domains/${encodeURIComponent(domain)}/action`, {
    action,
    notes: reason || '',
  })
  // The endpoint answers 200 with success: false when it refuses an action.
  if (data && data.success === false) {
    throw new Error(data.error || 'Action failed')
  }
  return data
}

export default function ShadowModePanel() {
  const queryClient = useQueryClient()
  const [expandedDomain, setExpandedDomain] = useState<string | null>(null)
  const [filterStatus, setFilterStatus] = useState<'observing' | 'blocked' | 'approved' | 'auto_blocked'>('observing')

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['shadowDomains', filterStatus],
    queryFn: () => fetchShadowDomains(filterStatus),
    staleTime: 0,           // Данные всегда устаревшие при refetch
    gcTime: 0,              // Не кэшировать
    refetchOnWindowFocus: false,  // Не обновлять автоматически
  })

  const actionMutation = useMutation({
    mutationFn: shadowAction,
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['shadowDomains'] })
      const messages = {
        promote: '🚫 Domain added to blocklist',
        dismiss: '✅ Domain approved and added to the allowlist - it will not be blocked',
        allow_device: '✅ Domain allowed for this device',
      }
      toast.success(messages[variables.action as keyof typeof messages] || 'Action completed')
    },
    onError: (error: any) => toast.error(error?.response?.data?.detail || error?.message || 'Action failed'),
  })

  const getSignalExplanations = (signals: Record<string, number>): SignalExplanation[] => {
    return Object.entries(signals)
      .filter(([_, score]) => score > 0)
      .sort((a, b) => b[1] - a[1])
      .map(([signal, score]) => {
        const info = SIGNAL_EXPLANATIONS[signal] || {
          icon: Info,
          color: 'gray',
          explain: () => `Signal: ${signal} (score: ${score})`,
        }
        return {
          signal,
          score,
          explanation: info.explain(score),
          icon: info.icon,
          color: info.color,
        }
      })
  }

  const getConfidenceLabel = (score: number) => {
    if (score >= 80) return { label: 'Very High', color: 'text-red-600 bg-red-100' }
    if (score >= 60) return { label: 'High', color: 'text-orange-600 bg-orange-100' }
    if (score >= 40) return { label: 'Medium', color: 'text-yellow-600 bg-yellow-100' }
    return { label: 'Low', color: 'text-blue-600 bg-blue-100' }
  }

  const allDomains = data?.domains || []
  
  const filteredDomains = allDomains.filter((d: ShadowDomain) => {
    if (filterStatus === 'observing') return true  // Show all
    return d.status === filterStatus
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 sm:gap-4">
            <Eye className="w-10 h-10 sm:w-16 sm:h-16 text-yellow-500" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">Shadow Mode</h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Review suspicious domains before they're blocked. No false positives.
              </p>
            </div>
          </div>
          <div className="text-left sm:text-right">
            <div className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">{data?.stats?.observing || 0}</div>
            <div className="text-sm text-gray-600 dark:text-gray-400">Under review</div>
          </div>
        </div>
      </div>

      {/* How it works */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-xl p-4">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-500 mt-0.5" />
          <div>
            <h4 className="font-medium text-blue-900 dark:text-blue-100">How Shadow Mode Works</h4>
            <p className="text-sm text-blue-700 dark:text-blue-300 mt-1">
              Shadow Mode watches suspicious domains and lists them for review — nothing here is
              blocked while it's uncertain. You decide: <strong>Block</strong> it or{' '}
              <strong>Approve</strong> (mark safe). Only high-confidence domains are auto-blocked,
              and those show only <strong>Unblock</strong>. Approve and Unblock add the domain to
              your allowlist, so it stays allowed.
            </p>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 sm:gap-4">
        <StatCard 
          label="Observing" 
          value={data?.stats?.observing || 0} 
          icon={Eye}
          color="yellow"
          active={filterStatus === 'observing'}
          onClick={() => setFilterStatus('observing')}
        />
        <StatCard
          label="User Blocked"
          value={data?.stats?.blocked || 0}
          icon={Ban}
          color="red"
          active={filterStatus === 'blocked'}
          onClick={() => setFilterStatus('blocked')}
        />
        <StatCard 
          label="Approved" 
          value={data?.stats?.approved || 0} 
          icon={Check}
          color="green"
          active={filterStatus === 'approved'}
          onClick={() => setFilterStatus('approved')}
        />
        <StatCard 
          label="Auto-blocked" 
          value={data?.stats?.auto_blocked || 0} 
          icon={Zap}
          color="purple"
          active={filterStatus === 'auto_blocked'}
          onClick={() => setFilterStatus('auto_blocked')}
        />
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500 flex-shrink-0" />
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as any)}
            className="flex-1 sm:flex-initial px-3 py-1.5 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-xs sm:text-sm"
          >
            <option value="observing">Observing (review queue)</option>
            <option value="blocked">User Blocked</option>
            <option value="auto_blocked">Auto-blocked</option>
            <option value="approved">Approved</option>
          </select>
        </div>
        <button
          onClick={() => {
            refetch()
            toast.success('Обновлено!')
          }}
          disabled={isFetching}
          className="flex items-center justify-center sm:justify-start gap-2 px-3 py-1.5 text-xs sm:text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
          {isFetching ? 'Загрузка...' : 'Refresh'}
        </button>
      </div>

      {/* Domain List */}
      <div className="space-y-2 sm:space-y-3">
        {isLoading ? (
          <div className="text-center py-12 text-gray-500">Loading...</div>
        ) : filteredDomains.length === 0 ? (
          <div className="text-center py-12">
            <Eye className="w-10 h-10 sm:w-12 sm:h-12 text-gray-300 mx-auto mb-3" />
            <p className="text-sm sm:text-base text-gray-500">No domains in shadow mode</p>
            <p className="text-xs sm:text-sm text-gray-400 mt-1">
              Suspicious domains will appear here for your review
            </p>
          </div>
        ) : (
          filteredDomains.map((domain: ShadowDomain) => (
            <DomainCard
              key={domain.domain}
              domain={domain}
              expanded={expandedDomain === domain.domain}
              onToggle={() => setExpandedDomain(
                expandedDomain === domain.domain ? null : domain.domain
              )}
              onAction={(action) => actionMutation.mutate({ domain: domain.domain, action })}
              getSignalExplanations={getSignalExplanations}
              getConfidenceLabel={getConfidenceLabel}
              isActioning={actionMutation.isPending}
            />
          ))
        )}
      </div>
    </div>
  )
}

// Stat Card Component
function StatCard({ 
  label, 
  value, 
  icon: Icon, 
  color, 
  active,
  onClick 
}: { 
  label: string
  value: number
  icon: any
  color: string
  active: boolean
  onClick: () => void
}) {
  const colors = {
    yellow: 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/30 dark:text-yellow-400',
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
    purple: 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400',
  }

  return (
    <button
      onClick={onClick}
      className={`p-3 sm:p-4 rounded-xl border-2 transition-all ${
        active 
          ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' 
          : 'border-transparent bg-white dark:bg-gray-800 hover:border-gray-200 dark:hover:border-gray-700'
      }`}
    >
      <div className={`w-8 h-8 sm:w-10 sm:h-10 rounded-lg ${colors[color as keyof typeof colors]} flex items-center justify-center mb-2`}>
        <Icon className="w-4 h-4 sm:w-5 sm:h-5" />
      </div>
      <div className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
      <div className="text-xs sm:text-sm text-gray-500">{label}</div>
    </button>
  )
}

// Domain Card Component
function DomainCard({
  domain,
  expanded,
  onToggle,
  onAction,
  getSignalExplanations,
  getConfidenceLabel,
  isActioning,
}: {
  domain: ShadowDomain
  expanded: boolean
  onToggle: () => void
  onAction: (action: string) => void
  getSignalExplanations: (signals: Record<string, number>) => SignalExplanation[]
  getConfidenceLabel: (score: number) => { label: string; color: string }
  isActioning: boolean
}) {
  const confidence = getConfidenceLabel(domain.score)
  const signals = getSignalExplanations(domain.signals || {})
  const isObserving = domain.status === 'observing'

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl border ${
      isObserving ? 'border-yellow-200 dark:border-yellow-800' : 'border-gray-200 dark:border-gray-700'
    } overflow-hidden`}>
      {/* Header */}
      <div 
        className="p-3 sm:p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50"
        onClick={onToggle}
      >
        <div className="flex flex-col gap-3">
          <div className="flex items-start gap-2 sm:gap-3">
            <div className={`w-8 h-8 sm:w-10 sm:h-10 flex-shrink-0 rounded-lg flex items-center justify-center ${
              domain.status === 'auto_blocked' ? 'bg-purple-100 dark:bg-purple-900/30' :
              domain.status === 'blocked' ? 'bg-red-100 dark:bg-red-900/30' :
              domain.status === 'approved' ? 'bg-green-100 dark:bg-green-900/30' :
              'bg-yellow-100 dark:bg-yellow-900/30'
            }`}>
              {domain.status === 'auto_blocked' ? <Zap className="w-4 h-4 sm:w-5 sm:h-5 text-purple-600" /> :
               domain.status === 'blocked' ? <Ban className="w-4 h-4 sm:w-5 sm:h-5 text-red-600" /> :
               domain.status === 'approved' ? <Check className="w-4 h-4 sm:w-5 sm:h-5 text-green-600" /> :
               <Eye className="w-4 h-4 sm:w-5 sm:h-5 text-yellow-600" />}
            </div>
            <div className="flex-1 min-w-0">
              <code className="text-xs sm:text-sm font-mono font-medium text-gray-900 dark:text-white break-all">
                {domain.domain}
              </code>
              <div className="flex flex-wrap items-center gap-2 mt-1">
                <span className={`px-2 py-0.5 text-xs font-medium rounded-full whitespace-nowrap ${confidence.color}`}>
                  {confidence.label} ({domain.score}%)
                </span>
                <span className="text-xs text-gray-500 whitespace-nowrap">
                  {domain.hit_count} hits
                </span>
              </div>
            </div>
            <div className="flex-shrink-0">
              {expanded ? <ChevronUp className="w-5 h-5 text-gray-400" /> : <ChevronDown className="w-5 h-5 text-gray-400" />}
            </div>
          </div>
          
          <div className="flex flex-wrap items-center justify-center sm:justify-end gap-2">
            {/* Block: only where the domain is NOT already blocked (review queue or approved). */}
            {(domain.status === 'observing' || domain.status === 'approved') && (
              <button
                onClick={(e) => { e.stopPropagation(); onAction('promote'); }}
                disabled={isActioning}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs sm:text-sm font-medium bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                <Ban className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                <span>Block</span>
              </button>
            )}
            {/* Approve (review queue) / Unblock (already blocked) — both call dismiss. */}
            {(domain.status === 'observing' || domain.status === 'blocked' || domain.status === 'auto_blocked') && (
              <button
                onClick={(e) => { e.stopPropagation(); onAction('dismiss'); }}
                disabled={isActioning}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs sm:text-sm font-medium bg-green-500 hover:bg-green-600 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                <Check className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                <span>{domain.status === 'observing' ? 'Approve' : 'Unblock'}</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="border-t border-gray-100 dark:border-gray-700 p-3 sm:p-4 bg-gray-50 dark:bg-gray-800/50">
          {/* Why flagged */}
          <div className="mb-4">
            <h4 className="text-xs sm:text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-yellow-500" />
              Why this domain was flagged:
            </h4>
            <div className="space-y-2">
              {signals.length > 0 ? signals.map((signal) => {
                const Icon = signal.icon
                const colorClasses = {
                  red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
                  orange: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400',
                  yellow: 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/30 dark:text-yellow-400',
                  blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
                  purple: 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400',
                  gray: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
                }
                return (
                  <div key={signal.signal} className="flex items-start gap-2 sm:gap-3 p-2 sm:p-3 bg-white dark:bg-gray-800 rounded-lg">
                    <div className={`p-1 sm:p-1.5 rounded flex-shrink-0 ${colorClasses[signal.color as keyof typeof colorClasses]}`}>
                      <Icon className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
                        <span className="text-xs sm:text-sm font-medium text-gray-900 dark:text-white capitalize">
                          {signal.signal.replace(/_/g, ' ')}
                        </span>
                        <span className="text-xs text-gray-500">+{signal.score} points</span>
                      </div>
                      <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 mt-1">
                        {signal.explanation}
                      </p>
                    </div>
                  </div>
                )
              }) : (
                <p className="text-xs sm:text-sm text-gray-500">No specific signals recorded</p>
              )}
            </div>
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-4 text-xs sm:text-sm">
            <div>
              <span className="text-gray-500">First seen</span>
              <div className="font-medium text-gray-900 dark:text-white">
                {new Date(domain.first_seen).toLocaleDateString()}
              </div>
            </div>
            <div>
              <span className="text-gray-500">Last seen</span>
              <div className="font-medium text-gray-900 dark:text-white">
                {new Date(domain.last_seen).toLocaleDateString()}
              </div>
            </div>
            <div>
              <span className="text-gray-500">Total hits</span>
              <div className="font-medium text-gray-900 dark:text-white">
                {domain.hit_count}
              </div>
            </div>
          </div>

          {/* Device-specific action */}
          {isObserving && domain.client_ips && domain.client_ips.length > 0 && (
            <div className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={() => onAction('allow_device')}
                disabled={isActioning}
                className="flex items-center gap-2 px-3 py-2 text-xs sm:text-sm text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition-colors w-full sm:w-auto"
              >
                <Monitor className="w-3.5 h-3.5 sm:w-4 sm:h-4 flex-shrink-0" />
                <span className="truncate">Allow only for devices: {domain.client_ips.join(', ')}</span>
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}


