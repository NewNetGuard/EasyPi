import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Search, Filter, RefreshCw, CheckCircle, XCircle, ArrowRight, AlertTriangle, Loader2, Trash2, Play, Pause, Activity } from 'lucide-react'
import type { DNSQuery, QueryStatus } from '../../types/security'
import { getQueryLog, clearQueryLog } from '../../api/guardSecurity'
import { blockSourceStyle } from './blockSourceStyles'

export default function QueryLog() {
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<QueryStatus | 'all'>('all')
  const [showFilters, setShowFilters] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const refreshInterval = 5000 // 5 seconds

  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['query-log'],
    queryFn: () => getQueryLog(undefined, 200),
    staleTime: 0,
    refetchInterval: autoRefresh ? refreshInterval : false,
  })

  const queries = useMemo<DNSQuery[]>(() => (Array.isArray(data) ? data : []), [data])

  const clearMutation = useMutation({
    mutationFn: clearQueryLog,
    onSuccess: () => refetch(),
  })

  const filteredQueries = useMemo(() => queries.filter(query => {
    const matchesSearch = query.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      query.client.includes(searchQuery)
    const matchesStatus = statusFilter === 'all' || query.status === statusFilter
    return matchesSearch && matchesStatus
  }), [queries, searchQuery, statusFilter])

  // Breakdown of blocked queries by WHO blocked them (list vs behavioural analysis).
  const blockSources = useMemo(() => {
    const counts: Record<string, { label: string; key: string; count: number }> = {}
    for (const q of queries) {
      if (q.status !== 'blocked' || !q.source) continue
      const key = q.sourceKey || 'other'
      if (!counts[key]) counts[key] = { label: q.source, key, count: 0 }
      counts[key].count++
    }
    return Object.values(counts).sort((a, b) => b.count - a.count)
  }, [queries])

  const getStatusIcon = (status: QueryStatus) => {
    switch (status) {
      case 'allowed':
        return <CheckCircle className="w-5 h-5 text-green-500" />
      case 'blocked':
        return <XCircle className="w-5 h-5 text-red-500" />
      case 'forwarded':
        return <ArrowRight className="w-5 h-5 text-blue-500" />
    }
  }

  const getStatusColor = (status: QueryStatus) => {
    switch (status) {
      case 'allowed':
        return 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
      case 'blocked':
        return 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
      case 'forwarded':
        return 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 sm:gap-4">
            <Activity className="w-10 h-10 sm:w-16 sm:h-16 text-blue-600 dark:text-blue-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">DNS Query Log</h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Real-time DNS query monitoring
                {autoRefresh && (
                  <span className="ml-2 text-green-500">
                    • Live {isFetching && <Loader2 className="inline w-3 h-3 animate-spin ml-1" />}
                  </span>
                )}
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-colors ${
                autoRefresh 
                  ? 'bg-green-500 hover:bg-green-600 text-white' 
                  : 'bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white'
              }`}
              onClick={() => setAutoRefresh(!autoRefresh)}
              title={autoRefresh ? 'Pause auto-refresh' : 'Start auto-refresh'}
            >
              {autoRefresh ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            </button>
            <button
              className="flex items-center gap-2 px-3 sm:px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors disabled:opacity-50 text-sm"
              onClick={() => refetch()}
              disabled={isFetching}
            >
              <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">Refresh</span>
            </button>
            <button
              className="flex items-center gap-2 px-3 sm:px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors disabled:opacity-50 text-sm"
              onClick={() => clearMutation.mutate()}
              disabled={clearMutation.isPending}
            >
              <Trash2 className="w-4 h-4" />
              <span className="hidden sm:inline">Clear</span>
            </button>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Total Queries</div>
          <div className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white mt-1">
            {queries.length}
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Allowed</div>
          <div className="text-xl sm:text-2xl font-bold text-green-500 mt-1">
            {queries.filter(q => q.status === 'allowed').length}
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Blocked</div>
          <div className="text-xl sm:text-2xl font-bold text-red-500 mt-1">
            {queries.filter(q => q.status === 'blocked').length}
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Avg Response</div>
          <div className="text-xl sm:text-2xl font-bold text-blue-500 mt-1">
            {queries.length
              ? Math.round(queries.reduce((acc, q) => acc + (q.responseTime || 0), 0) / queries.length)
              : 0}ms
          </div>
        </div>
      </div>

      {/* Blocked-by-source breakdown */}
      {blockSources.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 bg-white dark:bg-gray-800 rounded-lg p-3 border border-gray-200 dark:border-gray-700">
          <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Blocked by:</span>
          {blockSources.map((s) => (
            <span
              key={s.key}
              className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full ${blockSourceStyle(s.key).color}`}
            >
              {blockSourceStyle(s.key).emoji} {s.label} <span className="opacity-70">×{s.count}</span>
            </span>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-2 sm:gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search domain or client IP..."
            className="w-full pl-10 pr-4 py-2 sm:py-3 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
          />
        </div>
        <div className="flex gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as QueryStatus | 'all')}
            className="flex-1 sm:flex-none px-3 sm:px-4 py-2 sm:py-3 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
          >
            <option value="all">All Status</option>
            <option value="allowed">Allowed</option>
            <option value="blocked">Blocked</option>
          </select>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center gap-2 px-3 sm:px-4 py-2 sm:py-3 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors text-sm"
          >
            <Filter className="w-4 h-4" />
            <span className="hidden sm:inline">Filters</span>
          </button>
        </div>
      </div>

      {/* Query Log Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Time
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Domain
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Client
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Source
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Time (ms)
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-gray-500 dark:text-gray-400">
                    <div className="flex items-center justify-center gap-2">
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Loading queries...
                    </div>
                  </td>
                </tr>
              ) : isError ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-red-500">
                    <div className="flex items-center justify-center gap-2">
                      <AlertTriangle className="w-5 h-5" />
                      Failed to load query log.
                    </div>
                  </td>
                </tr>
              ) : filteredQueries.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-gray-500 dark:text-gray-400">
                    No queries found.
                  </td>
                </tr>
              ) : filteredQueries.map((query) => (
                <tr key={query.id} className={`hover:bg-gray-50 dark:hover:bg-gray-900/50 ${query.status === 'blocked' ? 'bg-red-50/50 dark:bg-red-900/10' : ''}`}>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-xs text-gray-600 dark:text-gray-400">
                      {new Date(query.timestamp).toLocaleTimeString()}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-gray-900 dark:text-white font-mono truncate block max-w-xs" title={query.domain}>
                        {query.domain}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-gray-600 dark:text-gray-400">
                      {query.queryType}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-xs font-mono text-gray-600 dark:text-gray-400">{query.client}</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className={`inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(query.status)}`}>
                      {getStatusIcon(query.status)}
                      {query.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    {query.source ? (
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full ${blockSourceStyle(query.sourceKey).color}`}
                        title={`Blocked by ${query.source}`}
                      >
                        {blockSourceStyle(query.sourceKey).emoji} {query.source}
                      </span>
                    ) : (
                      <span className="text-xs text-gray-400">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-xs text-gray-500 dark:text-gray-500">{query.responseTime || 0}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
