import { useState, useEffect, useCallback } from 'react'
import { Link2, Loader2, RefreshCw, X } from 'lucide-react'
import { useNetworkToolkitStore } from '../../../stores/networkToolkitStore'
import { getActiveConnections } from '../../../api/network'
import { DataTable, Column } from '../shared/DataTable'
import { StatCard } from '../shared/StatCard'
import { StatusBadge } from '../shared/StatusBadge'
import { ExportButtons } from '../shared/ExportButtons'
import type { ActiveConnection, ConnectionFilters, ConnectionState } from '../../../types/network'

export function ActiveConnections() {
  const { activeConnections, setActiveConnections, scanProgress, setScanProgress } = useNetworkToolkitStore()
  
  const [filters, setFilters] = useState<ConnectionFilters>({})
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const fetchConnections = useCallback(async (filtersToUse: ConnectionFilters) => {
    setScanProgress('active-connections', { status: 'running', progress: 0, message: 'Getting connections...' })
    
    try {
      const response = await getActiveConnections(filtersToUse)
      
      if (response.success && response.data) {
        setActiveConnections(response.data)
        setScanProgress('active-connections', { status: 'completed', progress: 100 })
        setLastUpdated(new Date())
      } else {
        setScanProgress('active-connections', { status: 'error', progress: 0, message: response.error })
      }
    } catch (error) {
      setScanProgress('active-connections', {
        status: 'error',
        progress: 0,
        message: error instanceof Error ? error.message : 'Error getting connections',
      })
    }
  }, [setActiveConnections, setScanProgress])

  useEffect(() => {
    void fetchConnections({})
  }, [fetchConnections])

  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval> | null = null

    if (autoRefresh) {
      intervalId = setInterval(() => fetchConnections(filters), 3000)
    }

    return () => {
      if (intervalId) clearInterval(intervalId)
    }
  }, [autoRefresh, fetchConnections, filters])

  const handleRefresh = () => {
    fetchConnections(filters)
  }

  const handleReset = () => {
    setFilters({})
    setActiveConnections([])
    setLastUpdated(null)
    setScanProgress('active-connections', { status: 'idle', progress: 0 })
  }

  const columns: Column<ActiveConnection>[] = [
    {
      key: 'protocol',
      header: 'Protocol',
      width: 'w-20',
      render: (value) => <span className="text-blue-600 dark:text-blue-400 font-mono text-xs">{value}</span>,
    },
    {
      key: 'localAddress',
      header: 'Local Address',
      sortable: true,
      render: (_, conn) => (
        <code className="text-sm text-gray-700 dark:text-gray-300">
          {conn.localAddress}:{conn.localPort}
        </code>
      ),
    },
    {
      key: 'remoteAddress',
      header: 'Remote Address',
      sortable: true,
      render: (_, conn) => (
        <code className="text-sm text-gray-700 dark:text-gray-300">
          {conn.remoteAddress ? (
            <>
              {conn.remoteAddress}:{conn.remotePort ?? '—'}
            </>
          ) : (
            '—'
          )}
        </code>
      ),
    },
    {
      key: 'state',
      header: 'State',
      render: (value) => {
        const statusMap: Record<ConnectionState, 'online' | 'offline' | 'limited'> = {
          ESTABLISHED: 'online',
          LISTENING: 'limited',
          TIME_WAIT: 'limited',
          CLOSE_WAIT: 'offline',
          SYN_SENT: 'limited',
          SYN_RECEIVED: 'limited',
        }
        return <StatusBadge status={statusMap[value as ConnectionState]} label={value} />
      },
    },
    {
      key: 'processName',
      header: 'Process',
      sortable: true,
      render: (value, conn) =>
        value ? (
          <span className="text-gray-700 dark:text-gray-300">
            {value} {conn.pid && <span className="text-gray-500 dark:text-gray-500 text-xs">({conn.pid})</span>}
          </span>
        ) : (
          <span className="text-gray-400 dark:text-gray-500">—</span>
        ),
    },
  ]

  const progress = scanProgress['active-connections']
  const connections = activeConnections || []

  const establishedCount = connections.filter((c) => c.state === 'ESTABLISHED').length
  const listeningCount = connections.filter((c) => c.state === 'LISTENING').length
  const tcpCount = connections.filter((c) => c.protocol === 'TCP').length
  const udpCount = connections.filter((c) => c.protocol === 'UDP').length

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 sm:gap-4">
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Protocol</label>
          <select
            value={filters.protocol || ''}
            onChange={(e) => setFilters({ ...filters, protocol: e.target.value ? (e.target.value as 'TCP' | 'UDP') : undefined })}
            className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-dark-800 border border-gray-300 dark:border-dark-600 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
          </select>
        </div>
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">State</label>
          <select
            value={filters.state || ''}
            onChange={(e) => setFilters({ ...filters, state: e.target.value ? (e.target.value as ConnectionState) : undefined })}
            className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-dark-800 border border-gray-300 dark:border-dark-600 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All</option>
            <option value="ESTABLISHED">ESTABLISHED</option>
            <option value="LISTENING">LISTENING</option>
            <option value="TIME_WAIT">TIME_WAIT</option>
            <option value="CLOSE_WAIT">CLOSE_WAIT</option>
            <option value="SYN_SENT">SYN_SENT</option>
            <option value="SYN_RECEIVED">SYN_RECEIVED</option>
          </select>
        </div>
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Process</label>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={filters.process || ''}
              onChange={(e) => setFilters({ ...filters, process: e.target.value || undefined })}
              placeholder="Process name"
              className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-white/5 border border-gray-300 dark:border-white/10 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            {(filters.protocol || filters.state || filters.process) && (
              <button
                onClick={() => setFilters({})}
                className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white bg-gray-100 dark:bg-white/5 border border-gray-300 dark:border-white/10 rounded-lg transition-colors"
                title="Reset filters"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
            />
            Auto-refresh (every 3 sec)
          </label>
          {lastUpdated && (
            <span className="text-xs text-gray-500 dark:text-gray-400">
              Updated: {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleReset}
            className="flex-1 sm:flex-initial px-3 py-2 bg-gray-100 dark:bg-white/5 border border-gray-300 dark:border-white/10 rounded-lg text-xs sm:text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-white/10 transition-colors"
          >
            Reset
          </button>
          <button
            onClick={handleRefresh}
            disabled={progress.status === 'running'}
            className="flex-1 sm:flex-initial flex items-center justify-center gap-2 px-4 sm:px-6 py-2.5 sm:py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 disabled:from-gray-600 disabled:to-gray-700 rounded-lg text-sm sm:text-base text-white font-medium transition-all"
          >
            {progress.status === 'running' ? (
              <>
                <Loader2 className="w-4 h-4 sm:w-5 sm:h-5 animate-spin" />
                <span className="hidden sm:inline">Loading...</span>
              </>
            ) : (
              <>
                <RefreshCw className="w-4 h-4 sm:w-5 sm:h-5" />
                <span className="hidden sm:inline">Refresh</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error */}
      {progress.status === 'error' && (
        <div className="p-3 sm:p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-xs sm:text-sm text-red-400">{progress.message}</div>
      )}

      {/* Results */}
      {connections.length > 0 ? (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
            <StatCard icon={Link2} label="Total Connections" value={connections.length} color="blue" />
            <StatCard icon={Link2} label="Established" value={establishedCount} color="green" />
            <StatCard icon={Link2} label="Listening" value={listeningCount} color="yellow" />
            <StatCard icon={Link2} label="TCP / UDP" value={`${tcpCount} / ${udpCount}`} color="purple" />
          </div>

          {/* Export */}
          <div className="flex justify-center sm:justify-end">
            <ExportButtons data={connections} filename={`connections-${Date.now()}`} formats={['json', 'csv']} />
          </div>

          {/* Table */}
          <div className="bg-gray-50 dark:bg-white/5 backdrop-blur-sm rounded-xl border border-gray-200 dark:border-white/10 overflow-hidden">
            <DataTable
              data={connections}
              columns={columns}
              keyExtractor={(conn) => conn.id}
              emptyMessage="No connections found"
            />
          </div>
        </div>
      ) : (
        <div className="flex items-center justify-center py-12 bg-gray-50 dark:bg-white/5 backdrop-blur-sm rounded-xl border border-gray-200 dark:border-white/10">
          <div className="text-center space-y-3">
            <Link2 className="w-10 h-10 sm:w-12 sm:h-12 mx-auto text-gray-400" />
            <p className="text-base sm:text-lg font-medium text-gray-800 dark:text-gray-200">No Connections Found</p>
            <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Change filters or refresh the list</p>
          </div>
        </div>
      )}
    </div>
  )
}
