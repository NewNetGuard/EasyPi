import { useCallback, useState, useEffect } from 'react'
import { AlertTriangle, Settings, X, Check, RefreshCw, Loader2 } from 'lucide-react'
import { useNetworkToolkitStore } from '../../../stores/networkToolkitStore'
import { getPortAlerts, updatePortAlertConfig, dismissPortAlert } from '../../../api/network'
import { DataTable, Column } from '../shared/DataTable'
import { StatCard } from '../shared/StatCard'
import { RiskBadge } from '../shared/RiskBadge'
import type { PortAlert, PortAlertConfig } from '../../../types/network'

export function OpenPortsAlert() {
  const { portAlerts, setPortAlerts, setScanProgress } = useNetworkToolkitStore()
  
  const [config, setConfig] = useState<PortAlertConfig>({
    enabled: true,
    monitoredPorts: [],
    checkInterval: 5,
    notifyOnNew: true,
  })
  
  const [showConfig, setShowConfig] = useState(false)
  const [newPort, setNewPort] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  const fetchAlerts = useCallback(async () => {
    setIsLoading(true)
    try {
      const response = await getPortAlerts()
      
      if (response.success && response.data) {
        setPortAlerts(response.data)
      }
    } catch (error) {
      console.error('Error fetching port alerts:', error)
    } finally {
      setIsLoading(false)
    }
  }, [setPortAlerts])

  useEffect(() => {
    if (config.enabled) {
      void fetchAlerts()
      const intervalId = setInterval(fetchAlerts, config.checkInterval * 60 * 1000)
      return () => clearInterval(intervalId)
    }
  }, [config.enabled, config.checkInterval, fetchAlerts])

  const handleSaveConfig = async () => {
    setScanProgress('open-ports-alert', { status: 'running', progress: 0, message: 'Saving settings...' })
    
    try {
      const response = await updatePortAlertConfig(config)
      
      if (response.success) {
        setScanProgress('open-ports-alert', { status: 'completed', progress: 100 })
        setShowConfig(false)
        fetchAlerts()
      } else {
        setScanProgress('open-ports-alert', { status: 'error', progress: 0, message: response.error })
      }
    } catch (error) {
      setScanProgress('open-ports-alert', {
        status: 'error',
        progress: 0,
        message: error instanceof Error ? error.message : 'Error saving settings',
      })
    }
  }

  const handleDismiss = async (alertId: string) => {
    try {
      await dismissPortAlert(alertId)
      setPortAlerts(portAlerts.filter((alert) => alert.id !== alertId))
    } catch (error) {
      console.error('Error dismissing alert:', error)
    }
  }

  const handleAddPort = () => {
    const port = parseInt(newPort)
    if (port > 0 && port <= 65535 && !config.monitoredPorts.includes(port)) {
      setConfig({ ...config, monitoredPorts: [...config.monitoredPorts, port].sort((a, b) => a - b) })
      setNewPort('')
    }
  }

  const handleRemovePort = (port: number) => {
    setConfig({ ...config, monitoredPorts: config.monitoredPorts.filter((p) => p !== port) })
  }

  const columns: Column<PortAlert>[] = [
    {
      key: 'port',
      header: 'Port',
      sortable: true,
      render: (value, alert) => (
        <div>
          <code className="text-blue-600 dark:text-blue-400 font-mono text-lg">{value}</code>
          <span className="text-gray-500 dark:text-gray-500 text-xs ml-2">{alert.protocol}</span>
        </div>
      ),
    },
    {
      key: 'service',
      header: 'Service',
      sortable: true,
    },
    {
      key: 'riskLevel',
      header: 'Risk Level',
      render: (value) => <RiskBadge level={value} />,
    },
    {
      key: 'description',
      header: 'Description',
      render: (value) => <span className="text-sm text-gray-600 dark:text-gray-400">{value}</span>,
    },
    {
      key: 'recommendation',
      header: 'Recommendation',
      render: (value) => <span className="text-sm text-yellow-600 dark:text-yellow-400">{value}</span>,
    },
    {
      key: 'lastDetected',
      header: 'Detected',
      render: (value) => <span className="text-xs text-gray-500 dark:text-gray-500">{new Date(value).toLocaleString()}</span>,
    },
    {
      key: 'id',
      header: '',
      width: 'w-20',
      render: (_, alert) => (
        <button
          onClick={() => handleDismiss(alert.id)}
          className="p-1 hover:bg-gray-200 dark:hover:bg-white/10 rounded text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-white transition-colors"
          title="Dismiss"
        >
          <X className="w-4 h-4" />
        </button>
      ),
    },
  ]

  const alerts = portAlerts || []
  const criticalCount = alerts.filter((a) => a.riskLevel === 'critical').length
  const highCount = alerts.filter((a) => a.riskLevel === 'high').length
  const mediumCount = alerts.filter((a) => a.riskLevel === 'medium').length
  const lowCount = alerts.filter((a) => a.riskLevel === 'low').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 sm:gap-4">
        <div>
          <h3 className="text-base sm:text-lg font-medium text-gray-900 dark:text-white">Open Ports Monitoring</h3>
          <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 mt-1">
            Automatic detection and alerts for open ports with potential risks
          </p>
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="flex-1 sm:flex-initial flex items-center justify-center gap-2 px-3 sm:px-4 py-2 bg-gray-100 dark:bg-white/5 hover:bg-gray-200 dark:hover:bg-white/10 border border-gray-300 dark:border-white/10 rounded-lg text-xs sm:text-sm text-gray-700 dark:text-gray-300 transition-colors"
          >
            <Settings className="w-4 h-4" />
            <span className="hidden sm:inline">Settings</span>
          </button>
          <button
            onClick={fetchAlerts}
            disabled={isLoading}
            className="flex-1 sm:flex-initial flex items-center justify-center gap-2 px-3 sm:px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 disabled:from-gray-600 disabled:to-gray-700 rounded-lg text-xs sm:text-sm text-white font-medium transition-all"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span className="hidden sm:inline">Loading...</span>
              </>
            ) : (
              <>
                <RefreshCw className="w-4 h-4" />
                <span className="hidden sm:inline">Refresh</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Config Panel */}
      {showConfig && (
        <div className="p-4 sm:p-6 bg-gray-100 dark:bg-white/5 backdrop-blur-sm rounded-xl border border-gray-200 dark:border-white/10 space-y-4">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-sm sm:text-md font-medium text-gray-900 dark:text-white">Monitoring Settings</h4>
            <button onClick={() => setShowConfig(false)} className="text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-white">
              <X className="w-5 h-5" />
            </button>
          </div>

          <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={config.enabled}
              onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
              className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
            />
            Enable monitoring
          </label>

          <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={config.notifyOnNew}
              onChange={(e) => setConfig({ ...config, notifyOnNew: e.target.checked })}
              className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
            />
            Notify about new open ports
          </label>

          <div>
            <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Check Interval (minutes)</label>
            <input
              type="number"
              value={config.checkInterval}
              onChange={(e) => setConfig({ ...config, checkInterval: parseInt(e.target.value) })}
              min={1}
              max={60}
              className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-white/5 border border-gray-300 dark:border-white/10 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Monitor Specific Ports</label>
            <div className="flex gap-2 mb-2">
              <input
                type="number"
                value={newPort}
                onChange={(e) => setNewPort(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleAddPort()}
                placeholder="Port number"
                min={1}
                max={65535}
                className="flex-1 px-3 sm:px-4 py-2 bg-white dark:bg-white/5 border border-gray-300 dark:border-white/10 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={handleAddPort}
                className="px-3 sm:px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm sm:text-base text-white transition-colors"
              >
                Add
              </button>
            </div>
            {config.monitoredPorts.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {config.monitoredPorts.map((port) => (
                  <span
                    key={port}
                    className="flex items-center gap-1 px-2 sm:px-3 py-1 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400 text-xs sm:text-sm"
                  >
                    {port}
                    <button onClick={() => handleRemovePort(port)} className="hover:text-blue-200">
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          <button
            onClick={handleSaveConfig}
            className="flex items-center justify-center gap-2 w-full sm:w-auto px-4 sm:px-6 py-2.5 sm:py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 rounded-lg text-sm sm:text-base text-white font-medium transition-all"
          >
            <Check className="w-4 h-4 sm:w-5 sm:h-5" />
            Save Settings
          </button>
        </div>
      )}

      {/* Stats */}
      {alerts.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2 sm:gap-4">
          <StatCard icon={AlertTriangle} label="Total Alerts" value={alerts.length} color="blue" />
          <StatCard icon={AlertTriangle} label="Critical" value={criticalCount} color="red" />
          <StatCard icon={AlertTriangle} label="High" value={highCount} color="yellow" />
          <StatCard icon={AlertTriangle} label="Medium" value={mediumCount} color="green" />
          <StatCard icon={AlertTriangle} label="Low" value={lowCount} color="blue" />
        </div>
      )}

      {/* Alerts Table */}
      {alerts.length > 0 ? (
        <div className="bg-gray-50 dark:bg-white/5 backdrop-blur-sm rounded-xl border border-gray-200 dark:border-white/10 overflow-hidden">
          <DataTable data={alerts} columns={columns} keyExtractor={(alert) => alert.id} emptyMessage="No alerts" />
        </div>
      ) : (
        <div className="flex items-center justify-center py-12 bg-gray-50 dark:bg-white/5 backdrop-blur-sm rounded-xl border border-gray-200 dark:border-white/10">
          <div className="text-center space-y-4">
            <Check className="w-12 h-12 sm:w-16 sm:h-16 mx-auto text-green-500 dark:text-green-400" />
            <p className="text-base sm:text-lg font-medium text-gray-800 dark:text-gray-200">No Alerts</p>
            <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">All ports are normal or monitoring is disabled</p>
          </div>
        </div>
      )}
    </div>
  )
}
