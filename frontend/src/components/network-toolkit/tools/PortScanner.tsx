import { useState } from 'react'
import { Shield, Loader2, AlertTriangle, Info } from 'lucide-react'
import { useNetworkToolkitStore } from '../../../stores/networkToolkitStore'
import { scanPorts } from '../../../api/network'
import { DataTable, Column } from '../shared/DataTable'
import { StatCard } from '../shared/StatCard'
import { StatusBadge } from '../shared/StatusBadge'
import { RiskBadge } from '../shared/RiskBadge'
import { ExportButtons } from '../shared/ExportButtons'
import type { PortInfo, PortScanConfig, ScanType } from '../../../types/network'

export function PortScanner() {
  const { portScanResult, setPortScanResult, scanProgress, setScanProgress } = useNetworkToolkitStore()
  
  const [config, setConfig] = useState<PortScanConfig>({
    targetHost: '',
    portRange: '1-1000',
    scanType: 'tcp-connect',
    timeout: 60,
  })

  const handleScan = async () => {
    if (!config.targetHost) {
      setScanProgress('port-scanner', { status: 'error', progress: 0, message: 'Enter target host' })
      return
    }

    setScanProgress('port-scanner', {
      status: 'running',
      progress: 0,
      message: 'Scanning ports; exact progress is not reported.',
    })
    
    try {
      const response = await scanPorts(config)
      
      if (response.success && response.data) {
        setPortScanResult(response.data)
        setScanProgress('port-scanner', { status: 'completed', progress: 100 })
      } else {
        setScanProgress('port-scanner', { status: 'error', progress: 0, message: response.error })
      }
    } catch (error) {
      setScanProgress('port-scanner', {
        status: 'error',
        progress: 0,
        message: error instanceof Error ? error.message : 'Scan error',
      })
    }
  }

  const columns: Column<PortInfo>[] = [
    {
      key: 'port',
      header: 'Port',
      sortable: true,
      render: (value) => <code className="text-blue-400 font-mono">{value}</code>,
    },
    {
      key: 'protocol',
      header: 'Protocol',
      render: (value) => <span className="text-gray-400">{value}</span>,
    },
    {
      key: 'status',
      header: 'Status',
      render: (value) => <StatusBadge status={value} />,
    },
    {
      key: 'service',
      header: 'Service',
      sortable: true,
      render: (value) => value || <span className="text-gray-500">—</span>,
    },
    {
      key: 'version',
      header: 'Version',
      render: (value) => value ? <span className="text-xs text-gray-400">{value}</span> : <span className="text-gray-500">—</span>,
    },
    {
      key: 'riskLevel',
      header: 'Risk',
      render: (value) => <RiskBadge level={value} size="sm" />,
    },
    {
      key: 'description',
      header: 'Description',
      render: (value) => <span className="text-sm text-gray-400">{value}</span>,
    },
  ]

  const progress = scanProgress['port-scanner']
  const ports = portScanResult?.ports || []

  return (
    <div className="space-y-6">
      {/* Configuration */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Target Host</label>
          <input
            type="text"
            value={config.targetHost}
            onChange={(e) => setConfig({ ...config, targetHost: e.target.value })}
            placeholder="192.168.1.1"
            className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-white/5 border border-gray-300 dark:border-white/10 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Port Range</label>
          <input
            type="text"
            value={config.portRange}
            onChange={(e) => setConfig({ ...config, portRange: e.target.value })}
            placeholder="1-1000 or 80,443,8080"
            className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-white/5 border border-gray-300 dark:border-white/10 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Scan Type</label>
          <select
            value={config.scanType}
            onChange={(e) => setConfig({ ...config, scanType: e.target.value as ScanType })}
            className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-dark-800 border border-gray-300 dark:border-dark-600 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="tcp-syn">TCP SYN</option>
            <option value="tcp-connect">TCP Connect</option>
            <option value="udp">UDP</option>
          </select>
        </div>
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Timeout (sec)</label>
          <input
            type="number"
            value={config.timeout}
            onChange={(e) => setConfig({ ...config, timeout: parseInt(e.target.value) || 60 })}
            min={10}
            max={300}
            className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Quick Presets */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setConfig({ ...config, portRange: '1-1000' })}
          className="px-2.5 sm:px-3 py-1.5 bg-gray-100 dark:bg-white/5 hover:bg-gray-200 dark:hover:bg-white/10 border border-gray-300 dark:border-white/10 rounded-lg text-xs sm:text-sm text-gray-700 dark:text-gray-300 transition-colors"
        >
          Top 1000
        </button>
        <button
          onClick={() => setConfig({ ...config, portRange: '20,21,22,23,25,53,80,110,143,443,3306,3389,8080' })}
          className="px-2.5 sm:px-3 py-1.5 bg-gray-100 dark:bg-white/5 hover:bg-gray-200 dark:hover:bg-white/10 border border-gray-300 dark:border-white/10 rounded-lg text-xs sm:text-sm text-gray-700 dark:text-gray-300 transition-colors"
        >
          Popular
        </button>
        <button
          onClick={() => setConfig({ ...config, portRange: '1-65535' })}
          className="px-2.5 sm:px-3 py-1.5 bg-gray-100 dark:bg-white/5 hover:bg-gray-200 dark:hover:bg-white/10 border border-gray-300 dark:border-white/10 rounded-lg text-xs sm:text-sm text-gray-700 dark:text-gray-300 transition-colors"
        >
          All Ports
        </button>
      </div>

      {/* UDP Warning */}
      {config.scanType === 'udp' && (
        <div className="flex flex-col sm:flex-row items-start gap-2 sm:gap-3 p-3 sm:p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
          <Info className="w-4 h-4 sm:w-5 sm:h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
          <div className="text-xs sm:text-sm text-yellow-700 dark:text-yellow-400">
            <strong>UDP scanning:</strong> May be slow and produce inaccurate results. 
            Some services (e.g., WireGuard) intentionally do not respond to scans. 
            For localhost, additional verification through system data is used.
          </div>
        </div>
      )}

      {/* Scan Button */}
      <button
        onClick={handleScan}
        disabled={progress.status === 'running'}
        className="flex items-center justify-center gap-2 w-full sm:w-auto px-4 sm:px-6 py-2.5 sm:py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 disabled:from-gray-600 disabled:to-gray-700 rounded-lg text-sm sm:text-base text-white font-medium transition-all"
      >
        {progress.status === 'running' ? (
          <>
            <Loader2 className="w-4 h-4 sm:w-5 sm:h-5 animate-spin" />
            Scanning...
          </>
        ) : (
          <>
            <Shield className="w-4 h-4 sm:w-5 sm:h-5" />
            Start Scan
          </>
        )}
      </button>

      {/* Progress */}
      {progress.status === 'running' && (
        <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
          <span>{progress.message}</span>
        </div>
      )}

      {/* Error */}
      {progress.status === 'error' && (
        <div className="p-3 sm:p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-xs sm:text-sm text-red-400">{progress.message}</div>
      )}

      {/* Results */}
      {portScanResult && (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
            <StatCard icon={Shield} label="Open" value={portScanResult.openCount} color="green" />
            <StatCard icon={AlertTriangle} label="Closed" value={portScanResult.closedCount} color="red" />
            <StatCard icon={Shield} label="Filtered" value={portScanResult.filteredCount} color="yellow" />
            <StatCard icon={Shield} label="Scan Time" value={portScanResult.scanTime.toFixed(2)} unit="s" color="purple" />
          </div>

          {/* Export */}
          <div className="flex justify-center sm:justify-end">
            <ExportButtons data={ports} filename={`port-scan-${portScanResult.host}-${Date.now()}`} formats={['json', 'csv']} />
          </div>

          {/* Table */}
          <div className="bg-white/5 backdrop-blur-sm rounded-xl border border-white/10 overflow-hidden">
            <DataTable
              data={ports}
              columns={columns}
              keyExtractor={(port) => `${port.port}-${port.protocol}`}
              emptyMessage="No open ports found"
            />
          </div>
        </div>
      )}
    </div>
  )
}
