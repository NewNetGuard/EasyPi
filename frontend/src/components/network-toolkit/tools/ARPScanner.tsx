import { Wifi, Loader2, RefreshCw } from 'lucide-react'
import { useNetworkToolkitStore } from '../../../stores/networkToolkitStore'
import { scanARP } from '../../../api/network'
import { DataTable, Column } from '../shared/DataTable'
import { StatCard } from '../shared/StatCard'
import { ExportButtons } from '../shared/ExportButtons'
import type { ARPEntry } from '../../../types/network'

export function ARPScanner() {
  const { arpScanResult, setARPScanResult, scanProgress, setScanProgress } = useNetworkToolkitStore()

  const handleScan = async () => {
    setScanProgress('arp-scanner', { status: 'running', progress: 0, message: 'Scanning ARP table...' })
    
    try {
      const response = await scanARP()
      
      if (response.success && response.data) {
        setARPScanResult(response.data)
        setScanProgress('arp-scanner', { status: 'completed', progress: 100 })
      } else {
        setScanProgress('arp-scanner', { status: 'error', progress: 0, message: response.error })
      }
    } catch (error) {
      setScanProgress('arp-scanner', {
        status: 'error',
        progress: 0,
        message: error instanceof Error ? error.message : 'ARP scan error',
      })
    }
  }

  const columns: Column<ARPEntry>[] = [
    {
      key: 'ip',
      header: 'IP Address',
      sortable: true,
      render: (value) => <code className="text-blue-400">{value}</code>,
    },
    {
      key: 'mac',
      header: 'MAC Address',
      sortable: true,
      render: (value) => <code className="text-gray-300 text-xs">{value}</code>,
    },
    {
      key: 'vendor',
      header: 'Vendor',
      sortable: true,
      render: (value) => value || <span className="text-gray-500">Unknown</span>,
    },
    {
      key: 'interface',
      header: 'Interface',
      render: (value) => <span className="text-gray-400 text-sm">{value}</span>,
    },
    {
      key: 'type',
      header: 'Type',
      render: (value) => (
        <span
          className={`px-2 py-1 rounded-full text-xs ${
            value === 'static' ? 'bg-purple-500/10 text-purple-400' : 'bg-blue-500/10 text-blue-400'
          }`}
        >
          {value === 'static' ? 'Static' : 'Dynamic'}
        </span>
      ),
    },
    {
      key: 'state',
      header: 'Status',
      render: (value) => {
        if (!value) return <span className="text-gray-500">-</span>
        const statusMap: Record<string, { label: string; color: string }> = {
          REACHABLE: { label: 'Active', color: 'bg-green-500/10 text-green-400' },
          STALE: { label: 'Cached', color: 'bg-yellow-500/10 text-yellow-400' },
          DELAY: { label: 'Verifying', color: 'bg-blue-500/10 text-blue-400' },
          PROBE: { label: 'Probing', color: 'bg-purple-500/10 text-purple-400' },
        }
        const status = statusMap[value] || { label: value, color: 'bg-gray-500/10 text-gray-400' }
        return (
          <span className={`px-2 py-1 rounded-full text-xs ${status.color}`}>
            {status.label}
          </span>
        )
      },
    },
  ]

  const progress = scanProgress['arp-scanner']
  const entries = arpScanResult?.entries || []
  const staticCount = entries.filter((e) => e.type === 'static').length
  const dynamicCount = entries.filter((e) => e.type === 'dynamic').length
  const reachableCount = entries.filter((e) => e.state === 'REACHABLE').length

  return (
    <div className="space-y-6">
      {/* Info */}
      <div className="p-3 sm:p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400 text-xs sm:text-sm">
        <p className="font-medium mb-1">What is ARP scanning?</p>
        <p className="text-blue-300/80">
          ARP (Address Resolution Protocol) scanning shows the mapping table of IP and MAC addresses in the local
          network. This is useful for discovering new devices and monitoring network activity.
        </p>
        
        {/* Status Legend */}
        <div className="mt-3 pt-3 border-t border-blue-500/20">
          <p className="font-medium mb-2 text-blue-400">Status Legend:</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded-full bg-green-500/10 text-green-400">Active</span>
              <span className="text-blue-300/70">Device responds</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded-full bg-yellow-500/10 text-yellow-400">Cached</span>
              <span className="text-blue-300/70">Entry in cache</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400">Verifying</span>
              <span className="text-blue-300/70">Awaiting confirmation</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400">Probing</span>
              <span className="text-blue-300/70">Sending probe requests</span>
            </div>
          </div>
        </div>
      </div>

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
            <RefreshCw className="w-4 h-4 sm:w-5 sm:h-5" />
            Scan ARP Table
          </>
        )}
      </button>

      {/* Progress */}
      {progress.status === 'running' && (
        <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
          <span>Scanning the ARP table; exact progress is not reported.</span>
        </div>
      )}

      {/* Error */}
      {progress.status === 'error' && (
        <div className="p-3 sm:p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-xs sm:text-sm text-red-400">{progress.message}</div>
      )}

      {/* Results */}
      {arpScanResult && (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
            <StatCard icon={Wifi} label="Total Entries" value={entries.length} color="blue" />
            <StatCard icon={Wifi} label="Static" value={staticCount} color="purple" />
            <StatCard icon={Wifi} label="Dynamic" value={dynamicCount} color="green" />
            <StatCard icon={Wifi} label="Reachable" value={reachableCount} color="yellow" />
          </div>

          {/* Export */}
          <div className="flex justify-center sm:justify-end">
            <ExportButtons data={entries} filename={`arp-scan-${Date.now()}`} formats={['json', 'csv']} />
          </div>

          {/* Table */}
          <div className="bg-white/5 backdrop-blur-sm rounded-xl border border-white/10 overflow-hidden">
            <DataTable data={entries} columns={columns} keyExtractor={(entry) => entry.id} emptyMessage="No ARP entries found" />
          </div>
        </div>
      )}
    </div>
  )
}
