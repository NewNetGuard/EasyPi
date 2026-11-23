import React, { useState, useEffect } from 'react'
import { Search, Loader2, Monitor, Smartphone, Printer, Router, Tv, Gamepad2, CircuitBoard, HelpCircle, RefreshCw, Wifi } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { useNetworkToolkitStore } from '../../../stores/networkToolkitStore'
import { scanLAN, getNetworkInfo } from '../../../api/network'
import { DataTable, Column } from '../shared/DataTable'
import { StatCard } from '../shared/StatCard'
import { StatusBadge } from '../shared/StatusBadge'
import { ExportButtons } from '../shared/ExportButtons'
import type { LANDevice, LANScanConfig, ScanSpeed, DeviceType } from '../../../types/network'

const deviceIcons: Record<DeviceType, { icon: React.ElementType; label: string; color: string }> = {
  computer: { icon: Monitor, label: 'Computer', color: 'text-blue-500' },
  phone: { icon: Smartphone, label: 'Phone', color: 'text-green-500' },
  printer: { icon: Printer, label: 'Printer', color: 'text-orange-500' },
  router: { icon: Router, label: 'Router/Gateway', color: 'text-purple-500' },
  tv: { icon: Tv, label: 'TV', color: 'text-red-500' },
  console: { icon: Gamepad2, label: 'Game Console', color: 'text-pink-500' },
  pi: { icon: CircuitBoard, label: 'Raspberry Pi', color: 'text-emerald-500' },
  nas: { icon: Monitor, label: 'NAS', color: 'text-blue-400' },
  sbc: { icon: CircuitBoard, label: 'Single Board', color: 'text-emerald-500' },
  iot: { icon: Wifi, label: 'IoT Device', color: 'text-teal-400' },
  'smart-tv': { icon: Tv, label: 'Smart TV', color: 'text-red-500' },
  'smart-speaker': { icon: Wifi, label: 'Smart Speaker', color: 'text-teal-400' },
  network: { icon: Router, label: 'Network Device', color: 'text-purple-500' },
  gaming: { icon: Gamepad2, label: 'Gaming Device', color: 'text-pink-500' },
  apple: { icon: Smartphone, label: 'Apple Device', color: 'text-green-500' },
  google: { icon: Smartphone, label: 'Google Device', color: 'text-green-500' },
  virtual: { icon: Monitor, label: 'Virtual Machine', color: 'text-blue-400' },
  camera: { icon: Tv, label: 'Camera', color: 'text-red-400' },
  tablet: { icon: Smartphone, label: 'Tablet', color: 'text-green-500' },
  server: { icon: Monitor, label: 'Server', color: 'text-blue-500' },
  media: { icon: Tv, label: 'Media Device', color: 'text-red-500' },
  unknown: { icon: HelpCircle, label: 'Unknown Device', color: 'text-gray-400' },
}

export function LANScanner() {
  const queryClient = useQueryClient()
  const { lanScanResult, setLANScanResult, scanProgress, setScanProgress } = useNetworkToolkitStore()
  
  const [config, setConfig] = useState<LANScanConfig>({
    networkRange: '',
    scanSpeed: 'normal',
    detectVendor: true,
    resolveHostnames: true,
    portDiscovery: true,  // Enabled by default for better device type detection
  })
  
  const [networkInfo, setNetworkInfo] = useState<{
    localIp: string
    gateway: string
    networkRange: string
  } | null>(null)
  const [loadingNetwork, setLoadingNetwork] = useState(true)
  const [expandedPorts, setExpandedPorts] = useState<Set<string>>(new Set())

  // Auto-detect network on mount
  useEffect(() => {
    const detectNetwork = async () => {
      setLoadingNetwork(true)
      try {
        const response = await getNetworkInfo()
        if (response.success && response.data) {
          setNetworkInfo({
            localIp: response.data.localIp,
            gateway: response.data.gateway,
            networkRange: response.data.networkRange,
          })
          setConfig(prev => ({
            ...prev,
            networkRange: response.data!.networkRange,
          }))
        }
      } catch (error) {
        console.error('Failed to detect network:', error)
        // Fallback
        setConfig(prev => ({
          ...prev,
          networkRange: prev.networkRange || '192.168.1.0/24',
        }))
      } finally {
        setLoadingNetwork(false)
      }
    }
    
    detectNetwork()
  }, [])

  const handleRefreshNetwork = async () => {
    setLoadingNetwork(true)
    try {
      const response = await getNetworkInfo()
      if (response.success && response.data) {
        setNetworkInfo({
          localIp: response.data.localIp,
          gateway: response.data.gateway,
          networkRange: response.data.networkRange,
        })
        setConfig(prev => ({
          ...prev,
          networkRange: response.data!.networkRange,
        }))
      }
    } catch (error) {
      console.error('Failed to detect network:', error)
    } finally {
      setLoadingNetwork(false)
    }
  }

  const handleScan = async () => {
    // Validate network range
    if (!config.networkRange || config.networkRange.length < 3) {
      setScanProgress('lan-scanner', { 
        status: 'error', 
        progress: 0, 
        message: 'Please specify network range (e.g.: 192.168.1.0/24)' 
      })
      return
    }

    setScanProgress('lan-scanner', {
      status: 'running',
      progress: 0,
      message: 'Scanning network; exact progress is not reported.',
    })
    
    try {
      const response = await scanLAN(config)
      
      if (response.success && response.data) {
        setLANScanResult(response.data)
        setScanProgress('lan-scanner', { status: 'completed', progress: 100 })
        // Invalidate cached devices so Schedules panel gets updated list
        queryClient.invalidateQueries({ queryKey: ['cachedDevices'] })
      } else {
        setScanProgress('lan-scanner', { status: 'error', progress: 0, message: response.error })
      }
    } catch (error) {
      setScanProgress('lan-scanner', {
        status: 'error',
        progress: 0,
        message: error instanceof Error ? error.message : 'Scan error',
      })
    }
  }

  const columns: Column<LANDevice>[] = [
    {
      key: 'deviceType',
      header: 'Type',
      width: 'w-16',
      render: (_, device) => {
        const deviceInfo = deviceIcons[device.deviceType || 'unknown']
        const Icon = deviceInfo.icon
        return (
          <div className="relative group">
            <Icon className={`w-5 h-5 ${deviceInfo.color} cursor-help`} />
            <div className="absolute left-full ml-2 top-1/2 -translate-y-1/2 z-50 hidden group-hover:block">
              <div className="bg-gray-900 text-white text-xs rounded-lg py-2 px-3 whitespace-nowrap shadow-lg">
                <div className="font-medium">{deviceInfo.label}</div>
                {device.vendor && <div className="text-gray-400 mt-1">{device.vendor}</div>}
                {device.mac && <div className="text-gray-400 font-mono">{device.mac}</div>}
              </div>
            </div>
          </div>
        )
      },
    },
    {
      key: 'ip',
      header: 'IP Address',
      sortable: true,
      render: (value, device) => device.interfaces && device.interfaces.length > 1 ? (
        <div className="space-y-1">
          {device.interfaces.map((item) => (
            <div key={`${item.name}-${item.ip}`}>
              <span>{item.ip}</span>
              <span className="ml-2 text-xs text-gray-500">{item.name}</span>
            </div>
          ))}
        </div>
      ) : value,
    },
    {
      key: 'customName',
      header: 'Custom Name',
      sortable: true,
      render: (value, device) => device.isLocalDevice ? (
        <span className="font-medium text-blue-600 dark:text-blue-400">This EasyPi</span>
      ) : value ? (
        <span title="Saved user name">{value}</span>
      ) : <span className="text-gray-500">—</span>,
    },
    {
      key: 'hostname',
      header: 'Hostname',
      sortable: true,
      render: (value) => value || <span className="text-gray-500">—</span>,
    },
    {
      key: 'mac',
      header: 'MAC Address',
      render: (value, device) => device.interfaces && device.interfaces.length > 1 ? (
        <div className="space-y-1">
          {device.interfaces.map((item) => (
            <code key={`${item.name}-${item.mac}`} className="block text-xs text-blue-600 dark:text-blue-400">{item.mac}</code>
          ))}
        </div>
      ) : value ? <code className="text-xs text-blue-600 dark:text-blue-400">{value}</code> : <span className="text-gray-500">—</span>,
    },
    {
      key: 'vendor',
      header: 'Vendor',
      sortable: true,
      render: (value) => value || <span className="text-gray-500">Unknown</span>,
    },
    {
      key: 'dhcpVendorClass',
      header: 'DHCP Client',
      sortable: true,
      render: (value) => value || <span className="text-gray-500">—</span>,
    },
    ...(config.portDiscovery ? [{
      key: 'ports' as keyof LANDevice,
      header: 'Open Ports',
      render: (value: number[] | undefined, device: LANDevice) => {
        if (!value || value.length === 0) {
          return <span className="text-gray-500">—</span>
        }
        const isExpanded = expandedPorts.has(device.id)
        const portsToShow = isExpanded ? value : value.slice(0, 5)
        const hiddenCount = value.length - 5
        
        return (
          <div className="flex flex-wrap gap-1">
            {portsToShow.map((port) => (
              <span 
                key={port} 
                className="px-1.5 py-0.5 text-xs bg-green-500/20 text-green-700 dark:text-green-400 rounded"
              >
                {port}
              </span>
            ))}
            {hiddenCount > 0 && !isExpanded && (
              <button
                onClick={() => setExpandedPorts(prev => new Set(prev).add(device.id))}
                className="px-1.5 py-0.5 text-xs bg-blue-500/20 text-blue-600 dark:text-blue-400 rounded hover:bg-blue-500/30 transition-colors"
              >
                +{hiddenCount}
              </button>
            )}
            {isExpanded && hiddenCount > 0 && (
              <button
                onClick={() => setExpandedPorts(prev => { const n = new Set(prev); n.delete(device.id); return n; })}
                className="px-1.5 py-0.5 text-xs bg-gray-500/20 text-gray-600 dark:text-gray-400 rounded hover:bg-gray-500/30 transition-colors"
              >
                ↩
              </button>
            )}
          </div>
        )
      },
    }] : []),
    {
      key: 'status',
      header: 'Status',
      render: (value) => <StatusBadge status={value} />,
    },
  ]

  const progress = scanProgress['lan-scanner']
  const devices = lanScanResult?.devices || []

  return (
    <div className="space-y-6">
      {/* Detected Network Info */}
      {networkInfo && (
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4 p-3 sm:p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg overflow-hidden">
          <Wifi className="w-4 h-4 sm:w-5 sm:h-5 text-blue-400 flex-shrink-0" />
          <div className="flex-1 text-xs sm:text-sm min-w-0 w-full">
            <div className="break-words">
              <span className="text-gray-600 dark:text-gray-400">Detected Network: </span>
              <span className="text-gray-900 dark:text-white font-medium">{networkInfo.networkRange}</span>
            </div>
            <div className="break-words mt-1 sm:mt-0">
              <span className="text-gray-500 mx-2 hidden sm:inline">|</span>
              <span className="text-gray-600 dark:text-gray-400">IP: </span>
              <span className="text-gray-900 dark:text-white">{networkInfo.localIp}</span>
            </div>
            <div className="break-words mt-1 sm:mt-0">
              <span className="text-gray-500 mx-2 hidden sm:inline">|</span>
              <span className="text-gray-600 dark:text-gray-400">Gateway: </span>
              <span className="text-gray-900 dark:text-white">{networkInfo.gateway}</span>
            </div>
          </div>
          <button
            onClick={handleRefreshNetwork}
            disabled={loadingNetwork}
            className="p-1.5 hover:bg-white/10 rounded transition-colors self-end sm:self-auto flex-shrink-0"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 text-blue-400 ${loadingNetwork ? 'animate-spin' : ''}`} />
          </button>
        </div>
      )}

      {loadingNetwork && !networkInfo && (
        <div className="flex items-center gap-2 p-3 sm:p-4 bg-gray-500/10 border border-gray-500/20 rounded-lg">
          <Loader2 className="w-4 h-4 sm:w-5 sm:h-5 text-gray-400 animate-spin" />
          <span className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Detecting network...</span>
        </div>
      )}

      {/* Configuration */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Network Range</label>
          <input
            type="text"
            value={config.networkRange}
            onChange={(e) => setConfig({ ...config, networkRange: e.target.value })}
            placeholder="192.168.1.0/24"
            className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-white/5 border border-gray-300 dark:border-white/10 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Scan Speed</label>
          <select
            value={config.scanSpeed}
            onChange={(e) => setConfig({ ...config, scanSpeed: e.target.value as ScanSpeed })}
            className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-dark-800 border border-gray-300 dark:border-dark-600 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="fast">Fast</option>
            <option value="normal">Normal</option>
            <option value="deep">Deep</option>
          </select>
        </div>
      </div>

      {/* Options */}
      <div className="flex flex-wrap gap-3 sm:gap-4">
        <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            checked={config.detectVendor}
            onChange={(e) => setConfig({ ...config, detectVendor: e.target.checked })}
            className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
          />
          Detect Vendor
        </label>
        <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            checked={config.resolveHostnames}
            onChange={(e) => setConfig({ ...config, resolveHostnames: e.target.checked })}
            className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
          />
          Resolve Hostnames
        </label>
        <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            checked={config.portDiscovery}
            onChange={(e) => setConfig({ ...config, portDiscovery: e.target.checked })}
            className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
          />
          Discover Open Ports
        </label>
      </div>

      {/* Scan Button */}
      <button
        onClick={handleScan}
        disabled={progress.status === 'running' || loadingNetwork || !config.networkRange}
        className="flex items-center justify-center gap-2 w-full sm:w-auto px-4 sm:px-6 py-2.5 sm:py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 disabled:from-gray-600 disabled:to-gray-700 disabled:cursor-not-allowed rounded-lg text-sm sm:text-base text-white font-medium transition-all"
      >
        {progress.status === 'running' ? (
          <>
            <Loader2 className="w-4 h-4 sm:w-5 sm:h-5 animate-spin" />
            Scanning...
          </>
        ) : (
          <>
            <Search className="w-4 h-4 sm:w-5 sm:h-5" />
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
      {lanScanResult && (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
            <StatCard icon={Monitor} label="Total Devices" value={devices.length} color="blue" />
            <StatCard
              icon={Monitor}
              label="Online"
              value={devices.filter((d) => d.status === 'online').length}
              color="green"
            />
            <StatCard icon={Search} label="Scan Time" value={lanScanResult.scanTime.toFixed(2)} unit="s" color="purple" />
            <StatCard icon={Router} label="Network" value={lanScanResult.networkRange.split('/')[0]} color="yellow" />
          </div>

          {/* Export */}
          <div className="flex justify-center sm:justify-end">
            <ExportButtons data={devices} filename={`lan-scan-${Date.now()}`} formats={['json', 'csv']} />
          </div>

          {/* Table */}
          <div className="bg-white/5 backdrop-blur-sm rounded-xl border border-white/10 overflow-hidden">
            <DataTable data={devices} columns={columns} keyExtractor={(device) => device.id} emptyMessage="No devices found" />
          </div>
        </div>
      )}
    </div>
  )
}
