import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useNetworkToolkitStore } from '../stores/networkToolkitStore'
import type { ToolId } from '../types/network'

// Components
import NetworkSidebar from '../components/network-toolkit/NetworkSidebar'
import { LANScanner } from '../components/network-toolkit/tools/LANScanner'
import { PortScanner } from '../components/network-toolkit/tools/PortScanner'
import { SpeedTest } from '../components/network-toolkit/tools/SpeedTest'
import { TrafficGraph } from '../components/network-toolkit/tools/TrafficGraph'
import { ActiveConnections } from '../components/network-toolkit/tools/ActiveConnections'
import { ARPScanner } from '../components/network-toolkit/tools/ARPScanner'
import { OpenPortsAlert } from '../components/network-toolkit/tools/OpenPortsAlert'
import { Network, Wifi, Menu, X } from 'lucide-react'

const availableTools: readonly ToolId[] = [
  'lan-scanner',
  'port-scanner',
  'speed-test',
  'traffic-graph',
  'active-connections',
  'arp-scanner',
  'open-ports-alert',
]

export default function NetworkToolkit() {
  const { activeTool, setActiveTool } = useNetworkToolkitStore()
  const [searchParams, setSearchParams] = useSearchParams()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  useEffect(() => {
    const requestedTool = searchParams.get('tab') as ToolId | null
    if (requestedTool && availableTools.includes(requestedTool) && requestedTool !== activeTool) {
      setActiveTool(requestedTool)
      return
    }
    if ((!requestedTool || !availableTools.includes(requestedTool)) && activeTool) {
      const nextParams = new URLSearchParams(searchParams)
      nextParams.set('tab', activeTool)
      setSearchParams(nextParams, { replace: true })
    }
  }, [activeTool, searchParams, setActiveTool, setSearchParams])

  const selectTool = (tool: ToolId) => {
    const nextParams = new URLSearchParams(searchParams)
    nextParams.set('tab', tool)
    setSearchParams(nextParams, { replace: true })
  }

  const renderToolContent = () => {
    switch (activeTool) {
      case 'lan-scanner':
        return <LANScanner />
      case 'port-scanner':
        return <PortScanner />
      case 'speed-test':
        return <SpeedTest />
      case 'traffic-graph':
        return <TrafficGraph />
      case 'active-connections':
        return <ActiveConnections />
      case 'arp-scanner':
        return <ARPScanner />
      case 'open-ports-alert':
        return <OpenPortsAlert />
      default:
        return null
    }
  }

  const getToolTitle = () => {
    switch (activeTool) {
      case 'lan-scanner':
        return 'LAN Scanner'
      case 'port-scanner':
        return 'Port Scanner'
      case 'speed-test':
        return 'Speed Test'
      case 'traffic-graph':
        return 'Traffic Graph'
      case 'active-connections':
        return 'Active Connections'
      case 'arp-scanner':
        return 'ARP Scanner'
      case 'open-ports-alert':
        return 'Port Alerts'
      default:
        return 'Network Toolkit'
    }
  }

  const getToolDescription = () => {
    switch (activeTool) {
      case 'lan-scanner':
        return 'Discover and analyze devices on your local network'
      case 'port-scanner':
        return 'Scan and analyze open ports on network devices'
      case 'speed-test':
        return 'Test your internet connection speed and latency'
      case 'traffic-graph':
        return 'Monitor real-time network traffic statistics'
      case 'active-connections':
        return 'View and manage active network connections'
      case 'arp-scanner':
        return 'Scan and display ARP table entries'
      case 'open-ports-alert':
        return 'Monitor and alert on suspicious open ports'
      default:
        return 'Select a tool from the sidebar to get started'
    }
  }

  return (
    <div className="flex h-screen overflow-hidden bg-gray-50 dark:bg-dark-950">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      
      {/* Sidebar */}
      <div className={`
        fixed lg:static inset-y-0 left-0 z-50 
        transform transition-transform duration-300 ease-in-out
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        <NetworkSidebar
          onItemClick={() => setSidebarOpen(false)}
          onToolSelect={selectTool}
        />
      </div>

      {/* Main Content */}
      <main className="flex flex-1 flex-col overflow-hidden">
        {/* Header */}
        <header className="border-b border-gray-200 dark:border-dark-800 bg-white dark:bg-dark-900 px-3 sm:px-6 py-3 sm:py-4">
          {/* Mobile menu button */}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="lg:hidden p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-800 mb-3"
          >
            {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
          
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
                <Wifi className="h-6 w-6 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <h1 className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white">{getToolTitle()}</h1>
                <p className="text-xs sm:text-sm text-gray-500 dark:text-gray-400">{getToolDescription()}</p>
              </div>
            </div>
          </div>
        </header>

        {/* Tool Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTool ? (
            renderToolContent()
          ) : (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Network className="w-20 h-20 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                  Welcome to Network Toolkit
                </h2>
                <p className="text-gray-500 dark:text-gray-400 max-w-md">
                  Select a tool from the sidebar to start monitoring and analyzing your network
                </p>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
