import { Activity, Network, Gauge, TrendingUp, Radio, Shield, AlertTriangle } from 'lucide-react'
import { useNetworkToolkitStore } from '../../stores/networkToolkitStore'
import type { ToolId } from '../../types/network'

const tools = [
  { id: 'lan-scanner' as ToolId, name: 'LAN Scanner', icon: Network, description: 'Scan network devices' },
  { id: 'port-scanner' as ToolId, name: 'Port Scanner', icon: Shield, description: 'Check open ports' },
  { id: 'speed-test' as ToolId, name: 'Speed Test', icon: Gauge, description: 'Test internet speed' },
  { id: 'traffic-graph' as ToolId, name: 'Traffic Graph', icon: TrendingUp, description: 'Monitor traffic' },
  { id: 'active-connections' as ToolId, name: 'Active Connections', icon: Activity, description: 'View connections' },
  { id: 'arp-scanner' as ToolId, name: 'ARP Scanner', icon: Radio, description: 'Scan ARP table' },
  { id: 'open-ports-alert' as ToolId, name: 'Port Alerts', icon: AlertTriangle, description: 'Security alerts' },
]

interface NetworkSidebarProps {
  onItemClick?: () => void
  onToolSelect?: (toolId: ToolId) => void
}

export default function NetworkSidebar({ onItemClick, onToolSelect }: NetworkSidebarProps = {}) {
  const { activeTool, setActiveTool } = useNetworkToolkitStore()

  const handleToolClick = (toolId: ToolId) => {
    setActiveTool(toolId)
    onToolSelect?.(toolId)
    onItemClick?.()
  }

  return (
    <aside className="w-64 bg-white dark:bg-dark-900 border-r border-gray-200 dark:border-dark-800 flex flex-col">
      {/* Header */}
      <div className="p-6 border-b border-gray-200 dark:border-dark-800">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-lg">
            <Network className="w-6 h-6 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-gray-900 dark:text-white">Network Toolkit</h2>
            <p className="text-xs text-gray-500 dark:text-gray-400">Monitoring & Analysis</p>
          </div>
        </div>
      </div>

      {/* Tools Navigation */}
      <nav className="flex-1 overflow-y-auto p-4">
        <div className="space-y-1">
          {tools.map((tool) => {
            const Icon = tool.icon
            const isActive = activeTool === tool.id

            return (
              <button
                key={tool.id}
                onClick={() => handleToolClick(tool.id)}
                className={`w-full flex items-start gap-3 p-3 rounded-lg transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white shadow-lg shadow-blue-500/20'
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-800'
                }`}
              >
                <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${isActive ? 'text-white' : 'text-gray-500 dark:text-gray-400'}`} />
                <div className="flex-1 text-left">
                  <div className={`font-medium text-sm ${isActive ? 'text-white' : 'text-gray-900 dark:text-white'}`}>
                    {tool.name}
                  </div>
                  <div className={`text-xs mt-0.5 ${isActive ? 'text-blue-100' : 'text-gray-500 dark:text-gray-400'}`}>
                    {tool.description}
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      </nav>
    </aside>
  )
}
