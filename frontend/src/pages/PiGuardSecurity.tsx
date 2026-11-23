import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Radar, Activity, List, Lock, Search, Users, AlertTriangle, BarChart3, Settings as SettingsIcon, Wrench, Eye, Brain, Shield, Calendar, Monitor, Target, Hourglass, ShieldOff } from 'lucide-react'
import SecurityDashboard from '../components/security/SecurityDashboard'
import BlockedAllowedPanel from '../components/security/BlockedAllowedPanel'
import AdBlockingPanel from '../components/security/AdBlockingPanel'
import AdTrackerPanel from '../components/security/AdTrackerPanel'
import NrdPanel from '../components/security/NrdPanel'
import ListManager from '../components/security/ListManager'
import FirewallPanel from '../components/security/FirewallPanel'
import QueryLog from '../components/security/QueryLog'
import ParentalControls from '../components/security/ParentalControls'
import SecurityMonitor from '../components/security/SecurityMonitor'
import Statistics from '../components/security/Statistics'
import DNSSettings from '../components/security/DNSSettings'
import AdvancedSettings from '../components/security/AdvancedSettings'
import HeuristicsDashboard from '../components/HeuristicsDashboard'
import ShadowModePanel from '../components/security/ShadowModePanel'
import SchedulesPanel from '../components/security/SchedulesPanel'
import DevicesPanel from '../components/security/DevicesPanel'

type SecurityTab =
  | 'dashboard'
  | 'blocked-allowed'
  | 'ad-tracker'
  | 'nrd'
  | 'shadow-mode'
  | 'heuristics'
  | 'schedules'
  | 'devices'
  | 'ad-blocking'
  | 'lists'
  | 'firewall'
  | 'query-log'
  | 'parental'
  | 'security'
  | 'statistics'
  | 'dns'
  | 'advanced'

const tabs: { id: SecurityTab; label: string; icon: any }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: Shield },
  { id: 'blocked-allowed', label: 'Blocked & Allowed', icon: ShieldOff },
  { id: 'ad-tracker', label: 'Ad/Tracker AI', icon: Target },
  { id: 'nrd', label: 'New Domains', icon: Hourglass },
  { id: 'shadow-mode', label: 'Shadow Mode', icon: Eye },
  { id: 'heuristics', label: 'AI Engine', icon: Brain },
  { id: 'parental', label: 'Parental Controls', icon: Users },
  { id: 'schedules', label: 'Schedules', icon: Calendar },
  { id: 'devices', label: 'Devices', icon: Monitor },
  { id: 'ad-blocking', label: 'Ad Blocking', icon: Activity },
  { id: 'lists', label: 'Lists', icon: List },
  { id: 'firewall', label: 'Firewall', icon: Lock },
  { id: 'query-log', label: 'Query Log', icon: Search },
  { id: 'security', label: 'Security Monitor', icon: AlertTriangle },
  { id: 'statistics', label: 'Statistics', icon: BarChart3 },
  { id: 'dns', label: 'DNS Settings', icon: SettingsIcon },
  { id: 'advanced', label: 'Advanced', icon: Wrench },
]

export default function PiGuardSecurity() {
  const [activeTab, setActiveTab] = useState<SecurityTab>('dashboard')
  const [searchParams, setSearchParams] = useSearchParams()

  useEffect(() => {
    const tabParam = searchParams.get('tab') as SecurityTab | null
    if (tabParam && tabs.some((t) => t.id === tabParam) && tabParam !== activeTab) {
      setActiveTab(tabParam)
    }
  }, [searchParams, activeTab])

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <SecurityDashboard />
      case 'blocked-allowed':
        return <BlockedAllowedPanel />
      case 'ad-tracker':
        return <AdTrackerPanel />
      case 'nrd':
        return <NrdPanel />
      case 'shadow-mode':
        return <ShadowModePanel />
      case 'heuristics':
        return <HeuristicsDashboard />
      case 'schedules':
        return <SchedulesPanel />
      case 'devices':
        return <DevicesPanel />
      case 'ad-blocking':
        return <AdBlockingPanel />
      case 'lists':
        return <ListManager />
      case 'firewall':
        return <FirewallPanel />
      case 'query-log':
        return <QueryLog />
      case 'parental':
        return <ParentalControls />
      case 'security':
        return <SecurityMonitor />
      case 'statistics':
        return <Statistics />
      case 'dns':
        return <DNSSettings />
      case 'advanced':
        return <AdvancedSettings />
      default:
        return <SecurityDashboard />
    }
  }

  const handleTabChange = (tab: SecurityTab) => {
    setActiveTab(tab)
    const next = new URLSearchParams(searchParams)
    next.set('tab', tab)
    setSearchParams(next)
  }

  return (
    <div className="h-screen flex flex-col bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="flex-none bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="px-3 sm:px-6 py-3 sm:py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2 sm:gap-3">
                <Radar className="w-6 h-6 sm:w-8 sm:h-8 text-blue-500" />
                Guard Security
              </h1>
              <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 mt-1">
                Powered by NetProtection DNS Engine
              </p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="px-2 sm:px-6 flex gap-0.5 sm:gap-1 overflow-x-auto">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => handleTabChange(id as SecurityTab)}
              className={`
                flex items-center gap-1 sm:gap-2 px-2 sm:px-4 py-2 sm:py-3 border-b-2 transition-colors whitespace-nowrap
                ${
                  activeTab === id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-500/10'
                    : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700/50'
                }
              `}
            >
              <Icon className="w-4 h-4" />
              <span className="text-xs sm:text-sm font-medium">{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        <div className="p-3 sm:p-6">
          {renderContent()}
        </div>
      </div>
    </div>
  )
}
