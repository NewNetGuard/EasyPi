import SystemStats from './SystemStats'
import QuickActions from './QuickActions'
import PermissionsBanner from './PermissionsBanner'
import RouterSetupCard from './RouterSetupCard'
import OnboardingCard from './OnboardingCard'
import { LayoutDashboard } from 'lucide-react'

const Dashboard = () => {
  return (
    <div className="space-y-4 sm:space-y-6">
      {/* Permissions Banner */}
      <PermissionsBanner />

      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
          <LayoutDashboard className="h-6 w-6 text-primary-600 dark:text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Welcome back! Here's what's happening with your Raspberry Pi.
          </p>
        </div>
      </div>

      {/* Agent-led first-run guide (auto-hides once set up) */}
      <OnboardingCard />

      {/* Router / DNS + gateway setup */}
      <div id="network-protection">
        <RouterSetupCard />
      </div>

      <SystemStats />

      <QuickActions />
    </div>
  )
}

export default Dashboard
