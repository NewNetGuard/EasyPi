import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import SetupWizard from '../setup/SetupWizard'
import { useSystemSetup } from '../../hooks/useSystemSetup'
import { useSidebarStore } from '../../stores/sidebarStore'
import AntiBypassBanner from '../common/AntiBypassBanner'
import FailClosedBanner from '../common/FailClosedBanner'
import AgentPanel from '../../features/agent/AgentPanel'
import UnknownDeviceBanner from '../common/UnknownDeviceBanner'

const Layout = () => {
  const { showWizard, completeSetup, skipSetup } = useSystemSetup()
  const { isOpen, isMobile, close, setMobile } = useSidebarStore()

  // Handle responsive behavior
  useEffect(() => {
    const checkMobile = () => {
      const mobile = window.innerWidth < 1024 // lg breakpoint
      setMobile(mobile)
    }
    
    checkMobile()
    window.addEventListener('resize', checkMobile)
    return () => window.removeEventListener('resize', checkMobile)
  }, [setMobile])

  return (
    <div className="flex h-screen overflow-hidden bg-gray-50 dark:bg-dark-950">
      {/* Setup Wizard */}
      {showWizard && (
        <SetupWizard onComplete={completeSetup} onSkip={skipSetup} />
      )}

      {/* Mobile overlay */}
      {isMobile && isOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden"
          onClick={close}
        />
      )}

      {/* Sidebar */}
      <Sidebar />
      
      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />
        <UnknownDeviceBanner />
        <AntiBypassBanner />
        <FailClosedBanner />
        
        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          <div className="mx-auto max-w-7xl">
            <div className="min-w-0">
              <Outlet />
            </div>
          </div>
        </main>
      </div>
      
      <AgentPanel />
    </div>
  )
}

export default Layout
