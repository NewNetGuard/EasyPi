import { Suspense, lazy, type ReactNode } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import ProtectedRoute from './components/auth/ProtectedRoute'
import Login from './pages/Login'
import PWAInstallPrompt from './components/pwa/PWAInstallPrompt'
import ServerErrorBanner from './components/common/ServerErrorBanner'

const SetupPage = lazy(() => import('./pages/Setup'))
const DashboardPage = lazy(() => import('./components/dashboard/Dashboard'))
const MonitoringDashboardPage = lazy(() => import('./components/monitoring/MonitoringDashboard'))
const TerminalPage = lazy(() => import('./components/terminal/Terminal'))
const FileManagerPage = lazy(() => import('./pages/files/FileManager'))
const BackupPage = lazy(() => import('./pages/Backup'))
const JobsPage = lazy(() => import('./pages/Jobs'))
const NotificationsPage = lazy(() => import('./pages/Notifications'))
const RollbackPage = lazy(() => import('./pages/Rollback'))
const SecurityPage = lazy(() => import('./pages/Security'))
const MarketplacePage = lazy(() => import('./components/marketplace/Marketplace'))
const AIAssistantPage = lazy(() => import('./pages/AIAssistant'))
const SettingsPage = lazy(() => import('./components/settings/Settings'))
const VPNPage = lazy(() => import('./pages/VPN'))
const InternetEncryptionPage = lazy(() => import('./pages/InternetEncryption'))
const StealthPage = lazy(() => import('./pages/Stealth'))
const PersonalDNSPage = lazy(() => import('./pages/PersonalDNS'))
const NetworkToolkitPage = lazy(() => import('./pages/NetworkToolkit'))
const NetworkActivityPage = lazy(() => import('./pages/NetworkActivity'))
const CloudPage = lazy(() => import('./pages/Cloud'))
const GuardSecurityPage = lazy(() => import('./pages/PiGuardSecurity'))
const HelpPage = lazy(() => import('./pages/Help'))
const SecurityCamerasPage = lazy(() => import('./pages/SecurityCameras'))
const RemoteAccessPage = lazy(() => import('./pages/RemoteAccess'))
const UsersPage = lazy(() => import('./pages/Users'))
const MobileAssistantPage = lazy(() => import('./pages/MobileAssistant'))

function RouteLoader() {
  return (
    <div className="flex min-h-[40vh] items-center justify-center">
      <div className="rounded-full border-2 border-slate-700 border-t-slate-300 h-10 w-10 animate-spin" aria-label="Loading page" />
    </div>
  )
}

function routeElement(element: ReactNode) {
  return <Suspense fallback={<RouteLoader />}>{element}</Suspense>
}

function App() {
  return (
    <>
      <Routes>
        {/* Public route */}
        <Route path="/login" element={<Login />} />
      
      {/* Protected routes */}
      <Route path="/" element={
        <ProtectedRoute>
          <Layout />
        </ProtectedRoute>
      }>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="setup" element={routeElement(<SetupPage />)} />
        <Route path="dashboard" element={routeElement(<DashboardPage />)} />
        <Route path="monitoring" element={routeElement(<MonitoringDashboardPage />)} />
        <Route path="network" element={routeElement(<NetworkToolkitPage />)} />
        <Route path="network-activity" element={routeElement(<NetworkActivityPage />)} />
        <Route path="cloud" element={routeElement(<CloudPage />)} />
        <Route path="picloud" element={<Navigate to="/cloud" replace />} />
        <Route path="guard" element={routeElement(<GuardSecurityPage />)} />
        <Route path="piguard" element={<Navigate to="/guard" replace />} />
        <Route path="netprotection" element={<Navigate to="/guard" replace />} />
        <Route path="terminal" element={routeElement(<TerminalPage />)} />
        <Route path="files" element={routeElement(<FileManagerPage />)} />
        <Route path="backup" element={routeElement(<BackupPage />)} />
        <Route path="jobs" element={routeElement(<JobsPage />)} />
        <Route path="notifications" element={routeElement(<NotificationsPage />)} />
        <Route path="rollback" element={routeElement(<RollbackPage />)} />
        <Route path="security" element={routeElement(<SecurityPage />)} />
        <Route path="devices" element={routeElement(<SecurityCamerasPage />)} />
        <Route path="marketplace" element={routeElement(<MarketplacePage />)} />
        <Route path="ai" element={routeElement(<AIAssistantPage />)} />
        <Route path="vpn" element={routeElement(<VPNPage />)} />
        <Route path="internet-encryption" element={routeElement(<InternetEncryptionPage />)} />
        <Route path="stealth" element={routeElement(<StealthPage />)} />
        <Route path="dns" element={routeElement(<PersonalDNSPage />)} />
        <Route path="remote-access" element={routeElement(<RemoteAccessPage />)} />
        <Route path="users" element={routeElement(<UsersPage />)} />
        <Route path="mobile" element={routeElement(<MobileAssistantPage />)} />
        <Route path="settings" element={routeElement(<SettingsPage />)} />
        <Route path="help" element={routeElement(<HelpPage />)} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
    
    {/* PWA Install Prompt */}
    <PWAInstallPrompt />
    
    {/* Server Error Banner */}
    <ServerErrorBanner />
  </>
  )
}

export default App
