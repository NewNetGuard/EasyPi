import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Activity,
  Terminal,
  FolderOpen,
  Database,
  ClipboardList,
  BellRing,
  RotateCcw,
  Shield,
  Radar,
  ShoppingBag,
  Bot,
  Settings,
  Cloud,
  Wifi,
  Box,
  Plug,
  LifeBuoy,
  Video,
  Radio,
  Globe,
  Server,
  Users,
  Lock,
  EyeOff,
  Smartphone,
  X
} from 'lucide-react'
import clsx from 'clsx'
import { useSidebarStore } from '../../stores/sidebarStore'
import { useAuthStore } from '../../stores/authStore'
import { useQuery } from '@tanstack/react-query'
import { getApiBaseUrl } from '../../utils/apiBase'

const API_BASE = getApiBaseUrl()

const Sidebar = () => {
  const { isOpen, isMobile, close } = useSidebarStore()
  const { user, isAuthenticated } = useAuthStore()
  
  // Get user display info
  const username = user?.username || 'User'
  const email = user?.email || ''
  const initial = username.charAt(0).toUpperCase()
  
  // Fetch user avatar - uses httpOnly cookies for auth
  const { data: avatarUrl } = useQuery({
    queryKey: ['user-avatar-sidebar', user?.id],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/api/v1/auth/avatar`, {
        credentials: 'include',  // Send httpOnly cookies
      })
      if (res.ok && res.status !== 204) {
        const blob = await res.blob()
        return URL.createObjectURL(blob)
      }
      return null
    },
    enabled: isAuthenticated,
    retry: false,
    staleTime: 60000,
  })
  
  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    { name: 'Setup', href: '/setup', icon: Plug },
    { name: 'VPN', href: '/vpn', icon: Shield },
    { name: 'Personal DNS', href: '/dns', icon: Server },
    { name: 'Guard Security', href: '/guard', icon: Radar },
    { name: 'Remote Access', href: '/remote-access', icon: Globe },
    { name: 'Internet Encryption', href: '/internet-encryption', icon: Lock },
    { name: 'Stealth', href: '/stealth', icon: EyeOff },
    { name: 'Monitoring', href: '/monitoring', icon: Activity },
    { name: 'Network Toolkit', href: '/network', icon: Wifi },
    { name: 'Network Activity', href: '/network-activity', icon: Radio },
    { name: 'Cloud', href: '/cloud', icon: Box },
    { name: 'Terminal', href: '/terminal', icon: Terminal },
    { name: 'Files', href: '/files', icon: FolderOpen },
    { name: 'Backup', href: '/backup', icon: Database },
    { name: 'Jobs', href: '/jobs', icon: ClipboardList },
    { name: 'Notifications', href: '/notifications', icon: BellRing },
    { name: 'Rollback', href: '/rollback', icon: RotateCcw },
    { name: 'Security', href: '/security', icon: Cloud },
    { name: 'IP Cameras', href: '/devices', icon: Video },
    { name: 'Marketplace', href: '/marketplace', icon: ShoppingBag },
    { name: 'AI Chat', href: '/ai', icon: Bot },
    { name: 'Mobile Assistant', href: '/mobile', icon: Smartphone },
    { name: 'Help & Support', href: '/help', icon: LifeBuoy },
    { name: 'Users', href: '/users', icon: Users },
    { name: 'Settings', href: '/settings', icon: Settings },
  ]

  // Handle link click on mobile - close sidebar
  const handleLinkClick = () => {
    if (isMobile) {
      close()
    }
  }

  return (
    <aside 
      className={clsx(
        'flex flex-col border-r border-gray-200 dark:border-dark-800 bg-white dark:bg-dark-900',
        'transition-all duration-300 ease-in-out',
        // Desktop: always visible, fixed width
        'lg:relative lg:translate-x-0 lg:w-64',
        // Mobile: overlay style
        'fixed inset-y-0 left-0 z-50 w-72',
        isMobile && !isOpen && '-translate-x-full',
        isMobile && isOpen && 'translate-x-0 shadow-2xl'
      )}
    >
      {/* Logo */}
      <div className="flex h-16 items-center justify-between border-b border-gray-200 dark:border-dark-800 px-4 lg:px-6">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 flex-col items-center justify-center rounded-xl bg-gradient-to-br from-[#0c1445] via-[#0c1445] to-red-500">
            <span className="text-[10px] font-bold text-white leading-none tracking-wide">Easy</span>
            <span className="text-lg font-serif text-red-500 leading-none -mt-0.5">π</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900 dark:text-white">
              EasyPi
            </h1>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              v{__APP_VERSION__}
            </p>
          </div>
        </div>
        
        {/* Close button - mobile only */}
        {isMobile && (
          <button
            onClick={close}
            className="p-2 rounded-lg text-gray-500 hover:text-gray-700 hover:bg-gray-100 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:bg-dark-800 lg:hidden"
          >
            <X className="h-5 w-5" />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 overflow-y-auto p-3 lg:p-4">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            onClick={handleLinkClick}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-400'
                  : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-800'
              )
            }
          >
            <item.icon className="h-5 w-5 flex-shrink-0" />
            <span className="truncate">{item.name}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-gray-200 dark:border-dark-800 p-3 lg:p-4">
        <div className="flex items-center gap-3 rounded-lg bg-gray-50 dark:bg-dark-800 p-3">
          {avatarUrl ? (
            <img 
              src={avatarUrl} 
              alt="Avatar" 
              className="h-10 w-10 rounded-full object-cover flex-shrink-0"
            />
          ) : (
            <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-primary-600 text-white font-semibold">
              {initial}
            </div>
          )}
          <div className="flex-1 min-w-0">
            <p className="truncate text-sm font-medium text-gray-900 dark:text-white">
              {username}
            </p>
            {email && <p className="truncate text-xs text-gray-500 dark:text-gray-400">{email}</p>}
          </div>
        </div>
      </div>
    </aside>
  )
}

export default Sidebar
