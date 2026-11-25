
import { useState, useEffect } from 'react'
import { Heart, Menu, Moon, Sun, Settings, LogOut } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import Button from '../common/Button'
import Tooltip from '../common/Tooltip'
import { getApiBaseUrl } from '../../utils/apiBase'
import { useAuthStore } from '../../stores/authStore'
import { useSidebarStore } from '../../stores/sidebarStore'
import api from '../../api/client'
import HeaderAgentActions from '../../features/agent/HeaderAgentActions'

const API_BASE = getApiBaseUrl()
// The donation banner appears only when a build sets VITE_DONATE_URL to an
// https:// address; there is no built-in default.
const configuredDonateUrl = (import.meta.env.VITE_DONATE_URL || '').trim()
const DONATE_URL = configuredDonateUrl.startsWith('https://') ? configuredDonateUrl : ''
const DONATE_MESSAGE = 'Like EasyPi? Help keep the project alive'

const Header = () => {
  const navigate = useNavigate()
  const { user, isAuthenticated, logout } = useAuthStore()
  const { toggle, isMobile } = useSidebarStore()
  
  // Handle logout - call API to clear cookies, then clear store
  const handleLogout = async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      // Ignore errors - still logout locally
    }
    logout()
    navigate('/login')
  }
  
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return localStorage.getItem('theme') as 'light' | 'dark' || 'dark'
  })

  // Apply theme on mount and when theme changes
  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [theme])

  // Fetch system info for Pi model
  const { data: systemInfo } = useQuery({
    queryKey: ['system-info'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/api/system/info`, {
        credentials: 'include',  // Send httpOnly cookies (endpoint requires auth)
      })
      if (!res.ok) return null
      return res.json()
    },
    staleTime: 60000, // Cache for 1 minute
  })

  // Fetch user avatar - uses httpOnly cookies for auth
  const { data: avatarUrl } = useQuery({
    queryKey: ['user-avatar-header', user?.id],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/api/v1/auth/avatar`, {
        credentials: 'include',  // Send httpOnly cookies
      })
      // Backend always returns valid PNG
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

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light'
    setTheme(newTheme)
    localStorage.setItem('theme', newTheme)
  }

  const getInitial = () => {
    if (user?.username) {
      return user.username.charAt(0).toUpperCase()
    }
    return 'A'
  }

  const getPiModelDisplay = () => {
    if (systemInfo?.pi_model) {
      // Clean up model name - remove null bytes and extra text
      const model = systemInfo.pi_model.replace(/\0/g, '').trim()
      // Extract just "Raspberry Pi X" part
      const match = model.match(/Raspberry Pi \d+/i)
      return match ? match[0] : model.split(' ').slice(0, 3).join(' ')
    }
    return systemInfo?.is_raspberry_pi ? 'Raspberry Pi' : 'EasyPi Server'
  }

  return (
    <header className="border-b border-gray-200 dark:border-dark-800 bg-white dark:bg-dark-900">
      {/* Donation banner, only when a donation address is configured */}
      {DONATE_URL && (
      <div className="w-full border-b border-rose-200/70 dark:border-rose-900/40 bg-gradient-to-r from-rose-50 via-amber-50 to-rose-50 dark:from-rose-900/20 dark:via-amber-900/10 dark:to-rose-900/20">
        <div className="mx-auto max-w-7xl px-4 lg:px-6 py-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Heart className="h-4 w-4 text-rose-600 dark:text-rose-300 shrink-0" />
            <p className="text-sm sm:text-base font-semibold text-rose-900 dark:text-rose-100 truncate">
              {DONATE_MESSAGE}
            </p>
          </div>
          <a
            href={DONATE_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-bold bg-rose-600 hover:bg-rose-700 text-white shadow-sm"
          >
            Support EasyPi
          </a>
        </div>
      </div>
      )}

      <div className="flex h-16 items-center justify-between px-4 lg:px-6">
        {/* Left side - Mobile menu button */}
        <div className="flex items-center gap-4">
          {/* Hamburger menu - mobile only */}
          {isMobile && (
            <button
              onClick={toggle}
              className="p-2 rounded-lg text-gray-500 hover:text-gray-700 hover:bg-gray-100 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:bg-dark-800 lg:hidden"
              aria-label="Toggle menu"
            >
              <Menu className="h-6 w-6" />
            </button>
          )}
          
          {/* Mobile logo */}
          {isMobile && (
            <div className="flex items-center gap-2 lg:hidden">
              <div className="flex h-10 w-10 flex-col items-center justify-center rounded-xl bg-gradient-to-br from-[#0c1445] via-[#0c1445] to-red-500">
                <span className="text-[9px] font-bold text-white leading-none tracking-wide">Easy</span>
                <span className="text-base font-serif text-red-500 leading-none -mt-0.5">π</span>
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1 sm:gap-2">
          {/* Agent actions (Ask Agent / Explain This Section) */}
          <HeaderAgentActions />

          {/* Theme Toggle */}
          <Tooltip content={theme === 'light' ? 'Dark mode' : 'Light mode'} position="bottom">
            <Button
              variant="ghost"
              size="sm"
              onClick={toggleTheme}
              icon={theme === 'light' ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
            >
              {null}
            </Button>
          </Tooltip>

          {/* Device Status - hidden on small screens */}
          <div className="hidden sm:flex ml-2 lg:ml-4 items-center gap-2 rounded-lg bg-green-50 dark:bg-green-900/20 px-2 lg:px-3 py-1.5">
            <span className="status-dot status-online" />
            <span className="text-xs lg:text-sm font-medium text-green-700 dark:text-green-400 truncate max-w-[100px] lg:max-w-none">
              {getPiModelDisplay()}
            </span>
          </div>

          {/* User Menu with Avatar */}
          <Link to="/settings" className="ml-1 sm:ml-2">
            <Tooltip content="Settings" position="bottom">
              <div className="flex items-center gap-1 sm:gap-2 px-2 sm:px-3 py-1.5 rounded-lg bg-gray-100 dark:bg-dark-800 hover:bg-gray-200 dark:hover:bg-dark-700 transition-colors cursor-pointer">
                {avatarUrl ? (
                  <img 
                    src={avatarUrl} 
                    alt="Avatar" 
                    className="h-6 w-6 rounded-full object-cover"
                  />
                ) : (
                  <div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary-600 text-white text-xs font-bold">
                    {getInitial()}
                  </div>
                )}
                <span className="hidden sm:block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {user?.username || 'Admin'}
                </span>
                <Settings className="hidden sm:block h-4 w-4 text-gray-400" />
              </div>
            </Tooltip>
          </Link>

          {/* Logout Button */}
          <Tooltip content="Logout" position="bottom">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLogout}
              icon={<LogOut className="h-4 w-4" />}
            >
              {null}
            </Button>
          </Tooltip>
        </div>
      </div>
    </header>
  )
}

export default Header
