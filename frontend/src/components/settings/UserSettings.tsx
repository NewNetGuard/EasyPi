import { useState, useRef } from 'react'
import { User, Camera, Key, Copy, RefreshCw, Check, Mail, HelpCircle, Clock, Globe, Monitor, LogOut, Smartphone } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import Card from '../common/Card'
import Button from '../common/Button'
import Tooltip from '../common/Tooltip'
import { toast } from 'react-hot-toast'
import { getApiBaseUrl } from '../../utils/apiBase'
import { copyToClipboard } from '../../utils/clipboard'
import { useAuthStore } from '../../stores/authStore'
import { ensureCsrfToken, getCsrfHeaders } from '../../utils/csrf'

const API_BASE = `${getApiBaseUrl()}/api/v1/auth`

interface UserSessionSummary {
  id: string
  ip_address: string
  device_name: string
  last_active: string
  is_current: boolean
  is_active: boolean
}

const UserSettings = () => {
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [showFullToken, setShowFullToken] = useState(false)
  const [newToken, setNewToken] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  
  // Get user from auth store (already authenticated via cookies)
  const { user, isAuthenticated } = useAuthStore()

  // Fetch avatar - uses httpOnly cookies for auth
  const { data: avatarUrl, refetch: refetchAvatar } = useQuery({
    queryKey: ['user-avatar', user?.id],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/avatar`, {
        credentials: 'include',  // Send httpOnly cookies
      })
      // Backend always returns valid PNG (generated if needed)
      if (res.ok && res.status !== 204) {
        const blob = await res.blob()
        return URL.createObjectURL(blob)
      }
      return null
    },
    enabled: isAuthenticated,
  })

  // Fetch API token status
  const { data: tokenStatus, refetch: refetchToken } = useQuery({
    queryKey: ['api-token'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/api-token`, {
        credentials: 'include',
      })
      return res.json()
    },
    enabled: isAuthenticated,
  })

  // Upload avatar mutation
  const uploadAvatarMutation = useMutation({
    mutationFn: async (file: File) => {
      const uploadOnce = async (csrfToken?: string) => {
        const formData = new FormData()
        formData.append('file', file)
        const csrfHeaders = csrfToken ? { 'X-CSRF-Token': csrfToken } : await getCsrfHeaders()
        const res = await fetch(`${API_BASE}/avatar`, {
          method: 'POST',
          credentials: 'include',  // Send httpOnly cookies
          headers: {
            ...csrfHeaders,
          },
          body: formData,
        })
        if (!res.ok) {
          let message = 'Failed to upload'
          try {
            const data = await res.json()
            if (data?.detail) message = data.detail
          } catch {
            // ignore
          }
          const err = new Error(message) as Error & { status?: number }
          err.status = res.status
          throw err
        }
        return res.json()
      }

      try {
        return await uploadOnce()
      } catch (err) {
        const status = (err as { status?: number }).status
        if (status === 403) {
          const refreshed = await ensureCsrfToken()
          if (refreshed) {
            return await uploadOnce(refreshed)
          }
        }
        throw err
      }
    },
    onSuccess: () => {
      toast.success('Avatar updated!')
      refetchAvatar()
      queryClient.invalidateQueries({
        predicate: (query) =>
          Array.isArray(query.queryKey) &&
          typeof query.queryKey[0] === 'string' &&
          query.queryKey[0].startsWith('user-avatar'),
      })
    },
    onError: (err) => {
      const message = err instanceof Error ? err.message : 'Failed to upload avatar'
      toast.error(message)
    }
  })

  // Fetch current session list as fallback for profile session fields.
  const { data: sessions = [] } = useQuery({
    queryKey: ['auth-sessions', user?.id],
    queryFn: async (): Promise<UserSessionSummary[]> => {
      const res = await fetch(`${API_BASE}/sessions`, {
        credentials: 'include',
      })
      if (!res.ok) return []
      const data = await res.json()
      return Array.isArray(data) ? data : []
    },
    enabled: isAuthenticated,
  })

  // Generate token mutation
  const generateTokenMutation = useMutation({
    mutationFn: async () => {
      const csrfHeaders = await getCsrfHeaders()
      const res = await fetch(`${API_BASE}/api-token/generate`, {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeaders,
      })
      if (!res.ok) throw new Error('Failed to generate')
      return res.json()
    },
    onSuccess: (data) => {
      setNewToken(data.token)
      setShowFullToken(true)
      toast.success('New API token generated!')
      refetchToken()
    },
    onError: () => toast.error('Failed to generate token')
  })

  const handleAvatarClick = () => {
    fileInputRef.current?.click()
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      if (file.size > 5 * 1024 * 1024) {
        toast.error('File too large (max 5MB)')
        return
      }
      uploadAvatarMutation.mutate(file)
    }
  }

  const copyToken = async () => {
    if (newToken) {
      const success = await copyToClipboard(newToken)
      if (success) {
        setCopied(true)
        toast.success('Token copied to clipboard!')
        setTimeout(() => setCopied(false), 2000)
      } else {
        toast.error('Failed to copy to clipboard')
      }
    }
  }

  const getInitial = () => {
    if (user?.username) {
      return user.username.charAt(0).toUpperCase()
    }
    return 'U'
  }

  const normalizeSessionValue = (value: string | null | undefined): string | null => {
    if (!value) return null
    const normalized = value.trim()
    if (!normalized) return null
    const lowered = normalized.toLowerCase()
    if (lowered === 'unknown' || lowered === 'unknown device') return null
    return normalized
  }

  const parseDeviceName = (userAgent: string | null | undefined): string | null => {
    const normalized = normalizeSessionValue(userAgent)
    if (!normalized) return null

    const ua = normalized.toLowerCase()

    if (
      ua.includes('python-requests') ||
      ua.includes('curl/') ||
      ua.includes('wget/') ||
      ua.includes('postmanruntime') ||
      ua.includes('insomnia/') ||
      ua.includes('httpx/') ||
      ua.includes('axios/')
    ) {
      return 'API Client'
    }

    if (ua.includes('iphone')) return 'iPhone'
    if (ua.includes('ipad')) return 'iPad'
    if (ua.includes('android')) {
      return ua.includes('mobile') ? 'Android Phone' : 'Android Tablet'
    }

    if (ua.includes('windows')) {
      if (ua.includes('edg/')) return 'Windows (Edge)'
      if (ua.includes('chrome')) return 'Windows (Chrome)'
      if (ua.includes('firefox')) return 'Windows (Firefox)'
      return 'Windows'
    }

    if (ua.includes('macintosh') || ua.includes('mac os')) {
      if (ua.includes('safari') && !ua.includes('chrome')) return 'Mac (Safari)'
      if (ua.includes('chrome')) return 'Mac (Chrome)'
      if (ua.includes('firefox')) return 'Mac (Firefox)'
      return 'Mac'
    }

    if (ua.includes('linux')) {
      if (ua.includes('chrome')) return 'Linux (Chrome)'
      if (ua.includes('firefox')) return 'Linux (Firefox)'
      return 'Linux'
    }

    return 'Unknown Device'
  }

  const latestSession = sessions[0]
  const lastLogin = user?.last_login || latestSession?.last_active || null
  const lastLoginIp = normalizeSessionValue(user?.last_login_ip) ?? normalizeSessionValue(latestSession?.ip_address)
  const lastLoginDevice =
    normalizeSessionValue(latestSession?.device_name) ?? parseDeviceName(user?.last_login_user_agent)

  return (
    <div className="space-y-6">
      {/* Profile Card */}
      <Card title="User Profile">
        <div className="space-y-6">
          {/* Avatar Section */}
          <div className="flex items-center gap-6">
            <div className="relative group">
              {avatarUrl ? (
                <img 
                  src={avatarUrl} 
                  alt="Avatar" 
                  className="h-24 w-24 rounded-full object-cover border-4 border-gray-200 dark:border-dark-700"
                />
              ) : (
                <div className="flex h-24 w-24 items-center justify-center rounded-full bg-primary-600 text-white text-3xl font-bold border-4 border-gray-200 dark:border-dark-700">
                  {getInitial()}
                </div>
              )}
              <button
                onClick={handleAvatarClick}
                className="absolute inset-0 flex items-center justify-center rounded-full bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer"
              >
                <Camera className="h-8 w-8 text-white" />
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileChange}
                className="hidden"
              />
            </div>
            <div>
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                {user?.username || 'User'}
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Role: {user?.role || 'admin'}
              </p>
              <Button 
                variant="outline" 
                size="sm" 
                className="mt-2"
                onClick={handleAvatarClick}
                disabled={uploadAvatarMutation.isPending}
                icon={<Camera className="h-4 w-4" />}
              >
                {uploadAvatarMutation.isPending ? 'Uploading...' : 'Change Avatar'}
              </Button>
            </div>
          </div>

          {/* Username (read-only) */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Username
            </label>
            <div className="flex items-center gap-2 px-4 py-2.5 bg-gray-100 dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700">
              <User className="h-4 w-4 text-gray-400" />
              <span className="text-gray-900 dark:text-white">{user?.username || 'admin'}</span>
            </div>
            <p className="mt-1 text-xs text-gray-500">Username cannot be changed</p>
          </div>

          {/* Email - Coming Soon */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Email
              <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 rounded-full">
                Coming soon
              </span>
            </label>
            <div className="flex items-center gap-2 px-4 py-2.5 bg-gray-100 dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700 opacity-60">
              <Mail className="h-4 w-4 text-gray-400" />
              <span className="text-gray-500">email@example.com</span>
            </div>
            <p className="mt-1 text-xs text-gray-500">Email notifications will be available soon</p>
          </div>
        </div>
      </Card>

      {/* Session Info Card */}
      <Card
        title="Session Info"
      >
        <div className="space-y-4">
          {/* Last Login */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-gray-50 dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="h-4 w-4 text-primary-500" />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Last Login</span>
              </div>
              <p className="text-sm text-gray-900 dark:text-white">
                {lastLogin ? new Date(lastLogin).toLocaleString() : 'Not available'}
              </p>
            </div>

            <div className="p-4 bg-gray-50 dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700">
              <div className="flex items-center gap-2 mb-2">
                <Globe className="h-4 w-4 text-primary-500" />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">IP Address</span>
              </div>
              <p className="text-sm text-gray-900 dark:text-white font-mono">
                {lastLoginIp || 'Not available'}
              </p>
            </div>

            <div className="p-4 bg-gray-50 dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700">
              <div className="flex items-center gap-2 mb-2">
                <Monitor className="h-4 w-4 text-primary-500" />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Device</span>
              </div>
              <p className="text-sm text-gray-900 dark:text-white truncate" title={lastLoginDevice || 'Not available'}>
                {lastLoginDevice
                  ? (lastLoginDevice.length > 40
                      ? `${lastLoginDevice.substring(0, 40)}...`
                      : lastLoginDevice)
                  : 'Not available'}
              </p>
            </div>
          </div>

          {/* Active Sessions - Coming Soon */}
          <div className="pt-4 border-t border-gray-200 dark:border-dark-700">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Smartphone className="h-4 w-4 text-gray-400" />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Active Sessions
                </span>
                <span className="px-2 py-0.5 text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 rounded-full">
                  Coming soon
                </span>
              </div>
            </div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              View and manage all devices where you're currently logged in.
            </p>
          </div>

          {/* Logout from all devices - Coming Soon */}
          <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-dark-700">
            <div>
              <div className="flex items-center gap-2">
                <LogOut className="h-4 w-4 text-gray-400" />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Logout from all devices
                </span>
                <span className="px-2 py-0.5 text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 rounded-full">
                  Coming soon
                </span>
              </div>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Sign out from all sessions except the current one.
              </p>
            </div>
            <Button variant="outline" size="sm" disabled className="opacity-50">
              Logout All
            </Button>
          </div>
        </div>
      </Card>
    </div>
  )
}

export default UserSettings
