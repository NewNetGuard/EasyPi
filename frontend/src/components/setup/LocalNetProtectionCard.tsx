import { useCallback, useEffect, useState } from 'react'
import { CheckCircle, Loader2, Shield } from 'lucide-react'
import { toast } from 'react-hot-toast'

import api from '../../api/client'

interface LocalNetProtectionCardProps {
  onStatusChange?: (running: boolean) => void
}

interface LocalNetProtectionStats {
  total_queries: number
  blocked_queries: number
  blocklist_size: number
}

export default function LocalNetProtectionCard({ onStatusChange }: LocalNetProtectionCardProps) {
  const [status, setStatus] = useState<'checking' | 'running' | 'stopped' | 'error'>('checking')
  const [stats, setStats] = useState<LocalNetProtectionStats | null>(null)
  const [transparentDns, setTransparentDns] = useState(false)
  const [isEnabling, setIsEnabling] = useState(false)

  const checkStatus = useCallback(async () => {
    try {
      const [statusResponse, dashboardResponse] = await Promise.all([
        api.get('/netprotection/status/full'),
        api.get('/netprotection/dashboard').catch(() => null),
      ])
      const statusData = statusResponse.data
      const isRunning = Boolean(statusData?.running || statusData?.service_status === 'active')
      onStatusChange?.(isRunning)

      if (isRunning) {
        setStatus('running')
        if (dashboardResponse?.data) {
          setStats({
            total_queries: dashboardResponse.data.totalQueries || 0,
            blocked_queries: dashboardResponse.data.blockedToday || 0,
            blocklist_size: dashboardResponse.data.blockedDomains || 0,
          })
        } else {
          setStats({ total_queries: 0, blocked_queries: 0, blocklist_size: 0 })
        }
        setTransparentDns(Boolean(statusData.transparent_dns))
      } else {
        setStatus('stopped')
        setStats(null)
        setTransparentDns(false)
      }
    } catch {
      try {
        const fallback = await api.get('/netprotection/status')
        const isRunning = Boolean(fallback.data?.configured)
        setStatus(isRunning ? 'running' : 'stopped')
        onStatusChange?.(isRunning)
      } catch {
        setStatus('error')
        onStatusChange?.(false)
      }
    }
  }, [onStatusChange])

  useEffect(() => {
    void checkStatus()
    const interval = window.setInterval(() => void checkStatus(), 30_000)
    return () => window.clearInterval(interval)
  }, [checkStatus])

  const toggleService = async (action: 'start' | 'stop') => {
    try {
      setIsEnabling(true)
      const response = await api.post(`/netprotection/${action}`)
      if (response.data?.success === false) {
        throw new Error(response.data?.error || `NetProtection ${action} failed`)
      }
      toast.success(`NetProtection ${action === 'start' ? 'started' : 'stopped'}`)
      await checkStatus()
    } catch (error) {
      const message = error instanceof Error ? error.message : `Failed to ${action} NetProtection`
      toast.error(message)
    } finally {
      setIsEnabling(false)
    }
  }

  const toggleTransparentDns = async () => {
    try {
      setIsEnabling(true)
      const nextValue = !transparentDns
      const response = await api.post('/netprotection/transparent-dns', { enabled: nextValue })
      if (response.data?.success === false) {
        throw new Error(response.data?.error || 'Transparent DNS update failed')
      }
      setTransparentDns(nextValue)
      toast.success(nextValue
        ? 'Transparent DNS enabled for forwarded plain DNS traffic'
        : 'Transparent DNS disabled')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to toggle transparent DNS'
      toast.error(message)
    } finally {
      setIsEnabling(false)
    }
  }

  return (
    <div className={`rounded-xl border p-6 ${status === 'running'
      ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
      : 'bg-white dark:bg-dark-800 border-gray-200 dark:border-dark-700'
      }`}>
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${status === 'running' ? 'bg-green-500' : 'bg-gray-400'}`}>
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              Local NetProtection
              {status === 'running' && (
                <span className="px-2 py-0.5 text-xs bg-green-500 text-white rounded-full">Running</span>
              )}
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              {status === 'running'
                ? `${stats?.blocklist_size?.toLocaleString() || 0} domains blocked • ${stats?.total_queries?.toLocaleString() || 0} queries`
                : 'DNS protection on this server'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {status === 'running' && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-600 dark:text-gray-400">Transparent DNS</span>
              <button
                onClick={toggleTransparentDns}
                disabled={isEnabling}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${transparentDns ? 'bg-green-500' : 'bg-gray-300 dark:bg-dark-600'}`}
                title={transparentDns
                  ? 'Forwarded UDP/TCP port 53 is redirected to NetProtection'
                  : 'Enable interception for forwarded plain DNS traffic'}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${transparentDns ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
          )}

          <button
            onClick={() => toggleService(status === 'running' ? 'stop' : 'start')}
            disabled={isEnabling || status === 'checking'}
            className={`px-4 py-2 rounded-lg font-medium flex items-center gap-2 transition-colors ${status === 'running'
              ? 'bg-red-500 hover:bg-red-600 text-white'
              : 'bg-green-500 hover:bg-green-600 text-white'
              }`}
          >
            {isEnabling ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : status === 'running' ? (
              <>Stop</>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                Start Protection
              </>
            )}
          </button>
        </div>
      </div>

      {status === 'running' && transparentDns && (
        <div className="mt-4 p-3 bg-green-100 dark:bg-green-900/40 rounded-lg">
          <p className="text-sm text-green-800 dark:text-green-200 flex items-center gap-2">
            <CheckCircle className="w-4 h-4" />
            <strong>Transparent DNS active:</strong> Forwarded plain DNS on UDP/TCP port 53 is redirected to NetProtection. Clients that bypass this Pi or use encrypted DNS still need separate policy controls.
          </p>
        </div>
      )}

      {status === 'running' && (
        <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
          <p className="text-sm text-blue-800 dark:text-blue-200">
            <strong>ℹ️ Transparent DNS</strong> — redirects forwarded UDP/TCP port 53 requests, including requests sent to resolvers such as 8.8.8.8. It cannot intercept encrypted DNS or traffic that does not pass through this Pi.
          </p>
          <p className="text-xs text-blue-600 dark:text-blue-400 mt-1">
            ⚠️ Only works when EasyPi is a <strong>router</strong> or <strong>Tailscale exit node</strong>. For normal networks, set EasyPi as the DNS server on your router.
          </p>
        </div>
      )}
    </div>
  )
}
