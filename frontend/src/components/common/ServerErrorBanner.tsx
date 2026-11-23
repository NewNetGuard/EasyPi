import { useEffect, useState } from 'react'
import { RefreshCw, Server } from 'lucide-react'

const ServerErrorBanner = () => {
  const [serverDown, setServerDown] = useState(false)
  const [checking, setChecking] = useState(false)

  const checkServer = async () => {
    setChecking(true)
    try {
      // Use /health endpoint at root level (not /api/v1/health)
      const response = await fetch('/health', {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      })
      if (response.ok) {
        setServerDown(false)
      } else {
        setServerDown(true)
      }
    } catch {
      setServerDown(true)
    } finally {
      setChecking(false)
    }
  }

  useEffect(() => {
    // Check on mount
    checkServer()

    // Listen for server errors from API client
    const handleServerError = () => {
      // Verify with /health before showing a global outage banner.
      void checkServer()
    }

    window.addEventListener('easypi:server-error', handleServerError)
    
    // Periodic health check every 30 seconds if server is down
    const interval = setInterval(() => {
      if (serverDown) {
        checkServer()
      }
    }, 30000)

    return () => {
      window.removeEventListener('easypi:server-error', handleServerError)
      clearInterval(interval)
    }
  }, [serverDown])

  if (!serverDown) return null

  return (
    <div className="fixed top-0 left-0 right-0 z-[100] bg-red-600 text-white px-4 py-3 shadow-lg">
      <div className="container mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Server className="h-5 w-5 animate-pulse" />
          <div>
            <p className="font-semibold">Server Unavailable</p>
            <p className="text-sm text-red-100">
              The backend service is not responding. Please check if the server is running.
            </p>
          </div>
        </div>
        <button
          onClick={checkServer}
          disabled={checking}
          className="flex items-center gap-2 rounded-lg bg-white/20 px-4 py-2 text-sm font-medium transition hover:bg-white/30 disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${checking ? 'animate-spin' : ''}`} />
          {checking ? 'Checking...' : 'Retry'}
        </button>
      </div>
    </div>
  )
}

export default ServerErrorBanner
