import { useState, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Router, Wifi, Shield, Copy, Check, Loader2, CheckCircle, AlertCircle } from 'lucide-react'
import { getCsrfHeaders } from '../../utils/csrf'
import {
  gatewayStatusQueryKey,
  useGatewayStatus,
  type GatewayModeStatus,
} from '../../hooks/useGatewayStatus'

interface NetworkInfo {
  localIp: string
  gateway: string
  netmask: string
  interface: string
  networkRange: string
}

interface EnableGatewayResult {
  success: boolean
  error?: string
  status?: GatewayModeStatus
  verification?: GatewayVerifyResult
}

interface GatewayVerifyResult {
  configured: boolean
  effective: boolean
  verification_available?: boolean
  devices_routed: number
  device_ips?: string[]
  devices_present?: number
  present_ips?: string[]
}

const RouterSetupCard = () => {
  const queryClient = useQueryClient()
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo | null>(null)
  const { data: gatewayStatus, refetch: refetchGatewayStatus } = useGatewayStatus()
  const [loading, setLoading] = useState(true)
  const [enabling, setEnabling] = useState(false)
  const [disabling, setDisabling] = useState(false)
  const [fixing, setFixing] = useState(false)
  const [copiedField, setCopiedField] = useState<string | null>(null)
  const [enableResult, setEnableResult] = useState<EnableGatewayResult | null>(null)
  const [fixResult, setFixResult] = useState<{ success: boolean; error?: string; log_tail?: string } | null>(null)
  const [verifyResult, setVerifyResult] = useState<GatewayVerifyResult | null>(null)
  const [verifying, setVerifying] = useState(false)

  useEffect(() => {
    fetchNetworkInfo()
  }, [])

  const fetchNetworkInfo = async () => {
    try {
      const response = await fetch('/api/network-toolkit/network-info', {
        credentials: 'include'
      })
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setNetworkInfo(data.data)
        }
      }
    } catch (error) {
      console.error('Failed to fetch network info:', error)
    } finally {
      setLoading(false)
    }
  }

  const enableGatewayMode = async () => {
    setEnabling(true)
    setEnableResult(null)
    try {
      const csrfHeaders = await getCsrfHeaders()
      const response = await fetch('/api/network-toolkit/gateway-mode/enable', {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeaders,
      })
      const data = await response.json()
      setEnableResult(data)
      if (data.success) {
        if (data.verification) {
          setVerifyResult(data.verification)
        }
        if (data.status) {
          queryClient.setQueryData(gatewayStatusQueryKey, data.status)
        } else {
          await refetchGatewayStatus()
        }
      }
    } catch (error) {
      setEnableResult({ success: false, error: 'Failed to enable gateway mode' })
    } finally {
      setEnabling(false)
    }
  }

  const disableGatewayMode = async () => {
    setDisabling(true)
    try {
      const csrfHeaders = await getCsrfHeaders()
      const response = await fetch('/api/network-toolkit/gateway-mode/disable', {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeaders,
      })
      const data = await response.json()
      if (data.status) {
        queryClient.setQueryData(gatewayStatusQueryKey, data.status)
      } else {
        await refetchGatewayStatus()
      }
      setEnableResult(null)
    } catch (error) {
      console.error('Failed to disable gateway mode:', error)
    } finally {
      setDisabling(false)
    }
  }

  const fixGatewayMode = async () => {
    setFixing(true)
    setFixResult(null)
    try {
      const csrfHeaders = await getCsrfHeaders()
      const response = await fetch('/api/network-toolkit/gateway-mode/fix', {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeaders,
      })
      const data = await response.json()
      setFixResult({ success: !!data.success, error: data.error, log_tail: data.log_tail })
      if (data.status) {
        queryClient.setQueryData(gatewayStatusQueryKey, data.status)
      } else {
        await refetchGatewayStatus()
      }
    } catch (error) {
      setFixResult({ success: false, error: 'Failed to fix gateway mode' })
    } finally {
      setFixing(false)
    }
  }

  const verifyGatewayMode = async (silent = false) => {
    if (!silent) setVerifying(true)
    try {
      const response = await fetch('/api/network-toolkit/gateway-mode/verify', {
        credentials: 'include',
      })
      if (response.ok) {
        setVerifyResult(await response.json())
      }
    } catch (error) {
      console.error('Failed to verify gateway:', error)
    } finally {
      if (!silent) setVerifying(false)
    }
  }

  // Auto-check effectiveness whenever gateway mode is enabled, so the badge
  // reflects whether devices are ACTUALLY routing through EasyPi (not just
  // whether it is configured on the Pi).
  useEffect(() => {
    if (gatewayStatus?.enabled) {
      void verifyGatewayMode(true)
      const timer = window.setInterval(() => void verifyGatewayMode(true), 5000)
      return () => window.clearInterval(timer)
    }
    setVerifyResult(null)
  }, [gatewayStatus?.enabled])

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const CopyButton = ({ text, field }: { text: string; field: string }) => (
    <button
      onClick={() => copyToClipboard(text, field)}
      className="p-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
      title="Copy to clipboard"
    >
      {copiedField === field ? (
        <Check className="w-4 h-4 text-green-500" />
      ) : (
        <Copy className="w-4 h-4 text-gray-400" />
      )}
    </button>
  )

  if (loading) {
    return (
      <div className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-xl border border-blue-200 dark:border-blue-800 p-4 sm:p-6">
        <div className="animate-pulse flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-200 dark:bg-blue-800 rounded-lg"></div>
          <div className="h-4 bg-blue-200 dark:bg-blue-800 rounded w-48"></div>
        </div>
      </div>
    )
  }

  if (!networkInfo) {
    return null
  }

  const isGatewayEnabled = gatewayStatus?.enabled === true
  return (
    <div className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-xl border border-blue-200 dark:border-blue-800 p-4 sm:p-6">
      {/* Header */}
      <div className="flex items-center gap-3 sm:gap-4 mb-4">
        <div className="p-2.5 bg-blue-500 rounded-lg shadow-lg shadow-blue-500/30">
          <Router className="w-5 h-5 sm:w-6 sm:h-6 text-white" />
        </div>
        <div>
          <h3 className="font-semibold text-gray-900 dark:text-white text-sm sm:text-base">
            Network Protection
          </h3>
          <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">
            Use EasyPi as your network gateway for complete protection
          </p>
        </div>
      </div>

      {/* IP Address Display */}
      <div className="p-4 bg-white dark:bg-gray-800 rounded-lg shadow-sm mb-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
            EasyPi IP Address
          </span>
          <CopyButton text={networkInfo.localIp} field="ip" />
        </div>
        <div className="font-mono text-2xl sm:text-3xl font-bold text-blue-600 dark:text-blue-400">
          {networkInfo.localIp}
        </div>
        {gatewayStatus && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {isGatewayEnabled ? (
              <>
                <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300 rounded-full">
                  <CheckCircle className="w-3 h-3" />
                  Full Gateway Mode Active
                </span>
                {verifyResult && (
                  verifyResult.verification_available === false ? (
                    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300 rounded-full">
                      <AlertCircle className="w-3 h-3" />
                      Traffic verification unavailable
                    </span>
                  ) : verifyResult.effective ? (
                    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300 rounded-full">
                      {verifyResult.devices_routed} device{verifyResult.devices_routed === 1 ? '' : 's'} routing through EasyPi
                    </span>
                  ) : verifyResult.devices_present && verifyResult.devices_present > 0 ? (
                    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300 rounded-full">
                      <AlertCircle className="w-3 h-3" />
                      {verifyResult.devices_present} device{verifyResult.devices_present === 1 ? '' : 's'} visible — internet route not verified
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300 rounded-full">
                      <AlertCircle className="w-3 h-3" />
                      No active devices visible on the gateway network
                    </span>
                  )
                )}
              </>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-full">
                DNS Only Mode
              </span>
            )}
          </div>
        )}
      </div>

      {/* Two Options Side by Side */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
        {/* DNS Only */}
        <div className={`p-4 bg-white dark:bg-gray-800 rounded-lg shadow-sm ${!isGatewayEnabled ? 'ring-2 ring-green-500' : ''}`}>
          <div className="flex items-center gap-2 mb-2">
            <Wifi className="w-5 h-5 text-green-500" />
            <h4 className="font-medium text-gray-900 dark:text-white">DNS Only</h4>
            {!isGatewayEnabled && (
              <span className="px-1.5 py-0.5 text-[10px] font-medium bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300 rounded">
                CURRENT
              </span>
            )}
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
            Block ads, trackers & malware. Works for most apps.
          </p>
          <div className="text-xs text-gray-600 dark:text-gray-400">
            Set your router's DNS to: <code className="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded font-mono">{networkInfo.localIp}</code>
          </div>
        </div>

        {/* Full Gateway */}
        <div className={`p-4 bg-white dark:bg-gray-800 rounded-lg shadow-sm ${isGatewayEnabled ? 'ring-2 ring-blue-500' : 'border-2 border-blue-200 dark:border-blue-700'}`}>
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-5 h-5 text-blue-500" />
            <h4 className="font-medium text-gray-900 dark:text-white">Full Gateway</h4>
            {isGatewayEnabled ? (
              <span className="px-1.5 py-0.5 text-[10px] font-medium bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 rounded">
                ACTIVE
              </span>
            ) : (
              <span className="px-1.5 py-0.5 text-[10px] font-medium bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 rounded">
                BEST
              </span>
            )}
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
            Gateway-wide routing and fail-closed controls for traffic that actually passes through this Pi.
          </p>
          
          {!isGatewayEnabled ? (
            <div className="space-y-3">
              <div className="rounded-lg bg-blue-50 dark:bg-blue-950/30 p-3 text-xs text-blue-900 dark:text-blue-200">
                <p className="mb-2 font-semibold">Configure your router first</p>
                <ol className="space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="font-semibold">1.</span>
                    <span>
                      Open router settings at{' '}
                      <code className="rounded bg-blue-100 px-1 py-0.5 font-mono dark:bg-blue-900/50">
                        {gatewayStatus?.current_gateway || networkInfo.gateway}
                      </code>.
                    </span>
                  </li>
                  <li className="flex items-center justify-between gap-2">
                    <span><strong>2.</strong> Set DHCP Gateway to:</span>
                    <span className="flex items-center gap-1">
                      <code className="rounded bg-blue-100 px-1 py-0.5 font-mono font-semibold dark:bg-blue-900/50">{networkInfo.localIp}</code>
                      <CopyButton text={networkInfo.localIp} field="setup-gateway" />
                    </span>
                  </li>
                  <li className="flex items-center justify-between gap-2">
                    <span><strong>3.</strong> Set DHCP DNS to:</span>
                    <span className="flex items-center gap-1">
                      <code className="rounded bg-blue-100 px-1 py-0.5 font-mono font-semibold dark:bg-blue-900/50">{networkInfo.localIp}</code>
                      <CopyButton text={networkInfo.localIp} field="setup-dns" />
                    </span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="font-semibold">4.</span>
                    <span>Save the router settings, then enable Full Gateway below.</span>
                  </li>
                </ol>
              </div>
              <button
                onClick={enableGatewayMode}
                disabled={enabling}
                className="w-full px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-400 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                {enabling ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Enabling...
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4" />
                    I configured the router — Enable Gateway
                  </>
                )}
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              <button
                onClick={() => void verifyGatewayMode()}
                disabled={verifying}
                className="w-full px-4 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:bg-emerald-400 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                {verifying ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Checking...
                  </>
                ) : (
                  'Verify devices are using EasyPi'
                )}
              </button>
              <button
                onClick={fixGatewayMode}
                disabled={fixing}
                className="w-full px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-400 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                {fixing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Fixing...
                  </>
                ) : (
                  'Fix Gateway (Internet Down)'
                )}
              </button>
              <button
                onClick={disableGatewayMode}
                disabled={disabling}
                className="w-full px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-200 font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                {disabling ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Disabling...
                  </>
                ) : (
                  'Disable Gateway Mode'
                )}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Result Message */}
      {enableResult && (
        <div className={`p-4 rounded-lg mb-4 ${enableResult.success ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-700' : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700'}`}>
          {enableResult.success ? (
            <>
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <h4 className="font-medium text-green-800 dark:text-green-300">
                  {verifyResult?.effective ? 'Full Gateway is active' : 'Gateway enabled — waiting for traffic'}
                </h4>
              </div>
              <p className="text-sm text-green-700 dark:text-green-400">
                {verifyResult?.effective
                  ? `EasyPi confirmed that ${verifyResult.devices_routed} device${verifyResult.devices_routed === 1 ? '' : 's'} are routing through it.`
                  : 'EasyPi will detect routed devices automatically. Reconnect a device or renew its DHCP lease, then open a website. No page refresh is needed.'}
              </p>
            </>
          ) : (
            <div className="flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-red-500" />
              <span className="text-sm text-red-700 dark:text-red-400">{enableResult.error}</span>
            </div>
          )}
        </div>
      )}

      {fixResult && (
        <div className={`p-4 rounded-lg mb-4 ${fixResult.success ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-700' : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700'}`}>
          {fixResult.success ? (
            <div className="flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-green-500" />
              <span className="text-sm text-green-700 dark:text-green-400">Gateway repair completed. Reconnect a device and verify its internet route.</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-red-500" />
              <span className="text-sm text-red-700 dark:text-red-400">{fixResult.error || 'Gateway fix failed'}</span>
            </div>
          )}
        </div>
      )}

      {verifyResult && isGatewayEnabled && (
        <div className={`p-4 rounded-lg mb-4 border ${verifyResult.effective ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-700' : 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-700'}`}>
          {verifyResult.verification_available === false ? (
            <div className="flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                  EasyPi gateway is active, but traffic verification is unavailable.
                </p>
                <p className="text-xs text-amber-700 dark:text-amber-400 mt-1">
                  The conntrack diagnostic tool is missing. EasyPi cannot confirm completed internet connections until it is installed.
                </p>
              </div>
            </div>
          ) : verifyResult.effective ? (
            <div className="flex items-start gap-2">
              <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-green-800 dark:text-green-300">
                  Internet routing verified — {verifyResult.devices_routed} device{verifyResult.devices_routed === 1 ? '' : 's'} successfully connected through EasyPi.
                </p>
                <p className="text-xs text-green-700 dark:text-green-400 mt-1">
                  EasyPi observed completed, bidirectional internet connections — not merely blocked connection attempts.
                </p>
                {verifyResult.device_ips && verifyResult.device_ips.length > 0 && (
                  <p className="text-xs text-green-600/80 dark:text-green-400/70 mt-1 font-mono break-all">
                    Routing now: {verifyResult.device_ips.join(', ')}
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
              <div>
                {verifyResult.devices_present && verifyResult.devices_present > 0 ? (
                  <>
                    <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                      {verifyResult.devices_present} device{verifyResult.devices_present === 1 ? '' : 's'} visible, but no successful internet traffic through EasyPi yet.
                    </p>
                    <p className="text-xs text-amber-700 dark:text-amber-400 mt-1">
                      Allowing a device only removes its quarantine. It does not change the device's gateway. Reconnect it to the protected Wi-Fi, renew its DHCP lease, open a website, and verify again.
                    </p>
                    {verifyResult.present_ips && verifyResult.present_ips.length > 0 && (
                      <p className="text-xs text-amber-600/80 dark:text-amber-400/70 mt-1 font-mono break-all">
                        Visible now: {verifyResult.present_ips.join(', ')}
                      </p>
                    )}
                  </>
                ) : (
                  <>
                    <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                      No active devices are visible on the EasyPi gateway network.
                    </p>
                    <p className="text-xs text-amber-700 dark:text-amber-400 mt-1">
                      Reconnect a device to the protected network or renew its DHCP lease, then open a website. EasyPi checks automatically; no page refresh is needed.
                    </p>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Info for DNS-only */}
      {!isGatewayEnabled && !enableResult && (
        <div className="p-4 bg-gray-50 dark:bg-gray-800/50 rounded-lg border border-gray-200 dark:border-gray-700">
          <h4 className="font-medium text-gray-800 dark:text-gray-300 mb-2 flex items-center gap-2">
            <Router className="w-4 h-4" />
            Quick DNS Setup
          </h4>
          <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">
            For basic protection, just set <code className="px-1 py-0.5 bg-gray-200 dark:bg-gray-700 rounded">{networkInfo.localIp}</code> as DNS in your router's DHCP settings.
            For complete protection, follow the router steps above, then enable Full Gateway.
          </p>
        </div>
      )}
    </div>
  )
}

export default RouterSetupCard
