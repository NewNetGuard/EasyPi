/**
 * TailscaleAdminPanel Component
 * 
 * Panel for managing Tailscale via Admin API:
 * - Set API credentials
 * - Configure DNS (set NetProtection as nameserver)
 * - Manage devices (approve routes, enable exit node)
 */

import { useState, useEffect, useCallback } from 'react'
import { toast } from 'react-hot-toast'
import {
  Key,
  Loader2,
  CheckCircle,
  AlertCircle,
  Server,
  Shield,
  Eye,
  EyeOff,
  Trash2,
  RefreshCw,
  Zap,
  Globe,
  Router,
  Settings,
  ExternalLink,
} from 'lucide-react'
import {
  getCredentialsStatus,
  setCredentials,
  deleteCredentials,
  getDNSSettings,
  setupNetProtectionDNS,
  listDevices,
  approveRoutes,
  setExitNode,
  autoApproveRoutes,
  type CredentialsStatus,
  type DNSConfig,
  type Device,
} from '../../api/tailscaleAdminApi'

// Helper to extract error message from API response
function getErrorMessage(err: any, fallback: string): string {
  const detail = err?.response?.data?.detail
  if (typeof detail === 'string') {
    return detail
  }
  if (Array.isArray(detail)) {
    return detail.map((e: any) => e.msg || e.message || String(e)).join('; ')
  }
  if (detail?.msg) {
    return detail.msg
  }
  return fallback
}

interface TailscaleAdminPanelProps {
  tailscaleIp?: string
}

export default function TailscaleAdminPanel({ tailscaleIp }: TailscaleAdminPanelProps) {
  const [loading, setLoading] = useState(true)
  const [refreshingStatus, setRefreshingStatus] = useState(false)
  const [credentials, setCredentialsState] = useState<CredentialsStatus | null>(null)
  const [dnsConfig, setDnsConfig] = useState<DNSConfig | null>(null)
  const [devices, setDevices] = useState<Device[]>([])
  const [devicesError, setDevicesError] = useState<string | null>(null)
  
  // Form state
  const [apiKey, setApiKey] = useState('')
  const [tailnet, setTailnet] = useState('')
  const [showApiKey, setShowApiKey] = useState(false)
  const [saving, setSaving] = useState(false)
  
  // Action states
  const [settingUpDns, setSettingUpDns] = useState(false)
  const [approvingRoutes, setApprovingRoutes] = useState(false)

  const fetchStatus = useCallback(async () => {
    try {
      const creds = await getCredentialsStatus()
      setCredentialsState(creds)
      
      if (creds.configured) {
        try {
          const dns = await getDNSSettings()
          setDnsConfig(dns)
        } catch {
          // DNS fetch failed, API might not have right permissions
        }
        
        try {
          const devs = await listDevices()
          setDevices(devs)
          setDevicesError(null)
        } catch (err: any) {
          // Devices fetch failed
          setDevices([])
          setDevicesError(getErrorMessage(err, 'Failed to fetch devices. Check API key permissions.'))
        }
      }
    } catch {
      setCredentialsState(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleRefreshStatus = async () => {
    if (refreshingStatus) return
    setRefreshingStatus(true)
    try {
      await fetchStatus()
    } finally {
      setRefreshingStatus(false)
    }
  }

  useEffect(() => {
    fetchStatus()
  }, [fetchStatus])

  const handleSaveCredentials = async () => {
    if (!apiKey.trim() || !tailnet.trim()) {
      toast.error('Please enter both API key and Tailnet name')
      return
    }
    
    setSaving(true)
    try {
      const result = await setCredentials(apiKey.trim(), tailnet.trim())
      if (result.success) {
        toast.success(result.message)
        setApiKey('')
        await fetchStatus()
      }
      if (result.warning) {
        toast.error(String(result.warning), { duration: 5000 })
      }
    } catch (err: any) {
      toast.error(getErrorMessage(err, 'Failed to save credentials'))
    } finally {
      setSaving(false)
    }
  }

  const handleDeleteCredentials = async () => {
    if (!confirm('Delete Tailscale API credentials?')) return
    
    try {
      await deleteCredentials()
      toast.success('Credentials deleted')
      setCredentialsState(null)
      setDnsConfig(null)
      setDevices([])
    } catch (err: any) {
      toast.error(getErrorMessage(err, 'Failed to delete credentials'))
    }
  }

  const handleSetupNetProtectionDNS = async () => {
    if (!tailscaleIp) {
      toast.error('Tailscale IP not detected. Enable Remote Access first.')
      return
    }
    
    setSettingUpDns(true)
    try {
      const result = await setupNetProtectionDNS(tailscaleIp)
      if (result.success) {
        toast.success('🎉 NetProtection DNS configured! All Tailscale clients will now use EasyPi for DNS protection.', {
          duration: 5000,
        })
        await fetchStatus()
      }
    } catch (err: any) {
      toast.error(getErrorMessage(err, 'Failed to setup DNS'))
    } finally {
      setSettingUpDns(false)
    }
  }

  const handleAutoApproveRoutes = async () => {
    setApprovingRoutes(true)
    try {
      const result = await autoApproveRoutes()
      if (result.success) {
        if (result.approved.length > 0) {
          toast.success('Routes approved for this EasyPi device')
        } else {
          toast.success('No pending routes to approve')
        }
        await fetchStatus()
      }
    } catch (err: any) {
      toast.error(getErrorMessage(err, 'Failed to approve routes'))
    } finally {
      setApprovingRoutes(false)
    }
  }

  const handleApproveDeviceRoutes = async (device: Device) => {
    if (device.advertised_routes.length === 0) {
      toast.error('No routes to approve')
      return
    }
    
    try {
      await approveRoutes(device.id, device.advertised_routes)
      toast.success(`Routes approved for ${device.hostname}`)
      await fetchStatus()
    } catch (err: any) {
      toast.error(getErrorMessage(err, 'Failed to approve routes'))
    }
  }

  const handleToggleExitNode = async (device: Device) => {
    try {
      await setExitNode(device.id, !device.is_exit_node_enabled)
      toast.success(`Exit node ${device.is_exit_node_enabled ? 'disabled' : 'enabled'} for ${device.hostname}`)
      await fetchStatus()
    } catch (err: any) {
      toast.error(getErrorMessage(err, 'Failed to toggle exit node'))
    }
  }

  // Check if NetProtection/NetProtection DNS is configured
  const isNetProtectionDnsConfigured = dnsConfig && 
    tailscaleIp && 
    dnsConfig.nameservers.includes(tailscaleIp) && 
    dnsConfig.override_local_dns
    
  // Label for DNS status (NetProtection preferred)
  const dnsLabel = isNetProtectionDnsConfigured ? 'NetProtection' : 'DNS'

  return (
    <div className="bg-gray-50 dark:bg-dark-900 rounded-lg border border-gray-200 dark:border-dark-700 overflow-hidden">
      {/* Header - Always visible */}
      <div className="px-3 sm:px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-gray-200 dark:border-dark-700">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${credentials?.configured ? 'bg-green-100 dark:bg-green-900/30' : 'bg-gray-200 dark:bg-dark-700'}`}>
            <Settings className={`w-4 h-4 ${credentials?.configured ? 'text-green-600 dark:text-green-400' : 'text-gray-500'}`} />
          </div>
          <div className="text-left">
            <p className="font-medium text-gray-900 dark:text-white text-sm sm:text-base">Tailscale Admin API</p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {credentials?.configured 
                ? `Connected to ${credentials.tailnet}`
                : 'Configure DNS & auto-approve routes'}
            </p>
          </div>
        </div>
        {credentials?.configured && isNetProtectionDnsConfigured && (
          <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 text-xs rounded-full self-start sm:self-center">
            DNS Active
          </span>
        )}
      </div>

      {/* Content - Always visible */}
      <div className="p-3 sm:p-4 space-y-4">
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 text-blue-500 animate-spin" />
          </div>
        ) : !credentials?.configured ? (
          /* Credentials Setup */
          <div className="space-y-4">
              {/* How it works diagram */}
              <div className="p-3 sm:p-4 bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
                <h4 className="font-medium text-blue-900 dark:text-blue-100 mb-2 flex items-center gap-2 text-sm sm:text-base">
                  <Zap className="w-4 h-4" />
                  Why do you need this?
                </h4>
                <p className="text-xs sm:text-sm text-blue-800 dark:text-blue-200 mb-3">
                  Tailscale Admin API allows EasyPi to automatically configure your network so that <strong>all devices</strong> use NetProtection for ad blocking.
                </p>
                
                {/* Visual flow diagram */}
                <div className="flex items-center justify-center gap-1 sm:gap-2 text-xs py-2 bg-white/50 dark:bg-dark-800/50 rounded-lg overflow-x-auto">
                  <div className="text-center flex-shrink-0">
                    <div className="w-6 h-6 sm:w-8 sm:h-8 bg-blue-500 rounded-lg flex items-center justify-center mx-auto mb-1">
                      <Server className="w-3 h-3 sm:w-4 sm:h-4 text-white" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400 text-[10px] sm:text-xs">Phone</span>
                  </div>
                  <span className="text-gray-400 text-xs sm:text-sm">→</span>
                  <div className="text-center flex-shrink-0">
                    <div className="w-6 h-6 sm:w-8 sm:h-8 bg-orange-500 rounded-lg flex items-center justify-center mx-auto mb-1">
                      <Globe className="w-3 h-3 sm:w-4 sm:h-4 text-white" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400 text-[10px] sm:text-xs">Tailscale</span>
                  </div>
                  <span className="text-gray-400 text-xs sm:text-sm">→</span>
                  <div className="text-center flex-shrink-0">
                    <div className="w-6 h-6 sm:w-8 sm:h-8 bg-purple-500 rounded-lg flex items-center justify-center mx-auto mb-1">
                      <Shield className="w-3 h-3 sm:w-4 sm:h-4 text-white" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400 text-[10px] sm:text-xs">NetProtect</span>
                  </div>
                  <span className="text-gray-400 text-xs sm:text-sm">→</span>
                  <div className="text-center flex-shrink-0">
                    <div className="w-6 h-6 sm:w-8 sm:h-8 bg-green-500 rounded-lg flex items-center justify-center mx-auto mb-1">
                      <CheckCircle className="w-3 h-3 sm:w-4 sm:h-4 text-white" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400 text-[10px] sm:text-xs">Ad-free</span>
                  </div>
                </div>
              </div>
              
              {/* Step by step guide */}
              <div className="space-y-3">
                {/* Step 1: API Key */}
                <div className="relative">
                  <div className="absolute -left-2 top-0 w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs font-bold">1</div>
                  <div className="pl-6">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      API Key
                    </label>
                    <div className="relative">
                      <input
                        type={showApiKey ? 'text' : 'password'}
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        placeholder="tskey-api-k..."
                        className="w-full px-3 py-2 pr-10 bg-white dark:bg-dark-800 border border-gray-300 dark:border-dark-600 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <button
                        type="button"
                        onClick={() => setShowApiKey(!showApiKey)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                      >
                        {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    <div className="mt-1.5 p-2 bg-amber-50 dark:bg-amber-900/20 rounded text-xs text-amber-800 dark:text-amber-200">
                      <strong>How to get:</strong>{' '}
                      <a 
                        href="https://login.tailscale.com/admin/settings/keys"
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-600 dark:text-blue-400 hover:underline inline-flex items-center gap-1"
                      >
                        Tailscale → Settings → Keys → Generate API Key <ExternalLink className="w-3 h-3" />
                      </a>
                      <br />
                      <span className="text-amber-600 dark:text-amber-400">
                        ⚠️ Select permissions: <code className="bg-amber-100 dark:bg-amber-900/40 px-1 rounded">dns:read</code>, <code className="bg-amber-100 dark:bg-amber-900/40 px-1 rounded">dns:write</code>, <code className="bg-amber-100 dark:bg-amber-900/40 px-1 rounded">devices:read</code>, <code className="bg-amber-100 dark:bg-amber-900/40 px-1 rounded">routes:write</code>
                      </span>
                    </div>
                  </div>
                </div>
                
                {/* Step 2: Tailnet */}
                <div className="relative">
                  <div className="absolute -left-2 top-0 w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs font-bold">2</div>
                  <div className="pl-6">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Tailnet Name
                    </label>
                    <input
                      type="text"
                      value={tailnet}
                      onChange={(e) => setTailnet(e.target.value)}
                      placeholder="-"
                      className="w-full px-3 py-2 bg-white dark:bg-dark-800 border border-gray-300 dark:border-dark-600 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <div className="mt-1.5 p-2 bg-green-50 dark:bg-green-900/20 rounded text-xs text-green-800 dark:text-green-200">
                      <strong>💡 Tip:</strong> Just enter <code className="bg-green-100 dark:bg-green-900/40 px-1 rounded font-bold">-</code> (dash) — the API will auto-detect your tailnet.
                      <br />
                      <span className="text-gray-500 dark:text-gray-400">
                        Or find the name in{' '}
                        <a 
                          href="https://login.tailscale.com/admin/settings/general"
                          target="_blank"
                          rel="noreferrer"
                          className="text-blue-600 dark:text-blue-400 hover:underline"
                        >
                          Settings → General → Tailnet name
                        </a>
                        {' '}(e.g.: <code className="bg-gray-200 dark:bg-dark-600 px-1 rounded">tail1a2b3c.ts.net</code>)
                      </span>
                    </div>
                  </div>
                </div>
                
                <button
                  onClick={handleSaveCredentials}
                  disabled={saving || !apiKey.trim() || !tailnet.trim()}
                  className="w-full px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white rounded-lg font-medium flex items-center justify-center gap-2 transition-colors"
                >
                  {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                  Save Credentials
                </button>
              </div>
            </div>
          ) : (
            /* API Configured - Show Controls */
            <div className="space-y-4">
              {/* Status */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  <span className="text-sm text-gray-700 dark:text-gray-300">
                    Connected to <strong>{credentials.tailnet}</strong>
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => void handleRefreshStatus()}
                    disabled={refreshingStatus}
                    className="p-1.5 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-700 rounded"
                    title="Refresh"
                  >
                    <RefreshCw className={`w-4 h-4 ${refreshingStatus ? 'animate-spin' : ''}`} />
                  </button>
                  <button
                    onClick={handleDeleteCredentials}
                    className="p-1.5 text-red-500 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                    title="Delete credentials"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* DNS Configuration */}
              <div className="p-4 bg-white dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Shield className="w-5 h-5 text-purple-500" />
                    <h4 className="font-medium text-gray-900 dark:text-white">DNS Settings</h4>
                  </div>
                  {isNetProtectionDnsConfigured && (
                    <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 text-xs rounded-full flex items-center gap-1">
                      <CheckCircle className="w-3 h-3" />
                      NetProtection Active
                    </span>
                  )}
                </div>
                
                {dnsConfig && (
                  <div className="space-y-2 mb-4 text-sm">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Nameservers:</span>
                      <span className="text-gray-900 dark:text-white font-mono">
                        {dnsConfig.nameservers.length > 0 ? dnsConfig.nameservers.join(', ') : 'Not set'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Override Local DNS:</span>
                      <span className={dnsConfig.override_local_dns ? 'text-green-600' : 'text-gray-500'}>
                        {dnsConfig.override_local_dns ? 'Yes ✓' : 'No'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-500 dark:text-gray-400">MagicDNS:</span>
                      <span className={dnsConfig.magic_dns ? 'text-green-600' : 'text-gray-500'}>
                        {dnsConfig.magic_dns ? 'Yes ✓' : 'No'}
                      </span>
                    </div>
                  </div>
                )}
                
                {!isNetProtectionDnsConfigured && (
                  <div className="space-y-2">
                    <button
                      onClick={handleSetupNetProtectionDNS}
                      disabled={settingUpDns || !tailscaleIp}
                      className="w-full px-4 py-2 bg-purple-500 hover:bg-purple-600 disabled:bg-gray-400 text-white rounded-lg font-medium flex items-center justify-center gap-2 transition-colors text-sm sm:text-base"
                    >
                      {settingUpDns ? (
                        <Loader2 className="w-4 h-4" />
                      ) : (
                        <Zap className="w-4 h-4" />
                      )}
                      Setup NetProtection DNS for All Devices
                    </button>
                    <p className="text-xs text-gray-500 dark:text-gray-400 text-center">
                      This will set your EasyPi IP ({tailscaleIp || '...'}) as the DNS server for all devices in your Tailscale network.
                      <br />
                      Ads and threats will be blocked automatically on all connected devices.
                    </p>
                  </div>
                )}
                
                {!tailscaleIp && (
                  <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
                    Enable Remote Access first to get Tailscale IP
                  </p>
                )}
              </div>

              {/* Device Management */}
              <div className="p-3 sm:p-4 bg-white dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 sm:w-5 sm:h-5 text-blue-500" />
                    <h4 className="font-medium text-gray-900 dark:text-white text-sm sm:text-base">Devices ({devices.length})</h4>
                  </div>
                  <button
                    onClick={handleAutoApproveRoutes}
                    disabled={approvingRoutes}
                    className="px-3 py-1 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white text-xs sm:text-sm rounded-lg flex items-center gap-1 transition-colors self-start sm:self-center"
                    title="Approve pending routes advertised by this EasyPi only"
                  >
                    {approvingRoutes ? <Loader2 className="w-3 h-3 animate-spin" /> : <Router className="w-3 h-3" />}
                    Approve EasyPi
                  </button>
                </div>
                
                {/* Help text */}
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
                  All devices in your Tailscale network are shown here. 
                  <strong> Routes</strong> — local network access, 
                  <strong> Exit Node</strong> — all traffic through this device.
                </p>
                
                {devicesError ? (
                  <div className="p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
                    <div className="flex items-center gap-2 text-amber-800 dark:text-amber-200 text-sm">
                      <AlertCircle className="w-4 h-4 flex-shrink-0" />
                      <span>{devicesError}</span>
                    </div>
                    <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
                      Make sure your API key has <code className="bg-amber-100 dark:bg-amber-900/40 px-1 rounded">devices:read</code> permission.
                    </p>
                  </div>
                ) : devices.length === 0 ? (
                  <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-4">
                    No devices found in your Tailnet
                  </p>
                ) : (
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {devices.map((device) => {
                      const pendingRoutes = device.advertised_routes.filter(
                        r => !device.enabled_routes.includes(r)
                      )
                      
                      return (
                        <div
                          key={device.id}
                          className="p-3 bg-gray-50 dark:bg-dark-900 rounded-lg"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-gray-900 dark:text-white">
                                {device.hostname}
                              </span>
                              {device.os && (
                                <span className="text-xs text-gray-500 bg-gray-200 dark:bg-dark-700 px-1.5 py-0.5 rounded">
                                  {device.os}
                                </span>
                              )}
                            </div>
                            <span className="text-xs text-gray-500 font-mono">
                              {device.tailscale_ips[0]}
                            </span>
                          </div>
                          
                          <div className="flex items-center gap-2 text-xs">
                            {/* Routes */}
                            {device.advertised_routes.length > 0 && (
                              <div className="flex items-center gap-1">
                                <Router className="w-3 h-3 text-blue-500" />
                                <span className={pendingRoutes.length > 0 ? 'text-amber-600' : 'text-green-600'}>
                                  {device.enabled_routes.length}/{device.advertised_routes.length} routes
                                </span>
                                {pendingRoutes.length > 0 && (
                                  <button
                                    onClick={() => handleApproveDeviceRoutes(device)}
                                    className="ml-1 px-1.5 py-0.5 bg-amber-500 hover:bg-amber-600 text-white rounded text-xs"
                                  >
                                    Approve
                                  </button>
                                )}
                              </div>
                            )}
                            
                            {/* Exit Node */}
                            {device.is_exit_node && (
                              <div className="flex items-center gap-1">
                                <Globe className="w-3 h-3 text-green-500" />
                                <span className={device.is_exit_node_enabled ? 'text-green-600' : 'text-gray-500'}>
                                  Exit Node
                                </span>
                                <button
                                  onClick={() => handleToggleExitNode(device)}
                                  className={`ml-1 px-1.5 py-0.5 rounded text-xs ${
                                    device.is_exit_node_enabled
                                      ? 'bg-gray-300 dark:bg-dark-600 text-gray-700 dark:text-gray-300'
                                      : 'bg-green-500 text-white'
                                  }`}
                                >
                                  {device.is_exit_node_enabled ? 'Disable' : 'Enable'}
                                </button>
                              </div>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            </div>
          )}
      </div>
    </div>
  )
}
