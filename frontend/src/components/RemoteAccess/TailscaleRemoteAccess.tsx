/**
 * TailscaleRemoteAccess Component
 * 
 * Clean UI for remote VPN access:
 * 1. Welcome screen with explanation + Enable button
 * 2. After enable: Status panel showing Subnet Routing is active
 * 3. Additional options: Exit Node, etc.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { toast } from 'react-hot-toast'
import {
  Globe,
  Power,
  Loader2,
  CheckCircle,
  Wifi,
  AlertCircle,
  RefreshCw,
  Network,
  Shield,
  ExternalLink,
  Info,
  Copy,
  Eye,
  EyeOff,
  Key,
  Download,
  Upload,
  Trash2,
} from 'lucide-react'
import { copyToClipboard as copyToClipboardUtil } from '../../utils/clipboard'
import {
  enableRemoteAccess,
  disableRemoteAccess,
  getRemoteAccessStatus,
  getConfig,
  saveAuthkey,
  getInstallStatus,
  installTailscale,
  uninstallTailscale,
  type TailscaleStatus,
  type InstallStatusResponse,
} from '../../api/tailscaleRemoteAccess'
import TailscaleAdminPanel from './TailscaleAdminPanel'
import FastMobileRelay from './FastMobileRelay'
import Modal from '../common/Modal'
import ActionPreviewPanel from '../../features/actions/ActionPreviewPanel'
import useActionPreview from '../../features/actions/useActionPreview'
import type { ActionPreviewId } from '../../api/actionPreview'

const STATUS_POLL_INTERVAL = 15000
const POST_INSTALL_POLL_INTERVAL = 3000
const POST_INSTALL_POLL_DURATION = 60000

export default function TailscaleRemoteAccess() {
  const [status, setStatus] = useState<TailscaleStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshingStatus, setRefreshingStatus] = useState(false)
  const [actionInProgress, setActionInProgress] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  // Auth key state
  const [hasAuthkey, setHasAuthkey] = useState<boolean | null>(null)
  const [authkeyInput, setAuthkeyInput] = useState('')
  const [showAuthkey, setShowAuthkey] = useState(false)
  const [savingAuthkey, setSavingAuthkey] = useState(false)

  // Install state
  const [installStatus, setInstallStatus] = useState<InstallStatusResponse | null>(null)
  const [installing, setInstalling] = useState(false)
  const [uninstalling, setUninstalling] = useState(false)
  const [pendingRuntimeAction, setPendingRuntimeAction] = useState<'install' | 'uninstall' | null>(null)
  const postInstallPollRef = useRef<number | null>(null)

  const previewActionId: ActionPreviewId | null =
    pendingRuntimeAction === 'install'
      ? 'remote-access.install'
      : pendingRuntimeAction === 'uninstall'
        ? 'remote-access.uninstall'
        : null

  const actionPreviewQuery = useActionPreview(
    previewActionId,
    status?.hostname || 'tailscale',
    Boolean(previewActionId),
  )

  // Fetch config (check if authkey exists)
  const fetchConfig = useCallback(async () => {
    try {
      const config = await getConfig()
      setHasAuthkey(config.has_authkey)
    } catch {
      setHasAuthkey(false)
    }
  }, [])

  // Fetch install status
  const fetchInstallStatus = useCallback(async () => {
    try {
      const data = await getInstallStatus()
      setInstallStatus(data)
      if (data.installing) {
        setInstalling(true)
      }
    } catch {
      // If we can't fetch, assume not installed
      setInstallStatus({ installed: false, version: null, installing: false })
    }
  }, [])

  // Fetch status
  const fetchStatus = useCallback(async () => {
    try {
      const data = await getRemoteAccessStatus()
      setStatus(data)
      setError(null)
    } catch (err: any) {
      // API might not be available yet
      setStatus(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleRefreshStatus = async () => {
    if (refreshingStatus) return
    setRefreshingStatus(true)
    try {
      await Promise.all([fetchInstallStatus(), fetchConfig(), fetchStatus()])
    } finally {
      setRefreshingStatus(false)
    }
  }

  useEffect(() => {
    fetchInstallStatus()
    fetchConfig()
    fetchStatus()
    const interval = setInterval(fetchStatus, STATUS_POLL_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchConfig, fetchStatus, fetchInstallStatus])

  const stopPostInstallPoll = useCallback(() => {
    if (postInstallPollRef.current) {
      clearInterval(postInstallPollRef.current)
      postInstallPollRef.current = null
    }
  }, [])

  const startPostInstallPoll = useCallback(() => {
    stopPostInstallPoll()
    const startedAt = Date.now()
    postInstallPollRef.current = window.setInterval(async () => {
      await fetchInstallStatus()
      await fetchStatus()
      if (Date.now() - startedAt > POST_INSTALL_POLL_DURATION) {
        stopPostInstallPoll()
      }
    }, POST_INSTALL_POLL_INTERVAL)
  }, [fetchInstallStatus, fetchStatus, stopPostInstallPoll])

  // Handle install Tailscale
  const executeInstall = async () => {
    setInstalling(true)
    setError(null)

    try {
      const result = await installTailscale()

      if (result.success) {
        toast.success(result.message)
        await fetchInstallStatus()
        await fetchStatus()
        startPostInstallPoll()
      } else {
        const errMsg = result.error?.message || 'Failed to install Tailscale'
        setError(errMsg)
        toast.error(errMsg)
      }
    } catch (err: any) {
      const errMsg = err.response?.data?.error?.message || err.message || 'Failed to install Tailscale'
      setError(errMsg)
      toast.error(errMsg)
    } finally {
      setInstalling(false)
    }
  }

  const handleInstall = () => {
    setPendingRuntimeAction('install')
  }

  const handleSaveAuthkey = async () => {
    if (!authkeyInput.trim()) {
      toast.error('Please enter an auth key')
      return
    }
    
    setSavingAuthkey(true)
    try {
      const result = await saveAuthkey(authkeyInput.trim())
      if (result.success) {
        setHasAuthkey(true)
        setAuthkeyInput('')
        toast.success('Auth key saved successfully!')
      } else {
        toast.error('Failed to save auth key')
      }
    } catch (err: any) {
      toast.error(err.message || 'Failed to save auth key')
    } finally {
      setSavingAuthkey(false)
    }
  }

  const handleEnable = async () => {
    if (!hasAuthkey) {
      setError('Please configure an auth key before enabling')
      toast.error('Please configure an auth key first')
      return
    }
    
    setActionInProgress(true)
    setError(null)
    
    try {
      const result = await enableRemoteAccess()
      
      if (result.success) {
        if (result.pending || (result.status && !result.status.tailscale_running)) {
          toast.success('Remote Access is starting. Waiting for Tailscale to come online.')
        } else {
          toast.success('Remote Access enabled! Subnet Routing is now active.')
        }
        if (result.status) {
          setStatus(result.status)
        } else {
          await fetchStatus()
        }
      } else {
        const errMsg = result.error?.message || 'Failed to enable'
        setError(errMsg)
        toast.error(errMsg)
      }
    } catch (err: any) {
      const errMsg = err.response?.data?.error?.message || err.message || 'Failed to enable'
      setError(errMsg)
      toast.error(errMsg)
    } finally {
      setActionInProgress(false)
    }
  }

  const handleDisable = async () => {
    setActionInProgress(true)
    setError(null)
    
    try {
      const result = await disableRemoteAccess()
      
      if (result.success) {
        toast.success('Remote Access disabled')
        if (result.status) {
          setStatus(result.status)
        } else {
          await fetchStatus()
        }
      } else {
        const errMsg = result.error?.message || 'Failed to disable'
        setError(errMsg)
        toast.error(errMsg)
      }
    } catch (err: any) {
      const errMsg = err.response?.data?.error?.message || err.message || 'Failed to disable'
      setError(errMsg)
      toast.error(errMsg)
    } finally {
      setActionInProgress(false)
    }
  }

  const executeUninstall = async () => {
    setUninstalling(true)
    setError(null)

    try {
      const result = await uninstallTailscale()
      if (result.success) {
        toast.success(result.message || 'Tailscale uninstalled')
      } else {
        const errMsg = result.error?.message || 'Failed to uninstall Tailscale'
        setError(errMsg)
        toast.error(errMsg)
      }
    } catch (err: any) {
      const errMsg = err.response?.data?.error?.message || err.message || 'Failed to uninstall Tailscale'
      setError(errMsg)
      toast.error(errMsg)
    } finally {
      setUninstalling(false)
      await fetchInstallStatus()
      await fetchStatus()
    }
  }

  const handleUninstall = () => {
    setPendingRuntimeAction('uninstall')
  }

  const handleConfirmRuntimeAction = () => {
    const action = pendingRuntimeAction
    setPendingRuntimeAction(null)

    if (action === 'install') {
      void executeInstall()
      return
    }

    if (action === 'uninstall') {
      void executeUninstall()
    }
  }

  const copyToClipboard = async (text: string) => {
    const success = await copyToClipboardUtil(text)
    if (success) {
      toast.success('Copied!')
    } else {
      toast.error('Failed to copy')
    }
  }

  const isActive = status?.enabled && status?.tailscale_running
  const isPending = status?.enabled && !status?.tailscale_running
  const tailscaleIp = status?.tailscale_ips?.[0] || '100.64.0.10'
  const aclIpSnippet = `{
  "hosts": {
    "easypi": "${tailscaleIp}"
  },
  "acls": [
    { "action": "accept", "src": ["you@example.com"], "dst": ["easypi:443"] }
  ]
}`
  const aclTagSnippet = `{
  "groups": {
    "group:admins": ["you@example.com"]
  },
  "tagOwners": {
    "tag:easypi": ["group:admins"]
  },
  "acls": [
    { "action": "accept", "src": ["group:admins"], "dst": ["tag:easypi:443"] }
  ]
}`

  // Loading state
  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Globe className="w-8 h-8 text-blue-500" />
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Remote VPN Access</h1>
        </div>
        <div className="bg-white dark:bg-dark-800 rounded-xl p-12 border border-gray-200 dark:border-dark-700 flex items-center justify-center">
          <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Globe className="w-8 h-8 text-blue-500" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Remote VPN Access</h1>
            <p className="text-gray-500 dark:text-gray-400 text-sm">
              Access your home network from anywhere in the world
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void handleRefreshStatus()}
            disabled={refreshingStatus}
            className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-dark-700 rounded-lg transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-5 h-5 ${refreshingStatus ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Content - depends on state */}
      {!isActive ? (
        /* ============ NOT ACTIVE - Welcome Screen ============ */
        <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 overflow-hidden">
          {/* Hero Section */}
          <div className="p-8 text-center border-b border-gray-200 dark:border-dark-700">
            <div className="w-20 h-20 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center mx-auto mb-6">
              <Wifi className="w-10 h-10 text-blue-500" />
            </div>
            
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-3">
              Connect to Your Home Network Remotely
            </h2>
            
            <p className="text-gray-600 dark:text-gray-400 max-w-lg mx-auto mb-6">
              Enable Remote Access to securely connect to all devices on your home network 
              from anywhere using Tailscale VPN. Access your NAS, smart home devices, 
              cameras, and more — as if you were at home.
            </p>

            {/* Features */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-2xl mx-auto mb-8">
              <div className="p-4 bg-gray-50 dark:bg-dark-900 rounded-lg">
                <Network className="w-6 h-6 text-blue-500 mx-auto mb-2" />
                <p className="text-sm font-medium text-gray-900 dark:text-white">Subnet Routing</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">Access all LAN devices</p>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-dark-900 rounded-lg">
                <Shield className="w-6 h-6 text-green-500 mx-auto mb-2" />
                <p className="text-sm font-medium text-gray-900 dark:text-white">Secure</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">End-to-end encrypted</p>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-dark-900 rounded-lg">
                <Globe className="w-6 h-6 text-purple-500 mx-auto mb-2" />
                <p className="text-sm font-medium text-gray-900 dark:text-white">Zero Config</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">No port forwarding</p>
              </div>
            </div>

            {/* Auth Key Setup Section */}
            <div className="max-w-md mx-auto mb-8 p-4 bg-gray-50 dark:bg-dark-900 rounded-lg border border-gray-200 dark:border-dark-700">
              <div className="flex items-center gap-2 mb-3">
                <Key className="w-5 h-5 text-blue-500" />
                <h3 className="font-medium text-gray-900 dark:text-white">Tailscale Setup</h3>
              </div>
              
              {/* Install Tailscale Section */}
              {installStatus && !installStatus.installed ? (
                <div className="mb-4 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
                  <div className="flex items-center gap-2 mb-2 text-amber-800 dark:text-amber-200 text-sm">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    <span>Tailscale is not installed on this server</span>
                  </div>
                  
                  {/* Install Button or Progress */}
                  {installing ? (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                        <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
                        <span>Installing Tailscale...</span>
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        The installer reports only its final result; this may take a few minutes.
                      </p>
                    </div>
                  ) : (
                    <button
                      onClick={handleInstall}
                      className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors font-medium"
                    >
                      <Download className="w-4 h-4" />
                      Install Tailscale on Server
                    </button>
                  )}
                </div>
              ) : installStatus?.installed ? (
                <div className="mb-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                  <div className="flex items-center justify-between gap-2 text-green-800 dark:text-green-200 text-sm">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 flex-shrink-0" />
                      <span>Tailscale installed {installStatus.version ? `(v${installStatus.version})` : ''}</span>
                    </div>
                    <button
                      onClick={handleUninstall}
                      disabled={uninstalling || actionInProgress}
                      className="px-3 py-1 text-xs border border-red-200 dark:border-red-800/60 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-md transition-colors disabled:opacity-60"
                    >
                      {uninstalling ? 'Uninstalling...' : 'Uninstall'}
                    </button>
                  </div>
                </div>
              ) : null}
              
              {/* Download Tailscale Client (for other devices) */}
              <a
                href="https://tailscale.com/download"
                target="_blank"
                rel="noreferrer"
                className="w-full flex items-center justify-center gap-2 px-4 py-2 mb-4 bg-gray-100 dark:bg-dark-800 hover:bg-gray-200 dark:hover:bg-dark-700 text-gray-700 dark:text-gray-300 rounded-lg transition-colors"
              >
                <Download className="w-4 h-4" />
                Download Tailscale Client
                <ExternalLink className="w-3 h-3" />
              </a>
              
              {/* Auth Key Input */}
              <div className="space-y-2">
                <label className="block text-sm text-gray-600 dark:text-gray-400">
                  Auth Key <span className="text-gray-400 dark:text-gray-500">(from Tailscale Admin)</span>
                </label>
                <div className="relative">
                  <input
                    type={showAuthkey ? 'text' : 'password'}
                    value={authkeyInput}
                    onChange={(e) => setAuthkeyInput(e.target.value)}
                    placeholder={hasAuthkey ? '••••••••••••••••••••' : 'tskey-auth-...'}
                    className="w-full px-3 py-2 pr-20 bg-white dark:bg-dark-800 border border-gray-300 dark:border-dark-600 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowAuthkey(!showAuthkey)}
                    className="absolute right-16 top-1/2 -translate-y-1/2 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                  >
                    {showAuthkey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                  <button
                    type="button"
                    onClick={handleSaveAuthkey}
                    disabled={savingAuthkey || !authkeyInput.trim()}
                    className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-1 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white text-xs rounded transition-colors"
                  >
                    {savingAuthkey ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Save'}
                  </button>
                </div>
                {hasAuthkey && (
                  <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" />
                    Auth key is configured
                  </p>
                )}
                {hasAuthkey === false && (
                  <p className="text-xs text-amber-600 dark:text-amber-400 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3" />
                    No auth key configured - enter your key above
                  </p>
                )}
              </div>
            </div>

            {/* Enable Button */}
            <button
              onClick={handleEnable}
              disabled={actionInProgress}
              className="px-8 py-3 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-400 text-white rounded-xl font-semibold text-lg flex items-center justify-center gap-3 mx-auto transition-colors"
            >
              {actionInProgress ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Enabling...
                </>
              ) : (
                <>
                  <Power className="w-5 h-5" />
                  Enable Remote Access
                </>
              )}
            </button>

            {/* Pending */}
            {isPending && (
              <div className="mt-4 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg max-w-md mx-auto">
                <div className="flex items-center gap-2 text-amber-800 dark:text-amber-200 text-sm">
                  <Info className="w-4 h-4 flex-shrink-0" />
                  <span>
                    Tailscale is starting
                    {status?.backend_state ? ` (state: ${status.backend_state})` : ''}. This can take a minute.
                  </span>
                </div>
                {status?.last_error && (
                  <p className="mt-2 text-xs text-amber-700 dark:text-amber-300 break-words">
                    {status.last_error}
                  </p>
                )}
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg max-w-md mx-auto">
                <div className="flex items-center gap-2 text-red-700 dark:text-red-300 text-sm">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  {error}
                </div>
              </div>
            )}
          </div>

          {/* How it works */}
          <div className="p-6 bg-gray-50 dark:bg-dark-900">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">How to connect:</h3>
            <div className="space-y-3 text-sm text-gray-600 dark:text-gray-400">
              <div className="flex items-start gap-3">
                <span className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">1</span>
                <p>Click "Enable Remote Access" above</p>
              </div>
              <div className="flex items-start gap-3">
                <span className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">2</span>
                <p>
                  Install Tailscale on your devices from{' '}
                  <a href="https://tailscale.com/download" target="_blank" rel="noreferrer" className="text-blue-500 hover:underline inline-flex items-center gap-1">
                    tailscale.com/download <ExternalLink className="w-3 h-3" />
                  </a>
                </p>
              </div>
              <div className="flex items-start gap-3">
                <span className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">3</span>
                <p>Log in with the same Tailscale account on all devices</p>
              </div>
              <div className="flex items-start gap-3">
                <span className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">4</span>
                <p>Approve subnet routes in Tailscale Admin Console</p>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* ============ ACTIVE - Status Dashboard ============ */
        <>
          {/* Status Banner */}
          <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-green-500 rounded-full flex items-center justify-center">
                  <CheckCircle className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h3 className="font-semibold text-green-800 dark:text-green-200">
                    Subnet Routing Active
                  </h3>
                  <p className="text-sm text-green-700 dark:text-green-300">
                    Your home network is accessible remotely via Tailscale
                  </p>
                </div>
              </div>
              <button
                onClick={handleDisable}
                disabled={actionInProgress}
                className="px-4 py-2 bg-red-500 hover:bg-red-600 disabled:bg-red-400 text-white rounded-lg font-medium flex items-center gap-2 transition-colors"
              >
                {actionInProgress ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Power className="w-4 h-4" />
                )}
                Disable
              </button>
              {installStatus?.installed && (
                <button
                  onClick={handleUninstall}
                  disabled={uninstalling || actionInProgress}
                  className="px-4 py-2 border border-red-200 dark:border-red-800/60 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg font-medium flex items-center gap-2 transition-colors disabled:opacity-60"
                >
                  {uninstalling ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Trash2 className="w-4 h-4" />
                  )}
                  Uninstall
                </button>
              )}
            </div>
          </div>

          {/* Connection Info */}
          <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Connection Details
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {/* Local Network */}
              <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Network className="w-4 h-4 text-blue-500" />
                  <p className="text-gray-500 dark:text-gray-400 text-sm">Local Network</p>
                </div>
                <p className="text-gray-900 dark:text-white font-mono text-lg">
                  {status?.lan_cidr || 'Detecting...'}
                </p>
              </div>

              {/* Tailscale IP */}
              <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Globe className="w-4 h-4 text-purple-500" />
                  <p className="text-gray-500 dark:text-gray-400 text-sm">Tailscale IP</p>
                </div>
                <div className="flex items-center gap-2">
                  <p className="text-gray-900 dark:text-white font-mono text-lg">
                    {status?.tailscale_ips?.[0] || '—'}
                  </p>
                  {status?.tailscale_ips?.[0] && (
                    <button
                      onClick={() => copyToClipboard(status.tailscale_ips[0])}
                      className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>

              {/* Status */}
              <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Wifi className="w-4 h-4 text-green-500" />
                  <p className="text-gray-500 dark:text-gray-400 text-sm">Status</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                  <p className="text-green-600 dark:text-green-400 font-medium">Connected</p>
                </div>
              </div>

              {/* Hostname */}
              {status?.hostname && (
                <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-4">
                  <p className="text-gray-500 dark:text-gray-400 text-sm mb-2">Hostname</p>
                  <p className="text-gray-900 dark:text-white">{status.hostname}</p>
                </div>
              )}

              {/* Tailnet */}
              {status?.tailnet && (
                <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-4">
                  <p className="text-gray-500 dark:text-gray-400 text-sm mb-2">Network</p>
                  <p className="text-gray-900 dark:text-white">{status.tailnet}</p>
                </div>
              )}

              {/* Advertised Routes */}
              <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-4">
                <p className="text-gray-500 dark:text-gray-400 text-sm mb-2">Advertised Routes</p>
                <p className="text-gray-900 dark:text-white">
                  {status?.advertised_routes?.length || 0} subnet(s)
                </p>
              </div>
            </div>

            {/* Tailscale Admin API Panel */}
            <div className="mt-4">
              <TailscaleAdminPanel tailscaleIp={status?.tailscale_ips?.[0]} />
            </div>
          </div>

          {/* Taildrop to PiCloud */}
          <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 p-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
              <div className="flex items-center gap-2">
                <Upload className="w-5 h-5 text-blue-500" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Send files directly to PiCloud
                </h3>
              </div>
              <span
                className={`inline-flex w-fit items-center rounded-full px-2.5 py-1 text-xs font-medium ${
                  status?.taildrop_importer_active
                    ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                    : 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
                }`}
              >
                {status?.taildrop_importer_active ? 'EasyPi receiver active' : 'Receiver not active'}
              </span>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              On Android, select a file, tap <strong>Share</strong>, choose <strong>Tailscale</strong>,
              then select this EasyPi. PiCloud sorts completed files into <strong>Photos</strong>,{' '}
              <strong>Videos</strong>, <strong>Documents</strong>, <strong>Music</strong>,{' '}
              <strong>Encrypted</strong>, or <strong>Files</strong>. The browser does not need to stay open.
            </p>
            <p className="mb-4 text-xs text-gray-500 dark:text-gray-400">
              File size is limited by available storage. EasyPi keeps{' '}
              {status?.taildrop_reserve_bytes
                ? `${(status.taildrop_reserve_bytes / 1024 ** 3).toFixed(1)} GB`
                : '5.0 GB'}{' '}
              free for the system.
            </p>
            <ol className="list-decimal list-inside space-y-2 text-sm text-gray-700 dark:text-gray-300">
              <li>
                Enable <strong>Send Files</strong> in{' '}
                <a
                  href="https://login.tailscale.com/admin/settings/general"
                  target="_blank"
                  rel="noreferrer"
                  className="text-blue-600 dark:text-blue-400 hover:underline"
                >
                  Tailscale General settings
                </a>.
              </li>
              <li>Sign in to Tailscale with the same account on EasyPi and every sending phone.</li>
              <li>Keep the EasyPi device owned by that account; Taildrop cannot use a tagged device.</li>
            </ol>
            {status?.tailscale_running && !status?.taildrop_device_eligible && (
              <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-300">
                <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                <span>
                  This EasyPi appears to be tagged or has no personal Tailscale owner. Taildrop will
                  not offer it as a destination until it is signed in as the same user as the phone.
                </span>
              </div>
            )}
            {status?.taildrop_error && (
              <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800/60 dark:bg-red-900/20 dark:text-red-300">
                <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                <span>{status.taildrop_error}</span>
              </div>
            )}
          </div>

          <FastMobileRelay />

          {/* Tailscale ACL Quick Setup */}
          <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 p-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-500" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Tailscale Access (ACL)</h3>
              </div>
              <a
                href="https://login.tailscale.com/admin/acls/file"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-sm text-blue-600 hover:underline"
              >
                Open Access Controls <ExternalLink className="w-4 h-4" />
              </a>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
              ACLs are simple rules that say who can open EasyPi through Tailscale.
              Open the link, paste one option, then save.
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
              Replace <span className="font-mono">you@example.com</span> with your Tailscale login.
              Port <span className="font-mono">443</span> is the web panel, port <span className="font-mono">8000</span> is the backend.
            </p>
            {!status?.tailscale_ips?.[0] && (
              <p className="text-xs text-amber-600 dark:text-amber-400 mb-3">
                IP not detected. Please set it manually.
              </p>
            )}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-3 border border-gray-200 dark:border-dark-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Option A: Single user (fixed IP)</span>
                  <button
                    onClick={() => copyToClipboard(aclIpSnippet)}
                    className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    Copy
                  </button>
                </div>
                <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">
                  One person only. Works when EasyPi IP does not change. If it changes, update the rule.
                </p>
                <pre className="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap font-mono">{aclIpSnippet}</pre>
              </div>
              <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-3 border border-gray-200 dark:border-dark-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Option B: Multiple users (group)</span>
                  <button
                    onClick={() => copyToClipboard(aclTagSnippet)}
                    className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    Copy
                  </button>
                </div>
                <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">
                  Add people to the group. Tag the EasyPi device once, and rules keep working even if IP changes.
                </p>
                <pre className="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap font-mono">{aclTagSnippet}</pre>
              </div>
            </div>
          </div>

          {/* How Remote Access Works */}
          <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 overflow-hidden">
            <div className="p-4 border-b border-gray-200 dark:border-dark-700">
              <div className="flex items-center gap-2">
                <Info className="w-5 h-5 text-blue-500" />
                <h3 className="font-semibold text-gray-900 dark:text-white">How It Works</h3>
              </div>
            </div>
            
            <div className="p-4 space-y-6">
              {/* What is Remote Access */}
              <div>
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">🌐 What is Remote Access?</h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Remote Access gives you secure access to your home network from anywhere in the world via Tailscale VPN. 
                  Connect to your NAS, cameras, printers, and other devices as if you were at home.
                </p>
              </div>

              {/* Subnet Router */}
              <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">📡 Subnet Router</h4>
                <p className="text-sm text-blue-700 dark:text-blue-300 mb-3">
                  Access all devices on your home network, even those without Tailscale installed. 
                  Just connect to VPN — and your phone or laptop can "see" your entire home network.
                </p>
                <div className="bg-white dark:bg-dark-800 rounded p-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="bg-purple-100 dark:bg-purple-900/30 px-2 py-1 rounded">📱 Your Device</span>
                    <span>→</span>
                    <span className="bg-blue-100 dark:bg-blue-900/30 px-2 py-1 rounded">🔒 Tailscale</span>
                    <span>→</span>
                    <span className="bg-green-100 dark:bg-green-900/30 px-2 py-1 rounded">🍓 EasyPi</span>
                    <span>→</span>
                    <span className="bg-orange-100 dark:bg-orange-900/30 px-2 py-1 rounded">🏠 Home Network</span>
                  </div>
                </div>
              </div>

              {/* Exit Node */}
              <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium text-green-800 dark:text-green-200">🚀 Exit Node</h4>
                  <div className={`flex items-center gap-2 px-2 py-0.5 rounded-full text-xs font-medium ${
                    status?.exit_node_advertised 
                      ? 'bg-green-200 dark:bg-green-800/50 text-green-800 dark:text-green-200'
                      : 'bg-gray-200 dark:bg-dark-600 text-gray-600 dark:text-gray-400'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      status?.exit_node_advertised ? 'bg-green-600 animate-pulse' : 'bg-gray-400'
                    }`}></span>
                    {status?.exit_node_advertised ? 'Active' : 'Inactive'}
                  </div>
                </div>
                <p className="text-sm text-green-700 dark:text-green-300 mb-3">
                  Route all your internet traffic through EasyPi. 
                  Useful for:
                </p>
                <ul className="text-sm text-green-700 dark:text-green-300 list-disc list-inside mb-3 space-y-1">
                  <li>Secure browsing on public Wi-Fi</li>
                  <li>Using your home IP while traveling abroad</li>
                  <li>Bypassing regional restrictions</li>
                </ul>
                <div className="bg-white dark:bg-dark-800 rounded p-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="bg-blue-100 dark:bg-blue-900/30 px-2 py-1 rounded">🌍 Internet</span>
                    <span>→</span>
                    <span className="bg-blue-100 dark:bg-blue-900/30 px-2 py-1 rounded">🔒 Tailscale</span>
                    <span>→</span>
                    <span className="bg-green-100 dark:bg-green-900/30 px-2 py-1 rounded">🍓 EasyPi (Exit Node)</span>
                    <span>→</span>
                    <span className="bg-orange-100 dark:bg-orange-900/30 px-2 py-1 rounded">🏠 Home Router</span>
                  </div>
                </div>
              </div>

              {/* How to enable Exit Node */}
              <div className="p-4 bg-amber-50 dark:bg-amber-900/20 rounded-lg">
                <h4 className="font-medium text-amber-800 dark:text-amber-200 mb-3">⚙️ How to Enable Exit Node</h4>
                <div className="space-y-2 text-sm text-amber-700 dark:text-amber-300">
                  <div className="flex items-start gap-2">
                    <span className="bg-amber-200 dark:bg-amber-800/50 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">1</span>
                    <p>Enable Remote Access in EasyPi (button above)</p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="bg-amber-200 dark:bg-amber-800/50 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">2</span>
                    <p>
                      Open{' '}
                      <a 
                        href="https://login.tailscale.com/admin/machines" 
                        target="_blank" 
                        rel="noreferrer"
                        className="underline hover:no-underline"
                      >
                        Tailscale Admin Console
                      </a>
                      {' '}→ find EasyPi → enable "Exit Node"
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="bg-amber-200 dark:bg-amber-800/50 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">3</span>
                    <p>On your phone/PC open Tailscale → "Use Exit Node" → select EasyPi</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Error */}
      {(error || status?.last_error) && (
        <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                <p className="text-red-700 dark:text-red-300 text-sm">
                  {error || status?.last_error}
                </p>
              </div>
            </div>
          )}
        </>
      )}

      <Modal
        isOpen={Boolean(pendingRuntimeAction)}
        onClose={() => setPendingRuntimeAction(null)}
        title={
          pendingRuntimeAction === 'install'
            ? 'Install Tailscale'
            : pendingRuntimeAction === 'uninstall'
              ? 'Uninstall Tailscale'
              : 'Action Preview'
        }
        footer={
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={() => setPendingRuntimeAction(null)}
              className="rounded-lg bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300 dark:hover:bg-dark-600"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirmRuntimeAction}
              disabled={actionPreviewQuery.isLoading || actionPreviewQuery.isFetching}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:bg-gray-400"
            >
              Continue
            </button>
          </div>
        }
      >
        <ActionPreviewPanel
          preview={actionPreviewQuery.data}
          isLoading={actionPreviewQuery.isLoading || actionPreviewQuery.isFetching}
          errorMessage={actionPreviewQuery.error instanceof Error ? actionPreviewQuery.error.message : null}
        />
      </Modal>
    </div>
  )
}
