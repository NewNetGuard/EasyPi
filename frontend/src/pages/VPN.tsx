import { useState, useEffect, useRef, useCallback } from 'react'
import { toast } from 'react-hot-toast'
import { 
  Shield, 
  Server, 
  Users, 
  Download, 
  QrCode, 
  Trash2, 
  Plus,
  Loader2,
  CheckCircle,
  AlertTriangle,
  Globe,
  Router,
  Smartphone,
  Laptop,
  Key,
  Copy,
  ExternalLink,
  RefreshCw,
  Info,
  ArrowRight,
  Network,
  Lock,
  Wifi
} from 'lucide-react'
import api from '../api/client'
import { getApiV1BaseUrl } from '../utils/apiBase'
import { copyToClipboard as copyToClipboardUtil } from '../utils/clipboard'
import Modal from '../components/common/Modal'
import ActionPreviewPanel from '../features/actions/ActionPreviewPanel'
import useActionPreview from '../features/actions/useActionPreview'
import type { ActionPreviewId } from '../api/actionPreview'

const API_URL = getApiV1BaseUrl()
const WG_POLL_INTERVAL = 3000
const WG_POLL_DURATION = 120000

interface WireGuardStatus {
  installed: boolean
  running: boolean
  port: number
  cidr: string
  dns: string
  endpoint: string
  server_public_key: string
  peers: PeerInfo[]
}

interface PeerInfo {
  name: string
  address: string
  public_key: string
  created_at?: string
  rx_bytes?: number
  tx_bytes?: number
  latest_handshake?: string
}

export default function VPN() {
  const [pendingAction, setPendingAction] = useState<'install' | 'reset' | 'uninstall' | null>(null)
  const [status, setStatus] = useState<WireGuardStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [installing, setInstalling] = useState(false)
  const [resetting, setResetting] = useState(false)
  const [uninstalling, setUninstalling] = useState(false)
  const [addingClient, setAddingClient] = useState(false)
  const [showAddClient, setShowAddClient] = useState(false)
  const [newClientName, setNewClientName] = useState('')
  const [publicIP, setPublicIP] = useState('')
  const [copied, setCopied] = useState<string | null>(null)
  const [qrClient, setQrClient] = useState<string | null>(null)
  const wgPollRef = useRef<number | null>(null)
  const wgPollStartedAtRef = useRef(0)

  const loadStatus = useCallback(async () => {
    setLoading(true)
    try {
      const response = await api.get('/wireguard/status')
      setStatus(response.data)
    } catch (error) {
      console.error('Failed to load WireGuard status:', error)
      setStatus(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const detectPublicIP = useCallback(async () => {
    try {
      // Keep browser connections same-origin so the panel's strict CSP remains
      // intact. The authenticated backend performs the optional lookup.
      const response = await api.get('/wireguard/public-ip')
      setPublicIP(response.data?.ip || '')
    } catch {
      setPublicIP('')
    }
  }, [])

  useEffect(() => {
    loadStatus()
    detectPublicIP()
  }, [loadStatus, detectPublicIP])

  const stopWireGuardPoll = useCallback(() => {
    if (wgPollRef.current) {
      clearInterval(wgPollRef.current)
      wgPollRef.current = null
    }
  }, [])

  const startWireGuardPoll = useCallback(() => {
    stopWireGuardPoll()
    wgPollStartedAtRef.current = Date.now()

    wgPollRef.current = window.setInterval(async () => {
      try {
        const response = await api.get('/wireguard/status')
        setStatus(response.data)
        if (response.data?.installed) {
          stopWireGuardPoll()
        }
      } catch {
        // Ignore transient errors while backend restarts
      }

      if (Date.now() - wgPollStartedAtRef.current > WG_POLL_DURATION) {
        stopWireGuardPoll()
      }
    }, WG_POLL_INTERVAL)
  }, [stopWireGuardPoll])

  useEffect(() => {
    return () => stopWireGuardPoll()
  }, [stopWireGuardPoll])

  const previewActionId: ActionPreviewId | null =
    pendingAction === 'install'
      ? 'wireguard.install'
      : pendingAction === 'reset'
        ? 'wireguard.reset'
        : pendingAction === 'uninstall'
          ? 'wireguard.uninstall'
          : null

  const actionPreviewQuery = useActionPreview(previewActionId, 'wireguard', Boolean(previewActionId))

  const executeInstall = async () => {
    setInstalling(true)
    startWireGuardPoll()
    try {
      const port = 51820
      const host = publicIP || window.location.hostname || ''
      if (!host) {
        toast.error('Cannot detect server address. Please set your public IP or domain.')
        stopWireGuardPoll()
        return
      }
      const endpoint = host.includes(':') ? host : `${host}:${port}`
      await api.post('/wireguard/install', {
        port: port,
        cidr: '10.8.0.0/24',
        dns: '1.1.1.1',
        endpoint,
      }, { timeout: 1800000 })
      
      // Poll status until installation completes with error recovery
      let consecutiveErrors = 0
      for (let attempt = 0; attempt < 20; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 2000))
        try {
          const response = await api.get('/wireguard/status')
          consecutiveErrors = 0
          setStatus(response.data)
          if (response.data?.installed) {
            stopWireGuardPoll()
            toast.success('WireGuard installed successfully')
            break
          }
        } catch {
          consecutiveErrors++
          // If server is temporarily unavailable (restarting), wait and retry
          if (consecutiveErrors >= 3) {
            toast('Server restarting, refreshing page...', { icon: 'ℹ️' })
            await new Promise((resolve) => setTimeout(resolve, 3000))
            window.location.reload()
            return
          }
        }
      }
    } catch (error) {
      console.error('Failed to install WireGuard:', error)
      const axiosError = error as any
      const statusCode = axiosError?.response?.status
      const message = typeof axiosError?.message === 'string' ? axiosError.message : ''
      if (statusCode === 504 || message.includes('timeout') || message.includes('Network') || message.includes('server error')) {
        toast('Installation still running in background, checking status...', { icon: 'ℹ️' })
        return
      }
      // Check if it's a network error (server crashed during install)
      if (error instanceof Error && (error.message.includes('Network') || error.message.includes('fetch'))) {
        toast('Server restarting after WireGuard installation, refreshing...', { icon: 'ℹ️' })
        await new Promise((resolve) => setTimeout(resolve, 5000))
        window.location.reload()
        return
      }
      if (error instanceof Error) {
        toast.error(error.message)
      } else {
        toast.error('Failed to install WireGuard')
      }
    } finally {
      setInstalling(false)
    }
  }

  const handleInstall = () => {
    setPendingAction('install')
  }

  const handleAddClient = async () => {
    if (!newClientName.trim()) return
    
    setAddingClient(true)
    try {
      await api.post('/wireguard/peers', {
        name: newClientName.trim()
      })
      setNewClientName('')
      setShowAddClient(false)
      await loadStatus()
    } catch (error) {
      console.error('Failed to add client:', error)
    } finally {
      setAddingClient(false)
    }
  }

  const executeReset = async () => {
    setResetting(true)
    try {
      await api.post('/wireguard/reset')
      await loadStatus()
      toast.success('WireGuard reset completed')
    } catch (error) {
      console.error('Failed to reset WireGuard:', error)
      if (error instanceof Error) {
        toast.error(error.message)
      } else {
        toast.error('Failed to reset WireGuard')
      }
    } finally {
      setResetting(false)
    }
  }

  const handleReset = () => {
    setPendingAction('reset')
  }

  const executeUninstall = async () => {
    setUninstalling(true)
    try {
      await api.post('/wireguard/uninstall')
      await loadStatus()
      toast.success('WireGuard uninstalled')
    } catch (error) {
      console.error('Failed to uninstall WireGuard:', error)
      if (error instanceof Error) {
        toast.error(error.message)
      } else {
        toast.error('Failed to uninstall WireGuard')
      }
    } finally {
      setUninstalling(false)
    }
  }

  const handleUninstall = () => {
    setPendingAction('uninstall')
  }

  const handleConfirmAction = () => {
    const action = pendingAction
    setPendingAction(null)
    if (action === 'install') {
      void executeInstall()
      return
    }
    if (action === 'reset') {
      void executeReset()
      return
    }
    if (action === 'uninstall') {
      void executeUninstall()
    }
  }

  const handleRemoveClient = async (name: string) => {
    if (!confirm(`Remove client "${name}"?`)) return
    
    try {
      await api.delete(`/wireguard/peers/${name}`)
      await loadStatus()
    } catch (error) {
      console.error('Failed to remove client:', error)
    }
  }

  const copyToClipboard = async (text: string, id: string) => {
    const success = await copyToClipboardUtil(text)
    if (success) {
      setCopied(id)
      setTimeout(() => setCopied(null), 2000)
    } else {
      toast.error('Failed to copy')
    }
  }

  const formatBytes = (bytes?: number) => {
    if (!bytes) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-dark-950 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-12 h-12 animate-spin text-blue-500 mx-auto mb-4" />
          <p className="text-gray-600 dark:text-gray-400">Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-dark-950">
      {/* Header */}
      <header className="bg-white dark:bg-dark-900 border-b border-gray-200 dark:border-dark-800">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-gradient-to-br from-purple-500 to-blue-600 rounded-xl shadow-lg shadow-purple-500/20">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">VPN Server</h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  WireGuard on your EasyPi
                </p>
              </div>
            </div>
            
            {status?.installed && (
              <div className="flex items-center gap-2">
                <button
                  onClick={handleReset}
                  disabled={resetting}
                  className="px-3 py-2 text-sm text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-700/50 rounded-lg hover:bg-amber-50 dark:hover:bg-amber-900/20 transition-colors disabled:opacity-60"
                >
                  {resetting ? 'Resetting...' : 'Reset WireGuard'}
                </button>
                <button
                  onClick={handleUninstall}
                  disabled={uninstalling}
                  className="px-3 py-2 text-sm text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800/60 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors disabled:opacity-60"
                >
                  {uninstalling ? 'Uninstalling...' : 'Uninstall WireGuard'}
                </button>
                <button
                  onClick={loadStatus}
                  disabled={loading}
                  className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-white/5 rounded-lg transition-colors"
                  title="Refresh"
                >
                  <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Not Installed State */}
        {!status?.installed && (
          <div className="space-y-8">
            {/* Hero Section */}
            <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm dark:border-dark-700 dark:bg-dark-900">
              <div className="max-w-3xl">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-primary-600 dark:text-primary-400" />
                  <span className="text-xs font-semibold uppercase tracking-wider text-primary-600 dark:text-primary-400">Secure remote access</span>
                </div>
                <h2 className="text-xl md:text-2xl font-bold text-gray-900 dark:text-white mb-2">
                  Install VPN Server
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-5">
                  WireGuard — modern VPN protocol. Fast, secure, and easy to set up. 
                  Connect to your home network from anywhere in the world.
                </p>
                <button
                  onClick={handleInstall}
                  disabled={installing}
                  className="inline-flex items-center gap-2 px-5 py-2.5 text-sm bg-primary-600 text-white rounded-xl font-semibold hover:bg-primary-700 transition-colors disabled:opacity-50"
                >
                  {installing ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Installing...
                    </>
                  ) : (
                    <>
                      <Shield className="w-5 h-5" />
                      Install WireGuard
                    </>
                  )}
                </button>
              </div>
              
            </div>

            {/* Requirements */}
            <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-2xl p-6">
              <div className="flex items-start gap-4">
                <div className="p-3 bg-yellow-100 dark:bg-yellow-500/20 rounded-xl">
                  <AlertTriangle className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-yellow-900 dark:text-yellow-300 mb-3">
                    Before installation check
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="flex items-start gap-3">
                      <Globe className="w-5 h-5 text-yellow-600 dark:text-yellow-400 mt-0.5" />
                      <div>
                        <p className="font-medium text-yellow-900 dark:text-yellow-200">Public IP address</p>
                        <p className="text-sm text-yellow-800 dark:text-yellow-400">
                          You need a public IPv4 address from your ISP (not behind NAT)
                        </p>
                        {publicIP && (
                          <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                            Your IP: <code className="bg-yellow-100 dark:bg-yellow-800/50 px-1 rounded">{publicIP}</code>
                          </p>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-3">
                      <Router className="w-5 h-5 text-yellow-600 dark:text-yellow-400 mt-0.5" />
                      <div>
                        <p className="font-medium text-yellow-900 dark:text-yellow-200">Port Forwarding</p>
                        <p className="text-sm text-yellow-800 dark:text-yellow-400">
                          Forward UDP port <code className="bg-yellow-100 dark:bg-yellow-800/50 px-1 rounded">51820</code> on router → EasyPi
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-3">
                      <Network className="w-5 h-5 text-yellow-600 dark:text-yellow-400 mt-0.5" />
                      <div>
                        <p className="font-medium text-yellow-900 dark:text-yellow-200">IP Forwarding</p>
                        <p className="text-sm text-yellow-800 dark:text-yellow-400">
                          Will be enabled automatically during installation
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-3">
                      <Lock className="w-5 h-5 text-yellow-600 dark:text-yellow-400 mt-0.5" />
                      <div>
                        <p className="font-medium text-yellow-900 dark:text-yellow-200">Firewall</p>
                        <p className="text-sm text-yellow-800 dark:text-yellow-400">
                          Port will be opened automatically via iptables
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* How it works */}
            <div className="bg-white dark:bg-dark-900 rounded-2xl border border-gray-200 dark:border-dark-800 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
                How it works
              </h3>
              
              <div className="flex flex-col md:flex-row items-center justify-between gap-6">
                {/* Step 1 */}
                <div className="flex-1 text-center">
                  <div className="w-16 h-16 bg-purple-100 dark:bg-purple-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    <Smartphone className="w-8 h-8 text-purple-600 dark:text-purple-400" />
                  </div>
                  <h4 className="font-medium text-gray-900 dark:text-white mb-1">Your device</h4>
                  <p className="text-sm text-gray-500 dark:text-gray-400">iPhone, Android, laptop</p>
                </div>

                <ArrowRight className="w-6 h-6 text-gray-300 dark:text-gray-600 hidden md:block" />
                
                {/* Step 2 */}
                <div className="flex-1 text-center">
                  <div className="w-16 h-16 bg-blue-100 dark:bg-blue-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    <Wifi className="w-8 h-8 text-blue-600 dark:text-blue-400" />
                  </div>
                  <h4 className="font-medium text-gray-900 dark:text-white mb-1">Internet</h4>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Encrypted tunnel</p>
                </div>

                <ArrowRight className="w-6 h-6 text-gray-300 dark:text-gray-600 hidden md:block" />
                
                {/* Step 3 */}
                <div className="flex-1 text-center">
                  <div className="w-16 h-16 bg-green-100 dark:bg-green-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    <Server className="w-8 h-8 text-green-600 dark:text-green-400" />
                  </div>
                  <h4 className="font-medium text-gray-900 dark:text-white mb-1">EasyPi (VPN)</h4>
                  <p className="text-sm text-gray-500 dark:text-gray-400">WireGuard server</p>
                </div>

                <ArrowRight className="w-6 h-6 text-gray-300 dark:text-gray-600 hidden md:block" />
                
                {/* Step 4 */}
                <div className="flex-1 text-center">
                  <div className="w-16 h-16 bg-cyan-100 dark:bg-cyan-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    <Network className="w-8 h-8 text-cyan-600 dark:text-cyan-400" />
                  </div>
                  <h4 className="font-medium text-gray-900 dark:text-white mb-1">Home network</h4>
                  <p className="text-sm text-gray-500 dark:text-gray-400">All devices accessible</p>
                </div>
              </div>
            </div>

            {/* Port forwarding guide */}
            <div className="bg-white dark:bg-dark-900 rounded-2xl border border-gray-200 dark:border-dark-800 overflow-hidden">
              <div className="p-6 border-b border-gray-200 dark:border-dark-800">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  How to forward port on router
                </h3>
              </div>
              <div className="p-6 space-y-4">
                <ol className="space-y-4 text-gray-600 dark:text-gray-400">
                  <li className="flex gap-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-purple-100 dark:bg-purple-500/20 text-purple-600 dark:text-purple-400 rounded-full flex items-center justify-center text-sm font-medium">1</span>
                    <span>Open your router's web interface (usually <code className="bg-gray-100 dark:bg-dark-800 px-1.5 py-0.5 rounded text-sm">192.168.1.1</code> or <code className="bg-gray-100 dark:bg-dark-800 px-1.5 py-0.5 rounded text-sm">192.168.0.1</code>)</span>
                  </li>
                  <li className="flex gap-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-purple-100 dark:bg-purple-500/20 text-purple-600 dark:text-purple-400 rounded-full flex items-center justify-center text-sm font-medium">2</span>
                    <span>Find section <strong>Port Forwarding</strong>, <strong>NAT</strong> or <strong>Virtual Servers</strong></span>
                  </li>
                  <li className="flex gap-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-purple-100 dark:bg-purple-500/20 text-purple-600 dark:text-purple-400 rounded-full flex items-center justify-center text-sm font-medium">3</span>
                    <span>Add rule: External port <code className="bg-gray-100 dark:bg-dark-800 px-1.5 py-0.5 rounded text-sm">51820 UDP</code> → EasyPi IP : <code className="bg-gray-100 dark:bg-dark-800 px-1.5 py-0.5 rounded text-sm">51820</code></span>
                  </li>
                  <li className="flex gap-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-purple-100 dark:bg-purple-500/20 text-purple-600 dark:text-purple-400 rounded-full flex items-center justify-center text-sm font-medium">4</span>
                    <span>Save settings and reboot router if needed</span>
                  </li>
                </ol>
                
                <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <div className="flex items-start gap-3">
                    <Info className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5" />
                    <div className="text-sm text-blue-800 dark:text-blue-300">
                      <p className="font-medium mb-1">How to find your EasyPi IP?</p>
                      <p>Check the Dashboard section or run <code className="bg-blue-100 dark:bg-blue-800/50 px-1 rounded">hostname -I</code> in terminal</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Features */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white dark:bg-dark-900 rounded-xl p-6 border border-gray-200 dark:border-dark-800">
                <div className="p-3 bg-purple-100 dark:bg-purple-500/10 rounded-lg w-fit mb-4">
                  <Lock className="w-6 h-6 text-purple-600 dark:text-purple-400" />
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-2">Encryption</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Modern cryptography: ChaCha20, Curve25519, BLAKE2s
                </p>
              </div>

              <div className="bg-white dark:bg-dark-900 rounded-xl p-6 border border-gray-200 dark:border-dark-800">
                <div className="p-3 bg-blue-100 dark:bg-blue-500/10 rounded-lg w-fit mb-4">
                  <Wifi className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-2">Speed</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Minimal latency, runs in Linux kernel
                </p>
              </div>

              <div className="bg-white dark:bg-dark-900 rounded-xl p-6 border border-gray-200 dark:border-dark-800">
                <div className="p-3 bg-green-100 dark:bg-green-500/10 rounded-lg w-fit mb-4">
                  <Smartphone className="w-6 h-6 text-green-600 dark:text-green-400" />
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-2">Cross-platform</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  iOS, Android, Windows, macOS, Linux
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Installed State */}
        {status?.installed && (
          <div className="space-y-6">
            {/* Status Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-white dark:bg-dark-900 rounded-xl p-6 border border-gray-200 dark:border-dark-800">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Status</p>
                    <p className="text-xl font-bold text-gray-900 dark:text-white mt-1">
                      {status.running ? 'Active' : 'Stopped'}
                    </p>
                  </div>
                  <div className={`p-3 rounded-xl ${status.running ? 'bg-green-100 dark:bg-green-500/10' : 'bg-red-100 dark:bg-red-500/10'}`}>
                    <CheckCircle className={`w-8 h-8 ${status.running ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`} />
                  </div>
                </div>
              </div>

              <div className="bg-white dark:bg-dark-900 rounded-xl p-6 border border-gray-200 dark:border-dark-800">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Port</p>
                    <p className="text-xl font-bold text-gray-900 dark:text-white mt-1">
                      {status.port} UDP
                    </p>
                  </div>
                  <div className="p-3 bg-blue-100 dark:bg-blue-500/10 rounded-xl">
                    <Server className="w-8 h-8 text-blue-600 dark:text-blue-400" />
                  </div>
                </div>
              </div>

              <div className="bg-white dark:bg-dark-900 rounded-xl p-6 border border-gray-200 dark:border-dark-800">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Endpoint</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1 truncate">
                      {status.endpoint || publicIP || 'Not set'}
                    </p>
                  </div>
                  <div className="p-3 bg-purple-100 dark:bg-purple-500/10 rounded-xl">
                    <Globe className="w-8 h-8 text-purple-600 dark:text-purple-400" />
                  </div>
                </div>
              </div>

              <div className="bg-white dark:bg-dark-900 rounded-xl p-6 border border-gray-200 dark:border-dark-800">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Clients</p>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                      {status.peers?.length || 0}
                    </p>
                  </div>
                  <div className="p-3 bg-cyan-100 dark:bg-cyan-500/10 rounded-xl">
                    <Users className="w-8 h-8 text-cyan-600 dark:text-cyan-400" />
                  </div>
                </div>
              </div>
            </div>

            {/* Server Public Key */}
            {status.server_public_key && (
              <div className="bg-white dark:bg-dark-900 rounded-xl p-6 border border-gray-200 dark:border-dark-800">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <Key className="w-5 h-5 text-gray-400" />
                    <h3 className="font-medium text-gray-900 dark:text-white">Server Public Key</h3>
                  </div>
                  <button
                    onClick={() => copyToClipboard(status.server_public_key, 'server-key')}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-dark-800 rounded-lg transition-colors"
                  >
                    {copied === 'server-key' ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                    {copied === 'server-key' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <code className="block p-3 bg-gray-100 dark:bg-dark-800 rounded-lg text-sm font-mono text-gray-700 dark:text-gray-300 break-all">
                  {status.server_public_key}
                </code>
              </div>
            )}

            {/* Clients Section */}
            <div className="bg-white dark:bg-dark-900 rounded-xl border border-gray-200 dark:border-dark-800 overflow-hidden">
              <div className="p-6 border-b border-gray-200 dark:border-dark-800">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">VPN Clients</h2>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      Connected devices
                    </p>
                  </div>
                  <button
                    onClick={() => setShowAddClient(true)}
                    className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-lg text-white font-medium transition-all"
                  >
                    <Plus className="w-5 h-5" />
                    Add
                  </button>
                </div>
              </div>

              {(!status.peers || status.peers.length === 0) ? (
                <div className="p-12 text-center">
                  <div className="p-4 bg-gray-100 dark:bg-dark-800 rounded-full w-fit mx-auto mb-4">
                    <Users className="w-12 h-12 text-gray-400" />
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                    No clients
                  </h3>
                  <p className="text-gray-500 dark:text-gray-400 mb-6">
                    Add your first client to connect
                  </p>
                  <button
                    onClick={() => setShowAddClient(true)}
                    className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-lg text-white font-medium transition-all"
                  >
                    <Plus className="w-5 h-5" />
                    Add client
                  </button>
                </div>
              ) : (
                <div className="divide-y divide-gray-200 dark:divide-dark-800">
                  {status.peers.map((client) => (
                    <div 
                      key={client.name} 
                      className="p-6 hover:bg-gray-50 dark:hover:bg-dark-800/50 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="p-3 bg-purple-100 dark:bg-purple-500/10 rounded-xl">
                            <Laptop className="w-6 h-6 text-purple-600 dark:text-purple-400" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <h3 className="font-semibold text-gray-900 dark:text-white">
                                {client.name}
                              </h3>
                            </div>
                            <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
                              {client.address}
                            </p>
                          </div>
                        </div>

                        <div className="flex items-center gap-4">
                          {client.rx_bytes !== undefined && (
                            <div className="text-right text-sm text-gray-500 dark:text-gray-400">
                              <p>↓ {formatBytes(client.rx_bytes)}</p>
                              <p>↑ {formatBytes(client.tx_bytes)}</p>
                            </div>
                          )}
                          
                          <div className="flex items-center gap-2">
                            <a
                              href={`${API_URL}/wireguard/peers/${client.name}/config`}
                              download
                              className="p-2.5 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-500/10 rounded-lg transition-colors"
                              title="Download config"
                            >
                              <Download className="w-5 h-5" />
                            </a>
                            <button
                              onClick={() => setQrClient(client.name)}
                              className="p-2.5 text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-500/10 rounded-lg transition-colors"
                              title="QR code"
                            >
                              <QrCode className="w-5 h-5" />
                            </button>
                            <button
                              onClick={() => handleRemoveClient(client.name)}
                              className="p-2.5 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors"
                              title="Delete"
                            >
                              <Trash2 className="w-5 h-5" />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Client Apps */}
            <div className="bg-gradient-to-r from-purple-500/10 to-blue-500/10 dark:from-purple-500/5 dark:to-blue-500/5 rounded-xl p-6 border border-purple-200 dark:border-purple-500/20">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
                WireGuard Apps
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <a href="https://apps.apple.com/app/wireguard/id1441195209" target="_blank" rel="noopener noreferrer" 
                   className="flex items-center gap-2 p-3 bg-white dark:bg-dark-800 rounded-lg hover:shadow-md transition-shadow">
                  <Smartphone className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">iOS</span>
                  <ExternalLink className="w-3 h-3 text-gray-400 ml-auto" />
                </a>
                <a href="https://play.google.com/store/apps/details?id=com.wireguard.android" target="_blank" rel="noopener noreferrer"
                   className="flex items-center gap-2 p-3 bg-white dark:bg-dark-800 rounded-lg hover:shadow-md transition-shadow">
                  <Smartphone className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Android</span>
                  <ExternalLink className="w-3 h-3 text-gray-400 ml-auto" />
                </a>
                <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener noreferrer"
                   className="flex items-center gap-2 p-3 bg-white dark:bg-dark-800 rounded-lg hover:shadow-md transition-shadow">
                  <Laptop className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Windows</span>
                  <ExternalLink className="w-3 h-3 text-gray-400 ml-auto" />
                </a>
                <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener noreferrer"
                   className="flex items-center gap-2 p-3 bg-white dark:bg-dark-800 rounded-lg hover:shadow-md transition-shadow">
                  <Laptop className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">macOS</span>
                  <ExternalLink className="w-3 h-3 text-gray-400 ml-auto" />
                </a>
                <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener noreferrer"
                   className="flex items-center gap-2 p-3 bg-white dark:bg-dark-800 rounded-lg hover:shadow-md transition-shadow">
                  <Laptop className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Linux</span>
                  <ExternalLink className="w-3 h-3 text-gray-400 ml-auto" />
                </a>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Add Client Modal */}
      {showAddClient && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-dark-900 rounded-2xl shadow-xl max-w-md w-full">
            <div className="p-6 border-b border-gray-200 dark:border-dark-800">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">Add Client</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">New device for VPN</p>
            </div>
            
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Device name
                </label>
                <input
                  type="text"
                  value={newClientName}
                  onChange={(e) => setNewClientName(e.target.value.replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 32))}
                  placeholder="iPhone, Laptop, MacBook..."
                  className="w-full px-4 py-2.5 border border-gray-300 dark:border-dark-700 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 dark:bg-dark-800 dark:text-white"
                  autoFocus
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Only letters, numbers, dots, hyphens (max 32 chars)
                </p>
              </div>
              
              <div className="flex gap-3 pt-4">
                <button
                  onClick={() => setShowAddClient(false)}
                  className="flex-1 px-6 py-3 border border-gray-300 dark:border-dark-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-800 transition-colors font-medium"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddClient}
                  disabled={addingClient || !newClientName.trim()}
                  className="flex-1 px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white rounded-lg disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed transition-all font-medium"
                >
                  {addingClient ? 'Adding...' : 'Add'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* QR Code Modal */}
      {qrClient && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
          <div className="bg-white dark:bg-dark-900 rounded-2xl shadow-2xl max-w-md w-full p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-gray-900 dark:text-white">
                QR Code: {qrClient}
              </h3>
              <button
                onClick={() => setQrClient(null)}
                className="p-2 hover:bg-gray-100 dark:hover:bg-dark-800 rounded-lg transition-colors"
              >
                <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="flex justify-center bg-white p-4 rounded-xl">
              <img 
                src={`${API_URL}/wireguard/peers/${qrClient}/qr`}
                alt={`QR code for ${qrClient}`}
                className="w-64 h-64"
              />
            </div>
            <p className="text-center text-sm text-gray-500 dark:text-gray-400 mt-4">
              Scan QR code in WireGuard app
            </p>
            <div className="flex gap-3 mt-6">
              <a
                href={`${API_URL}/wireguard/peers/${qrClient}/config`}
                download
                className="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium"
              >
                <Download className="w-5 h-5" />
                Download Config
              </a>
              <button
                onClick={() => setQrClient(null)}
                className="px-6 py-3 bg-gray-100 dark:bg-dark-800 hover:bg-gray-200 dark:hover:bg-dark-700 text-gray-700 dark:text-gray-300 rounded-lg transition-colors font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <Modal
        isOpen={Boolean(pendingAction)}
        onClose={() => setPendingAction(null)}
        title={
          pendingAction === 'install'
            ? 'Install WireGuard'
            : pendingAction === 'reset'
              ? 'Reset WireGuard'
              : pendingAction === 'uninstall'
                ? 'Uninstall WireGuard'
                : 'Action Preview'
        }
        footer={
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={() => setPendingAction(null)}
              className="rounded-lg bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300 dark:hover:bg-dark-600"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirmAction}
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
