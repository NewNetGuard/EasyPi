/**
 * Setup Page
 * Central place for all connection settings and EasyPi configuration
 */

import { useCallback, useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Plug,
  Server,
  Radar,
  CheckCircle,
  XCircle,
  RefreshCw,
  Info,
  Users,
  Key,
  Globe,
  ShieldCheck,
  Copy,
  Check,
  Lock,
  DownloadCloud,
  Package,
  Link2,
  LifeBuoy
} from 'lucide-react'
import api from '../api/client'
import OnboardingCard from '../components/dashboard/OnboardingCard'
import LocalNetProtectionCard from '../components/setup/LocalNetProtectionCard'
import {
  runSystemUpdate,
  getSystemUpdateStatus,
  getSystemDnsStatus,
  configureSystemDns,
  type SystemUpdateMode,
  type SystemUpdateStatusResponse
} from '../api/system'

interface ConnectionStatus {
  backend: 'checking' | 'connected' | 'error'
  netprotection: 'checking' | 'active' | 'not-running' | 'error'
}

interface PermissionStatus {
  group_exists: boolean
  in_easypi_group: boolean
  sudo_configured: boolean
  permissions_ok: boolean
  current_user: string
  is_development: boolean
  needs_relogin: boolean
}

interface DNSStatus {
  current_dns: string[]
  connection_name: string | null
  ignore_dhcp_dns: boolean
  is_development: boolean
  gateway?: string | null
}

interface EncryptedDnsSettings {
  doh_enabled: boolean
  dot_enabled: boolean
  doh_address: string
  doh_port: number
  doh_path: string
  dot_address: string
  dot_port: number
  tls_ready?: boolean
}

type EncryptedToggleKind = 'doh' | 'dot'

interface EncryptedConfirmState {
  kind: EncryptedToggleKind
  port: number
  label: string
  updates: Partial<EncryptedDnsSettings>
}

const DEFAULT_NetProtection_URL = 'http://easypi.local:3000'

export default function Setup() {
  // Status
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>({
    backend: 'checking',
    netprotection: 'checking'
  })
  const [permissions, setPermissions] = useState<PermissionStatus | null>(null)
  const [dnsStatus, setDnsStatus] = useState<DNSStatus | null>(null)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)
  const [encryptedDns, setEncryptedDns] = useState<EncryptedDnsSettings | null>(null)
  const [encryptedDnsLoading, setEncryptedDnsLoading] = useState(false)
  const [encryptedConfirm, setEncryptedConfirm] = useState<EncryptedConfirmState | null>(null)
  const [encryptedConfirming, setEncryptedConfirming] = useState(false)
  const [trustedCert, setTrustedCert] = useState<{ mode?: string; domain?: string; expiry?: string; ddns?: string; available?: boolean } | null>(null)
  const [tcDomain, setTcDomain] = useState('')
  const [tcToken, setTcToken] = useState('')
  const [tcEmail, setTcEmail] = useState('')
  const [tcBusy, setTcBusy] = useState(false)
  const [updateMode, setUpdateMode] = useState<SystemUpdateMode>('url')
  const [updateUrl, setUpdateUrl] = useState('')
  const [updateArchivePath, setUpdateArchivePath] = useState('/opt/EasyPi/data/updates/easypi-full-aarch64-trixie.tar.gz')
  const [updateSignatureUrl, setUpdateSignatureUrl] = useState('')
  const [updateSignaturePath, setUpdateSignaturePath] = useState('/opt/EasyPi/data/updates/easypi-full-aarch64-trixie.tar.gz.sig')
  const [updateBusy, setUpdateBusy] = useState(false)
  const [updateOutput, setUpdateOutput] = useState('')
  const [updateError, setUpdateError] = useState<string | null>(null)
  const certsPath = '/opt/EasyPi/certs'
  const navigate = useNavigate()

  const deviceHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost'
  const formatHostWithPort = (host: string, port: number) => (
    host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`
  )
  const dohPort = encryptedDns?.doh_port ?? 8053
  const dotPort = encryptedDns?.dot_port ?? 853
  const dohPath = encryptedDns?.doh_path ?? '/dns-query'
  const dohUrl = `https://${formatHostWithPort(deviceHost, dohPort)}${dohPath.startsWith('/') ? dohPath : `/${dohPath}`}`
  const dotHostWithPort = formatHostWithPort(deviceHost, dotPort)

  const getTimeoutSignal = (ms: number) => {
    if (typeof AbortSignal !== 'undefined' && 'timeout' in AbortSignal) {
      const timeout = (AbortSignal as typeof AbortSignal & { timeout: (ms: number) => AbortSignal }).timeout
      return timeout(ms)
    }
    const controller = new AbortController()
    window.setTimeout(() => controller.abort(), ms)
    return controller.signal
  }

  // Check backend connection using relative URL
  const checkBackend = async () => {
    setConnectionStatus(prev => ({ ...prev, backend: 'checking' }))
    try {
      let response = await fetch('/api/health/live', {
        signal: getTimeoutSignal(5000)
      })
      if (!response.ok) {
        response = await fetch('/healthz', {
          signal: getTimeoutSignal(3000)
        })
      }
      if (response.ok) {
        setConnectionStatus(prev => ({ ...prev, backend: 'connected' }))
        fetchPermissions()
        fetchDnsStatus()
        checkNetProtection()
        fetchEncryptedDns()
        fetchTrustedCert()
      } else {
        setConnectionStatus(prev => ({ ...prev, backend: 'error' }))
      }
    } catch {
      setConnectionStatus(prev => ({ ...prev, backend: 'error' }))
    }
  }

  // Check NetProtection status
  const checkNetProtection = async () => {
    setConnectionStatus(prev => ({ ...prev, netprotection: 'checking' }))
    try {
      const statusRes = await fetch('/api/v1/netprotection/status/full', {
        credentials: 'include',
        signal: getTimeoutSignal(5000)
      }).catch(() => ({ ok: false, status: 0 }))

      if (statusRes.ok) {
        const statusData = await (statusRes as Response).json()
        const isRunning = statusData && (statusData.running || statusData.service_status === 'active')
        setConnectionStatus(prev => ({
          ...prev,
          netprotection: isRunning ? 'active' : 'not-running'
        }))
        return
      }

      if (statusRes.status === 401 || statusRes.status === 403) {
        const publicResponse = await fetch('/api/v1/netprotection/status', {
          signal: getTimeoutSignal(3000)
        })
        if (publicResponse.ok) {
          const data = await publicResponse.json()
          if (data?.configured) {
            setConnectionStatus(prev => ({ ...prev, netprotection: 'active' }))
          } else {
            setConnectionStatus(prev => ({ ...prev, netprotection: 'not-running' }))
          }
        } else {
          setConnectionStatus(prev => ({ ...prev, netprotection: 'not-running' }))
        }
        return
      }

      setConnectionStatus(prev => ({ ...prev, netprotection: 'not-running' }))
    } catch {
      setConnectionStatus(prev => ({ ...prev, netprotection: 'not-running' }))
    }
  }

  const handleLocalNetProtectionStatus = useCallback((running: boolean) => {
    setConnectionStatus(prev => ({
      ...prev,
      netprotection: running ? 'active' : 'not-running'
    }))
  }, [])

  // Fetch permissions status
  const fetchPermissions = async () => {
    try {
      const response = await fetch('/api/system/permissions/status')
      if (response.ok) {
        const data = await response.json()
        setPermissions(data)
      }
    } catch {
      // ignore
    }
  }

  // Fetch DNS status
  const fetchDnsStatus = async () => {
    try {
      const data = await getSystemDnsStatus()
      setDnsStatus(data)
    } catch {
      // ignore
    }
  }

  const fetchEncryptedDns = async (silent: boolean = false) => {
    if (!silent) {
      setEncryptedDnsLoading(true)
    }
    try {
      const response = await api.get('/netprotection/encrypted-dns')
      const payload = response.data?.data ?? response.data
      setEncryptedDns(payload)
    } catch {
      setEncryptedDns(null)
    }
    if (!silent) {
      setEncryptedDnsLoading(false)
    }
  }

  // Configure DNS for Pi (bypass NetProtection)
  // Button 1: public DNS (Google + Cloudflare). Via systemApi → CSRF attached.
  const applyPublicDns = async () => {
    setSaving(true)
    setMessage(null)
    try {
      const data = await configureSystemDns({ primary_dns: '8.8.8.8', secondary_dns: '1.1.1.1', ignore_dhcp_dns: true })
      setMessage({ type: 'success', text: data.message || 'DNS set to Google & Cloudflare (8.8.8.8 / 1.1.1.1)' })
      fetchDnsStatus()
    } catch (err: any) {
      setMessage({ type: 'error', text: err?.response?.data?.detail || err?.message || 'Failed to set DNS' })
    }
    setSaving(false)
  }

  // Reset DNS to DHCP defaults
  // Button 2: use the router/gateway as DNS.
  const applyRouterDns = async () => {
    const gw = dnsStatus?.gateway
    if (!gw) {
      setMessage({ type: 'error', text: 'Router (gateway) IP not detected' })
      return
    }
    setSaving(true)
    setMessage(null)
    try {
      const data = await configureSystemDns({ primary_dns: gw, secondary_dns: '', ignore_dhcp_dns: true })
      setMessage({ type: 'success', text: data.message || `DNS set to router (${gw})` })
      fetchDnsStatus()
    } catch (err: any) {
      setMessage({ type: 'error', text: err?.response?.data?.detail || err?.message || 'Failed to set DNS' })
    }
    setSaving(false)
  }

  const runUpdateAction = async (opts: {
    dryRun: boolean
    runInstall?: boolean
    deleteObsolete?: boolean
    restartServices?: boolean
  }) => {
    setUpdateBusy(true)
    setUpdateError(null)
    setUpdateOutput('')

    try {
      const payload: any = {
        mode: updateMode,
        run_install: opts.runInstall ?? false,
        delete_obsolete: opts.deleteObsolete ?? false,
        dry_run: opts.dryRun,
        restart_services: opts.restartServices ?? true,
      }

      if (updateMode === 'url') {
        payload.url = updateUrl.trim()
        payload.signature = updateSignatureUrl.trim()
      } else if (updateMode === 'archive') {
        payload.archive_path = updateArchivePath.trim()
        payload.signature = updateSignaturePath.trim()
      }

      const response = await runSystemUpdate(payload)
      const initialOutput = [`$ ${response.command}`]
      if (response.job_id) initialOutput.push(`Job: ${response.job_id}`)
      initialOutput.push(`Status: ${response.status}`)
      setUpdateOutput(initialOutput.join('\n\n'))

      let finalStatus: SystemUpdateStatusResponse | null = null
      if (response.status === 'running' && response.job_id) {
        const deadline = Date.now() + 15 * 60 * 1000
        while (Date.now() < deadline) {
          await new Promise(resolve => window.setTimeout(resolve, 2000))
          try {
            const status = await getSystemUpdateStatus(response.job_id)
            const outputParts = [
              `$ ${response.command}`,
              `Job: ${response.job_id}`,
              `Status: ${status.status}`,
            ]
            if (status.exit_code !== null) outputParts.push(`Exit code: ${status.exit_code}`)
            if (status.stdout) outputParts.push(`OUTPUT:\n${status.stdout}`)
            if (status.stderr) outputParts.push(`ERROR:\n${status.stderr}`)
            setUpdateOutput(outputParts.join('\n\n'))
            if (status.status !== 'running') {
              finalStatus = status
              break
            }
          } catch {
            // The backend and nginx intentionally restart during a real update.
            // Keep the current page and retry the persistent job status instead
            // of turning the expected short outage into a false update failure.
            setUpdateOutput(current => (
              current.includes('Reconnecting after service restart...')
                ? current
                : `${current}\n\nReconnecting after service restart...`
            ))
          }
        }
        if (!finalStatus) {
          throw new Error('Update status timed out. The update job may still be running; inspect the job log before retrying.')
        }
      }

      const succeeded = finalStatus ? finalStatus.status === 'success' : response.success
      const finalMessage = finalStatus?.message || response.message
      if (succeeded) {
        setMessage({ type: 'success', text: opts.dryRun ? 'Dry run completed.' : finalMessage })
      } else {
        const failure = finalMessage || 'Update failed'
        setUpdateError(failure)
        setMessage({ type: 'error', text: failure })
      }
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Update request failed'
      setUpdateError(String(detail))
      setMessage({ type: 'error', text: String(detail) })
    }

    setUpdateBusy(false)
  }

  const handleSafeUpdate = async () => {
    await runUpdateAction({
      dryRun: false,
      runInstall: false,
      deleteObsolete: false,
      restartServices: true,
    })
  }

  const handleCleanReinstall = async () => {
    await runUpdateAction({
      dryRun: false,
      runInstall: true,
      deleteObsolete: true,
      restartServices: true,
    })
  }

  const copyToClipboard = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedField(field)
      setTimeout(() => setCopiedField(null), 2000)
    } catch {
      // ignore
    }
  }

  const updateEncryptedDns = async (updates: Partial<EncryptedDnsSettings>) => {
    setEncryptedDnsLoading(true)
    let success = false
    try {
      const response = await api.put('/netprotection/encrypted-dns', updates)
      const payload = response.data?.data ?? response.data
      setEncryptedDns(payload)
      setMessage({ type: 'success', text: 'Encrypted DNS updated' })
      success = true
    } catch {
      setMessage({ type: 'error', text: 'Failed to update encrypted DNS' })
    }
    setEncryptedDnsLoading(false)
    return success
  }

  const generateTlsCerts = async () => {
    setEncryptedDnsLoading(true)
    setMessage(null)
    try {
      const response = await api.post('/netprotection/encrypted-dns/generate-certs?force=true')
      const payload = response.data ?? {}
      setMessage({
        type: 'success',
        text: payload.message || 'TLS server certificate renewed. The trusted EasyPi Root CA was preserved.',
      })
    } catch {
      setMessage({ type: 'error', text: 'Failed to generate TLS certificates' })
    }
    await fetchEncryptedDns(true)
    setEncryptedDnsLoading(false)
  }

  const fetchTrustedCert = async () => {
    try {
      const { data } = await api.get('/netprotection/encrypted-dns/trusted-cert')
      setTrustedCert(data ?? null)
      if (data?.domain && !tcDomain) setTcDomain(data.domain)
    } catch {
      setTrustedCert(null)
    }
  }

  const submitTrustedCert = async () => {
    if (!tcDomain.trim() || !tcToken.trim()) {
      setMessage({ type: 'error', text: 'Enter your DuckDNS domain and token' })
      return
    }
    setTcBusy(true)
    setMessage(null)
    try {
      const { data } = await api.post('/netprotection/encrypted-dns/trusted-cert', {
        domain: tcDomain.trim(), token: tcToken.trim(), email: tcEmail.trim(),
      })
      setMessage({
        type: 'success',
        text: `Trusted certificate issued for ${data.domain || tcDomain.trim()}. DoH/DoT now use it — set Android Private DNS to your domain.`,
      })
      setTcToken('')
      await fetchEncryptedDns(true)
      await fetchTrustedCert()
    } catch (e: any) {
      setMessage({ type: 'error', text: e?.response?.data?.detail || 'Failed to obtain certificate' })
    }
    setTcBusy(false)
  }

  const buildEncryptedUpdate = (kind: EncryptedToggleKind, enabled: boolean) => (
    { [`${kind}_enabled`]: enabled } as Partial<EncryptedDnsSettings>
  )

  const requestEncryptedToggle = async (kind: EncryptedToggleKind) => {
    if (!encryptedDns) {
      return
    }
    const isEnabled = kind === 'doh' ? encryptedDns.doh_enabled : encryptedDns.dot_enabled
    if (isEnabled) {
      const port = kind === 'doh' ? dohPort : dotPort
      const updated = await updateEncryptedDns(buildEncryptedUpdate(kind, false))
      if (updated) {
        try {
          await closeFirewallPort(port)
        } catch {
          setMessage({
            type: 'error',
            text: `Disabled ${kind.toUpperCase()}, but failed to close firewall port ${port}.`
          })
        }
      }
      return
    }
    const port = kind === 'doh' ? dohPort : dotPort
    const label = kind === 'doh' ? 'DNS over HTTPS (DoH)' : 'DNS over TLS (DoT)'
    setEncryptedConfirm({
      kind,
      port,
      label,
      updates: buildEncryptedUpdate(kind, true)
    })
  }

  const openFirewallPort = async (port: number) => {
    // Guard Security firewall compat endpoints live under /netprotection
    // (the /security router only exposes /firewall/add|rules|remove).
    await api.post('/netprotection/firewall/rule', {
      action: 'allow',
      protocol: 'tcp',
      port: String(port),
      source: 'any',
    })
  }

  const closeFirewallPort = async (port: number) => {
    const response = await api.get('/netprotection/firewall/rules')
    const rules = Array.isArray(response.data) ? response.data : []
    const matches = rules.filter(
      (rule: { port?: string | number; protocol?: string; action?: string; source?: string; id?: string | number }) => {
        const action = String(rule.action ?? '').toLowerCase()
        return (
          String(rule.port ?? '') === String(port) &&
          String(rule.protocol ?? '').toLowerCase() === 'tcp' &&
          (action === 'allow' || action === 'accept') &&
          (rule.source === 'any' || rule.source === undefined)
        )
      }
    )
    for (const rule of matches) {
      await api.delete(`/netprotection/firewall/rule/${encodeURIComponent(String(rule.id ?? ''))}`)
    }
  }

  const confirmEncryptedEnable = async () => {
    if (!encryptedConfirm) {
      return
    }
    setEncryptedConfirming(true)
    setMessage(null)
    try {
      // Enable the listener first (the core action); opening the firewall is
      // best-effort so a firewall hiccup never blocks enabling.
      const updated = await updateEncryptedDns(encryptedConfirm.updates)
      if (!updated) {
        setMessage({ type: 'error', text: 'Failed to enable encrypted DNS.' })
        return
      }
      try {
        await openFirewallPort(encryptedConfirm.port)
        setMessage({
          type: 'success',
          text: `${encryptedConfirm.label} enabled and TCP port ${encryptedConfirm.port} opened in the firewall.`
        })
      } catch {
        setMessage({
          type: 'error',
          text: `${encryptedConfirm.label} enabled, but the firewall port ${encryptedConfirm.port} could not be opened automatically. Allow TCP ${encryptedConfirm.port} manually if you need access from other devices.`
        })
      }
      setEncryptedConfirm(null)
    } catch {
      setMessage({ type: 'error', text: 'Failed to enable encrypted DNS.' })
    } finally {
      setEncryptedConfirming(false)
    }
  }

  const renderEncryptedToggle = (
    label: string,
    description: string,
    enabled: boolean,
    onToggle: () => void
  ) => {
    const disabled = encryptedDnsLoading || encryptedConfirming || !!encryptedConfirm || !encryptedDns || !encryptedDns.tls_ready
    return (
      <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-900/50 border border-gray-200 dark:border-gray-700 rounded-lg">
        <div>
          <p className="text-sm font-medium text-gray-900 dark:text-white">{label}</p>
          <p className="text-xs text-gray-600 dark:text-gray-400">{description}</p>
        </div>
        <button
          type="button"
          onClick={onToggle}
          disabled={disabled}
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${enabled ? 'bg-green-500' : 'bg-gray-600'
            } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
          title={enabled ? 'Disable' : 'Enable'}
        >
          <span
            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${enabled ? 'translate-x-5' : 'translate-x-1'
              }`}
          />
        </button>
      </div>
    )
  }

  const checkBackendRef = useRef(checkBackend)

  useEffect(() => {
    checkBackendRef.current = checkBackend
  })

  useEffect(() => {
    void checkBackendRef.current()
  }, [])

  const StatusIcon = ({ status }: { status: 'checking' | 'connected' | 'error' | 'not-configured' | 'active' | 'not-running' }) => {
    if (status === 'checking') return <RefreshCw className="w-5 h-5 text-blue-400 animate-spin" />
    if (status === 'connected' || status === 'active') return <CheckCircle className="w-5 h-5 text-green-400" />
    return <XCircle className="w-5 h-5 text-red-400" />
  }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
          <Plug className="w-6 h-6 text-blue-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-gray-800 dark:text-white">Setup</h1>
          <p className="text-gray-500 dark:text-gray-400">Configure connections and system access</p>
        </div>
      </div>

      {/* Info Box */}
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
        <div className="flex gap-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-medium text-gray-700 dark:text-gray-300 mb-2">What's configured here:</p>
            <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400">
              <li><strong>Backend Status</strong> — connection status to EasyPi server. Connection is automatic.</li>
              <li><strong>NetProtection</strong> — DNS filtering and threat protection service status.</li>
              <li><strong>System Permissions</strong> — access rights for system management (sudo, groups).</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Setup checklist — permanent status of the key steps (protection / DNS /
          gateway / profiles), green where good, warning where not. */}
      <OnboardingCard variant="setup" />

      {/* Message */}
      {message && (
        <div className={`p-4 rounded-lg border ${message.type === 'success'
          ? 'bg-green-500/10 border-green-500/30 text-green-400'
          : 'bg-red-500/10 border-red-500/30 text-red-400'
          }`}>
          {message.text}
        </div>
      )}

      {/* Connection Status Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Server className="w-5 h-5 text-gray-600 dark:text-gray-400" />
              <span className="font-medium text-gray-900 dark:text-white">Backend</span>
            </div>
            <StatusIcon status={connectionStatus.backend} />
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            {connectionStatus.backend === 'connected' ? 'Connected' :
              connectionStatus.backend === 'checking' ? 'Checking...' : 'Not connected'}
          </p>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Radar className="w-5 h-5 text-gray-400" />
              <span className="font-medium text-white">NetProtection</span>
            </div>
            <StatusIcon status={connectionStatus.netprotection} />
          </div>
          <p className="text-sm text-gray-400">
            {connectionStatus.netprotection === 'active' ? 'Active' :
              connectionStatus.netprotection === 'checking' ? 'Checking...' : 'Not Running'}
          </p>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Key className="w-5 h-5 text-gray-600 dark:text-gray-400" />
              <span className="font-medium text-gray-900 dark:text-white">Permissions</span>
            </div>
            {permissions ? (
              permissions.permissions_ok || permissions.is_development ? (
                <CheckCircle className="w-5 h-5 text-green-400" />
              ) : (
                <XCircle className="w-5 h-5 text-yellow-400" />
              )
            ) : (
              <RefreshCw className="w-5 h-5 text-gray-400 animate-spin" />
            )}
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            {permissions?.is_development ? 'Development Mode' :
              permissions?.permissions_ok ? 'Configured' :
                permissions ? 'Needs setup' : 'Checking...'}
          </p>
        </div>
      </div>

      {/* Backend Status Section */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center gap-3">
          <Server className="w-5 h-5 text-blue-400" />
          <div>
            <h2 className="font-semibold text-gray-900 dark:text-white">Backend Connection</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">EasyPi server status</p>
          </div>
        </div>

        <div className="p-4 space-y-4">
          <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-900/50 border border-gray-200 dark:border-gray-700 rounded-lg">
            <div className="flex items-center gap-3">
              <StatusIcon status={connectionStatus.backend} />
              <div>
                <p className="text-gray-900 dark:text-white font-medium">
                  {connectionStatus.backend === 'connected' ? 'Connected' :
                    connectionStatus.backend === 'checking' ? 'Checking...' : 'Not Connected'}
                </p>
                <p className="text-xs text-gray-600 dark:text-gray-400">
                  {connectionStatus.backend === 'connected'
                    ? `Connected to ${window.location.origin}`
                    : 'Backend API is not responding'}
                </p>
              </div>
            </div>
            <button
              onClick={checkBackend}
              disabled={connectionStatus.backend === 'checking'}
              className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${connectionStatus.backend === 'checking' ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <p className="text-xs text-gray-500">
            The frontend automatically connects to the backend at the same origin.
            Access EasyPi from any network (LAN, Tailscale, etc.) and it will work.
          </p>
        </div>
      </div>

      {/* Local DNS filtering and Transparent DNS belong to system setup. */}
      <LocalNetProtectionCard onStatusChange={handleLocalNetProtectionStatus} />

      {/* Encrypted DNS (DoH/DoT) Section */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center gap-3">
          <Lock className="w-5 h-5 text-cyan-400" />
          <div>
            <h2 className="font-semibold text-gray-900 dark:text-white">Encrypted DNS (DoH/DoT)</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">Use these in device DNS settings</p>
          </div>
        </div>

        <div className="p-4 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {renderEncryptedToggle(
              'DNS over HTTPS (DoH)',
              `HTTPS endpoint on port ${dohPort}`,
              encryptedDns?.doh_enabled ?? false,
              () => requestEncryptedToggle('doh')
            )}
            {renderEncryptedToggle(
              'DNS over TLS (DoT)',
              `TLS endpoint on port ${dotPort}`,
              encryptedDns?.dot_enabled ?? false,
              () => requestEncryptedToggle('dot')
            )}
          </div>

          {encryptedConfirm && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
              <p className="font-medium text-amber-100 mb-2">
                Enabling {encryptedConfirm.label} will open TCP port {encryptedConfirm.port} in the firewall.
              </p>
              <ul className="list-disc list-inside space-y-1 text-amber-200/90">
                <li>Only enable this if you need encrypted DNS from other devices.</li>
                <li>If your firewall allows public access, strangers could use your DNS service.</li>
                <li>For safest access, keep it limited to LAN or Tailscale.</li>
              </ul>
              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => setEncryptedConfirm(null)}
                  disabled={encryptedConfirming}
                  className="px-3 py-2 text-xs font-medium rounded-md border border-gray-400 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={confirmEncryptedEnable}
                  disabled={encryptedConfirming}
                  className="px-3 py-2 text-xs font-medium rounded-md border border-amber-400/60 text-amber-100 hover:bg-amber-500/10 transition-colors disabled:opacity-50"
                >
                  Open port & enable
                </button>
              </div>
            </div>
          )}

          <div className="flex items-center gap-2 text-xs text-gray-400">
            {encryptedDnsLoading ? (
              <RefreshCw className="w-3.5 h-3.5 text-blue-400 animate-spin" />
            ) : encryptedDns?.tls_ready ? (
              <CheckCircle className="w-3.5 h-3.5 text-green-400" />
            ) : (
              <XCircle className="w-3.5 h-3.5 text-amber-400" />
            )}
            <span>
              {encryptedDnsLoading
                ? 'Checking TLS certificates...'
                : encryptedDns?.tls_ready
                  ? 'TLS certificates found'
                  : 'TLS certificates missing or invalid'}
            </span>
          </div>

          {!encryptedDnsLoading && encryptedDns && !encryptedDns.tls_ready && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-300">
              DoH/DoT require a valid TLS certificate (with a SubjectAltName for this host/IP).
              Click <span className="font-medium">Generate TLS certs</span> below to create one in
              <span className="font-mono"> /opt/EasyPi/certs</span>.
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => navigate(`/files?path=${encodeURIComponent(certsPath)}`)}
              className="px-3 py-2 text-xs font-medium rounded-md border border-gray-400 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            >
              Open certs folder
            </button>
            <button
              type="button"
              onClick={generateTlsCerts}
              disabled={encryptedDnsLoading}
              className="px-3 py-2 text-xs font-medium rounded-md border border-cyan-500/50 text-cyan-200 hover:bg-cyan-500/10 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {encryptedDns?.tls_ready ? 'Renew TLS certificate' : 'Generate TLS certificates'}
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3 bg-gray-50 dark:bg-gray-900/50 border border-gray-200 dark:border-gray-700 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-600 dark:text-gray-400">DoH URL</span>
                <button
                  onClick={() => copyToClipboard(dohUrl, 'doh')}
                  className="p-1.5 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                  title="Copy"
                >
                  {copiedField === 'doh' ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4 text-gray-600 dark:text-gray-400" />
                  )}
                </button>
              </div>
              <code className="text-sm font-mono text-gray-900 dark:text-white break-all">{dohUrl}</code>
            </div>

            <div className="p-3 bg-gray-50 dark:bg-gray-900/50 border border-gray-200 dark:border-gray-700 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-600 dark:text-gray-400">DoT Host</span>
                <button
                  onClick={() => copyToClipboard(dotHostWithPort, 'dot')}
                  className="p-1.5 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                  title="Copy"
                >
                  {copiedField === 'dot' ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4 text-gray-600 dark:text-gray-400" />
                  )}
                </button>
              </div>
              <code className="text-sm font-mono text-gray-900 dark:text-white break-all">{dotHostWithPort}</code>
            </div>
          </div>

          {!encryptedDnsLoading && encryptedDns && !encryptedDns.tls_ready && (
            <p className="text-xs text-amber-400">
              TLS certificates not found. Add certs at `/opt/EasyPi/certs/cert.pem` and `/opt/EasyPi/certs/key.pem`.
            </p>
          )}
          <p className="text-xs text-gray-500">
            If you use Tailscale, you can replace the host with your EasyPi Tailscale IP or hostname.
          </p>

          {/* Trusted certificate (Let's Encrypt + DuckDNS) — so Android Private DNS accepts DoT */}
          <div className="mt-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4">
            <div className="flex items-start gap-3">
              <ShieldCheck className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
              <div className="min-w-0 flex-1">
                <h3 className="font-semibold text-gray-900 dark:text-white">Trusted certificate (for Android Private DNS)</h3>
                <p className="text-xs text-gray-600 dark:text-gray-400 mt-0.5">
                  A self-signed cert works for the web UI, but phones reject it for DoT. Get a free
                  trusted Let&apos;s Encrypt certificate via a DuckDNS domain — then Android
                  &ldquo;Private DNS&rdquo; accepts it.
                </p>
                <p className="mt-2 text-xs text-amber-700 dark:text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-md px-2.5 py-2">
                  ⚠️ This needs your box to be reachable from the internet on port 853. It won&apos;t work
                  if your ISP uses <b>CGNAT</b> (no real public IP) or blocks 853 — the phone can&apos;t reach
                  the box from outside. To check: run a traceroute; several private hops (192.168.x / 10.x /
                  100.64.x) before the first public IP means CGNAT. In that case use <b>Remote Access
                  (Tailscale)</b> instead — it works through CGNAT without any port forwarding.
                </p>

                <div className="mt-2 flex items-center gap-2 text-xs">
                  {trustedCert?.mode === 'letsencrypt' ? (
                    <>
                      <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                      <span className="text-green-300">
                        Trusted certificate active{trustedCert.domain ? ` for ${trustedCert.domain}` : ''}
                        {trustedCert.expiry ? ` · expires ${trustedCert.expiry}` : ''}
                      </span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
                      <span className="text-amber-300">Currently self-signed — phones will reject DoT</span>
                    </>
                  )}
                </div>

                <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2">
                  <input
                    value={tcDomain}
                    onChange={(e) => setTcDomain(e.target.value)}
                    placeholder="myhome.duckdns.org"
                    className="px-3 py-2 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                  />
                  <input
                    value={tcToken}
                    onChange={(e) => setTcToken(e.target.value)}
                    placeholder="DuckDNS token"
                    type="password"
                    autoComplete="off"
                    className="px-3 py-2 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                  />
                  <input
                    value={tcEmail}
                    onChange={(e) => setTcEmail(e.target.value)}
                    placeholder="email (optional — expiry notices)"
                    className="px-3 py-2 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white md:col-span-2"
                  />
                </div>

                <div className="mt-2 flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={submitTrustedCert}
                    disabled={tcBusy}
                    className="px-3 py-2 text-xs font-medium rounded-md border border-emerald-500/50 text-emerald-200 hover:bg-emerald-500/10 disabled:opacity-50 flex items-center gap-1.5"
                  >
                    {tcBusy ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                    {tcBusy ? 'Obtaining…' : 'Get trusted certificate'}
                  </button>
                  <a href="https://www.duckdns.org" target="_blank" rel="noreferrer" className="text-xs text-cyan-300 hover:underline">
                    Get a free DuckDNS domain + token ↗
                  </a>
                </div>

                <div className="mt-3 rounded-md border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/40 p-3 text-xs text-gray-600 dark:text-gray-400 space-y-1">
                  <p className="font-medium text-gray-700 dark:text-gray-300">After it succeeds:</p>
                  <p>• Android → Settings → Private DNS → <span className="font-mono">{tcDomain || 'myhome.duckdns.org'}</span></p>
                  <p>• To use it on mobile data (not just home Wi-Fi), forward router port <span className="font-mono">853/TCP</span> to this box.</p>
                  <p>• The domain is auto-kept on your public IP and the certificate auto-renews — nothing else to do.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Permissions Section */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center gap-3">
          <Users className="w-5 h-5 text-purple-400" />
          <div>
            <h2 className="font-semibold text-gray-900 dark:text-white">System Permissions</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">Access rights for system management</p>
          </div>
        </div>

        <div className="p-4 space-y-4">
          {permissions?.is_development ? (
            <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
              <p className="text-sm text-blue-300">
                <strong>Development Mode:</strong> Running on Windows. Linux permissions are not applicable.
              </p>
            </div>
          ) : (
            <>
              <div className="p-3 bg-gray-50 dark:bg-gray-900/50 border border-gray-200 dark:border-gray-700 rounded-lg">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  To manage the system (services, firewall, backups) EasyPi needs sudo privileges.
                  This is configured via the <code className="bg-gray-200 dark:bg-gray-800 px-1 rounded">easypi</code> group and sudoers file.
                </p>
              </div>

              {permissions && (
                <div className="grid grid-cols-2 gap-3">
                  <div className={`p-3 rounded-lg border ${permissions.group_exists ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                    <div className="flex items-center gap-2">
                      {permissions.group_exists ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                      <span className="text-sm text-gray-900 dark:text-white">Group exists</span>
                    </div>
                  </div>
                  <div className={`p-3 rounded-lg border ${permissions.in_easypi_group ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                    <div className="flex items-center gap-2">
                      {permissions.in_easypi_group ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                      <span className="text-sm text-gray-900 dark:text-white">User in group</span>
                    </div>
                  </div>
                  <div className={`p-3 rounded-lg border ${permissions.sudo_configured ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                    <div className="flex items-center gap-2">
                      {permissions.sudo_configured ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                      <span className="text-sm text-gray-900 dark:text-white">Sudo configured</span>
                    </div>
                  </div>
                  <div className={`p-3 rounded-lg border ${permissions.permissions_ok ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                    <div className="flex items-center gap-2">
                      {permissions.permissions_ok ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                      <span className="text-sm text-gray-900 dark:text-white">All OK</span>
                    </div>
                  </div>
                </div>
              )}

              {permissions && !permissions.permissions_ok && (
                <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-200 space-y-2">
                  <p className="font-medium text-amber-800 dark:text-amber-100">
                    Permissions are set up by the installer (as root). EasyPi runs unprivileged and intentionally cannot create groups, modify users, or install sudoers itself — so this can't be fixed from the browser.
                  </p>
                  <p>Run this on the Pi from a root shell, then reload this page:</p>
                  <pre className="overflow-x-auto rounded bg-black/30 dark:bg-black/40 p-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">{`sudo groupadd -f easypi
sudo usermod -aG easypi ${permissions.current_user}
sudo install -m 440 -o root -g root /opt/EasyPi/scripts/sudoers.d/easypi /etc/sudoers.d/easypi
sudo systemctl restart easypi-backend`}</pre>
                  <p className="text-amber-700/80 dark:text-amber-200/80">Or simply re-run the installer: <span className="font-mono">sudo bash /opt/EasyPi/install.sh</span></p>
                </div>
              )}

              {permissions?.current_user && (
                <p className="text-xs text-gray-500">Current user: {permissions.current_user}</p>
              )}
            </>
          )}
        </div>
      </div>

      {/* DNS Settings Section */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center gap-3">
          <Globe className="w-5 h-5 text-orange-400" />
          <div>
            <h2 className="font-semibold text-gray-900 dark:text-white">EasyPi DNS Settings</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">DNS configuration for the EasyPi server itself</p>
          </div>
        </div>

        <div className="p-4 space-y-4">
          {dnsStatus?.is_development ? (
            <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
              <p className="text-sm text-blue-300">
                <strong>Development Mode:</strong> Running on Windows. DNS settings are not applicable.
              </p>
            </div>
          ) : (
            <>
              <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                <p className="text-sm text-yellow-300">
                  <strong>Important:</strong> If you use NetProtection as DNS for your entire network (in router),
                  it's recommended to configure EasyPi itself to use external DNS directly.
                  Otherwise NetProtection may block addresses needed for system updates.
                </p>
              </div>

              {/* Current DNS Status */}
              {dnsStatus && (
                <div className="p-3 bg-gray-50 dark:bg-gray-900/50 border border-gray-200 dark:border-gray-700 rounded-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Current DNS servers:</span>
                    <span className="text-sm text-gray-900 dark:text-white font-mono">{dnsStatus.current_dns.join(', ')}</span>
                  </div>
                  {dnsStatus.connection_name && (
                    <div className="flex items-center justify-between mt-2">
                      <span className="text-sm text-gray-600 dark:text-gray-400">Connection:</span>
                      <span className="text-sm text-gray-900 dark:text-white">{dnsStatus.connection_name}</span>
                    </div>
                  )}
                  <div className="flex items-center justify-between mt-2">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Ignore DHCP DNS:</span>
                    <span className={`text-sm ${dnsStatus.ignore_dhcp_dns ? 'text-green-400' : 'text-gray-600 dark:text-gray-400'}`}>
                      {dnsStatus.ignore_dhcp_dns ? 'Yes' : 'No'}
                    </span>
                  </div>
                </div>
              )}

              {(() => {
                const gw = dnsStatus?.gateway || ''
                const curr = dnsStatus?.current_dns || []
                const googleActive = curr.includes('8.8.8.8') || curr.includes('1.1.1.1')
                const routerActive = !!gw && curr.includes(gw)
                const base = 'p-4 text-left rounded-xl border transition-colors disabled:opacity-50'
                const activeCls = 'border-emerald-500 ring-2 ring-emerald-500/40 bg-emerald-50 dark:bg-emerald-900/20'
                const idleCls = 'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900/40 hover:bg-gray-50 dark:hover:bg-gray-800'
                return (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <button
                      onClick={applyPublicDns}
                      disabled={saving || connectionStatus.backend !== 'connected'}
                      className={`${base} ${googleActive ? activeCls : idleCls}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="font-semibold text-gray-900 dark:text-white">Google &amp; Cloudflare</div>
                        {googleActive && <span className="text-xs font-medium text-emerald-600 dark:text-emerald-400">● Active</span>}
                      </div>
                      <div className="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1">8.8.8.8 · 1.1.1.1</div>
                      <div className="text-xs text-gray-500 dark:text-gray-500 mt-1">Public DNS (bypasses local filtering)</div>
                    </button>
                    <button
                      onClick={applyRouterDns}
                      disabled={saving || connectionStatus.backend !== 'connected' || !gw}
                      className={`${base} ${routerActive ? activeCls : idleCls}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="font-semibold text-gray-900 dark:text-white">Router DNS</div>
                        {routerActive && <span className="text-xs font-medium text-emerald-600 dark:text-emerald-400">● Active</span>}
                      </div>
                      <div className="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1">{gw || 'not detected (auto)'}</div>
                      <div className="text-xs text-gray-500 dark:text-gray-500 mt-1">Use the router/gateway as DNS</div>
                    </button>
                  </div>
                )
              })()}
            </>
          )}
        </div>
      </div>

      {/* EasyPi Update Section */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center gap-3">
          <Package className="w-5 h-5 text-emerald-500" />
          <div>
            <h2 className="font-semibold text-gray-900 dark:text-white">EasyPi Update</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">Update from URL or archive directly from UI</p>
          </div>
        </div>

        <div className="p-4 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {(['url', 'archive'] as SystemUpdateMode[]).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setUpdateMode(mode)}
                className={`px-3 py-2 rounded-lg border text-sm transition-colors ${
                  updateMode === mode
                    ? 'bg-emerald-500 text-white border-emerald-500'
                    : 'bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200 border-gray-300 dark:border-gray-700 hover:bg-gray-200 dark:hover:bg-gray-800'
                }`}
              >
                {mode === 'url' ? 'From URL' : 'From Archive'}
              </button>
            ))}
          </div>

          {updateMode === 'url' && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-700 dark:text-gray-300 mb-2">
                  Release URL
                </label>
                <div className="flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    value={updateUrl}
                    onChange={(e) => setUpdateUrl(e.target.value)}
                    placeholder="https://example.com/easypi-full-aarch64-trixie.tar.gz"
                    className="flex-1 px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm text-gray-700 dark:text-gray-300 mb-2">
                  Signature URL <span className="text-emerald-600 dark:text-emerald-400">(required)</span>
                </label>
                <div className="flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    value={updateSignatureUrl}
                    onChange={(e) => setUpdateSignatureUrl(e.target.value)}
                    placeholder="https://example.com/easypi-full-aarch64-trixie.tar.gz.sig"
                    className="flex-1 px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
                  />
                </div>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Detached signature of the archive, made with the EasyPi release key. The update is rejected if it doesn't verify.
                </p>
              </div>
            </div>
          )}

          {updateMode === 'archive' && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-700 dark:text-gray-300 mb-2">
                  Archive path on server
                </label>
                <div className="flex items-center gap-2">
                  <DownloadCloud className="w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    value={updateArchivePath}
                    onChange={(e) => setUpdateArchivePath(e.target.value)}
                    placeholder="/opt/EasyPi/data/updates/easypi-full-aarch64-trixie.tar.gz"
                    className="flex-1 px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm text-gray-700 dark:text-gray-300 mb-2">
                  Signature path on server <span className="text-emerald-600 dark:text-emerald-400">(required)</span>
                </label>
                <div className="flex items-center gap-2">
                  <DownloadCloud className="w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    value={updateSignaturePath}
                    onChange={(e) => setUpdateSignaturePath(e.target.value)}
                    placeholder="/opt/EasyPi/data/updates/easypi-full-aarch64-trixie.tar.gz.sig"
                    className="flex-1 px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
                  />
                </div>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Detached signature file (.sig) of the archive, made with the EasyPi release key.
                </p>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <button
              type="button"
              onClick={handleSafeUpdate}
              disabled={updateBusy}
              className="p-4 text-left rounded-xl border border-emerald-400/60 bg-emerald-50 dark:bg-emerald-900/20 hover:bg-emerald-100 dark:hover:bg-emerald-900/30 transition-colors disabled:opacity-50"
            >
              <div className="text-sm font-semibold text-emerald-800 dark:text-emerald-300">Safe Update (Recommended)</div>
              <div className="mt-1 text-xs text-emerald-700/90 dark:text-emerald-200/90">
                Keeps existing files, applies update, restarts services. Runs the installer automatically when the release changes system configuration.
              </div>
              <div className="mt-2 text-xs font-medium text-emerald-800 dark:text-emerald-300">
                {updateBusy ? 'Running update...' : 'Run Safe Update'}
              </div>
            </button>

            <button
              type="button"
              onClick={handleCleanReinstall}
              disabled={updateBusy}
              className="p-4 text-left rounded-xl border border-amber-400/60 bg-amber-50 dark:bg-amber-900/20 hover:bg-amber-100 dark:hover:bg-amber-900/30 transition-colors disabled:opacity-50"
            >
              <div className="text-sm font-semibold text-amber-800 dark:text-amber-300">Clean Reinstall</div>
              <div className="mt-1 text-xs text-amber-700/90 dark:text-amber-200/90">
                Runs installer and deletes obsolete release files.
              </div>
              <div className="mt-2 text-xs font-medium text-amber-800 dark:text-amber-300">
                {updateBusy ? 'Running reinstall...' : 'Run Clean Reinstall'}
              </div>
            </button>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => navigate('/help?guide=guide-setup-updates-ui')}
              disabled={updateBusy}
              className="px-4 py-2 bg-sky-600 text-white rounded-lg hover:bg-sky-700 transition-colors disabled:opacity-50 inline-flex items-center gap-2"
            >
              <LifeBuoy className="w-4 h-4" />
              Help & Support
            </button>
          </div>

          <p className="text-xs text-gray-500 dark:text-gray-400">
            Simple mode: use <strong>Safe Update</strong>. Use <strong>Clean Reinstall</strong> only if you need a full cleanup.
          </p>

          {(updateOutput || updateError) && (
            <div className="rounded-lg border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 p-3">
              {updateError && (
                <div className="mb-2 text-xs text-red-500">{updateError}</div>
              )}
              <pre className="text-xs text-gray-800 dark:text-gray-200 whitespace-pre-wrap max-h-80 overflow-auto">
                {updateOutput || 'No output'}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div >
  )
}
