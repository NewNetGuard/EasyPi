import { useEffect, useMemo, useState } from 'react'
import { toast } from 'react-hot-toast'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Play,
  Power,
  RefreshCw,
  Server,
  ShieldCheck,
  Trash2,
  Zap,
} from 'lucide-react'
import Modal from '../common/Modal'
import { copyToClipboard } from '../../utils/clipboard'
import {
  checkRelayConnection,
  deployRelay,
  getRelayStatus,
  inspectRelayHostKey,
  manageRelay,
  trustRelayHostKey,
  type RelayAuthMethod,
  type RelayCredentials,
  type RelayHostKey,
  type RelayStatus,
} from '../../api/tailscaleRemoteAccess'

type RelayAction = 'deploy' | 'check-status' | 'restart' | 'disable' | 'uninstall'

const errorMessage = (error: any, fallback: string): string => {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => typeof item === 'string' ? item : item?.msg)
      .filter((item): item is string => typeof item === 'string' && item.length > 0)
    if (messages.length) return messages.join('; ')
  }
  if (detail && typeof detail.message === 'string') return detail.message
  return typeof error?.message === 'string' ? error.message : fallback
}

export default function FastMobileRelay() {
  const [status, setStatus] = useState<RelayStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [pendingAction, setPendingAction] = useState<RelayAction>('deploy')
  const [hostKey, setHostKey] = useState<RelayHostKey | null>(null)
  const [sshVerified, setSshVerified] = useState(false)
  const [showSecret, setShowSecret] = useState(false)
  const [operationError, setOperationError] = useState('')

  const [host, setHost] = useState('')
  const [sshPort, setSshPort] = useState(22)
  const [sshUser, setSshUser] = useState('root')
  const [authMethod, setAuthMethod] = useState<RelayAuthMethod>('password')
  const [sshPassword, setSshPassword] = useState('')
  const [sshKey, setSshKey] = useState('')
  const [authKey, setAuthKey] = useState('')
  const [relayName, setRelayName] = useState('easypi-fast-relay')
  const [relayPort, setRelayPort] = useState(40000)
  const [publicEndpoint, setPublicEndpoint] = useState('')

  const refresh = async () => {
    try {
      setStatus(await getRelayStatus())
    } catch (error) {
      toast.error(errorMessage(error, 'Could not load Fast Mobile Relay status'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  const credentials = useMemo<RelayCredentials>(() => ({
    host: host.trim(),
    ssh_port: sshPort,
    ssh_user: sshUser.trim(),
    auth_method: authMethod,
    ...(authMethod === 'password' && sshPassword ? { ssh_password: sshPassword } : {}),
    ...(authMethod === 'key' && sshKey ? { ssh_key: sshKey } : {}),
  }), [authMethod, host, sshKey, sshPassword, sshPort, sshUser])

  const savedCredentialApplies = Boolean(
    status?.credential_configured
    && status.host === host.trim()
    && status.ssh_port === sshPort
    && status.ssh_user === sshUser.trim(),
  )
  const hostTrustedForForm = Boolean(
    hostKey?.trust_status === 'trusted'
    || (status?.host_key_trusted && status.host === host.trim() && status.ssh_port === sshPort),
  )
  const tailscaleAlreadyConnected = Boolean(
    status?.tailscale_ip
    && status.relay_tagged
    && status.host === host.trim()
    && status.ssh_port === sshPort,
  )
  const relayIdentityBlocked = Boolean(
    pendingAction === 'deploy'
    && status?.tailscale_ip
    && !status.relay_tagged
    && status.host === host.trim()
    && status.ssh_port === sshPort,
  )
  const hasEnteredCredential = authMethod === 'password' ? Boolean(sshPassword) : Boolean(sshKey)

  const clearEnteredSecrets = () => {
    setSshPassword('')
    setSshKey('')
    setAuthKey('')
    setShowSecret(false)
  }

  const clearSecrets = () => {
    clearEnteredSecrets()
    setSshVerified(false)
  }

  const openAction = (action: RelayAction) => {
    const nextHost = status?.host || host
    const nextPort = status?.ssh_port || sshPort
    const nextUser = status?.ssh_user || sshUser
    const saved = Boolean(
      status?.credential_configured
      && status.host === nextHost
      && status.ssh_port === nextPort
      && status.ssh_user === nextUser
      && status.host_key_trusted,
    )
    setPendingAction(action)
    setHost(nextHost)
    setSshPort(nextPort)
    setSshUser(nextUser)
    setAuthMethod(status?.credential_type || authMethod)
    setRelayName(status?.relay_name || relayName)
    setRelayPort(status?.relay_port || relayPort)
    const savedEndpoint = status?.public_endpoint || ''
    const endpointWasAutomatic = Boolean(
      status?.host && savedEndpoint === `${status.host}:${status.relay_port}`,
    )
    setPublicEndpoint(endpointWasAutomatic ? '' : savedEndpoint)
    setHostKey(null)
    setSshVerified(saved)
    setOperationError('')
    setModalOpen(true)
  }

  const closeModal = () => {
    if (working) return
    setModalOpen(false)
    clearSecrets()
  }

  const inspectHost = async () => {
    setWorking(true)
    setSshVerified(false)
    setOperationError('')
    try {
      const result = await inspectRelayHostKey(host.trim(), sshPort)
      setHostKey(result)
      if (result.trust_status === 'changed') {
        toast.error('The VPS SSH key changed. Verify it in the VPS console before continuing.')
      } else if (result.trust_status === 'trusted') {
        toast.success('The VPS identity matches the trusted SSH key')
      }
    } catch (error) {
      const message = errorMessage(error, 'Could not inspect the VPS SSH key')
      setOperationError(message)
      toast.error(message)
    } finally {
      setWorking(false)
    }
  }

  const trustHost = async () => {
    if (!hostKey) return
    setWorking(true)
    setOperationError('')
    try {
      const trusted = await trustRelayHostKey(host.trim(), sshPort, hostKey.fingerprint)
      setHostKey(trusted)
      toast.success('VPS SSH key trusted')
    } catch (error) {
      const message = errorMessage(error, 'Could not trust the VPS SSH key')
      setOperationError(message)
      toast.error(message)
    } finally {
      setWorking(false)
    }
  }

  const testConnection = async () => {
    setWorking(true)
    setOperationError('')
    try {
      const result = await checkRelayConnection(credentials)
      setSshVerified(true)
      setStatus((current) => current ? {
        ...current,
        host: host.trim(),
        ssh_port: sshPort,
        ssh_user: sshUser.trim(),
        credential_configured: result.credential_configured,
        credential_type: result.credential_type,
        credential_protection: result.credential_protection,
        host_key_trusted: true,
      } : current)
      clearEnteredSecrets()
      toast.success(`${result.message} (${result.os})`)
    } catch (error) {
      setSshVerified(false)
      const message = errorMessage(error, 'SSH connection failed')
      setOperationError(message)
      toast.error(message)
    } finally {
      setWorking(false)
    }
  }

  const execute = async () => {
    if (!sshVerified) {
      toast.error('Test the SSH connection first')
      return
    }
    setWorking(true)
    setOperationError('')
    try {
      const next = pendingAction === 'deploy'
        ? await deployRelay({
            ...credentials,
            relay_name: relayName.trim(),
            relay_port: relayPort,
            ...(publicEndpoint.trim() ? { public_endpoint: publicEndpoint.trim() } : {}),
            ...(authKey.trim() ? { auth_key: authKey.trim() } : {}),
          })
        : await manageRelay(pendingAction, credentials)
      setStatus(next)
      toast.success(
        pendingAction === 'deploy' ? 'Fast Mobile Relay deployed' :
        pendingAction === 'check-status' ? 'Relay status refreshed' :
        pendingAction === 'restart' ? 'Fast Mobile Relay restarted' :
        pendingAction === 'disable' ? 'Fast Mobile Relay disabled' :
        'Fast Mobile Relay removed',
      )
      setModalOpen(false)
      clearSecrets()
    } catch (error) {
      const message = errorMessage(error, 'Fast Mobile Relay operation failed')
      setOperationError(message)
      toast.error(message)
    } finally {
      setWorking(false)
    }
  }

  const statusLabel = loading ? 'Checking' : status?.enabled
    ? status.listening ? 'VPS relay ready' : 'Enabled, checking listener'
    : status?.configured ? 'Disabled' : 'Not configured'

  return (
    <>
      <div className="rounded-xl border border-gray-200 bg-white p-6 dark:border-dark-700 dark:bg-dark-800">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex gap-3">
            <div className="rounded-xl bg-violet-100 p-3 text-violet-600 dark:bg-violet-900/30 dark:text-violet-300">
              <Zap className="h-6 w-6" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Fast Mobile Relay</h3>
                <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${status?.enabled
                  ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                  : 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-300'}`}>
                  {statusLabel}
                </span>
              </div>
              <p className="mt-1 max-w-2xl text-sm text-gray-600 dark:text-gray-400">
                Deploy a Tailscale Peer Relay on your VPS for faster connections when mobile networks cannot reach EasyPi directly.
                EasyPi remains the exit node; the VPS only relays encrypted WireGuard traffic.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => openAction('deploy')} className="inline-flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-semibold text-white hover:bg-violet-700">
              <Server className="h-4 w-4" />
              {status?.configured ? 'Update settings' : 'Configure VPS'}
            </button>
            {status?.configured && (
              <button onClick={() => openAction('check-status')} className="inline-flex items-center gap-2 rounded-lg bg-gray-100 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-200 dark:hover:bg-dark-600">
                <RefreshCw className="h-4 w-4" /> Status
              </button>
            )}
          </div>
        </div>

        {status?.configured && (
          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <div className="rounded-lg bg-gray-50 p-3 dark:bg-dark-900">
              <p className="text-xs text-gray-500">VPS endpoint</p>
              <p className="mt-1 font-mono text-sm text-gray-900 dark:text-white">{status.public_endpoint || `${status.host}:${status.relay_port}`}</p>
            </div>
            <div className="rounded-lg bg-gray-50 p-3 dark:bg-dark-900">
              <p className="text-xs text-gray-500">Tailscale address</p>
              <p className="mt-1 font-mono text-sm text-gray-900 dark:text-white">{status.tailscale_ip || 'Not available'}</p>
            </div>
            <div className="rounded-lg bg-gray-50 p-3 dark:bg-dark-900">
              <p className="text-xs text-gray-500">UDP listener</p>
              <p className={`mt-1 text-sm font-medium ${status.listening ? 'text-green-600' : 'text-amber-600'}`}>
                {status.listening ? `Listening on ${status.relay_port}` : 'Not confirmed'}
              </p>
            </div>
            <div className="rounded-lg bg-gray-50 p-3 dark:bg-dark-900">
              <p className="text-xs text-gray-500">Tailscale version</p>
              <p className="mt-1 text-sm text-gray-900 dark:text-white">{status.tailscale_version || 'Unknown'}</p>
            </div>
            <div className="rounded-lg bg-gray-50 p-3 dark:bg-dark-900">
              <p className="text-xs text-gray-500">Relay isolation</p>
              <p className={`mt-1 text-sm font-medium ${status.isolation_active ? 'text-green-600' : 'text-red-600'}`}>
                {status.isolation_active ? 'Tag + shields-up active' : 'Not confirmed'}
              </p>
            </div>
          </div>
        )}

        {status?.enabled && !status.isolation_active && (
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            Relay host isolation is incomplete. Do not rely on this relay until the VPS has tag:easypi-relay and shields-up is active.
          </div>
        )}

        {status?.policy_grant && (
          <div className="mt-5 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-900/20">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
              <div className="min-w-0 flex-1">
                <h4 className="font-semibold text-amber-900 dark:text-amber-200">Secure Tailscale policy required</h4>
                <p className="mt-1 text-sm text-amber-800 dark:text-amber-300">
                  Merge this tag owner and grant into Tailscale Access Controls before deployment. Remove the default
                  <code className="mx-1">{'{"src":["*"],"dst":["*"],"ip":["*"]}'}</code>
                  grant because it would let a compromised relay reach every tailnet device. This fragment preserves access to each user's own devices and exit-node internet. Add explicit grants for shared EasyPi devices or subnet routes when required.
                </p>
                <pre className="mt-3 overflow-x-auto rounded bg-white/80 p-3 text-xs text-gray-800 dark:bg-dark-900 dark:text-gray-200">{status.policy_grant}</pre>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button onClick={() => void copyToClipboard(status.policy_grant || '')} className="inline-flex items-center gap-1.5 rounded bg-amber-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-700">
                    <Copy className="h-3.5 w-3.5" /> Copy secure policy fragment
                  </button>
                  <a href="https://login.tailscale.com/admin/acls/file" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded border border-amber-300 px-3 py-1.5 text-xs font-semibold text-amber-800 hover:bg-amber-100 dark:text-amber-200">
                    <ExternalLink className="h-3.5 w-3.5" /> Open Access Controls
                  </a>
                </div>
              </div>
            </div>
          </div>
        )}

        {status?.last_error && (
          <div className="mt-4 flex items-start gap-2 rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> {status.last_error}
          </div>
        )}

        {status?.configured && (
          <div className="mt-5 flex flex-wrap gap-2 border-t border-gray-200 pt-4 dark:border-dark-700">
            <button onClick={() => openAction('restart')} className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700"><Play className="h-4 w-4" /> Restart</button>
            {status.enabled && <button onClick={() => openAction('disable')} className="inline-flex items-center gap-2 rounded-lg bg-amber-100 px-3 py-2 text-sm font-medium text-amber-800 hover:bg-amber-200 dark:bg-amber-900/30 dark:text-amber-200"><Power className="h-4 w-4" /> Disable</button>}
            <button onClick={() => openAction('uninstall')} className="inline-flex items-center gap-2 rounded-lg bg-red-100 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-200 dark:bg-red-900/30 dark:text-red-300"><Trash2 className="h-4 w-4" /> Uninstall Relay</button>
          </div>
        )}
      </div>

      <Modal isOpen={modalOpen} onClose={closeModal} title={pendingAction === 'deploy' ? 'Configure Fast Mobile Relay' : `${pendingAction.replace('-', ' ')} Fast Mobile Relay`} size="xl" closeOnOutsideClick={!working}>
        <div className="space-y-5">
          <div className="rounded-lg bg-blue-50 p-3 text-sm text-blue-800 dark:bg-blue-900/20 dark:text-blue-200">
            The VPS must run Debian or Ubuntu and allow inbound UDP {relayPort}. All participating Tailscale clients need version 1.86 or newer. After a successful test, EasyPi keeps the SSH credential in host-bound encrypted storage. A Tailscale auth key is used only once and is never saved.
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            <label className="md:col-span-2 text-sm font-medium text-gray-700 dark:text-gray-300">VPS public IPv4
              <input value={host} onChange={(event) => { setHost(event.target.value); setHostKey(null); setSshVerified(false); setOperationError('') }} placeholder="203.0.113.10" className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" />
            </label>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">SSH port
              <input type="number" min={1} max={65535} value={sshPort} onChange={(event) => { setSshPort(Number(event.target.value)); setHostKey(null); setSshVerified(false); setOperationError('') }} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" />
            </label>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">SSH login
              <input value={sshUser} onChange={(event) => { setSshUser(event.target.value); setSshVerified(false); setOperationError('') }} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" />
            </label>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">Authentication
              <select value={authMethod} onChange={(event) => { setAuthMethod(event.target.value as RelayAuthMethod); setSshPassword(''); setSshKey(''); setSshVerified(false); setOperationError('') }} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800">
                <option value="password">Password</option>
                <option value="key">Private key</option>
              </select>
            </label>
            <label className="relative text-sm font-medium text-gray-700 dark:text-gray-300">{authMethod === 'password' ? 'SSH password' : 'SSH private key'}
              {authMethod === 'password' ? (
                <input type={showSecret ? 'text' : 'password'} value={sshPassword} onChange={(event) => { setSshPassword(event.target.value); setSshVerified(false); setOperationError('') }} placeholder={savedCredentialApplies ? 'Saved securely — leave blank to use it' : ''} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 pr-10 dark:border-dark-600 dark:bg-dark-800" />
              ) : (
                <textarea rows={3} value={sshKey} onChange={(event) => { setSshKey(event.target.value); setSshVerified(false); setOperationError('') }} placeholder={savedCredentialApplies ? 'Saved securely — leave blank to use it' : '-----BEGIN OPENSSH PRIVATE KEY-----'} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-mono text-xs dark:border-dark-600 dark:bg-dark-800" />
              )}
              {authMethod === 'password' && <button type="button" onClick={() => setShowSecret((value) => !value)} className="absolute bottom-2.5 right-3 text-gray-400">{showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>}
            </label>
          </div>

          {savedCredentialApplies && (
            <div className="flex items-start gap-2 rounded-lg bg-green-50 p-3 text-sm text-green-700 dark:bg-green-900/20 dark:text-green-300">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              SSH access is saved with {status?.credential_protection || 'system encryption'}. Leave the credential field empty to reuse it.
            </div>
          )}

          <div className="rounded-lg border border-gray-200 p-4 dark:border-dark-700">
            <div className="flex flex-wrap items-center gap-2">
              <button disabled={working || !host} onClick={inspectHost} className="inline-flex items-center gap-2 rounded-lg bg-gray-100 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-200 disabled:opacity-50 dark:bg-dark-700 dark:text-gray-200"><KeyRound className="h-4 w-4" /> Inspect SSH key</button>
              {hostKey?.trust_status === 'unknown' && <button disabled={working} onClick={trustHost} className="inline-flex items-center gap-2 rounded-lg bg-amber-600 px-3 py-2 text-sm font-semibold text-white hover:bg-amber-700"><ShieldCheck className="h-4 w-4" /> Trust this key</button>}
              {hostKey?.trust_status === 'trusted' && <span className="inline-flex items-center gap-1 text-sm font-medium text-green-600"><CheckCircle2 className="h-4 w-4" /> Trusted</span>}
              {!hostKey && hostTrustedForForm && <span className="inline-flex items-center gap-1 text-sm font-medium text-green-600"><CheckCircle2 className="h-4 w-4" /> Trusted</span>}
            </div>
            {hostKey && <p className="mt-3 break-all font-mono text-xs text-gray-600 dark:text-gray-400">{hostKey.key_type} · {hostKey.fingerprint}</p>}
          </div>

          <button disabled={working || !hostTrustedForForm || (!savedCredentialApplies && !hasEnteredCredential)} onClick={testConnection} className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:bg-gray-400">
            {working ? <Loader2 className="h-4 w-4 animate-spin" /> : <Activity className="h-4 w-4" />} Test connection
          </button>
          {sshVerified && <span className="ml-3 inline-flex items-center gap-1 text-sm font-medium text-green-600"><CheckCircle2 className="h-4 w-4" /> Connection verified</span>}

          {pendingAction === 'deploy' && (
            <div className="grid gap-4 border-t border-gray-200 pt-5 md:grid-cols-2 dark:border-dark-700">
              <div className="md:col-span-2 rounded-lg border border-violet-200 bg-violet-50 p-3 text-sm text-violet-800 dark:border-violet-800 dark:bg-violet-900/20 dark:text-violet-200">
                The relay must use the machine identity <strong>tag:easypi-relay</strong>. For a new VPS, generate a one-off pre-authorized auth key with that tag. EasyPi also enables shields-up and disables route, DNS, and Tailscale SSH acceptance on the VPS.
              </div>
              <label className="text-sm font-medium text-gray-700 dark:text-gray-300">Relay name
                <input value={relayName} onChange={(event) => setRelayName(event.target.value.toLowerCase())} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" />
              </label>
              <label className="text-sm font-medium text-gray-700 dark:text-gray-300">Relay UDP port
                <input type="number" min={1} max={65535} value={relayPort} onChange={(event) => setRelayPort(Number(event.target.value))} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" />
                <span className="mt-1 block text-xs text-gray-500">Use UDP 443 or a port from 1024 to 65535.</span>
              </label>
              <label className="text-sm font-medium text-gray-700 dark:text-gray-300">Public endpoint (optional)
                <input value={publicEndpoint} onChange={(event) => setPublicEndpoint(event.target.value)} placeholder={`${host || '203.0.113.10'}:${relayPort}`} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" />
                <span className="mt-1 block text-xs text-gray-500">Leave blank to use the VPS address and relay port.</span>
              </label>
              {relayIdentityBlocked ? (
                <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
                  This existing VPS is not tagged. In Tailscale Machines, assign <strong>tag:easypi-relay</strong>, then refresh Relay Status before updating settings.
                </div>
              ) : tailscaleAlreadyConnected ? (
                <div className="rounded-lg bg-green-50 p-3 text-sm text-green-700 dark:bg-green-900/20 dark:text-green-300">
                  <CheckCircle2 className="mr-2 inline h-4 w-4" /> VPS has the isolated relay tag. No auth key is required.
                </div>
              ) : (
                <label className="text-sm font-medium text-gray-700 dark:text-gray-300">One-time Tailscale auth key (first connection only)
                  <input type={showSecret ? 'text' : 'password'} value={authKey} onChange={(event) => setAuthKey(event.target.value)} placeholder="tskey-auth-..." className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" />
                  <span className="mt-1 block text-xs text-gray-500">Generate a one-off, pre-authorized key carrying tag:easypi-relay. EasyPi never stores it.</span>
                </label>
              )}
              <div className="md:col-span-2 rounded-lg border border-gray-200 bg-gray-50 p-3 text-xs text-gray-600 dark:border-dark-700 dark:bg-dark-900 dark:text-gray-400">
                <strong className="text-gray-800 dark:text-gray-200">Safe on the same VPS:</strong>{' '}
                Chameleon uses TCP 443, Personal DNS commonly uses 53/853/8443, and Fast Mobile Relay uses UDP {relayPort}.
              </div>
            </div>
          )}

          {pendingAction === 'uninstall' && <div className="rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">This removes only relay settings and firewall rules created by EasyPi. A pre-existing Tailscale installation on the VPS is preserved.</div>}

          {operationError && (
            <div className="flex items-start gap-2 rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> {operationError}
            </div>
          )}

          <div className="flex justify-end gap-2 border-t border-gray-200 pt-4 dark:border-dark-700">
            <button disabled={working} onClick={closeModal} className="rounded-lg bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-200">Cancel</button>
            <button disabled={working || !sshVerified || relayIdentityBlocked} onClick={execute} className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white disabled:bg-gray-400 ${pendingAction === 'uninstall' ? 'bg-red-600 hover:bg-red-700' : 'bg-violet-600 hover:bg-violet-700'}`}>
              {working && <Loader2 className="h-4 w-4 animate-spin" />}
              {pendingAction === 'deploy' ? 'Deploy & Enable' : pendingAction === 'check-status' ? 'Check Status' : pendingAction === 'restart' ? 'Restart Relay' : pendingAction === 'disable' ? 'Disable Relay' : 'Uninstall Relay'}
            </button>
          </div>
        </div>
      </Modal>
    </>
  )
}
