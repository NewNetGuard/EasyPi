import { useEffect, useMemo, useState } from 'react'
import { Eye, EyeOff, KeyRound, Loader2, Play, Power, RefreshCw, Server, ShieldCheck, Trash2 } from 'lucide-react'
import { toast } from 'react-hot-toast'

import Modal from '../common/Modal'
import {
  checkMobileLinkRelayConnection,
  deployMobileLinkRelay,
  getMobileLinkRelayStatus,
  inspectMobileLinkRelayHostKey,
  manageMobileLinkRelay,
  trustMobileLinkRelayHostKey,
  type MobileLinkRelayAuthMethod,
  type MobileLinkRelayCredentials,
  type MobileLinkRelayHostKey,
  type MobileLinkRelayStatus,
} from '../../api/mobile'

type Action = 'deploy' | 'check-status' | 'restart' | 'disable' | 'uninstall'

const message = (error: any, fallback: string): string => {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map((item) => item?.msg).filter(Boolean).join('; ') || fallback
  return error?.message || fallback
}

export default function MobileLinkRelay({ onChanged }: { onChanged?: () => void }) {
  const [status, setStatus] = useState<MobileLinkRelayStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [open, setOpen] = useState(false)
  const [action, setAction] = useState<Action>('deploy')
  const [hostKey, setHostKey] = useState<MobileLinkRelayHostKey | null>(null)
  const [sshVerified, setSshVerified] = useState(false)
  const [showSecret, setShowSecret] = useState(false)
  const [error, setError] = useState('')
  const [host, setHost] = useState('')
  const [sshPort, setSshPort] = useState(22)
  const [sshUser, setSshUser] = useState('root')
  const [authMethod, setAuthMethod] = useState<MobileLinkRelayAuthMethod>('password')
  const [sshPassword, setSshPassword] = useState('')
  const [sshKey, setSshKey] = useState('')
  const [domain, setDomain] = useState('')
  const [agentPort, setAgentPort] = useState(9443)
  const [mobilePort, setMobilePort] = useState(9444)

  const refresh = async () => {
    try { setStatus(await getMobileLinkRelayStatus()) }
    catch (failure) { toast.error(message(failure, 'Could not load VPS relay status')) }
    finally { setLoading(false) }
  }
  useEffect(() => { void refresh() }, [])

  const credentials = useMemo<MobileLinkRelayCredentials>(() => ({
    host: host.trim(), ssh_port: sshPort, ssh_user: sshUser.trim(), auth_method: authMethod,
    ...(authMethod === 'password' && sshPassword ? { ssh_password: sshPassword } : {}),
    ...(authMethod === 'key' && sshKey ? { ssh_key: sshKey } : {}),
  }), [authMethod, host, sshKey, sshPassword, sshPort, sshUser])

  const savedCredentialApplies = Boolean(
    status?.credential_configured && status.host === host.trim()
    && status.ssh_port === sshPort && status.ssh_user === sshUser.trim(),
  )
  const trusted = Boolean(
    hostKey?.trust_status === 'trusted'
    || (status?.host_key_trusted && status.host === host.trim() && status.ssh_port === sshPort),
  )
  const enteredCredential = authMethod === 'password' ? Boolean(sshPassword) : Boolean(sshKey)

  const begin = (next: Action) => {
    const nextHost = status?.host || host
    const nextPort = status?.ssh_port || sshPort
    const nextUser = status?.ssh_user || sshUser
    setAction(next)
    setHost(nextHost); setSshPort(nextPort); setSshUser(nextUser)
    setAuthMethod(status?.credential_type || authMethod)
    setDomain(status?.domain || domain)
    setAgentPort(status?.agent_port || agentPort); setMobilePort(status?.mobile_port || mobilePort)
    setHostKey(null); setError('')
    setSshVerified(Boolean(status?.credential_configured && status.host_key_trusted && status.host === nextHost))
    setOpen(true)
  }

  const inspect = async () => {
    setWorking(true); setError(''); setSshVerified(false)
    try { setHostKey(await inspectMobileLinkRelayHostKey(host.trim(), sshPort)) }
    catch (failure) { const text = message(failure, 'Could not inspect VPS SSH key'); setError(text); toast.error(text) }
    finally { setWorking(false) }
  }

  const trust = async () => {
    if (!hostKey) return
    setWorking(true); setError('')
    try { setHostKey(await trustMobileLinkRelayHostKey(host.trim(), sshPort, hostKey.fingerprint)); toast.success('VPS SSH key trusted') }
    catch (failure) { const text = message(failure, 'Could not trust VPS SSH key'); setError(text); toast.error(text) }
    finally { setWorking(false) }
  }

  const check = async () => {
    setWorking(true); setError('')
    try {
      const result = await checkMobileLinkRelayConnection(credentials)
      setSshVerified(true)
      setStatus((current) => current ? { ...current, host: host.trim(), ssh_port: sshPort, ssh_user: sshUser.trim(), host_key_trusted: true, credential_configured: result.credential_configured, credential_type: result.credential_type, credential_protection: result.credential_protection } : current)
      setSshPassword(''); setSshKey(''); setShowSecret(false)
      toast.success(result.message)
    } catch (failure) { setSshVerified(false); const text = message(failure, 'SSH connection failed'); setError(text); toast.error(text) }
    finally { setWorking(false) }
  }

  const execute = async () => {
    if (!sshVerified) return toast.error('Test the SSH connection first')
    setWorking(true); setError('')
    try {
      const next = action === 'deploy'
        ? await deployMobileLinkRelay({ ...credentials, domain: domain.trim(), agent_port: agentPort, mobile_port: mobilePort })
        : await manageMobileLinkRelay(action, credentials)
      setStatus(next); setOpen(false); setSshPassword(''); setSshKey('')
      onChanged?.()
      toast.success(action === 'deploy' ? 'Mobile Link relay deployed' : action === 'uninstall' ? 'Mobile Link relay removed' : 'Mobile Link relay updated')
    } catch (failure) { const text = message(failure, 'Mobile Link relay operation failed'); setError(text); toast.error(text) }
    finally { setWorking(false) }
  }

  return <>
    <section className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900 md:p-7">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex gap-3">
          <div className="rounded-xl bg-violet-500/15 p-3 text-violet-500"><Server className="h-6 w-6" /></div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">VPS Mobile Link relay</h2>
            <p className="mt-1 max-w-2xl text-sm text-gray-500 dark:text-gray-400">Forwards encrypted mobile connections to this EasyPi. It is independent from Stealth and never receives decrypted photos, tokens, or API requests.</p>
          </div>
        </div>
        <span className={`rounded-full px-3 py-1 text-xs font-semibold ${status?.active ? 'bg-emerald-500/15 text-emerald-500' : 'bg-gray-500/15 text-gray-500'}`}>
          {loading ? 'Checking' : status?.active ? 'Relay running' : status?.configured ? 'Relay stopped' : 'Not deployed'}
        </span>
      </div>
      {status?.configured && <div className="mt-5 grid gap-3 text-sm sm:grid-cols-3">
        <div className="rounded-xl bg-gray-50 p-3 dark:bg-dark-800"><span className="text-gray-500">Domain</span><div className="mt-1 break-all font-medium dark:text-white">{status.domain}</div></div>
        <div className="rounded-xl bg-gray-50 p-3 dark:bg-dark-800"><span className="text-gray-500">Agent TLS</span><div className="mt-1 font-medium dark:text-white">TCP {status.agent_port}</div></div>
        <div className="rounded-xl bg-gray-50 p-3 dark:bg-dark-800"><span className="text-gray-500">Mobile HTTPS</span><div className="mt-1 font-medium dark:text-white">TCP {status.mobile_port}</div></div>
      </div>}
      {status?.last_error && <div className="mt-4 rounded-xl bg-red-500/10 px-4 py-3 text-sm text-red-500">{status.last_error}</div>}
      <div className="mt-5 flex flex-wrap gap-3">
        <button onClick={() => begin('deploy')} className="inline-flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-semibold text-white hover:bg-violet-700"><Play className="h-4 w-4" />{status?.configured ? 'Update relay' : 'Deploy relay'}</button>
        {status?.configured && <>
          <button onClick={() => begin('check-status')} className="inline-flex items-center gap-2 rounded-lg bg-gray-100 px-4 py-2 text-sm font-medium dark:bg-dark-700 dark:text-white"><RefreshCw className="h-4 w-4" />Refresh VPS</button>
          <button onClick={() => begin(status.enabled ? 'disable' : 'restart')} className="inline-flex items-center gap-2 rounded-lg bg-gray-100 px-4 py-2 text-sm font-medium dark:bg-dark-700 dark:text-white"><Power className="h-4 w-4" />{status.enabled ? 'Disable' : 'Start'}</button>
          <button onClick={() => begin('uninstall')} className="inline-flex items-center gap-2 rounded-lg bg-red-500/10 px-4 py-2 text-sm font-medium text-red-500"><Trash2 className="h-4 w-4" />Uninstall</button>
        </>}
      </div>
    </section>

    <Modal isOpen={open} onClose={() => { if (!working) setOpen(false) }} title={action === 'deploy' ? 'Configure VPS Mobile Link relay' : `${action.replace('-', ' ')} Mobile Link relay`} size="xl" closeOnOutsideClick={!working}>
      <div className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-[1fr_140px]">
          <label className="text-sm font-medium dark:text-gray-200">VPS IPv4<input value={host} onChange={(e) => { setHost(e.target.value); setHostKey(null); setSshVerified(false) }} placeholder="203.0.113.10" className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" /></label>
          <label className="text-sm font-medium dark:text-gray-200">SSH port<input type="number" value={sshPort} onChange={(e) => { setSshPort(Number(e.target.value)); setHostKey(null); setSshVerified(false) }} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" /></label>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm font-medium dark:text-gray-200">SSH user<input value={sshUser} onChange={(e) => { setSshUser(e.target.value); setSshVerified(false) }} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" /></label>
          <label className="text-sm font-medium dark:text-gray-200">Authentication<select value={authMethod} onChange={(e) => { setAuthMethod(e.target.value as MobileLinkRelayAuthMethod); setSshVerified(false) }} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800"><option value="password">Password</option><option value="key">Private key</option></select></label>
        </div>
        <label className="block text-sm font-medium dark:text-gray-200">{authMethod === 'password' ? 'SSH password' : 'SSH private key'}{savedCredentialApplies && <span className="ml-2 text-xs text-emerald-500">encrypted credential already saved</span>}
          <div className="relative mt-1">{authMethod === 'password' ? <input type={showSecret ? 'text' : 'password'} value={sshPassword} onChange={(e) => { setSshPassword(e.target.value); setSshVerified(false) }} placeholder={savedCredentialApplies ? 'Leave empty to use saved credential' : ''} className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 pr-10 dark:border-dark-600 dark:bg-dark-800" /> : <textarea rows={5} value={sshKey} onChange={(e) => { setSshKey(e.target.value); setSshVerified(false) }} placeholder={savedCredentialApplies ? 'Leave empty to use saved credential' : '-----BEGIN OPENSSH PRIVATE KEY-----'} className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-mono text-xs dark:border-dark-600 dark:bg-dark-800" />}
          {authMethod === 'password' && <button type="button" onClick={() => setShowSecret((v) => !v)} className="absolute right-2 top-2 p-1 text-gray-500">{showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>}</div>
        </label>
        <div className="flex flex-wrap gap-2"><button disabled={working || !host} onClick={() => void inspect()} className="inline-flex items-center gap-2 rounded-lg bg-gray-100 px-3 py-2 text-sm font-medium disabled:opacity-50 dark:bg-dark-700 dark:text-white"><KeyRound className="h-4 w-4" />Inspect SSH key</button>{hostKey?.trust_status === 'unknown' && <button disabled={working} onClick={() => void trust()} className="inline-flex items-center gap-2 rounded-lg bg-amber-600 px-3 py-2 text-sm font-semibold text-white"><ShieldCheck className="h-4 w-4" />Trust this key</button>}<button disabled={working || !trusted || (!enteredCredential && !savedCredentialApplies)} onClick={() => void check()} className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">Test & save SSH</button></div>
        {hostKey && <div className="rounded-lg bg-gray-50 p-3 text-xs dark:bg-dark-800"><div>{hostKey.algorithm}</div><code className="break-all">{hostKey.fingerprint}</code>{hostKey.trust_status === 'changed' && <div className="mt-2 font-semibold text-red-500">SSH host key changed. Verify it from the VPS provider console.</div>}</div>}
        {action === 'deploy' && <><div className="grid gap-4 sm:grid-cols-3"><label className="text-sm font-medium dark:text-gray-200 sm:col-span-3">DuckDNS domain<input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="mobile.example.duckdns.org" className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" /></label><label className="text-sm font-medium dark:text-gray-200">Agent port<input type="number" min={1024} max={65535} value={agentPort} onChange={(e) => setAgentPort(Number(e.target.value))} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" /></label><label className="text-sm font-medium dark:text-gray-200">Mobile port<input type="number" min={1024} max={65535} value={mobilePort} onChange={(e) => setMobilePort(Number(e.target.value))} className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-600 dark:bg-dark-800" /></label></div><div className="rounded-lg bg-sky-500/10 p-3 text-sm text-sky-700 dark:text-sky-300">The domain must already have a valid Let&apos;s Encrypt certificate on this VPS. Open TCP {agentPort} and {mobilePort} in the VPS provider firewall. These ports do not replace Chameleon TCP 443 or Private DNS TCP 8443.</div></>}
        {error && <div className="rounded-lg bg-red-500/10 p-3 text-sm text-red-500">{error}</div>}
        <div className="flex justify-end gap-3"><button disabled={working} onClick={() => setOpen(false)} className="rounded-lg bg-gray-100 px-4 py-2 text-sm font-medium dark:bg-dark-700 dark:text-white">Cancel</button><button disabled={working || !sshVerified || (action === 'deploy' && !domain)} onClick={() => void execute()} className="inline-flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">{working && <Loader2 className="h-4 w-4 animate-spin" />}{action === 'deploy' ? 'Deploy' : 'Continue'}</button></div>
      </div>
    </Modal>
  </>
}
