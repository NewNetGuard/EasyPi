import { useState, useEffect, type ComponentType, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import {
  EyeOff, ShieldCheck, ShieldAlert, Globe, Power, Trash2, Loader2, Info,
  CheckCircle2, XCircle, Users, Smartphone, Save, Fingerprint, RefreshCw,
  Rocket, Server, Wifi, KeyRound, Activity,
} from 'lucide-react'
import {
  getStealthStatus, saveStealthClient, generatePsk, generateReality, enableStealth,
  disableStealth, setStealthTargets, resetStealthProfile, deleteStealthConfig,
  saveStealthServer, checkStealthSsh, deployStealthServer, stopStealthServer,
  uninstallStealthServer, fetchStealthServerLogs, trustStealthSshHostKey,
  configureStealthDomainTls, removeStealthDomainTls, type StealthStatus,
} from '../api/stealth'
import { apiErrorMessage, withRoutingConflictConfirmation } from '../utils/routingConflict'
import { getCachedDevices, type CachedDevice } from '../api/vpn'

function fmtBytes(n?: number) {
  if (!n) return '0 B'
  const k = 1024, u = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(n) / Math.log(k))
  return `${parseFloat((n / Math.pow(k, i)).toFixed(1))} ${u[i]}`
}

type Tab = 'client' | 'server' | 'profile'

export default function Stealth() {
  const qc = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedTab = searchParams.get('tab')
  const tab: Tab = requestedTab === 'server' || requestedTab === 'profile' ? requestedTab : 'client'
  const setTab = (nextTab: Tab) => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', nextTab)
    setSearchParams(next, { replace: true })
  }
  const openServerSetup = () => {
    setTab('server')
    requestAnimationFrame(() => requestAnimationFrame(() => {
      document.getElementById('stealth-server-setup')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }))
  }
  const [deployLog, setDeployLog] = useState('')
  const [pendingHostFingerprint, setPendingHostFingerprint] = useState('')

  // client form
  const [serverAddr, setServerAddr] = useState('')
  const [reality, setReality] = useState('')
  const [psk, setPsk] = useState('')
  const [doh, setDoh] = useState('')
  const [buffer, setBuffer] = useState(1000)
  const [reconnect, setReconnect] = useState(5)
  const [blockQuic, setBlockQuic] = useState(true)
  const [fingerprintMode, setFingerprintMode] = useState<'auto' | 'mobile' | 'desktop'>('auto')
  const [scope, setScope] = useState<'all' | 'selected'>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  // server form
  const [sshHost, setSshHost] = useState('')
  const [sshUser, setSshUser] = useState('root')
  const [sshPort, setSshPort] = useState(22)
  const [sshPass, setSshPass] = useState('')
  const [remotePath, setRemotePath] = useState('/opt/chameleon-server')
  const [acmeTermsAccepted, setAcmeTermsAccepted] = useState(false)
  const [domain, setDomain] = useState('')
  const [seeded, setSeeded] = useState(false)

  const { data: st, isLoading } = useQuery({
    queryKey: ['stealth'],
    queryFn: getStealthStatus,
    refetchInterval: (q) => (q.state.data?.enabled ? 6000 : false),
  })
  const { data: devices = [] } = useQuery({
    queryKey: ['vpn-devices'],
    queryFn: getCachedDevices,
    refetchInterval: 6000,
  })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['stealth'] })
  const publishStatus = (next: StealthStatus) => {
    qc.setQueryData<StealthStatus>(['stealth'], next)
  }

  useEffect(() => {
    if (st && !seeded) {
      setServerAddr(st.server_address || '')
      setReality(st.reality_public || '')
      setDoh(st.doh_domain || '')
      setBuffer(st.buffer_size || 1000)
      setReconnect(st.reconnect_interval || 5)
      setBlockQuic(!!st.block_quic)
      setFingerprintMode(st.fingerprint_mode || 'auto')
      setScope(st.scope === 'selected' ? 'selected' : 'all')
      setSelected(new Set((st.device_list || []).map((d) => d.mac.toLowerCase())))
      setSshHost(st.ssh_host || '')
      setSshUser(st.ssh_user || 'root')
      setSshPort(st.ssh_port || 22)
      setRemotePath(st.remote_path || '/opt/chameleon-server')
      setAcmeTermsAccepted(!!st.acme_terms_accepted)
      setDomain(st.domain || '')
      setSeeded(true)
    }
  }, [st, seeded])

  const genPsk = useMutation({ mutationFn: generatePsk, onSuccess: (d) => { setPsk(d.psk_key); toast.success('PSK generated') } })
  const genReality = useMutation({ mutationFn: generateReality, onSuccess: (d) => { setReality(d.reality_public); invalidate(); toast.success('Public marker generated') } })
  const saveClient = useMutation({
    mutationFn: () => saveStealthClient({
      server_address: serverAddr.trim(), shield_preset: 'ip', doh_domain: doh.trim(),
      buffer_size: buffer, reconnect_interval: reconnect, block_quic: blockQuic,
      fingerprint_mode: fingerprintMode,
      ...(psk.trim() ? { psk_key: psk.trim() } : {}),
      ...(reality.trim() ? { reality_public: reality.trim() } : {}),
    }),
    onSuccess: (d) => {
      setPsk('')
      invalidate()
      if (d?.warning) toast(d.warning)
      else if (d?.running) toast.success('Settings applied; Stealth restarted')
      else toast.success('Client settings saved')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Save failed'),
  })
  const enable = useMutation({
    mutationFn: () => withRoutingConflictConfirmation((confirmed) => enableStealth(confirmed)),
    onSuccess: (d) => {
      if (!d) return
      // The mutation response is the authoritative post-operation state. Put
      // it in the cache before notifying the user so the badge and toast move
      // together instead of waiting for a second status request.
      publishStatus(d)
      d?.connected ? toast.success('Stealth connected') : d?.health_error ? toast.error(d.health_title || 'Stealth server unavailable') : d?.running ? toast.success('Stealth starting') : toast.error(d?.error || 'Did not start')
    },
    onError: (e: any) => toast.error(apiErrorMessage(e, 'Enable failed')),
  })
  const disable = useMutation({
    mutationFn: disableStealth,
    onSuccess: (d) => {
      publishStatus(d)
      toast.success('Stealth disabled')
    },
    onError: (e: any) => toast.error(apiErrorMessage(e, 'Disable failed')),
  })
  const del = useMutation({ mutationFn: deleteStealthConfig, onSuccess: () => { invalidate(); setSeeded(false); toast.success('Removed') } })
  const targets = useMutation({
    mutationFn: () => {
      const chosen = devices.filter((d) => d.mac && selected.has(d.mac.toLowerCase())).map((d) => ({ mac: d.mac as string, name: d.hostname || '', ip: d.ip }))
      return withRoutingConflictConfirmation((confirmed) =>
        setStealthTargets(scope, scope === 'selected' ? chosen : [], confirmed),
      )
    },
    onSuccess: (d) => { if (d) { invalidate(); toast.success('Routing scope saved') } },
    onError: (e: any) => toast.error(apiErrorMessage(e, 'Save failed')),
  })
  const resetProfile = useMutation({ mutationFn: resetStealthProfile, onSuccess: () => toast.success('Profile reset') })
  const persistServer = () => saveStealthServer({
    host: sshHost.trim(), user: sshUser.trim(), port: sshPort, password: sshPass || undefined,
    remote_path: remotePath.trim(), acme_terms_accepted: acmeTermsAccepted,
    domain: domain.trim(),
  })
  const saveServer = useMutation({
    mutationFn: persistServer,
    onSuccess: () => { setSshPass(''); invalidate(); toast.success('Server settings saved') },
  })
  // Check / Deploy / Stop auto-save the current form first, so no separate Save is required.
  const checkSsh = useMutation({
    mutationFn: async () => { await persistServer(); return checkStealthSsh() },
    onSuccess: (d) => {
      setDeployLog(d.log)
      setPendingHostFingerprint(d.needs_trust ? (d.fingerprint || '') : '')
      // Check SSH may trust the pinned host identity, install the device key,
      // and remove the stored password. Refresh the authoritative server state
      // immediately so TLS/deploy controls do not remain disabled by stale UI.
      setSshPass('')
      invalidate()
      d.needs_trust
        ? toast('Confirm the SSH host key', { icon: '🔐' })
        : d.success
          ? toast.success('SSH OK')
          : toast.error('SSH failed')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Check failed'),
  })
  const trustHostKey = useMutation({
    mutationFn: () => trustStealthSshHostKey(pendingHostFingerprint),
    onSuccess: (d) => {
      setDeployLog(d.log)
      if (d.host_key_trusted) setPendingHostFingerprint('')
      invalidate()
      if (d.success) {
        toast.success('SSH host key trusted and EasyPi key verified')
      } else if (d.host_key_trusted) {
        toast.error(d.error || 'Host key trusted, but SSH authentication setup failed')
      } else {
        toast.error(d.error || d.log || 'Host key was not trusted')
      }
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Trust failed'),
  })
  const deploy = useMutation({
    mutationFn: async () => { await persistServer(); return deployStealthServer() },
    onSuccess: (d) => { setDeployLog(d.log); invalidate(); d.success ? toast.success('Server deployed & started') : toast.error('Deploy failed — see log') },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Deploy failed'),
  })
  const configureDomainTls = useMutation({
    mutationFn: async () => { await persistServer(); return configureStealthDomainTls() },
    onSuccess: (d) => {
      setDeployLog(d.log)
      invalidate()
      d.success ? toast.success('Domain HTTPS configured') : toast.error('Domain setup failed — see log')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Domain setup failed'),
  })
  const removeDomainTls = useMutation({
    mutationFn: removeStealthDomainTls,
    onSuccess: (d) => {
      setDeployLog(d.log)
      invalidate()
      if (d.success) {
        setDomain('')
        setServerAddr(st?.ssh_host ? `${st.ssh_host}:443` : serverAddr)
        toast.success('Domain and token removed')
      } else {
        toast.error('Domain removal failed — see log')
      }
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Domain removal failed'),
  })
  const stopSrv = useMutation({
    mutationFn: async () => { await persistServer(); return stopStealthServer() },
    onSuccess: (d) => { setDeployLog(d.log); toast.success('Stop requested') },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Stop failed'),
  })
  const uninstall = useMutation({
    mutationFn: async () => { await persistServer(); return uninstallStealthServer() },
    onSuccess: (d) => { setDeployLog(d.log); d.success ? toast.success('Server removed from VPS') : toast.error('Uninstall failed — see log') },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Uninstall failed'),
  })
  const serverLogs = useMutation({
    mutationFn: async () => { await persistServer(); return fetchStealthServerLogs() },
    onSuccess: (d) => { setDeployLog(d.log) },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Fetch failed'),
  })

  const busy = enable.isPending || disable.isPending || del.isPending
  const running = !!st?.running, connected = !!st?.connected, configured = !!st?.configured
  const unhealthy = !!st?.health_error && !connected
  const toggleDev = (mac: string) => { const m = mac.toLowerCase(); setSelected((p) => { const n = new Set(p); n.has(m) ? n.delete(m) : n.add(m); return n }) }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-dark-950">
      <header className="bg-white dark:bg-dark-900 border-b border-gray-200 dark:border-dark-800">
        <div className="max-w-5xl mx-auto px-6 py-6 flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl shadow-lg shadow-indigo-500/20"><EyeOff className="w-8 h-8 text-white" /></div>
          <div className="flex-1">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Stealth</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">Adaptive anti-censorship tunnel designed to resemble ordinary HTTPS</p>
          </div>
          {configured && (st?.enabled ? (
            <button onClick={() => disable.mutate()} disabled={busy} className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium disabled:opacity-50">
              {disable.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Power className="w-4 h-4" />} Disable
            </button>
          ) : (
            <button onClick={() => enable.mutate()} disabled={busy} className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-medium disabled:opacity-50">
              {enable.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Power className="w-4 h-4" />} Enable
            </button>
          ))}
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-6 space-y-5">
        {/* status strip */}
        <div className="flex items-center gap-3 rounded-xl border border-gray-200 dark:border-dark-800 bg-white dark:bg-dark-900 px-4 py-3">
          {connected ? <ShieldCheck className="w-5 h-5 text-emerald-500" /> : <ShieldAlert className={`w-5 h-5 ${unhealthy ? 'text-red-500' : running ? 'text-amber-500' : 'text-gray-400'}`} />}
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {connected ? 'Stealth active' : unhealthy ? 'Server unavailable' : running ? 'Connecting…' : configured ? 'Not connected' : 'Not configured'}
          </span>
          {connected && st?.server && <span className="text-xs text-gray-500 font-mono">{st.server}</span>}
          <span className="ml-auto text-xs text-gray-400">
            {st?.killswitch ? 'kill-switch on' : ''}
            {st?.dns_protected ? ' · DNS protected' : ''}
            {st?.quic_blocked ? ' · QUIC blocked' : ''}
          </span>
        </div>

        {unhealthy && (
          <div role="alert" className="border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/30 px-4 py-4">
            <div className="flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold text-red-900 dark:text-red-200">{st?.health_title || 'Stealth server unavailable'}</div>
                <p className="mt-1 text-sm text-red-800 dark:text-red-300">{st?.health_hint}</p>
                <p className="mt-1 text-xs text-red-700 dark:text-red-400 break-words">Traffic remains blocked by the kill switch to prevent a direct connection.</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button onClick={openServerSetup} className="inline-flex items-center gap-2 px-3 py-2 bg-red-700 hover:bg-red-800 text-white text-sm font-medium">
                    <Server className="w-4 h-4" /> Check or deploy server
                  </button>
                  <button onClick={() => disable.mutate()} disabled={disable.isPending} className="inline-flex items-center gap-2 px-3 py-2 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-200 text-sm disabled:opacity-50">
                    {disable.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Power className="w-4 h-4" />} Disable Stealth
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* how-to */}
        <details className="rounded-xl border border-gray-200 dark:border-dark-800 bg-white dark:bg-dark-900 px-4 py-3" open={!configured}>
          <summary className="cursor-pointer text-sm font-medium text-gray-900 dark:text-white">How to set up Stealth</summary>
          <ol className="mt-3 text-sm text-gray-600 dark:text-gray-400 space-y-1.5 list-decimal list-inside">
            <li><strong>Client</strong> tab → <strong>Generate</strong> the PSK and public marker, type your VPS address (the <code>:443</code> port is added automatically), then <strong>Save client</strong>.</li>
            <li><strong>Server</strong> tab → enter the VPS SSH (host / root / password) → <strong>Deploy &amp; Start</strong>. This installs the tunnel server on your VPS with the same keys. Click once and wait — the VPS rate-limits rapid SSH connections.</li>
            <li>Back on <strong>Client</strong> → press <strong>Enable</strong> (top-right). Your network now exits through the VPS — check a device's public IP, it should be the VPS.</li>
            <li><strong>To stop:</strong> press <strong>Disable</strong> (top-right). Only selected devices (or the whole network) route through the tunnel; the EasyPi panel itself always stays reachable. If it ever doesn't, <strong>reboot the EasyPi</strong> — Stealth never survives a reboot, so it always comes back OFF.</li>
          </ol>
        </details>

        {/* tabs */}
        <div className="flex gap-2">
          {(['client', 'server', 'profile'] as Tab[]).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${tab === t ? 'bg-indigo-600 text-white' : 'bg-white dark:bg-dark-900 text-gray-600 dark:text-gray-300 border border-gray-200 dark:border-dark-700'}`}>
              {t}
            </button>
          ))}
        </div>

        {isLoading ? <div className="flex justify-center py-16 text-gray-400"><Loader2 className="w-6 h-6 animate-spin" /></div> : (
          <>
            {tab === 'client' && (
              <div className="space-y-5">
                <div className="bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-200 dark:border-indigo-800 rounded-xl p-4 flex gap-3">
                  <Info className="w-5 h-5 text-indigo-600 dark:text-indigo-400 flex-shrink-0 mt-0.5" />
                  <div className="text-sm text-indigo-800 dark:text-indigo-300">Generate the keys here, then deploy them to your VPS in the <strong>Server</strong> tab — the app pushes the same keys to both sides, so nothing is copied by hand.</div>
                </div>

                <Card title="Connection" icon={Wifi}>
                  <Field label="Server address — :443 is used automatically if you omit the port">
                    <input value={serverAddr} onChange={(e) => setServerAddr(e.target.value)} placeholder="203.0.113.10  (→ :443)" className={inp} />
                  </Field>
                  <Field label="Transport"><div className={ro}>HTTP/2</div></Field>
                </Card>

                <Card title="Server identity" icon={ShieldCheck}>
                  <Field label="TLS identity">
                    <div className={ro}>IP Shield — verified VPS certificate</div>
                    {st?.shield_migration_required && (
                      <div className="mt-2 text-xs text-amber-600 dark:text-amber-400">
                        A legacy session is still active. Accept the certificate agreement on Server and run Deploy &amp; Start to migrate it.
                      </div>
                    )}
                  </Field>
                  <Field label="REALITY server public key (hex)">
                    <div className="flex gap-2">
                      <input value={reality} onChange={(e) => setReality(e.target.value)} placeholder="click Generate →" className={`${inp} font-mono text-xs flex-1`} />
                      <GenBtn onClick={() => genReality.mutate()} loading={genReality.isPending} />
                    </div>
                  </Field>
                </Card>

                <Card title="Security" icon={KeyRound}>
                  <Field label="PSK key">
                    <div className="flex gap-2">
                      <input value={psk} onChange={(e) => setPsk(e.target.value)} type={psk ? 'text' : 'password'}
                        placeholder={st?.has_psk ? '•••••••• saved — Generate to replace' : 'click Generate →'} className={`${inp} font-mono text-xs flex-1`} />
                      <GenBtn onClick={() => genPsk.mutate()} loading={genPsk.isPending} />
                    </div>
                  </Field>
                  <Field label="DoH domain (fallback, optional)"><input value={doh} onChange={(e) => setDoh(e.target.value)} placeholder="updates.example.com" className={inp} /></Field>
                </Card>

                <Card title="Advanced" icon={Activity}>
                  <div className="grid grid-cols-2 gap-3">
                    <Field label="Buffer size"><input type="number" value={buffer} onChange={(e) => setBuffer(+e.target.value)} className={inp} /></Field>
                    <Field label="Reconnect interval (sec)"><input type="number" value={reconnect} onChange={(e) => setReconnect(+e.target.value)} className={inp} /></Field>
                  </div>
                  <Field label="TLS fingerprint profile">
                    <select value={fingerprintMode} onChange={(e) => setFingerprintMode(e.target.value as 'auto' | 'mobile' | 'desktop')} className={inp}>
                      <option value="auto">Auto</option>
                      <option value="mobile">Mobile browser</option>
                      <option value="desktop">Desktop browser</option>
                    </select>
                  </Field>
                  <label className="flex items-center gap-2 mt-3 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
                    <input type="checkbox" checked={blockQuic} onChange={(e) => setBlockQuic(e.target.checked)} className="w-4 h-4 rounded accent-indigo-600" />
                    Block QUIC (UDP/443) — forces YouTube etc. onto TCP
                  </label>
                </Card>

                <div className="flex gap-2">
                  <button onClick={() => saveClient.mutate()} disabled={saveClient.isPending} className={btnPrimary}>
                    {saveClient.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} Save client
                  </button>
                  {configured && <button onClick={() => { if (confirm('Remove the stealth config?')) del.mutate() }} className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-gray-300 dark:border-dark-700 text-gray-600 hover:text-red-600"><Trash2 className="w-4 h-4" /> Remove</button>}
                </div>

                {/* routing scope */}
                <Card title="Routing scope" icon={Users}>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <ScopeCard active={scope === 'all'} onClick={() => setScope('all')} icon={Globe} title="All approved devices" desc="Every approved device uses the stealth tunnel." />
                    <ScopeCard active={scope === 'selected'} onClick={() => setScope('selected')} icon={Users} title="Selected devices" desc="Only chosen devices (coexists with Internet Encryption)." />
                  </div>
                  {scope === 'selected' && (
                    <div className="mt-3 max-h-56 overflow-y-auto rounded-lg border border-gray-200 dark:border-dark-700 divide-y divide-gray-100 dark:divide-dark-800">
                      {devices.length === 0 ? <p className="text-sm text-gray-500 p-3">No approved or discovered devices yet.</p> :
                        devices.map((d: CachedDevice) => {
                          const m = (d.mac || '').toLowerCase()
                          return (
                            <label key={m} className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-gray-50 dark:hover:bg-dark-800/50">
                              <input type="checkbox" checked={selected.has(m)} onChange={() => toggleDev(m)} className="w-4 h-4 rounded accent-indigo-600" />
                              <Smartphone className="w-4 h-4 text-gray-400" />
                              <span className="flex-1 text-sm text-gray-900 dark:text-white truncate">{d.hostname || d.vendor || 'Unknown'}</span>
                              <span className="text-xs text-gray-400 font-mono">{d.ip}</span>
                            </label>
                          )
                        })}
                    </div>
                  )}
                  <button onClick={() => targets.mutate()} disabled={targets.isPending || (scope === 'selected' && selected.size === 0)} className={`${btnPrimary} mt-3`}>
                    {targets.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />} Save routing
                  </button>
                </Card>
              </div>
            )}

            {tab === 'server' && (
              <div id="stealth-server-setup" className="space-y-5 scroll-mt-4">
                <details className="group bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-200 dark:border-indigo-800 rounded-xl">
                  <summary className="p-4 flex items-center gap-3 cursor-pointer select-none text-sm font-medium text-indigo-900 dark:text-indigo-200">
                    <Info className="w-5 h-5 text-indigo-600 dark:text-indigo-400 flex-shrink-0" />
                    How deployment and optional Domain HTTPS work
                  </summary>
                  <div className="px-4 pb-4 pl-12 space-y-3 text-sm text-indigo-800 dark:text-indigo-300">
                    <p><strong>Deploy &amp; Start</strong> uploads Chameleon to your VPS over SSH and starts it with the keys generated on the Client tab. The VPS is your tunnel's exit point and must be outside the censored network. Generate the client keys first.</p>
                    <div>
                      <div className="font-semibold">First deployment — press the buttons in this order</div>
                      <ol className="mt-2 ml-5 list-decimal space-y-2">
                        <li>On the <strong>Client</strong> tab, generate both the <strong>PSK</strong> and <strong>public marker</strong>, enter the VPS address, then press <strong>Save client</strong>.</li>
                        <li>Return to <strong>Server</strong> and enter <strong>Host / IP</strong>, <strong>Login</strong>, <strong>Port</strong> and the VPS <strong>Password</strong>.</li>
                        <li>Press <strong>Check SSH</strong> once and wait for the fingerprint to appear in the Deployment log.</li>
                        <li>Compare that fingerprint with the one shown by your VPS provider. Only if they match, press <strong>Trust host key</strong> and wait until the SSH identity is trusted and the Ed25519 key is verified.</li>
                        <li>Accept the <strong>Let's Encrypt Subscriber Agreement</strong>.</li>
                        <li>Press <strong>Deploy &amp; Start</strong> once and wait. Deployment is complete when the log reports successful certificate verification, TUN/firewall setup and Chameleon restart, followed by an <strong>active</strong> status.</li>
                        <li>
                          Choose how Stealth should identify itself:
                          <ul className="mt-1 ml-5 list-disc space-y-1">
                            <li><strong>Without a domain:</strong> skip <strong>Configure Domain &amp; TLS</strong> and continue to the next step. IP Shield is already fully operational.</li>
                            <li><strong>With Domain HTTPS:</strong> point the DuckDNS domain to the VPS public IPv4, wait until it resolves, enter the domain, then press <strong>Configure Domain &amp; TLS</strong> once. Continue only after <strong>Active HTTPS identity</strong> shows that domain.</li>
                          </ul>
                        </li>
                        <li>Open <strong>Client</strong>, press <strong>Enable</strong>, then confirm that the page shows <strong>Stealth active</strong>.</li>
                      </ol>
                      <p className="mt-2 text-xs">The <strong>Save</strong> button only stores the Server form. <strong>Check SSH</strong> and <strong>Deploy &amp; Start</strong> save it automatically. Do not repeatedly press SSH or deployment buttons while an operation is running.</p>
                    </div>
                    <div>
                      <div className="font-semibold">Without a domain — fully supported</div>
                      <p className="mt-1">EasyPi uses a trusted TLS certificate for the VPS IP address. The tunnel remains encrypted, authenticated and fully functional, with no DNS name or DuckDNS token required. This is the simplest setup, but network observers can see that HTTPS connects directly to a bare IP address rather than a normal website hostname.</p>
                    </div>
                    <div>
                      <div className="font-semibold">With Domain HTTPS — optional extra camouflage</div>
                      <p className="mt-1">After deployment, point a DuckDNS domain to the VPS IP and add the domain here. EasyPi obtains and renews a trusted certificate without needing your DuckDNS token, then uses the domain for TLS SNI and HTTP Host. This looks more like an ordinary HTTPS endpoint, but does not guarantee invisibility against every DPI system.</p>
                    </div>
                    <p>You can add the domain later or remove it at any time. Removal switches the live tunnel back to IP Shield before deleting the saved domain.</p>
                  </div>
                </details>

                <Card title="SSH connection" icon={Server}>
                  <Field label="Host / IP"><input value={sshHost} onChange={(e) => { setSshHost(e.target.value); setPendingHostFingerprint('') }} placeholder="203.0.113.5" className={inp} /></Field>
                  <div className="grid grid-cols-2 gap-3">
                    <Field label="Login"><input value={sshUser} onChange={(e) => setSshUser(e.target.value)} className={inp} /></Field>
                    <Field label="Port"><input type="number" value={sshPort} onChange={(e) => { setSshPort(+e.target.value); setPendingHostFingerprint('') }} className={inp} /></Field>
                  </div>
                  <Field label="Password"><input value={sshPass} onChange={(e) => setSshPass(e.target.value)} type="password" autoComplete="off" placeholder={st?.ssh_key_verified ? 'Not needed — SSH key active' : st?.has_password ? '•••••••••• encrypted' : 'root password'} className={inp} /></Field>
                  <div className={`text-xs ${st?.ssh_host_key_trusted ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`}>
                    SSH identity: {st?.ssh_host_key_trusted ? `trusted (${st.ssh_host_key_fingerprint})` : 'not trusted'}
                  </div>
                  <div className={`text-xs mt-1 ${st?.ssh_key_verified ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`}>
                    SSH authentication: {st?.ssh_key_verified
                      ? `Ed25519 key verified · ${st.credential_protection || 'system encryption'}`
                      : st?.has_password ? 'password encrypted; EasyPi will replace it with an SSH key automatically' : 'credentials required'}
                  </div>
                  {st?.ssh_host_key_trusted && !st?.ssh_key_verified && (
                    <div className="mt-2 rounded-lg bg-amber-50 dark:bg-amber-950/30 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
                      The VPS identity is trusted, but SSH authentication is not ready. Enter the correct SSH password and click <strong>Check SSH</strong> to install and verify the EasyPi key.
                    </div>
                  )}
                </Card>

                <Card title="Deployment" icon={Rocket}>
                  <Field label="Remote path"><input value={remotePath} onChange={(e) => setRemotePath(e.target.value)} className={inp} /></Field>
                  <div className={`mb-3 text-xs ${st?.ip_shield_deployed ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`}>
                    IP Shield certificate: {st?.ip_shield_deployed ? 'deployed' : 'not deployed'}
                  </div>
                  <label className="flex items-start gap-2 mb-3 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
                    <input type="checkbox" checked={acmeTermsAccepted} onChange={(e) => setAcmeTermsAccepted(e.target.checked)} className="w-4 h-4 mt-0.5 rounded accent-indigo-600" />
                    <span>
                      I agree to the{' '}
                      <a href="https://letsencrypt.org/repository/" target="_blank" rel="noreferrer" className="text-indigo-600 dark:text-indigo-400 hover:underline">
                        Let's Encrypt Subscriber Agreement
                      </a>
                    </span>
                  </label>
                  <div className="rounded-lg border border-gray-200 dark:border-dark-700 p-3 space-y-3">
                    <div className="flex items-center gap-2 text-sm font-medium text-gray-900 dark:text-white">
                      <Globe className="w-4 h-4 text-indigo-500" /> Domain HTTPS
                    </div>
                    <Field label="DuckDNS domain">
                      <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="my-stealth.duckdns.org" className={inp} />
                    </Field>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      The domain must already resolve to the VPS IP. This form does not request or submit your DuckDNS token.
                    </p>
                    <div className={`text-xs ${st?.domain_tls_deployed ? 'text-emerald-600 dark:text-emerald-400' : 'text-gray-500 dark:text-gray-400'}`}>
                      {st?.domain_tls_deployed
                        ? `Active HTTPS identity: ${st.domain}`
                        : 'Optional — Stealth already works with IP Shield. Add a domain for a more website-like HTTPS identity.'}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button onClick={() => configureDomainTls.mutate()}
                        disabled={configureDomainTls.isPending || removeDomainTls.isPending || !st?.ssh_key_verified || !acmeTermsAccepted || !domain.trim()}
                        className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-medium disabled:opacity-50">
                        {configureDomainTls.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                        Configure Domain &amp; TLS
                      </button>
                      <button
                        onClick={() => {
                          if (window.confirm('Remove the DuckDNS domain? EasyPi will switch Stealth back to IP Shield first.')) removeDomainTls.mutate()
                        }}
                        disabled={removeDomainTls.isPending || configureDomainTls.isPending || (!st?.domain && !st?.domain_tls_deployed)}
                        className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-sm font-medium disabled:opacity-50">
                        {removeDomainTls.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                        Remove domain
                      </button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    <button onClick={() => saveServer.mutate()} disabled={saveServer.isPending} className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg border border-gray-300 dark:border-dark-700 text-gray-700 dark:text-gray-200 text-sm">
                      {saveServer.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} Save
                    </button>
                    <button onClick={() => checkSsh.mutate()} disabled={checkSsh.isPending} className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-700 text-white text-sm">
                      {checkSsh.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wifi className="w-4 h-4" />} Check SSH
                    </button>
                    {pendingHostFingerprint && (
                      <button onClick={() => trustHostKey.mutate()} disabled={trustHostKey.isPending} className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium">
                        {trustHostKey.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />} Trust host key
                      </button>
                    )}
                    <button onClick={() => deploy.mutate()} disabled={deploy.isPending || !st?.ssh_key_verified || !acmeTermsAccepted} className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium disabled:opacity-50">
                      {deploy.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Rocket className="w-4 h-4" />} Deploy &amp; Start
                    </button>
                    <button onClick={() => serverLogs.mutate()} disabled={serverLogs.isPending || !st?.ssh_key_verified} className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg border border-gray-300 dark:border-dark-700 text-gray-700 dark:text-gray-200 text-sm disabled:opacity-50">
                      {serverLogs.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />} Server logs
                    </button>
                    <button onClick={() => stopSrv.mutate()} disabled={stopSrv.isPending || !st?.ssh_key_verified} className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-sm disabled:opacity-50">
                      {stopSrv.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <XCircle className="w-4 h-4" />} Stop
                    </button>
                    <button onClick={() => { if (confirm('Remove chameleon-server from the VPS? (stop, disable, delete the unit + folder)')) uninstall.mutate() }} disabled={uninstall.isPending || !st?.ssh_key_verified} className="inline-flex items-center gap-2 px-3 py-2.5 rounded-lg border border-red-300 dark:border-red-800/60 text-red-600 text-sm hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50">
                      {uninstall.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />} Remove from server
                    </button>
                  </div>
                  <p className="text-xs text-gray-400 mt-2">For a new VPS, click Check SSH, compare the fingerprint with your provider, then trust it. EasyPi installs a device-specific Ed25519 key, verifies it, and removes the saved SSH password automatically. Parallel Deployment operations are rejected safely.</p>
                </Card>

                <Card title="Deployment log" icon={Activity}>
                  <pre className="text-xs font-mono whitespace-pre-wrap max-h-72 overflow-y-auto bg-gray-50 dark:bg-dark-950 rounded-lg p-3 text-gray-700 dark:text-gray-300">{deployLog || '—'}</pre>
                </Card>
              </div>
            )}

            {tab === 'profile' && (
              <div className="space-y-5">
                <div className="bg-white dark:bg-dark-900 rounded-xl border border-gray-200 dark:border-dark-800 p-6">
                  <div className="flex items-center gap-2 mb-4">
                    {connected ? <ShieldCheck className="w-5 h-5 text-emerald-500" /> : <XCircle className="w-5 h-5 text-gray-400" />}
                    <span className="font-semibold text-gray-900 dark:text-white">{connected ? 'Connected' : 'Not connected'}</span>
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                    Chameleon presents a browser-like TLS/HTTP/2 profile while IP Shield verifies the VPS identity.
                    This is the live runtime state.
                  </p>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <Metric label="Masquerading as" value={st?.fingerprint || '—'} icon={Fingerprint} />
                    <Metric label="Active identity" value={st?.shield || '—'} icon={Globe} />
                    <Metric label="Behavior" value={st?.behavior || '—'} icon={Activity} />
                    <Metric label="Kill-switch" value={st?.killswitch ? 'On' : 'Off'} good={st?.killswitch} icon={st?.killswitch ? CheckCircle2 : XCircle} />
                  </div>
                  <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t border-gray-100 dark:border-dark-800">
                    <Metric label="↓ Downloaded" value={fmtBytes(st?.bytes_recv)} />
                    <Metric label="↑ Uploaded" value={fmtBytes(st?.bytes_sent)} />
                    <Metric label="Scope" value={st?.scope === 'selected' ? `${st?.online_targets ?? 0} device(s)` : 'Whole net'} icon={Users} />
                  </div>
                  <button onClick={() => resetProfile.mutate()} disabled={resetProfile.isPending} className="mt-4 inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-red-200 dark:border-red-800/60 text-red-600 text-sm hover:bg-red-50 dark:hover:bg-red-900/20">
                    <RefreshCw className="w-4 h-4" /> Reset learned profile
                  </button>
                </div>
                <Card title="Runtime log" icon={Activity}>
                  <pre className="text-xs font-mono whitespace-pre-wrap max-h-80 overflow-y-auto bg-gray-50 dark:bg-dark-950 rounded-lg p-3 text-gray-700 dark:text-gray-300">{st?.runtime_log || '—'}</pre>
                </Card>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  )
}

const inp = 'w-full px-3 py-2.5 text-sm rounded-lg border border-gray-300 dark:border-dark-700 bg-white dark:bg-dark-900 text-gray-900 dark:text-white'
const ro = 'w-full px-3 py-2.5 text-sm rounded-lg border border-gray-200 dark:border-dark-800 bg-gray-50 dark:bg-dark-950 text-gray-500'
const btnPrimary = 'inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-medium disabled:opacity-50'

function Card({ title, icon: Icon, children }: { title: string; icon: ComponentType<{ className?: string }>; children: ReactNode }) {
  return (
    <div className="bg-white dark:bg-dark-900 rounded-xl border border-gray-200 dark:border-dark-800 p-5">
      <div className="flex items-center gap-2 mb-4"><Icon className="w-4 h-4 text-indigo-500" /><h3 className="text-xs font-bold uppercase tracking-wide text-indigo-500">{title}</h3></div>
      <div className="space-y-3">{children}</div>
    </div>
  )
}
function Field({ label, children }: { label: string; children: ReactNode }) {
  return <div><label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">{label}</label>{children}</div>
}
function GenBtn({ onClick, loading }: { onClick: () => void; loading: boolean }) {
  return <button onClick={onClick} disabled={loading} className="px-4 rounded-lg bg-purple-600 hover:bg-purple-700 text-white text-sm font-medium disabled:opacity-50">{loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'GENERATE'}</button>
}
function Metric({ label, value, good, icon: Icon }: { label: string; value: string; good?: boolean; icon?: ComponentType<{ className?: string }> }) {
  return (
    <div>
      <p className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">{Icon && <Icon className={`w-3.5 h-3.5 ${good === undefined ? 'text-gray-400' : good ? 'text-emerald-500' : 'text-red-500'}`} />}{label}</p>
      <p className="text-base font-semibold text-gray-900 dark:text-white mt-0.5 truncate">{value}</p>
    </div>
  )
}
function ScopeCard({ active, onClick, icon: Icon, title, desc }: { active: boolean; onClick: () => void; icon: ComponentType<{ className?: string }>; title: string; desc: string }) {
  return (
    <button onClick={onClick} type="button" className={`text-left p-4 rounded-lg border-2 transition-colors ${active ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-500/10' : 'border-gray-200 dark:border-dark-700 hover:border-gray-300'}`}>
      <div className="flex items-center gap-2 mb-1"><Icon className={`w-4 h-4 ${active ? 'text-indigo-600 dark:text-indigo-400' : 'text-gray-400'}`} /><span className="font-medium text-gray-900 dark:text-white">{title}</span></div>
      <p className="text-xs text-gray-500 dark:text-gray-400">{desc}</p>
    </button>
  )
}
