import { useState, useEffect, type ComponentType } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import {
  Lock, ShieldCheck, ShieldAlert, Globe, Upload, Power, Trash2,
  Loader2, Info, CheckCircle2, XCircle, Users, Router, Smartphone,
} from 'lucide-react'
import {
  getVpnStatus, importVpnConfig, enableVpn, disableVpn, deleteVpnConfig,
  getCachedDevices, setVpnTargets, saveOpenVpnCredentials, deleteOpenVpnCredentials, type CachedDevice,
} from '../api/vpn'
import { apiErrorMessage, withRoutingConflictConfirmation } from '../utils/routingConflict'

function fmtBytes(n?: number) {
  if (!n) return '0 B'
  const k = 1024, units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(n) / Math.log(k))
  return `${parseFloat((n / Math.pow(k, i)).toFixed(1))} ${units[i]}`
}
function fmtHandshake(ts?: number) {
  if (!ts) return 'never'
  const secs = Math.floor(Date.now() / 1000) - ts
  if (secs < 0) return 'just now'
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  return `${Math.floor(secs / 3600)}h ago`
}

export default function InternetEncryption() {
  const qc = useQueryClient()
  const [configText, setConfigText] = useState('')
  const [scope, setScope] = useState<'all' | 'selected'>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [seeded, setSeeded] = useState(false)
  const [openVpnUsername, setOpenVpnUsername] = useState('')
  const [openVpnPassword, setOpenVpnPassword] = useState('')

  const { data: status, isLoading } = useQuery({
    queryKey: ['outbound-vpn'],
    queryFn: getVpnStatus,
    refetchInterval: (q) => (q.state.data?.running ? 10000 : false),
  })
  const { data: devices = [] } = useQuery({
    queryKey: ['vpn-devices'],
    queryFn: getCachedDevices,
    refetchInterval: 10000,
  })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['outbound-vpn'] })

  // Seed the scope + selection from server state once it loads.
  useEffect(() => {
    if (status && !seeded) {
      setScope(status.scope === 'selected' ? 'selected' : 'all')
      setSelected(new Set((status.device_list || []).map((d) => d.mac.toLowerCase())))
      setSeeded(true)
    }
  }, [status, seeded])

  const importMut = useMutation({
    mutationFn: () => importVpnConfig(configText),
    onSuccess: (d) => {
      setConfigText('')
      invalidate()
      const label = d.engine === 'openvpn' ? 'OpenVPN' : d.engine === 'outline' ? 'Outline' : 'WireGuard'
      toast.success(`Imported ${label} config`)
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Import failed'),
  })
  const enableMut = useMutation({
    mutationFn: () => withRoutingConflictConfirmation((confirmed) => enableVpn(confirmed)),
    onSuccess: (d) => {
      if (!d) return
      invalidate()
      if (d?.running) toast.success('VPN enabled — traffic now goes through the tunnel')
      else toast.error(d?.error || 'Tunnel did not come up')
    },
    onError: (e: any) => toast.error(apiErrorMessage(e, 'Enable failed')),
  })
  const disableMut = useMutation({
    mutationFn: disableVpn,
    onSuccess: (d) => {
      invalidate()
      if (!d?.success || d.running || d.killswitch) {
        toast.error(d?.error || 'VPN is still active')
        return
      }
      qc.setQueryData(['outbound-vpn'], d)
      toast.success('VPN disabled')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Disable failed'),
  })
  const deleteMut = useMutation({
    mutationFn: deleteVpnConfig,
    onSuccess: () => { invalidate(); setSeeded(false); toast.success('Config removed') },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Remove failed'),
  })
  const targetsMut = useMutation({
    mutationFn: () => {
      const chosen = devices.filter((d) => d.mac && selected.has(d.mac.toLowerCase()))
        .map((d) => ({ mac: d.mac as string, name: d.hostname || '', ip: d.ip }))
      return withRoutingConflictConfirmation((confirmed) =>
        setVpnTargets(scope, scope === 'selected' ? chosen : [], confirmed),
      )
    },
    onSuccess: (d) => { if (d) { invalidate(); toast.success('Routing scope saved') } },
    onError: (e: any) => toast.error(apiErrorMessage(e, 'Save failed')),
  })
  const credentialsMut = useMutation({
    mutationFn: () => saveOpenVpnCredentials(openVpnUsername, openVpnPassword),
    onSuccess: (d) => {
      setOpenVpnUsername('')
      setOpenVpnPassword('')
      invalidate()
      toast.success(`OpenVPN credentials saved with ${d.credential_protection || 'system encryption'}`)
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Could not save OpenVPN credentials'),
  })
  const deleteCredentialsMut = useMutation({
    mutationFn: deleteOpenVpnCredentials,
    onSuccess: () => { invalidate(); toast.success('OpenVPN credentials removed') },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Could not remove OpenVPN credentials'),
  })

  const busy = enableMut.isPending || disableMut.isPending || deleteMut.isPending || credentialsMut.isPending || deleteCredentialsMut.isPending
  const running = !!status?.running
  const configured = !!status?.configured
  const engineLabel = status?.engine === 'openvpn' ? 'OpenVPN' : status?.engine === 'outline' ? 'Outline' : 'WireGuard'

  const onFile = (f?: File | null) => {
    if (!f) return
    const reader = new FileReader()
    reader.onload = () => setConfigText(String(reader.result || ''))
    reader.readAsText(f)
  }
  const toggleDev = (mac: string) => {
    const m = mac.toLowerCase()
    setSelected((prev) => { const n = new Set(prev); n.has(m) ? n.delete(m) : n.add(m); return n })
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-dark-950">
      <header className="bg-white dark:bg-dark-900 border-b border-gray-200 dark:border-dark-800">
        <div className="max-w-5xl mx-auto px-6 py-6 flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl shadow-lg shadow-emerald-500/20">
            <Lock className="w-8 h-8 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Internet Encryption</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Route forwarded LAN traffic through a private VPN
            </p>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8 space-y-6">
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-xl p-4 flex gap-3">
          <Info className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-blue-800 dark:text-blue-300">
            This is the <strong>opposite</strong> of the VPN Server. It sends selected forwarded LAN traffic <em>out</em> through a
            commercial VPN (Proton, NordVPN, Outline, or any WireGuard / OpenVPN provider). For traffic inside that tunnel,
            the ISP sees the encrypted tunnel rather than individual destinations. Pi-hosted traffic and local DNS recursion
            are not necessarily tunneled. You can target all forwarded clients or selected devices; DNS filtering and parental
            controls remain separate policy layers.
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-16 text-gray-400"><Loader2 className="w-6 h-6 animate-spin" /></div>
        ) : (
          <>
            {/* Status */}
            <div className="bg-white dark:bg-dark-900 rounded-xl border border-gray-200 dark:border-dark-800 p-6">
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <span className={`p-3 rounded-xl ${running ? 'bg-emerald-100 dark:bg-emerald-500/10' : 'bg-gray-100 dark:bg-dark-800'}`}>
                    {running ? <ShieldCheck className="w-8 h-8 text-emerald-600 dark:text-emerald-400" />
                             : <ShieldAlert className="w-8 h-8 text-gray-400" />}
                  </span>
                  <div>
                    <p className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
                      {running ? 'Encrypted' : configured ? 'Not connected' : 'Not configured'}
                      {configured && (
                        <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-gray-100 dark:bg-dark-800 text-gray-600 dark:text-gray-300">{engineLabel}</span>
                      )}
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {running && status?.endpoint
                        ? <>via <span className="font-mono">{status.endpoint}</span>{status?.scope === 'selected' ? ` · ${status?.online_targets ?? 0} device(s)` : ' · whole network'}</>
                        : configured ? 'Config imported — enable to start' : 'Import a WireGuard or OpenVPN config below'}
                    </p>
                  </div>
                </div>

                {configured && (
                  <div className="flex items-center gap-2">
                    {running ? (
                      <button onClick={() => disableMut.mutate()} disabled={busy}
                        className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium disabled:opacity-50">
                        {disableMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Power className="w-4 h-4" />} Disable
                      </button>
                    ) : (
                      <button onClick={() => enableMut.mutate()} disabled={busy}
                        className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-medium disabled:opacity-50">
                        {enableMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Power className="w-4 h-4" />} Enable
                      </button>
                    )}
                    <button onClick={() => { if (confirm('Remove the VPN config?')) deleteMut.mutate() }} disabled={busy}
                      title="Remove config" className="p-2.5 rounded-lg text-gray-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 disabled:opacity-50">
                      <Trash2 className="w-5 h-5" />
                    </button>
                  </div>
                )}
              </div>

              {running && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-6 border-t border-gray-100 dark:border-dark-800">
                  <Metric label="Kill-switch" value={status?.killswitch ? 'On' : 'Off'} good={status?.killswitch} icon={status?.killswitch ? CheckCircle2 : XCircle} />
                  <Metric
                    label={status?.engine === 'wireguard' ? 'Last handshake' : 'Connection'}
                    value={status?.engine === 'wireguard' ? fmtHandshake(status?.latest_handshake) : 'Active'}
                    good={status?.engine !== 'wireguard'}
                  />
                  <Metric label="Downloaded" value={fmtBytes(status?.rx_bytes)} />
                  <Metric label="Uploaded" value={fmtBytes(status?.tx_bytes)} />
                </div>
              )}
              {running && !status?.killswitch && (
                <div className="mt-4 text-sm text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-3">
                  Kill-switch is off — if the tunnel drops, traffic could leak to your ISP. Try disabling and re-enabling.
                </div>
              )}
            </div>

            {/* Routing scope */}
            {configured && status?.engine === 'openvpn' && status?.requires_credentials && (
              <div className="bg-white dark:bg-dark-900 rounded-xl border border-gray-200 dark:border-dark-800 p-6">
                <h2 className="font-semibold text-gray-900 dark:text-white mb-1">OpenVPN account</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                  This profile requires the VPN provider username and password. They are encrypted by the EasyPi host
                  (and TPM when available), never added to the .ovpn file, and never returned by the API.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <input value={openVpnUsername} onChange={(e) => setOpenVpnUsername(e.target.value)}
                    autoComplete="username" placeholder="VPN username"
                    className="px-3 py-2.5 rounded-lg border border-gray-300 dark:border-dark-700 bg-gray-50 dark:bg-dark-950 text-gray-900 dark:text-gray-100" />
                  <input value={openVpnPassword} onChange={(e) => setOpenVpnPassword(e.target.value)} type="password"
                    autoComplete="current-password" placeholder="VPN password"
                    className="px-3 py-2.5 rounded-lg border border-gray-300 dark:border-dark-700 bg-gray-50 dark:bg-dark-950 text-gray-900 dark:text-gray-100" />
                </div>
                <div className="mt-3 flex items-center gap-2">
                  <button onClick={() => credentialsMut.mutate()}
                    disabled={credentialsMut.isPending || !openVpnUsername || !openVpnPassword}
                    className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-medium disabled:opacity-50">
                    {credentialsMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
                    {status.credentials_configured ? 'Replace credentials' : 'Save credentials'}
                  </button>
                  {status.credentials_configured && (
                    <button onClick={() => deleteCredentialsMut.mutate()} disabled={deleteCredentialsMut.isPending || running}
                      className="px-4 py-2.5 rounded-lg border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 disabled:opacity-50">
                      Remove credentials
                    </button>
                  )}
                  <span className={`text-sm ${status.credentials_configured ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`}>
                    {status.credentials_configured ? 'Credentials protected' : 'Credentials required before Enable'}
                  </span>
                </div>
              </div>
            )}

            {configured && (
              <div className="bg-white dark:bg-dark-900 rounded-xl border border-gray-200 dark:border-dark-800 p-6">
                <h2 className="font-semibold text-gray-900 dark:text-white mb-3">Routing scope</h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <ScopeCard active={scope === 'all'} onClick={() => setScope('all')} icon={Globe}
                    title="Whole network" desc="Every device goes through the VPN." />
                  <ScopeCard active={scope === 'selected'} onClick={() => setScope('selected')} icon={Users}
                    title="Selected devices" desc="Only the devices you pick; everyone else stays direct." />
                </div>

                {scope === 'selected' && (
                  <div className="mt-4">
                    {devices.length === 0 ? (
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        No approved or discovered devices yet.
                      </p>
                    ) : (
                      <div className="max-h-64 overflow-y-auto rounded-lg border border-gray-200 dark:border-dark-700 divide-y divide-gray-100 dark:divide-dark-800">
                        {devices.map((d: CachedDevice) => {
                          const m = (d.mac || '').toLowerCase()
                          const on = selected.has(m)
                          return (
                            <label key={m} className="flex items-center gap-3 px-3 py-2.5 cursor-pointer hover:bg-gray-50 dark:hover:bg-dark-800/50">
                              <input type="checkbox" checked={on} onChange={() => toggleDev(m)}
                                className="w-4 h-4 rounded accent-emerald-600" />
                              <Smartphone className="w-4 h-4 text-gray-400" />
                              <span className="flex-1 text-sm text-gray-900 dark:text-white truncate">
                                {d.hostname || d.vendor || 'Unknown device'}
                              </span>
                              <span className="text-xs text-gray-400 font-mono">{d.ip}</span>
                            </label>
                          )
                        })}
                      </div>
                    )}
                    <p className="text-xs text-gray-400 mt-2">{selected.size} selected · targeting follows devices across DHCP renewals (matched by MAC).</p>
                  </div>
                )}

                <div className="mt-4">
                  <button onClick={() => targetsMut.mutate()} disabled={targetsMut.isPending || (scope === 'selected' && selected.size === 0)}
                    className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-medium disabled:opacity-50">
                    {targetsMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                    Save routing {running ? '& apply now' : ''}
                  </button>
                </div>
              </div>
            )}

            {/* Import / replace */}
            <div className="bg-white dark:bg-dark-900 rounded-xl border border-gray-200 dark:border-dark-800 p-6">
              <h2 className="font-semibold text-gray-900 dark:text-white mb-1">
                {configured ? 'Replace config' : 'Import VPN config'}
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                Paste a WireGuard <code>.conf</code>, an OpenVPN <code>.ovpn</code>, or a static Outline <code>ss://</code> access key.
                Your keys are stored locally with 600 permissions and never shown again.
              </p>
              <div className="mb-4 rounded-xl border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 p-4">
                <div className="flex items-start gap-3">
                  <ShieldAlert className="w-5 h-5 text-amber-600 dark:text-amber-400 flex-shrink-0 mt-0.5" />
                  <div className="text-sm text-amber-950 dark:text-amber-200 space-y-2">
                    <p className="font-semibold">Which VPN profile should I use?</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li><strong>Recommended:</strong> WireGuard UDP using the exact port supplied by your provider.</li>
                      <li><strong>OpenVPN:</strong> UDP 1194 or 25000 for speed; TCP 443 for maximum compatibility.</li>
                      <li><strong>Outline:</strong> paste the complete static <code>ss://</code> access key. TCP and UDP are supported; dynamic <code>ssconf://</code> keys are not supported yet.</li>
                      <li><strong>Fallback:</strong> OpenVPN TCP 80 when TCP 443 is unavailable.</li>
                      <li><strong>Avoid port 53:</strong> UDP/TCP 53 is DNS traffic and may be intercepted or filtered by EasyPi, your router, or your ISP.</li>
                    </ul>
                    <p className="font-medium">Do not edit the protocol or port inside a profile. Download the matching profile from the VPN provider.</p>
                  </div>
                </div>
              </div>
              {status?.transport_warning && (
                <div className="mb-4 rounded-lg border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-3 text-sm text-red-800 dark:text-red-300 flex items-start gap-2">
                  <ShieldAlert className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span><strong>Current profile warning:</strong> {status.transport_warning}</span>
                </div>
              )}
              <textarea value={configText} onChange={(e) => setConfigText(e.target.value)} spellCheck={false} rows={8}
                placeholder={'WireGuard / OpenVPN config, or Outline access key:\nss://...'}
                className="w-full font-mono text-xs px-3 py-2.5 rounded-lg border border-gray-300 dark:border-dark-700 bg-gray-50 dark:bg-dark-950 text-gray-900 dark:text-gray-100" />
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button onClick={() => importMut.mutate()} disabled={importMut.isPending || !configText.trim()}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-medium disabled:opacity-50">
                  {importMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                  {configured ? 'Replace' : 'Import'}
                </button>
                <label className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-gray-300 dark:border-dark-700 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-dark-800 cursor-pointer">
                  <Globe className="w-4 h-4" /> Choose file
                  <input type="file" accept=".conf,.ovpn,text/plain" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
                </label>
              </div>
            </div>

            <p className="text-xs text-gray-400 dark:text-gray-500 flex items-start gap-1.5">
              <Router className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
              After enabling, check a routed device's public IP — it should show the VPN server's location. Because
              EasyPi connects <em>out</em>, this works even behind CGNAT (no port-forwarding needed).
            </p>
          </>
        )}
      </main>
    </div>
  )
}

function Metric({ label, value, good, icon: Icon }: {
  label: string; value: string; good?: boolean; icon?: ComponentType<{ className?: string }>
}) {
  return (
    <div>
      <p className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
        {Icon && <Icon className={`w-3.5 h-3.5 ${good === undefined ? 'text-gray-400' : good ? 'text-emerald-500' : 'text-red-500'}`} />}
        {label}
      </p>
      <p className="text-base font-semibold text-gray-900 dark:text-white mt-0.5">{value}</p>
    </div>
  )
}

function ScopeCard({ active, onClick, icon: Icon, title, desc }: {
  active: boolean; onClick: () => void; icon: ComponentType<{ className?: string }>; title: string; desc: string
}) {
  return (
    <button onClick={onClick} type="button"
      className={`text-left p-4 rounded-lg border-2 transition-colors ${active
        ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-500/10'
        : 'border-gray-200 dark:border-dark-700 hover:border-gray-300 dark:hover:border-dark-600'}`}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className={`w-4 h-4 ${active ? 'text-emerald-600 dark:text-emerald-400' : 'text-gray-400'}`} />
        <span className="font-medium text-gray-900 dark:text-white">{title}</span>
      </div>
      <p className="text-xs text-gray-500 dark:text-gray-400">{desc}</p>
    </button>
  )
}
