import { useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Shield, Monitor, RefreshCw, Edit2, X, Search, Ban, ShieldAlert, Users, Globe, History } from 'lucide-react'
import { toast } from 'react-hot-toast'
import {
  getParentalClients,
  addParentalClient,
  updateParentalClient,
  deleteParentalClient,
  restoreFailClosedInternetByIp,
  getBlockedServicesList,
  getBypassHistory,
  clearBypassHistory,
  type ParentalClient,
} from '../../api/guardSecurity'
import { getDeviceDetail } from '../../api/analytics'
import { getCachedDevices, type CachedDevice } from '../../api/vpn'
import { useGatewayStatus } from '../../hooks/useGatewayStatus'

// Bypass channel labels for the "attempts blocked" activity card.
const BYPASS_CHANNEL_LABELS: Record<string, string> = {
  doh: '🌐 DoH/DoT',
  vpn: '🔐 VPN',
  proxy: '🔀 Proxy',
  tor: '🧅 Tor',
  smartdns: '🧠 Smart DNS',
}
const bypassChannelLabel = (ch: string) => BYPASS_CHANNEL_LABELS[ch] || ch

// Service icons/labels mapping
const SERVICE_LABELS: Record<string, string> = {
  // Popular services (from backup - first priority)
  youtube: '📺 YouTube',
  tiktok: '🎵 TikTok',
  instagram: '📷 Instagram',
  snapchat: '👻 Snapchat',
  facebook: '👥 Facebook',
  twitter: '🐦 Twitter/X',
  twitch: '🎮 Twitch',
  discord: '💬 Discord',
  telegram: '✈️ Telegram',
  whatsapp: '💚 WhatsApp',
  netflix: '🎬 Netflix',
  spotify: '🎧 Spotify',
  reddit: '🤖 Reddit',
  pinterest: '📌 Pinterest',
  tinder: '💕 Tinder',
  steam: '🎮 Steam',
  epicgames: '🎮 Epic Games',
  minecraft: '⛏️ Minecraft',
  roblox: '🎮 Roblox',
  google_play: '🛒 Google Play',
  // Additional services
  disney: '🏰 Disney+',
  hbo: '🎭 HBO Max',
  amazon_video: '📦 Prime Video',
  vimeo: '📹 Vimeo',
  dailymotion: '📺 Dailymotion',
  tumblr: '📝 Tumblr',
  signal: '🔒 Signal',
  apple_music: '🎵 Apple Music',
  soundcloud: '🎵 SoundCloud',
  deezer: '🎵 Deezer',
  xbox: '🎮 Xbox Live',
  playstation: '🎮 PlayStation',
  bumble: '🐝 Bumble',
  badoo: '💕 Badoo',
  line: '💚 LINE',
  viber: '📞 Viber',
  wechat: '💬 WeChat',
  pornography: '🔞 Pornography',
  adult: '🔞 Adult Content',
}

// VPN/Proxy bypass services - shown as toggles, not in quick add
const BYPASS_SERVICES: Record<string, { label: string; description: string; icon: string }> = {
  bypass: { label: 'VPN/Proxy Bypass', description: 'Block all VPN and proxy bypass methods', icon: '🛡️' },
  strict_parental: { label: 'Strict Mode', description: 'Maximum restrictions for children', icon: '🔒' },
  vpn: { label: 'VPN Services', description: 'Block commercial VPN providers', icon: '🔐' },
  doh: { label: 'DNS-over-HTTPS', description: 'Prevent DNS encryption bypass', icon: '🌐' },
  tor: { label: 'Tor Network', description: 'Block Tor anonymity network', icon: '🧅' },
  proxy: { label: 'Web Proxies', description: 'Block web-based proxy sites', icon: '🔀' },
  smartdns: { label: 'Smart DNS', description: 'Block Smart DNS services', icon: '🌐' },
}

const PORNOGRAPHY_SERVICE = 'pornography'
const HIDDEN_QUICK_ADD_SERVICES = new Set(['adult'])

const FALLBACK_SERVICE_ICON = '🧩'

const getServiceDisplayLabel = (service: string): string => {
  const key = String(service || '').trim().toLowerCase()
  if (!key) return service

  const known = SERVICE_LABELS[key]
  if (known) return known

  const bypass = BYPASS_SERVICES[key]
  if (bypass) return `${bypass.icon} ${bypass.label}`

  // Custom domains / wildcard entries in blocked list
  if (key.includes('.') || key.includes('*')) {
    return `🌐 ${service}`
  }

  return `${FALLBACK_SERVICE_ICON} ${service}`
}

const GATEWAY_REQUIRED_SERVICES = new Set([
  'telegram',
  'whatsapp',
  'signal',
  'tor',
  'telegram_ip',
  'whatsapp_ip',
  'signal_ip',
])

interface NewClientForm {
  name: string
  ip: string
  mac: string
  parental_enabled: boolean
  safesearch_enabled: boolean
  safebrowsing_enabled: boolean
  blocked_services: string[]
}

const defaultNewClient: NewClientForm = {
  name: '',
  ip: '',
  mac: '',
  parental_enabled: true,
  safesearch_enabled: true,
  safebrowsing_enabled: true,
  blocked_services: [],
}

const formatAge = (seconds: number) => {
  const s = Math.max(0, Math.floor(seconds))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h`
  const d = Math.floor(h / 24)
  return `${d}d`
}

// Modal: the domains a given device (profile) has actually queried, from the DNS
// query log. Reuses the analytics device-detail endpoint (accepts a raw IP).
function VisitedSitesModal({ client, onClose }: { client: ParentalClient; onClose: () => void }) {
  const [period, setPeriod] = useState<'24h' | '7d'>('24h')
  const [search, setSearch] = useState('')
  const [tab, setTab] = useState<'sites' | 'other'>('sites')
  const { data, isLoading } = useQuery({
    queryKey: ['device-sites', client.ip, period, search],
    queryFn: () => getDeviceDetail(client.ip, period, search.trim() || undefined),
    enabled: !!client.ip,
  })
  const visited = data?.visited ?? { sites: [], trackers: [], background: [] }
  const sites = visited.sites ?? []
  const trackers = visited.trackers ?? []
  const background = visited.background ?? []
  const otherCount = trackers.length + background.length
  const topBlocked = data?.topBlocked ?? []
  const hasAny = sites.length + otherCount + topBlocked.length > 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-lg max-h-[80vh] flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="min-w-0">
            <h3 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <History className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              <span className="truncate">Visited sites — {client.name}</span>
            </h3>
            <p className="text-xs font-mono text-gray-500 dark:text-gray-400">{client.ip}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700" title="Close">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex gap-1 px-4 py-2 border-b border-gray-100 dark:border-gray-700">
          {(['24h', '7d'] as const).map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                period === p
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300'
              }`}
            >
              {p}
            </button>
          ))}
        </div>

        <div className="px-4 py-2 border-b border-gray-100 dark:border-gray-700">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search a site (e.g. youtube, 2ip)…"
              className="w-full pl-8 pr-3 py-1.5 text-sm rounded-lg bg-gray-100 dark:bg-gray-700 border border-transparent focus:border-blue-500 focus:bg-white dark:focus:bg-gray-800 outline-none text-gray-800 dark:text-gray-200"
            />
          </div>
        </div>

        <div className="flex gap-1 px-4 pt-2">
          {([['sites', `Sites${sites.length ? ` (${sites.length})` : ''}`],
             ['other', `Trackers & background${otherCount ? ` (${otherCount})` : ''}`]] as const).map(([k, label]) => (
            <button
              key={k}
              onClick={() => setTab(k)}
              className={`px-3 py-1.5 text-xs font-medium rounded-t-lg border-b-2 transition-colors ${
                tab === k
                  ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="p-4 pt-3 overflow-y-auto border-t border-gray-100 dark:border-gray-700">
          {isLoading ? (
            <div className="py-10 text-center text-sm text-gray-500">Loading…</div>
          ) : !hasAny ? (
            <div className="py-10 text-center text-sm text-gray-500">
              {search.trim()
                ? `Nothing matching “${search.trim()}” in this period.`
                : 'No DNS activity recorded for this device in this period.'}
            </div>
          ) : (
            <>
              {tab === 'sites' ? (
                sites.length === 0 ? (
                  <div className="py-8 text-center text-sm text-gray-500">
                    {search.trim()
                      ? 'No matching sites — check the “Trackers & background” tab.'
                      : 'No first-party sites recorded — see “Trackers & background”.'}
                  </div>
                ) : (
                  <>
                    <div className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">
                      {search.trim() ? 'Matching sites' : 'Sites visited'}
                    </div>
                    <ul className="space-y-1">
                      {sites.map((d) => (
                        <li key={d.domain} className="flex items-center justify-between gap-3 text-sm">
                          <span
                            className="font-mono text-gray-800 dark:text-gray-200 truncate"
                            title={d.hosts && d.hosts > 1 ? `${d.hosts} subdomains` : undefined}
                          >
                            {d.domain}
                          </span>
                          <span className="text-gray-400 tabular-nums shrink-0">{d.count}</span>
                        </li>
                      ))}
                    </ul>
                  </>
                )
              ) : (
                <>
                  {trackers.length > 0 && (
                    <>
                      <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-500 mb-2">
                        <span className="w-2 h-2 rounded-full bg-amber-500" /> Trackers &amp; ads
                      </div>
                      <ul className="space-y-1 mb-4">
                        {trackers.map((d) => (
                          <li key={d.domain} className="flex items-center justify-between gap-3 text-sm">
                            <span className="font-mono text-gray-700 dark:text-gray-300 truncate">{d.domain}</span>
                            <span className="text-gray-400 tabular-nums shrink-0">{d.count}</span>
                          </li>
                        ))}
                      </ul>
                    </>
                  )}
                  {background.length > 0 && (
                    <>
                      <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">
                        <span className="w-2 h-2 rounded-full bg-gray-400" /> Background · CDN · APIs
                      </div>
                      <ul className="space-y-1">
                        {background.map((d) => (
                          <li key={d.domain} className="flex items-center justify-between gap-3 text-sm">
                            <span className="font-mono text-gray-500 dark:text-gray-400 truncate">{d.domain}</span>
                            <span className="text-gray-400 tabular-nums shrink-0">{d.count}</span>
                          </li>
                        ))}
                      </ul>
                    </>
                  )}
                  {otherCount === 0 && (
                    <div className="py-8 text-center text-sm text-gray-500">
                      {search.trim()
                        ? 'No matching trackers or background domains.'
                        : 'No trackers or background traffic recorded.'}
                    </div>
                  )}
                </>
              )}

              {topBlocked.length > 0 && (
                <>
                  <div className="text-xs font-semibold uppercase tracking-wide text-red-500 mt-5 mb-2">Blocked</div>
                  <ul className="space-y-1">
                    {topBlocked.map((d) => (
                      <li key={d.domain} className="flex items-center justify-between gap-3 text-sm">
                        <span className="font-mono text-red-700 dark:text-red-300 truncate">{d.domain}</span>
                        <span className="text-gray-400 tabular-nums shrink-0">{d.count}</span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          )}
        </div>

        <div className="px-4 py-2.5 border-t border-gray-100 dark:border-gray-700 text-[11px] text-gray-400">
          Top domains from the DNS query log. If empty, enable the Query Log in NetProtection settings.
        </div>
      </div>
    </div>
  )
}

export default function ParentalControls() {
  const queryClient = useQueryClient()
  const [showAddForm, setShowAddForm] = useState(false)
  const [editingClient, setEditingClient] = useState<string | null>(null)
  const [sitesClient, setSitesClient] = useState<ParentalClient | null>(null)
  const [newClient, setNewClient] = useState<NewClientForm>(defaultNewClient)
  const [editForm, setEditForm] = useState<NewClientForm>(defaultNewClient)
  const [customDomain, setCustomDomain] = useState('')
  const [editCustomDomain, setEditCustomDomain] = useState('')
  const { data: gatewayStatus } = useGatewayStatus()
  const editSaveInFlight = useRef(false)

  const { data: clients, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['parental-clients'],
    queryFn: getParentalClients,
    staleTime: 0,
    // Keep UI in sync with live fail-closed/quarantine state without manual refresh.
    refetchInterval: 2000,
  })
  const { data: lanDevices = [] } = useQuery({
    queryKey: ['vpn-devices'],
    queryFn: getCachedDevices,
  })

  const { data: availableServices } = useQuery({
    queryKey: ['blocked-services-list'],
    queryFn: getBlockedServicesList,
  })

  // Persistent per-device history of bypass attempts (accumulates over time,
  // survives reboots / firewall-counter resets).
  const { data: bypassHistory } = useQuery({
    queryKey: ['bypass-history'],
    queryFn: getBypassHistory,
    refetchInterval: 5000,
  })
  const clearBypassHistoryMutation = useMutation({
    mutationFn: clearBypassHistory,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['bypass-history'] }),
  })

  const clientList = Array.isArray(clients)
    ? clients.filter((client) => client.parental_managed)
    : []
  
  // Prioritize services from SERVICE_LABELS (backup order), then add any others from API
  const priorityServices = Object.keys(SERVICE_LABELS)
  const apiServices = Array.isArray(availableServices) ? availableServices : []
  // Keep Quick Add curated to known UI-labeled services only.
  // Backend can expose technical service IDs (e.g. *_ip) for other flows.
  const servicesList = priorityServices.filter(
    (service) => apiServices.length === 0 || apiServices.includes(service)
  )

  const showSyncWarnings = (data: any) => {
    const warnings: string[] = []
    const syncWarnings = data?.sync?.warnings
    const ipWarnings = data?.ip_blocking?.warnings
    if (Array.isArray(syncWarnings)) warnings.push(...syncWarnings)
    if (Array.isArray(ipWarnings)) warnings.push(...ipWarnings)
    if (warnings.length > 0) {
      const first = warnings[0]
      const extra = warnings.length > 1 ? ` (+${warnings.length - 1} more)` : ''
      toast.error(`${first}${extra}`, { duration: 8000 })
    }
  }

  const normalizeParentalShortcut = (form: NewClientForm): NewClientForm => {
    const hasPornographyShortcut = form.blocked_services.includes(PORNOGRAPHY_SERVICE)
    return {
      ...form,
      parental_enabled: form.parental_enabled || hasPornographyShortcut,
      blocked_services: form.blocked_services.filter((service) => service !== PORNOGRAPHY_SERVICE),
    }
  }

  const isServiceSelected = (service: string, form: NewClientForm): boolean =>
    service === PORNOGRAPHY_SERVICE
      ? form.parental_enabled
      : form.blocked_services.includes(service)

  const getDisplayedBlockedServices = (form: NewClientForm): string[] => {
    const values = form.blocked_services.filter(
      (service) =>
        service !== PORNOGRAPHY_SERVICE && !(form.parental_enabled && service === 'adult')
    )
    if (form.parental_enabled) {
      values.unshift(PORNOGRAPHY_SERVICE)
    }
    return Array.from(new Set(values))
  }

  const addClientMutation = useMutation({
    mutationFn: () => addParentalClient(normalizeParentalShortcut(newClient)),
    onSuccess: (data) => {
      showSyncWarnings(data)
      queryClient.invalidateQueries({ queryKey: ['parental-clients'] })
      setNewClient(defaultNewClient)
      setShowAddForm(false)
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.detail || error?.message || 'Failed to add device'
      toast.error(String(detail))
    },
  })

  const updateClientMutation = useMutation({
    mutationFn: ({ name, data }: { name: string; data: Partial<ParentalClient> }) =>
      updateParentalClient(name, data),
    onSuccess: (data) => {
      showSyncWarnings(data)
      queryClient.invalidateQueries({ queryKey: ['parental-clients'] })
      setEditingClient(null)
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.detail || error?.message || 'Failed to save settings'
      toast.error(String(detail))
    },
  })

  const saveEditedClient = (client: ParentalClient) => {
    if (editSaveInFlight.current) return
    editSaveInFlight.current = true
    updateClientMutation.mutate(
      {
        name: client.record_name || client.name,
        data: normalizeParentalShortcut(editForm),
      },
      {
        onSettled: () => {
          editSaveInFlight.current = false
        },
      }
    )
  }

  const deleteClientMutation = useMutation({
    mutationFn: (name: string) => deleteParentalClient(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['parental-clients'] })
    },
  })

  const restoreInternetMutation = useMutation({
    mutationFn: (ip: string) => restoreFailClosedInternetByIp(ip),
    onSuccess: () => {
      toast.success('Internet access restored')
      queryClient.invalidateQueries({ queryKey: ['parental-clients'] })
      queryClient.invalidateQueries({ queryKey: ['fail-closed-status'] })
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.detail || 'Failed to restore internet'
      toast.error(String(detail))
    },
  })

  const toggleService = (service: string, form: NewClientForm, setForm: (f: NewClientForm) => void) => {
    if (service === PORNOGRAPHY_SERVICE) {
      setForm({
        ...form,
        parental_enabled: !form.parental_enabled,
        blocked_services: form.blocked_services.filter((s) => s !== PORNOGRAPHY_SERVICE),
      })
      return
    }

    const services = form.blocked_services.includes(service)
      ? form.blocked_services.filter((s) => s !== service)
      : [...form.blocked_services, service]
    setForm({ ...form, blocked_services: services.filter((s) => s !== PORNOGRAPHY_SERVICE) })
  }

  const startEditing = (client: ParentalClient) => {
    setEditingClient(client.name)
    setEditForm(normalizeParentalShortcut({
      name: client.name,
      ip: client.ip,
      mac: client.mac || '',
      parental_enabled: client.parental_enabled,
      safesearch_enabled: client.safesearch_enabled,
      safebrowsing_enabled: client.safebrowsing_enabled,
      blocked_services: client.blocked_services || [],
    }))
  }

  const renderToggle = (
    enabled: boolean,
    onChange: () => void,
    label: string,
    description: string,
    icon: React.ReactNode
  ) => (
    <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
      <div className="flex items-center gap-3">
        {icon}
        <div>
          <div className="text-sm font-medium text-gray-900 dark:text-white">{label}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400">{description}</div>
        </div>
      </div>
      <button
        type="button"
        onClick={onChange}
        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
          enabled ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'
        }`}
      >
        <span
          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
            enabled ? 'translate-x-5' : 'translate-x-1'
          }`}
        />
      </button>
    </div>
  )

  const renderBypassProtectionToggles = (
    form: NewClientForm,
    setForm: (f: NewClientForm) => void
  ) => (
    <div className="space-y-2">
      <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
        Bypass Protection
      </label>
      <div className="space-y-2">
        {Object.entries(BYPASS_SERVICES).map(([key, { label, description, icon }]) => (
          <div key={key} className="space-y-2">
            <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <div className="flex items-center gap-3">
                <span className="text-lg">{icon}</span>
                <div>
                  <div className="text-sm font-medium text-gray-900 dark:text-white">{label}</div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">{description}</div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => toggleService(key, form, setForm)}
                className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                  form.blocked_services.includes(key) ? 'bg-red-500' : 'bg-gray-300 dark:bg-gray-600'
                }`}
              >
                <span
                  className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                    form.blocked_services.includes(key) ? 'translate-x-5' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

          </div>
        ))}
      </div>
    </div>
  )

  const renderServiceSelector = (
    form: NewClientForm, 
    setForm: (f: NewClientForm) => void,
    domainInput: string,
    setDomainInput: (v: string) => void
  ) => {
    const displayedBlockedServices = getDisplayedBlockedServices(form)

    const addCustomDomain = () => {
      const domain = domainInput.trim().toLowerCase()
      if (domain && !form.blocked_services.includes(domain)) {
        setForm({
          ...form,
          blocked_services: [...form.blocked_services, domain].filter((s) => s !== PORNOGRAPHY_SERVICE),
        })
        setDomainInput('')
      }
    }
    
    const removeDomain = (domain: string) => {
      if (domain === PORNOGRAPHY_SERVICE) {
        setForm({
          ...form,
          parental_enabled: false,
          blocked_services: form.blocked_services.filter((s) => s !== PORNOGRAPHY_SERVICE),
        })
        return
      }
      setForm({ ...form, blocked_services: form.blocked_services.filter(s => s !== domain) })
    }

    const needsGateway = form.blocked_services.some((service) => GATEWAY_REQUIRED_SERVICES.has(service))
    const gatewayEnabled = gatewayStatus?.enabled === true
    const showGatewayWarning = needsGateway && gatewayStatus && !gatewayEnabled
    
    return (
      <div className="space-y-3">
        <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
          Blocked Sites & Services
        </label>
        
        {/* Custom domain input */}
        <div className="flex gap-2">
          <input
            type="text"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addCustomDomain())}
            placeholder="Enter domain (e.g., tiktok.com)"
            className="flex-1 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
          />
          <button
            type="button"
            onClick={addCustomDomain}
            disabled={!domainInput.trim()}
            className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Block
          </button>
        </div>
        
        {/* Quick select popular services */}
        <div className="text-xs text-gray-500 dark:text-gray-400">Quick add popular services:</div>
        <div className="grid grid-cols-4 sm:flex sm:flex-wrap gap-1 sm:gap-2 p-2 sm:p-3 bg-gray-50 dark:bg-gray-900 rounded-lg max-h-64 overflow-y-auto">
          {servicesList
            .filter((service) => !Object.keys(BYPASS_SERVICES).includes(service))
            .filter((service) => !HIDDEN_QUICK_ADD_SERVICES.has(service))
            .map((service) => (
            <button
              key={service}
              type="button"
              onClick={() => toggleService(service, form, setForm)}
              className={`px-2 py-1 text-xs rounded-full transition-colors ${
                isServiceSelected(service, form)
                  ? 'bg-red-500 text-white'
                  : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
              }`}
            >
              {SERVICE_LABELS[service] || service}
            </button>
          ))}
        </div>

        {showGatewayWarning && (
          <div className="flex items-start gap-2 p-3 rounded-lg border border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
            <ShieldAlert className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <div className="text-xs sm:text-sm">
              Full Gateway is currently disabled. Telegram/WhatsApp/Signal/Tor blocking may not work without gateway mode.
            </div>
          </div>
        )}
        
        {/* Currently blocked list */}
        {displayedBlockedServices.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs text-gray-500 dark:text-gray-400">
              Currently blocked ({displayedBlockedServices.length}):
            </div>
            <div className="flex flex-wrap gap-2">
              {displayedBlockedServices.map((service) => (
                <span
                  key={service}
                  className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-full"
                >
                  {getServiceDisplayLabel(service)}
                  <button
                    type="button"
                    onClick={() => removeDomain(service)}
                    className="hover:text-red-900 dark:hover:text-red-100"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {sitesClient && <VisitedSitesModal client={sitesClient} onClose={() => setSitesClient(null)} />}
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 sm:gap-4">
            <Users className="w-10 h-10 sm:w-16 sm:h-16 text-blue-600 dark:text-blue-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">Parental Controls</h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Configure per-device filtering and restrictions
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
              title="Refresh"
            >
              <RefreshCw className={`w-5 h-5 text-gray-500 ${isFetching ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={() => setShowAddForm(true)}
              className="flex items-center gap-2 px-3 sm:px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors text-sm"
            >
              <Plus className="w-4 h-4" />
              <span className="hidden sm:inline">Add Device</span>
              <span className="sm:hidden">Add</span>
            </button>
          </div>
        </div>
      </div>

      {/* Info Box */}
      <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3 sm:p-4 border border-blue-200 dark:border-blue-800">
        <div className="flex items-start gap-2 sm:gap-3">
          <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-blue-600 dark:text-blue-400 mt-0.5 flex-shrink-0" />
          <div className="text-xs sm:text-sm text-blue-800 dark:text-blue-200">
            <p className="font-medium mb-1">How it works</p>
            <p className="text-blue-700 dark:text-blue-300">
              Parental Controls are DNS-based. A device is protected only when it uses EasyPi DNS (see the "DNS active / stale / not seen" badge on each device).
              <span className="ml-1">
                <a
                  href="/help?guide=guide-parental-controls"
                  className="underline underline-offset-2 hover:text-blue-900 dark:hover:text-blue-100"
                >
                  Read the full guide
                </a>
                .
              </span>
            </p>
          </div>
        </div>
      </div>

      {/* Bypass attempt history — who tried DoH/DoT/QUIC/VPN/proxy/Tor over time */}
      {bypassHistory && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-emerald-200 dark:border-emerald-800/50 p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
            <h3 className="text-base font-semibold text-gray-900 dark:text-white">Bypass attempt history</h3>
            <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300">
              {bypassHistory.total_all.toLocaleString()} total
            </span>
            {bypassHistory.devices.length > 0 && (
              <button
                type="button"
                onClick={() => clearBypassHistoryMutation.mutate()}
                disabled={clearBypassHistoryMutation.isPending}
                className="text-xs px-2 py-0.5 rounded-full border border-gray-200 dark:border-gray-700 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 disabled:opacity-50"
                title="Clear history"
              >
                Clear
              </button>
            )}
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
            Every DoH / DoT / QUIC / VPN / proxy / Tor attempt a protected device made to escape filtering — kept over time, per device and channel (survives reboots).
          </p>
          {bypassHistory.devices.length > 0 ? (
            <div className="space-y-2">
              {bypassHistory.devices.map((d) => (
                <div key={d.ip} className="flex flex-wrap items-center gap-2 p-2 rounded-lg bg-gray-50 dark:bg-gray-900/40">
                  <span className="text-sm font-medium text-gray-900 dark:text-white">{d.name}</span>
                  <span className="text-xs text-gray-400">{d.ip}</span>
                  <span className="text-xs font-semibold text-amber-600 dark:text-amber-400">⚠️ {d.total.toLocaleString()} attempts</span>
                  {d.last_seen && (
                    <span
                      className="text-[11px] text-gray-400"
                      title={d.first_seen ? `first seen ${new Date(d.first_seen).toLocaleString()}` : undefined}
                    >
                      last {new Date(d.last_seen).toLocaleString()}
                    </span>
                  )}
                  <div className="flex flex-wrap gap-1 ml-auto">
                    {Object.entries(d.channels)
                      .sort((a, b) => b[1] - a[1])
                      .map(([ch, n]) => (
                        <span key={ch} className="text-[11px] px-1.5 py-0.5 rounded bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                          {bypassChannelLabel(ch)} ×{n.toLocaleString()}
                        </span>
                      ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-emerald-700 dark:text-emerald-300">
              ✅ Force-block active — no bypass attempts recorded yet. If a protected device tries encrypted DNS, a VPN, Tor or a proxy, it appears here with the device, channel and time.
            </p>
          )}
        </div>
      )}

      {/* Add Device Form */}
      {showAddForm && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 sm:p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white">Add New Device</h3>
            <button
              onClick={() => {
                setShowAddForm(false)
                setNewClient(defaultNewClient)
              }}
              className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
            >
              <X className="w-5 h-5 text-gray-500" />
            </button>
          </div>

          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Device Name *
                </label>
                <input
                  type="text"
                  value={newClient.name}
                  onChange={(e) => setNewClient({ ...newClient, name: e.target.value })}
                  placeholder="e.g., Kid's Phone"
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Device *
                </label>
                <select
                  value={newClient.mac}
                  onChange={(e) => {
                    const device = lanDevices.find((item: CachedDevice) => item.mac?.toLowerCase() === e.target.value)
                    if (!device?.mac) return
                    setNewClient({
                      ...newClient,
                      name: newClient.name || device.hostname || device.ip,
                      ip: device.ip,
                      mac: device.mac.toLowerCase(),
                    })
                  }}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
                >
                  <option value="">Select a known device</option>
                  {lanDevices.map((device: CachedDevice) => (
                    <option key={device.mac || device.ip} value={(device.mac || '').toLowerCase()}>
                      {device.hostname || device.ip} - {device.mac}
                    </option>
                  ))}
                </select>
                {newClient.mac && (
                  <p className="mt-1 text-xs font-mono text-gray-500 dark:text-gray-400">
                    MAC {newClient.mac} · current IP {newClient.ip}
                  </p>
                )}
              </div>
            </div>

            <div className="space-y-2">
              {renderToggle(
                newClient.parental_enabled,
                () => setNewClient({ ...newClient, parental_enabled: !newClient.parental_enabled }),
                'Parental Filter',
                'Block adult and explicit content',
                <ShieldAlert className="w-5 h-5 text-orange-500" />
              )}
              {renderToggle(
                newClient.safesearch_enabled,
                () => setNewClient({ ...newClient, safesearch_enabled: !newClient.safesearch_enabled }),
                'Safe Search',
                'Enforce safe search in Google, Bing, YouTube',
                <Search className="w-5 h-5 text-blue-500" />
              )}
              {renderToggle(
                newClient.safebrowsing_enabled,
                () => setNewClient({ ...newClient, safebrowsing_enabled: !newClient.safebrowsing_enabled }),
                'Safe Browsing',
                'Block malware and phishing sites',
                <Shield className="w-5 h-5 text-green-500" />
              )}
            </div>

            {renderBypassProtectionToggles(newClient, setNewClient)}

            {renderServiceSelector(newClient, setNewClient, customDomain, setCustomDomain)}

            <div className="flex justify-end gap-2 pt-4 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={() => {
                  setShowAddForm(false)
                  setNewClient(defaultNewClient)
                }}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => addClientMutation.mutate()}
                disabled={!newClient.name || !newClient.mac || addClientMutation.isPending}
                className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {addClientMutation.isPending ? 'Adding...' : 'Add Device'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Device List */}
      {isLoading && (
        <div className="text-center py-8 text-gray-500">Loading devices...</div>
      )}

      {!isLoading && clientList.length === 0 && !showAddForm && (
        <div className="text-center py-12 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
          <Monitor className="w-12 h-12 text-gray-400 mx-auto mb-3" />
          <p className="text-gray-600 dark:text-gray-400 mb-4">No devices configured yet</p>
          <button
            onClick={() => setShowAddForm(true)}
            className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
          >
            Add Your First Device
          </button>
        </div>
      )}

      <div className="space-y-4">
        {clientList.map((client) => (
          <div
            key={client.name}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden"
          >
            {editingClient === client.name ? (
              /* Edit Mode */
              <div className="p-6 space-y-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Edit Device</h3>
                  <button
                    onClick={() => setEditingClient(null)}
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                  >
                    <X className="w-5 h-5 text-gray-500" />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Device Name
                    </label>
                    <input
                      type="text"
                      value={editForm.name}
                      onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                      className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      IP Address
                    </label>
                    <input
                      type="text"
                      value={editForm.ip}
                      onChange={(e) => setEditForm({ ...editForm, ip: e.target.value })}
                      className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-mono"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  {renderToggle(
                    editForm.parental_enabled,
                    () => setEditForm({ ...editForm, parental_enabled: !editForm.parental_enabled }),
                    'Parental Filter',
                    'Block adult and explicit content',
                    <ShieldAlert className="w-5 h-5 text-orange-500" />
                  )}
                  {renderToggle(
                    editForm.safesearch_enabled,
                    () => setEditForm({ ...editForm, safesearch_enabled: !editForm.safesearch_enabled }),
                    'Safe Search',
                    'Enforce safe search in Google, Bing, YouTube',
                    <Search className="w-5 h-5 text-blue-500" />
                  )}
                  {renderToggle(
                    editForm.safebrowsing_enabled,
                    () => setEditForm({ ...editForm, safebrowsing_enabled: !editForm.safebrowsing_enabled }),
                    'Safe Browsing',
                    'Block malware and phishing sites',
                    <Shield className="w-5 h-5 text-green-500" />
                  )}
                </div>

                {renderBypassProtectionToggles(editForm, setEditForm)}

                {renderServiceSelector(editForm, setEditForm, editCustomDomain, setEditCustomDomain)}

                <div className="flex justify-end gap-2 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <button
                    onClick={() => setEditingClient(null)}
                    className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => saveEditedClient(client)}
                    disabled={updateClientMutation.isPending}
                    className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg disabled:opacity-50"
                  >
                    {updateClientMutation.isPending ? 'Saving...' : 'Save Changes'}
                  </button>
                </div>
              </div>
            ) : (
              /* View Mode */
              <div className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                      <Monitor className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                    </div>
                    <div>
                      <div className="font-semibold text-gray-900 dark:text-white">{client.name}</div>
                      <div className="text-sm font-mono text-gray-500 dark:text-gray-400">{client.ip}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {client.fail_closed && (
                      <button
                        onClick={() => restoreInternetMutation.mutate(client.ip)}
                        disabled={restoreInternetMutation.isPending}
                        className="px-2 py-1 text-xs bg-green-600 hover:bg-green-700 text-white rounded-lg disabled:opacity-50"
                        title="Restore Internet"
                      >
                        <Globe className="w-3 h-3 inline mr-1" />
                        Restore Internet
                      </button>
                    )}
                    <button
                      onClick={() => setSitesClient(client)}
                      className="p-2 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                      title="Visited sites"
                    >
                      <History className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => startEditing(client)}
                      className="p-2 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                      title="Edit"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => {
                        if (confirm(`Delete device "${client.name}"?`)) {
                          deleteClientMutation.mutate(client.record_name || client.name)
                        }
                      }}
                      className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* Status Badges */}
                <div className="flex flex-wrap gap-2 mt-4">
                  {(() => {
                    const raw = client.dns_last_seen
                    if (!raw) {
                      return (
                        <span
                          className="px-2 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500"
                          title="No DNS activity seen from this device yet"
                        >
                          <Globe className="w-3 h-3 inline mr-1" />
                          DNS not seen
                        </span>
                      )
                    }
                    const dt = new Date(raw)
                    if (Number.isNaN(dt.getTime())) {
                      return (
                        <span
                          className="px-2 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500"
                          title="DNS activity timestamp could not be parsed"
                        >
                          <Globe className="w-3 h-3 inline mr-1" />
                          DNS unknown
                        </span>
                      )
                    }
                    const ageSec = (Date.now() - dt.getTime()) / 1000
                    const active = ageSec >= 0 && ageSec < 120
                    const cls = active
                      ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                      : 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300'
                    const label = active ? 'DNS active' : 'DNS stale'
                    return (
                      <span className={`px-2 py-1 text-xs rounded-full ${cls}`} title={dt.toISOString()}>
                        <Globe className="w-3 h-3 inline mr-1" />
                        {label} ({formatAge(ageSec)} ago)
                      </span>
                    )
                  })()}
                  {client.fail_closed && (
                    <span className="px-2 py-1 text-xs rounded-full bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">
                      <ShieldAlert className="w-3 h-3 inline mr-1" />
                      Fail-Closed: Internet blocked
                    </span>
                  )}
                  <span
                    className={`px-2 py-1 text-xs rounded-full ${
                      client.parental_enabled
                        ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-500'
                    }`}
                  >
                    <ShieldAlert className="w-3 h-3 inline mr-1" />
                    Parental {client.parental_enabled ? 'ON' : 'OFF'}
                  </span>
                  <span
                    className={`px-2 py-1 text-xs rounded-full ${
                      client.safesearch_enabled
                        ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-500'
                    }`}
                  >
                    <Search className="w-3 h-3 inline mr-1" />
                    Safe Search {client.safesearch_enabled ? 'ON' : 'OFF'}
                  </span>
                  <span
                    className={`px-2 py-1 text-xs rounded-full ${
                      client.safebrowsing_enabled
                        ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-500'
                    }`}
                  >
                    <Shield className="w-3 h-3 inline mr-1" />
                    Safe Browsing {client.safebrowsing_enabled ? 'ON' : 'OFF'}
                  </span>
                  {client.blocked_services && client.blocked_services.length > 0 && (
                    <span className="px-2 py-1 text-xs rounded-full bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">
                      <Ban className="w-3 h-3 inline mr-1" />
                      {client.blocked_services.length} service(s) blocked
                    </span>
                  )}
                </div>

                {/* Blocked Services List */}
                {client.blocked_services && client.blocked_services.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                    <div className="text-xs text-gray-500 dark:text-gray-400 mb-2">Blocked services:</div>
                    <div className="flex flex-wrap gap-1">
                      {client.blocked_services.map((service) => (
                        <span
                          key={service}
                          className="px-2 py-0.5 text-xs bg-red-500/10 text-red-600 dark:text-red-400 rounded"
                        >
                          {getServiceDisplayLabel(service)}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
