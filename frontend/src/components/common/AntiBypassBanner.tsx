import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Eye, ShieldAlert, X } from 'lucide-react'
import { toast } from 'react-hot-toast'
import {
  acknowledgeBypassAlertByIp,
  getBypassStatus,
  setBypassModeByIp,
  type BypassDevice,
} from '../../api/guardSecurity'

const DISMISSED_STORAGE_KEY = 'easypi_bypass_banner_dismissed_v1'
const AUTO_MINIMIZE_MS = 15000

type DismissedMap = Record<string, number>

function loadDismissed(): DismissedMap {
  try {
    const raw = localStorage.getItem(DISMISSED_STORAGE_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object') return {}
    return parsed as DismissedMap
  } catch {
    return {}
  }
}

function saveDismissed(value: DismissedMap) {
  try {
    localStorage.setItem(DISMISSED_STORAGE_KEY, JSON.stringify(value))
  } catch {
    // ignore localStorage issues
  }
}

function eventKey(device: BypassDevice): string {
  const groups = Array.isArray(device.groups) ? device.groups.join(',') : ''
  return [
    String(device.ip || '').trim(),
    String(device.triggered_at || '').trim(),
    String(device.domain || '').trim(),
    groups,
  ].join('|')
}

function leakIcons(device: BypassDevice): string {
  const groups = new Set(
    (Array.isArray(device.groups) ? device.groups : []).map((g) => String(g || '').trim().toLowerCase())
  )
  const icons: string[] = []
  if (device.tor_bridge || groups.has('tor')) icons.push('🧅')
  if (groups.has('doh')) icons.push('🌐')
  if (groups.has('vpn')) icons.push('🔐')
  if (groups.has('proxy')) icons.push('🔀')
  if (groups.has('smartdns')) icons.push('🧠')
  if (icons.length === 0) icons.push('⚠️')
  return icons.join(' ')
}

function sortAlertsNewestFirst(items: BypassDevice[]): BypassDevice[] {
  return [...items].sort((a, b) => {
    const ta = Date.parse(String(a.triggered_at || ''))
    const tb = Date.parse(String(b.triggered_at || ''))
    if (Number.isFinite(ta) && Number.isFinite(tb) && ta !== tb) return tb - ta
    return String(a.ip || '').localeCompare(String(b.ip || ''))
  })
}

export default function AntiBypassBanner() {
  const queryClient = useQueryClient()
  const [dismissedMap, setDismissedMap] = useState<DismissedMap>(() => loadDismissed())
  const [activeKey, setActiveKey] = useState<string | null>(null)
  const [minimized, setMinimized] = useState(false)
  const [showList, setShowList] = useState(false)

  const { data, isFetching } = useQuery({
    queryKey: ['bypass-status'],
    queryFn: getBypassStatus,
    staleTime: 0,
    refetchInterval: 2000,
  })

  const devices = useMemo(() => (data?.devices || []).filter(Boolean), [data]) as BypassDevice[]
  // Don't duplicate UI with Fail-Closed banner: once a device is quarantined,
  // only the red restore banner should remain visible.
  const alertDevices = useMemo(
    () => sortAlertsNewestFirst(devices.filter((d) => !!d.has_alert && !d.quarantine && !!d.leak)),
    [devices]
  )

  const unseenAlerts = useMemo(
    () => alertDevices.filter((d) => !dismissedMap[eventKey(d)]),
    [alertDevices, dismissedMap]
  )

  const acknowledgeMutation = useMutation({
    mutationFn: (ip: string) => acknowledgeBypassAlertByIp(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['bypass-status'] })
    },
  })

  const modeMutation = useMutation({
    mutationFn: (vars: { ip: string; mode: 'warn' | 'quarantine'; quarantineNow?: boolean }) =>
      setBypassModeByIp(vars.ip, vars.mode, !!vars.quarantineNow),
    onSuccess: (_data, vars) => {
      if (vars.mode === 'warn') toast.success('Observe mode applied')
      if (vars.mode === 'quarantine') toast.success('Quarantine enabled')
      queryClient.invalidateQueries({ queryKey: ['bypass-status'] })
      queryClient.invalidateQueries({ queryKey: ['parental-clients'] })
      queryClient.invalidateQueries({ queryKey: ['fail-closed-status'] })
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.detail || 'Failed to apply mode'
      toast.error(String(detail))
    },
  })

  const rememberDismissed = (key: string) => {
    setDismissedMap((prev) => {
      const next: DismissedMap = { ...prev, [key]: Date.now() }
      const entries = Object.entries(next).sort((a, b) => b[1] - a[1]).slice(0, 200)
      const compact: DismissedMap = {}
      for (const [k, ts] of entries) compact[k] = ts
      saveDismissed(compact)
      return compact
    })
  }

  useEffect(() => {
    if (!activeKey) {
      if (unseenAlerts.length > 0) {
        setActiveKey(eventKey(unseenAlerts[0]))
        setMinimized(false)
      }
      return
    }

    const stillActive = alertDevices.some((d) => eventKey(d) === activeKey)
    if (!stillActive) {
      setActiveKey(null)
      setMinimized(false)
    }
  }, [activeKey, alertDevices, unseenAlerts])

  const activeDevice = useMemo(
    () => alertDevices.find((d) => eventKey(d) === activeKey) || null,
    [alertDevices, activeKey]
  )

  useEffect(() => {
    if (!activeDevice || minimized) return
    const timer = window.setTimeout(() => setMinimized(true), AUTO_MINIMIZE_MS)
    return () => window.clearTimeout(timer)
  }, [activeDevice, minimized])

  const dismissActiveAlert = () => {
    if (!activeDevice || !activeKey) return
    rememberDismissed(activeKey)
    acknowledgeMutation.mutate(activeDevice.ip)
    setActiveKey(null)
    setMinimized(false)
  }

  const minimizeActiveBanner = () => {
    if (!activeDevice) return
    setMinimized(true)
  }

  const applyObserve = () => {
    if (!activeDevice || !activeKey) return
    rememberDismissed(activeKey)
    modeMutation.mutate({ ip: activeDevice.ip, mode: 'warn' })
    setActiveKey(null)
    setMinimized(false)
  }

  const applyQuarantine = () => {
    if (!activeDevice || !activeKey) return
    rememberDismissed(activeKey)
    modeMutation.mutate({ ip: activeDevice.ip, mode: 'quarantine', quarantineNow: true })
    setActiveKey(null)
    setMinimized(false)
  }

  if (!activeDevice) return null

  const pendingCount = unseenAlerts.length
  const isTorBridge = !!activeDevice.tor_bridge
  const leakIconSet = leakIcons(activeDevice)
  const subtitle = isTorBridge ? 'Tor Bridges' : activeDevice.group_label || 'Bypass'
  const sourceHint = activeDevice.source_hint || (isTorBridge ? 'Possible source: Tor Browser Bridges' : null)
  const eventTime = activeDevice.triggered_at ? new Date(activeDevice.triggered_at).toLocaleString() : null
  // Auto-quarantine (the "1 minute auto-disable") ONLY fires in quarantine mode; warn /
  // log_only devices are never fail-closed by the timeout loop, so don't threaten it.
  const autoQuarantines = String(activeDevice.bypass_mode || 'warn').toLowerCase() === 'quarantine'

  if (minimized) {
    return (
      <div className="border-b border-amber-200 dark:border-amber-900/40 bg-amber-50 dark:bg-amber-900/20">
        <div className="mx-auto max-w-7xl px-4 lg:px-6 py-2">
          <div className="flex items-center justify-between gap-2 text-xs">
            <div className="min-w-0 flex items-center gap-2 text-amber-900 dark:text-amber-100">
              <ShieldAlert className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <span className="truncate">
                {leakIconSet} {isTorBridge ? 'Tor bridge bypass detected' : 'Protection bypass detected'}: {activeDevice.name || activeDevice.ip} ({activeDevice.ip})
                {pendingCount > 1 ? (
                  <>
                    {' '}
                    <button
                      type="button"
                      onClick={() => { setMinimized(false); setShowList(true) }}
                      className="underline underline-offset-2 decoration-dotted hover:decoration-solid"
                    >
                      (+{pendingCount - 1} more)
                    </button>
                  </>
                ) : null}
              </span>
              {isFetching ? <span className="opacity-70">syncing...</span> : null}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => setMinimized(false)}
                className="inline-flex items-center gap-1 rounded-md px-2 py-1 bg-white/70 hover:bg-white/90 dark:bg-black/10 dark:hover:bg-black/20 text-amber-900 dark:text-amber-100 border border-amber-200/70 dark:border-amber-900/40"
              >
                <Eye className="h-3.5 w-3.5" />
                Open
              </button>
              <button
                type="button"
                onClick={dismissActiveAlert}
                className="inline-flex items-center gap-1 rounded-md px-2 py-1 bg-white/70 hover:bg-white/90 dark:bg-black/10 dark:hover:bg-black/20 text-amber-900 dark:text-amber-100 border border-amber-200/70 dark:border-amber-900/40"
              >
                <X className="h-3.5 w-3.5" />
                Dismiss
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="border-b border-amber-200 dark:border-amber-900/40 bg-amber-50 dark:bg-amber-900/20">
      <div className="mx-auto max-w-7xl px-4 lg:px-6 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex items-start gap-3">
            <ShieldAlert className="h-5 w-5 mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-amber-900 dark:text-amber-100">
                {leakIconSet} {isTorBridge ? 'Tor bridge bypass detected —' : 'Protection bypass detected —'} {activeDevice.name || activeDevice.ip} ({activeDevice.ip})
                {pendingCount > 1 ? (
                  <>
                    {' '}
                    <button
                      type="button"
                      onClick={() => setShowList((v) => !v)}
                      aria-expanded={showList}
                      className="font-medium underline underline-offset-2 decoration-dotted hover:decoration-solid"
                    >
                      (+{pendingCount - 1} more)
                    </button>
                  </>
                ) : null}
              </p>
              <p className="text-xs text-amber-800/90 dark:text-amber-200/80">
                {subtitle}
                {activeDevice.domain ? ` • ${activeDevice.domain}` : ''}
                {eventTime ? ` • ${eventTime}` : ''}
              </p>
              {sourceHint ? (
                <p className="text-xs text-amber-800/90 dark:text-amber-200/80">{sourceHint}</p>
              ) : null}
              <p className="mt-1 text-xs text-amber-800/90 dark:text-amber-200/80">
                {isTorBridge
                  ? 'Traffic leaked through Tor bridges. '
                  : 'Encrypted DNS/VPN bypass traffic is leaking. '}
                Observe hardens bypass-channel blocking, Quarantine disables internet for this device.{' '}
                {autoQuarantines
                  ? 'If no action is taken for 1 minute, internet is auto-disabled.'
                  : 'No internet is cut automatically in this mode — choose an action below.'}
              </p>
              {showList && unseenAlerts.length > 1 ? (
                <div className="mt-2 rounded-md border border-amber-300/70 dark:border-amber-900/50 overflow-hidden">
                  {unseenAlerts.map((d) => {
                    const isCurrent = eventKey(d) === activeKey
                    const t = d.triggered_at ? new Date(d.triggered_at).toLocaleTimeString() : ''
                    return (
                      <button
                        key={eventKey(d)}
                        type="button"
                        onClick={() => {
                          setActiveKey(eventKey(d))
                          setMinimized(false)
                          setShowList(false)
                        }}
                        className={`w-full text-left px-2.5 py-1.5 text-xs flex items-center gap-2 border-b last:border-b-0 border-amber-200/50 dark:border-amber-900/30 ${
                          isCurrent
                            ? 'bg-amber-100/80 dark:bg-amber-900/30'
                            : 'bg-white/50 dark:bg-black/10 hover:bg-amber-100/60 dark:hover:bg-amber-900/20'
                        }`}
                      >
                        <span className="shrink-0">{leakIcons(d)}</span>
                        <span className="font-medium text-amber-900 dark:text-amber-100 truncate">
                          {d.name || d.ip} ({d.ip})
                        </span>
                        <span className="text-amber-800/80 dark:text-amber-200/70 truncate">
                          {d.group_label || 'Bypass'}{t ? ` • ${t}` : ''}
                        </span>
                        {isCurrent ? (
                          <span className="ml-auto shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase bg-amber-500/20 text-amber-800 dark:text-amber-200">
                            current
                          </span>
                        ) : null}
                      </button>
                    )
                  })}
                </div>
              ) : null}
            </div>
          </div>

          <button
            type="button"
            onClick={minimizeActiveBanner}
            className="shrink-0 inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-medium bg-white/70 hover:bg-white/90 dark:bg-black/10 dark:hover:bg-black/20 text-amber-900 dark:text-amber-100 border border-amber-200/70 dark:border-amber-900/40"
          >
            <X className="h-4 w-4" />
            Minimize
          </button>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={applyObserve}
            disabled={modeMutation.isPending}
            className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold bg-amber-600 hover:bg-amber-700 text-white disabled:opacity-50"
            title="Observe (recommended): block bypass channels, keep normal internet"
          >
            <AlertTriangle className="h-4 w-4" />
            Observe
          </button>
          <button
            type="button"
            onClick={applyQuarantine}
            disabled={modeMutation.isPending}
            className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold bg-red-600 hover:bg-red-700 text-white disabled:opacity-50"
            title="Quarantine: full internet off for this device"
          >
            <ShieldAlert className="h-4 w-4" />
            Quarantine
          </button>
          <button
            type="button"
            onClick={dismissActiveAlert}
            disabled={acknowledgeMutation.isPending}
            className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold bg-white/70 hover:bg-white/90 dark:bg-black/10 dark:hover:bg-black/20 text-amber-900 dark:text-amber-100 border border-amber-200/70 dark:border-amber-900/40 disabled:opacity-50"
            title="Dismiss this alert"
          >
            <X className="h-4 w-4" />
            Dismiss
          </button>
          <a
            href="/help?guide=guide-parental-controls"
            className="ml-1 text-xs underline underline-offset-2 text-amber-800 hover:text-amber-950 dark:text-amber-200 dark:hover:text-white"
          >
            How this works
          </a>
          {isFetching ? <span className="text-xs text-amber-800/80 dark:text-amber-200/70">syncing...</span> : null}
        </div>
      </div>
    </div>
  )
}
