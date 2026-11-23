import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Clock, Globe2, Link2, Loader2, RefreshCw, ShieldCheck, Smartphone, Trash2 } from 'lucide-react'
import { toast } from 'react-hot-toast'
import QRCode from 'qrcode'

import Button from '../components/common/Button'
import MobileLinkRelay from '../components/Mobile/MobileLinkRelay'
import {
  listMobileDevices,
  deleteMobileDevice,
  getMobileLinkSettings,
  getMobileLinkAgentStatus,
  startMobilePairing,
  type MobileDevice,
  type MobileLinkSettings,
  type MobileLinkAgentStatus,
  type MobilePairing,
} from '../api/mobile'

function parseServerUtc(value: string): Date {
  // EasyPi stores timestamps as naive UTC. Accept older API responses that did
  // not include an explicit timezone, while newer releases return RFC 3339 Z.
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value)
  return new Date(hasTimezone ? value : `${value}Z`)
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(parseServerUtc(value))
}

function errorMessage(error: unknown, fallback: string): string {
  const candidate = error as { response?: { data?: { detail?: string } }; message?: string }
  return candidate?.response?.data?.detail || candidate?.message || fallback
}

export default function MobileAssistant() {
  const [devices, setDevices] = useState<MobileDevice[]>([])
  const [pairing, setPairing] = useState<MobilePairing | null>(null)
  const [qrCode, setQrCode] = useState('')
  const qrImageRef = useRef<HTMLImageElement>(null)
  const [loading, setLoading] = useState(true)
  const [pairingLoading, setPairingLoading] = useState(false)
  const [pairingError, setPairingError] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)
  const [now, setNow] = useState(Date.now())
  const [linkSettings, setLinkSettings] = useState<MobileLinkSettings>({ enabled: false, public_url: null })
  const [linkSettingsLoading, setLinkSettingsLoading] = useState(true)
  const [agent, setAgent] = useState<MobileLinkAgentStatus | null>(null)

  const refreshDevices = useCallback(async () => {
    try {
      setDevices(await listMobileDevices())
    } catch (error) {
      toast.error(errorMessage(error, 'Could not load mobile devices'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void refreshDevices() }, [refreshDevices])

  useEffect(() => {
    if (!pairing || !qrCode) return
    qrImageRef.current?.scrollIntoView({
      block: 'center',
      inline: 'nearest',
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth',
    })
  }, [pairing, qrCode])

  useEffect(() => {
    void getMobileLinkSettings()
      .then(setLinkSettings)
      .catch((error) => toast.error(errorMessage(error, 'Could not load Mobile Link settings')))
      .finally(() => setLinkSettingsLoading(false))
  }, [])

  const refreshAgent = useCallback(async () => {
    try {
      const status = await getMobileLinkAgentStatus()
      setAgent(status)
    } catch (error) {
      toast.error(errorMessage(error, 'Could not load Mobile Link agent status'))
    }
  }, [])

  useEffect(() => { void refreshAgent() }, [refreshAgent])

  useEffect(() => {
    if (!pairing) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    const polling = window.setInterval(() => { void refreshDevices() }, 3000)
    return () => {
      window.clearInterval(timer)
      window.clearInterval(polling)
    }
  }, [pairing, refreshDevices])

  const secondsLeft = useMemo(() => {
    if (!pairing) return 0
    return Math.max(0, Math.ceil((parseServerUtc(pairing.expires_at).getTime() - now) / 1000))
  }, [now, pairing])

  useEffect(() => {
    if (pairing && secondsLeft === 0) {
      setPairing(null)
      setQrCode('')
    }
  }, [pairing, secondsLeft])

  const beginPairing = async () => {
    setPairingLoading(true)
    setPairingError('')
    try {
      const result = await startMobilePairing()
      const certificate = result.certificate_sha256
        ? `&cert=${encodeURIComponent(result.certificate_sha256)}`
        : ''
      // Use the app's direct custom scheme. Some Android camera apps treat an
      // intent:// QR code as a Play Store lookup and report that a sideloaded
      // EasyPi Mobile installation does not exist.
      const serverUrl = result.server_url || window.location.origin
      const home = window.location.protocol === 'https:' && window.location.origin !== serverUrl
        ? `&home=${encodeURIComponent(window.location.origin)}`
        : ''
      const pairingIntent = `easypi-mobile://pair?server=${encodeURIComponent(serverUrl)}&code=${encodeURIComponent(result.pairing_code)}${certificate}${home}`
      const image = await QRCode.toDataURL(pairingIntent, {
        width: 360,
        margin: 2,
        errorCorrectionLevel: 'M',
        color: { dark: '#07111f', light: '#ffffff' },
      })
      setNow(Date.now())
      setPairing(result)
      setQrCode(image)
    } catch (error) {
      const message = errorMessage(error, 'Could not create pairing code')
      setPairingError(message)
      toast.error(message)
    } finally {
      setPairingLoading(false)
    }
  }

  const refreshLink = useCallback(async () => {
    try {
      const [settings, status] = await Promise.all([getMobileLinkSettings(), getMobileLinkAgentStatus()])
      setLinkSettings(settings)
      setAgent(status)
    } catch (error) {
      toast.error(errorMessage(error, 'Could not refresh Mobile Link state'))
    }
  }, [])

  const remove = async (device: MobileDevice) => {
    if (!window.confirm(`Delete ${device.name}? This permanently removes the phone pairing and immediately revokes its EasyPi access.`)) return
    setDeleting(device.id)
    try {
      await deleteMobileDevice(device.id)
      toast.success(`${device.name} deleted`)
      await refreshDevices()
    } catch (error) {
      toast.error(errorMessage(error, 'Could not delete phone pairing'))
    } finally {
      setDeleting(null)
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6 lg:p-8">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-sky-500/15 p-3 text-sky-400"><Smartphone className="h-7 w-7" /></div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">EasyPi Mobile</h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">Link phones, delete old pairings, and configure secure remote access.</p>
            </div>
          </div>
        </div>
        <Button onClick={() => void beginPairing()} loading={pairingLoading} icon={<Link2 className="h-4 w-4" />}>
          Add phone
        </Button>
      </header>

      {pairingError && (
        <div role="alert" className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-600 dark:text-red-400">
          {pairingError}. Please try again.
        </div>
      )}

      <section className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900 md:p-7">
        <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
          <div className="min-w-0 flex-1 space-y-2">
            <div className="flex items-center gap-2">
              <Globe2 className="h-5 w-5 text-sky-500" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Remote Mobile Link</h2>
            </div>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Lets EasyPi Mobile reach this EasyPi over HTTPS without using the phone VPN slot. Full-traffic protection remains a separate optional mode.
            </p>
            <div className="break-all font-mono text-sm text-gray-700 dark:text-gray-200">
              {linkSettingsLoading ? 'Checking…' : linkSettings.public_url || 'Deploy the VPS relay to create the remote address'}
            </div>
          </div>
          <span className={`rounded-full px-3 py-1 text-xs font-semibold ${linkSettings.enabled ? 'bg-emerald-500/15 text-emerald-500' : 'bg-gray-500/15 text-gray-500'}`}>{linkSettings.enabled ? 'Remote pairing active' : 'Remote pairing off'}</span>
        </div>
      </section>

      <section className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900 md:p-7">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Home agent</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">Persistent outgoing TLS connection from this EasyPi to the VPS relay.</p>
          </div>
          <span className={`rounded-full px-3 py-1 text-xs font-semibold ${agent?.active ? 'bg-emerald-500/15 text-emerald-500' : 'bg-gray-500/15 text-gray-500'}`}>
            {agent?.active ? 'Agent service running' : agent?.configured ? 'Configured, stopped' : 'Not configured'}
          </span>
        </div>
        <div className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
          <div className="rounded-xl bg-gray-50 p-3 dark:bg-dark-800"><span className="text-gray-500">Relay</span><div className="mt-1 font-medium dark:text-white">{agent?.relay_address || 'Not configured'}</div></div>
          <div className="rounded-xl bg-gray-50 p-3 dark:bg-dark-800"><span className="text-gray-500">Transport identity</span><div className="mt-1 break-all font-mono text-xs dark:text-white">{agent?.installation_id || 'Created during relay deployment'}</div></div>
        </div>
      </section>

      <MobileLinkRelay onChanged={() => void refreshLink()} />

      {pairing && qrCode && (
        <section className="grid gap-6 rounded-2xl border border-sky-500/30 bg-sky-500/5 p-5 md:grid-cols-[minmax(0,1fr)_360px] md:p-7">
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-sky-500"><ShieldCheck className="h-5 w-5" /><span className="font-semibold">One-time secure link</span></div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Scan this QR code with the phone camera</h2>
            <ol className="list-decimal space-y-2 pl-5 text-sm text-gray-600 dark:text-gray-300">
              <li>Install and open EasyPi Mobile on the phone.</li>
              <li>Scan this code with the phone camera.</li>
              <li>Confirm the EasyPi address shown by the app.</li>
            </ol>
            <div className="flex items-center gap-2 text-sm text-amber-600 dark:text-amber-400">
              <Clock className="h-4 w-4" /> Expires in {secondsLeft} seconds and can be used only once.
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              The phone receives a restricted mobile token. It does not receive your administrator password or browser session.
            </p>
          </div>
          <div className="mx-auto rounded-2xl bg-white p-4 shadow-lg">
            <img ref={qrImageRef} src={qrCode} width={328} height={328} alt="One-time EasyPi Mobile pairing QR code" className="h-auto w-full max-w-[328px] scroll-m-4" />
          </div>
        </section>
      )}

      <section className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900 md:p-7">
        <div className="mb-5 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Linked phones</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">Deleting a phone permanently removes its pairing and immediately revokes access.</p>
          </div>
          <button onClick={() => void refreshDevices()} className="rounded-lg p-2 text-gray-500 hover:bg-gray-100 dark:hover:bg-dark-800" aria-label="Refresh devices">
            <RefreshCw className="h-5 w-5" />
          </button>
        </div>

        {loading ? (
          <div className="flex justify-center py-12"><Loader2 className="h-7 w-7 animate-spin text-sky-500" /></div>
        ) : devices.length === 0 ? (
          <div className="rounded-xl border border-dashed border-gray-300 py-12 text-center dark:border-dark-700">
            <Smartphone className="mx-auto mb-3 h-9 w-9 text-gray-400" />
            <p className="font-medium text-gray-700 dark:text-gray-200">No phones linked yet</p>
            <p className="mt-1 text-sm text-gray-500">Choose Add phone to create a one-time QR code.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {devices.map((device) => (
              <div key={device.id} className="flex flex-col gap-4 rounded-xl bg-gray-50 p-4 dark:bg-dark-800 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-semibold text-gray-900 dark:text-white">{device.name}</span>
                    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${device.is_active ? 'bg-emerald-500/15 text-emerald-500' : 'bg-gray-500/15 text-gray-500'}`}>
                      {device.is_active ? 'Active' : 'Disconnected'}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Linked {formatDate(device.created_at)} · Last contact {formatDate(device.last_seen_at)}
                  </p>
                </div>
                <Button variant="danger" size="sm" loading={deleting === device.id} icon={<Trash2 className="h-4 w-4" />} onClick={() => void remove(device)}>
                  Delete
                </Button>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
