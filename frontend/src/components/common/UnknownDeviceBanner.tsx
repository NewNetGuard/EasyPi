import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Check, RotateCw, ShieldAlert, Wifi, X } from 'lucide-react'
import { toast } from 'react-hot-toast'
import {
  allowUnknownDevice,
  blockUnknownDevice,
  getUnknownDeviceQuarantine,
  replaceUnknownDeviceIdentity,
  type DeviceAccessProfile,
  type UnknownDevice,
} from '../../api/guardSecurityDevices'

const detailFromError = (error: any, fallback: string) =>
  String(error?.response?.data?.detail || fallback)

export default function UnknownDeviceBanner() {
  const queryClient = useQueryClient()
  const [approvalDevice, setApprovalDevice] = useState<UnknownDevice | null>(null)
  const [name, setName] = useState('')
  const [profile, setProfile] = useState<DeviceAccessProfile['id']>('balanced')

  const { data } = useQuery({
    queryKey: ['unknown-device-quarantine'],
    queryFn: getUnknownDeviceQuarantine,
    staleTime: 0,
    refetchInterval: 2000,
    retry: 1,
  })

  const pending = useMemo(() => data?.pending || [], [data])
  const active = pending[0]

  useEffect(() => {
    if (approvalDevice && !pending.some((item) => item.id === approvalDevice.id)) {
      setApprovalDevice(null)
    }
  }, [approvalDevice, pending])

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['unknown-device-quarantine'] })
    queryClient.invalidateQueries({ queryKey: ['devices'] })
    queryClient.invalidateQueries({ queryKey: ['parental-clients'] })
    queryClient.invalidateQueries({ queryKey: ['vpn-devices'] })
    queryClient.invalidateQueries({ queryKey: ['cachedDevices'] })
  }

  const blockMutation = useMutation({
    mutationFn: (device: UnknownDevice) => blockUnknownDevice(device.id),
    onSuccess: () => {
      toast.success('Device remains blocked')
      refresh()
    },
    onError: (error: any) => toast.error(detailFromError(error, 'Failed to block device')),
  })

  const allowMutation = useMutation({
    mutationFn: (device: UnknownDevice) =>
      allowUnknownDevice(device.id, { name: name.trim(), access_profile: profile }),
    onSuccess: () => {
      toast.success('Device allowed')
      setApprovalDevice(null)
      refresh()
    },
    onError: (error: any) =>
      toast.error(detailFromError(error, 'Device remains blocked because access could not be activated')),
  })

  const replaceMutation = useMutation({
    mutationFn: (device: UnknownDevice) => {
      if (!device.identity_candidate) throw new Error('No verified identity candidate')
      return replaceUnknownDeviceIdentity(device.id, device.identity_candidate.device_id)
    },
    onSuccess: () => {
      toast.success('Existing device policy restored')
      setApprovalDevice(null)
      refresh()
    },
    onError: (error: any) =>
      toast.error(detailFromError(error, 'Device remains blocked because identity migration failed')),
  })

  const openApproval = (device: UnknownDevice) => {
    setApprovalDevice(device)
    setName(device.managed_name || device.hostname || device.vendor || `Device ${device.ip}`)
    setProfile(device.managed_profile || 'balanced')
  }

  if (!active || data?.enabled === false) return null

  const profiles = data?.access_profiles || []
  const label = active.hostname || active.vendor || 'Unknown device'
  const identityCandidate = active.identity_candidate?.identity_state === 'possible_mac_change'
    ? active.identity_candidate
    : null
  const identityConflict = Boolean(identityCandidate?.conflicts.length)
  const mutationPending = blockMutation.isPending || allowMutation.isPending || replaceMutation.isPending

  return (
    <>
      <div className="border-b border-amber-300 bg-amber-50 dark:border-amber-900/60 dark:bg-amber-950/40">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-3 lg:flex-row lg:items-center lg:justify-between lg:px-6">
          <div className="flex min-w-0 items-start gap-3">
            <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-700 dark:text-amber-400" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-amber-950 dark:text-amber-100">
                {identityConflict
                  ? 'Possible device identity conflict'
                  : identityCandidate
                    ? 'Known device may have changed its private MAC'
                    : 'New device detected'}
                {pending.length > 1 ? ` (${pending.length} awaiting review)` : ''}
              </p>
              <p className="mt-0.5 text-xs text-amber-900/90 dark:text-amber-200/90">
                <span className="font-medium">{label}</span>{' '}
                <span className="font-mono">{active.ip} · {active.mac}</span>.{' '}
                {identityConflict
                  ? `Signals overlap with ${identityCandidate?.name}, but the identities conflict. EasyPi will not merge them automatically.`
                  : identityCandidate
                    ? `Possible match: ${identityCandidate.name}. Confirm only if this is the same physical device. Reconnecting transfers its saved rules.`
                  : 'Internet access is blocked until you allow it.'}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 gap-2 pl-8 lg:pl-0">
            <button
              type="button"
              onClick={() => blockMutation.mutate(active)}
              disabled={mutationPending}
              className="inline-flex items-center gap-2 rounded-lg border border-red-300 bg-white px-3 py-2 text-xs font-semibold text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:bg-black/10 dark:text-red-300"
            >
              <Ban className="h-4 w-4" />
              Block
            </button>
            {identityCandidate && identityCandidate.conflicts.length === 0 && (
              <button
                type="button"
                onClick={() => replaceMutation.mutate(active)}
                disabled={mutationPending}
                className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
              >
                <RotateCw className="h-4 w-4" />
                Reconnect as {identityCandidate.name}
              </button>
            )}
            <button
              type="button"
              onClick={() => openApproval(active)}
              disabled={mutationPending}
              className="inline-flex items-center gap-2 rounded-lg bg-green-600 px-3 py-2 text-xs font-semibold text-white hover:bg-green-700 disabled:opacity-50"
            >
              <Check className="h-4 w-4" />
              Add as new device
            </button>
          </div>
        </div>
      </div>

      {approvalDevice && (
        <div
          className="fixed inset-0 z-[70] flex items-center justify-center bg-black/55 p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !allowMutation.isPending) setApprovalDevice(null)
          }}
        >
          <form
            className="w-full max-w-lg rounded-xl bg-white shadow-2xl dark:bg-gray-900"
            onSubmit={(event) => {
              event.preventDefault()
              if (name.trim()) allowMutation.mutate(approvalDevice)
            }}
          >
            <div className="flex items-start justify-between border-b border-gray-200 p-4 dark:border-gray-700">
              <div>
                <h2 className="flex items-center gap-2 text-lg font-semibold text-gray-950 dark:text-white">
                  <Wifi className="h-5 w-5 text-green-600" />
                  Allow device
                </h2>
                <p className="mt-1 text-xs text-gray-500">The observed network identity cannot be edited.</p>
              </div>
              <button
                type="button"
                onClick={() => setApprovalDevice(null)}
                disabled={allowMutation.isPending}
                className="rounded-lg p-1.5 hover:bg-gray-100 disabled:opacity-50 dark:hover:bg-gray-800"
                aria-label="Close"
              >
                <X className="h-5 w-5 text-gray-500" />
              </button>
            </div>

            <div className="space-y-4 p-4">
              <div className="grid grid-cols-1 gap-3 rounded-lg bg-gray-50 p-3 text-sm dark:bg-gray-800 sm:grid-cols-2">
                <div>
                  <div className="text-xs text-gray-500">IP address</div>
                  <div className="font-mono text-gray-900 dark:text-gray-100">{approvalDevice.ip}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">MAC address</div>
                  <div className="font-mono text-gray-900 dark:text-gray-100">{approvalDevice.mac}</div>
                </div>
              </div>

              <label className="block">
                <span className="mb-1 block text-sm font-medium text-gray-800 dark:text-gray-200">Device name</span>
                <input
                  autoFocus
                  required
                  maxLength={64}
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-950 outline-none focus:border-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:text-white"
                />
              </label>

              <label className="block">
                <span className="mb-1 block text-sm font-medium text-gray-800 dark:text-gray-200">Access profile</span>
                <select
                  value={profile}
                  onChange={(event) => setProfile(event.target.value as DeviceAccessProfile['id'])}
                  className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-950 outline-none focus:border-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:text-white"
                >
                  {profiles.map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
                <p className="mt-1 text-xs text-gray-500">
                  {profiles.find((item) => item.id === profile)?.description || 'Standard EasyPi protection.'}
                </p>
              </label>

              <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-200">
                Allow creates one managed MAC+IP pair. MAC and IP admission is suitable for a trusted home LAN, but it is not cryptographic device authentication.
              </div>
            </div>

            <div className="flex justify-end gap-2 border-t border-gray-200 p-4 dark:border-gray-700">
              <button
                type="button"
                onClick={() => setApprovalDevice(null)}
                disabled={allowMutation.isPending}
                className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!name.trim() || allowMutation.isPending}
                className="inline-flex items-center gap-2 rounded-lg bg-green-600 px-4 py-2 text-sm font-semibold text-white hover:bg-green-700 disabled:opacity-50"
              >
                <Check className="h-4 w-4" />
                {allowMutation.isPending ? 'Activating…' : 'Allow device'}
              </button>
            </div>
          </form>
        </div>
      )}
    </>
  )
}
