import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ChevronDown, ChevronUp, Globe, ShieldAlert } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { getFailClosedStatus, restoreFailClosedInternetByIp } from '../../api/guardSecurity'

export default function FailClosedBanner() {
  const queryClient = useQueryClient()
  const [expanded, setExpanded] = useState(false)

  const { data, isFetching } = useQuery({
    queryKey: ['fail-closed-status'],
    queryFn: getFailClosedStatus,
    staleTime: 0,
    refetchInterval: 2000,
  })

  const devices = useMemo(() => (data?.devices || []).filter(Boolean), [data])

  const restoreMutation = useMutation({
    mutationFn: (ip: string) => restoreFailClosedInternetByIp(ip),
    onSuccess: () => {
      toast.success('Internet access restored')
      queryClient.invalidateQueries({ queryKey: ['fail-closed-status'] })
      queryClient.invalidateQueries({ queryKey: ['parental-clients'] })
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.detail || 'Failed to restore internet'
      toast.error(String(detail))
    },
  })

  if (!devices.length) return null

  const title = devices.length === 1 ? 'Internet blocked for 1 device' : `Internet blocked for ${devices.length} devices`

  return (
    <div className="border-b border-red-200 dark:border-red-900/40 bg-red-50 dark:bg-red-900/20">
      <div className="mx-auto max-w-7xl px-4 lg:px-6 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="mt-0.5">
              <ShieldAlert className="h-5 w-5 text-red-600 dark:text-red-400" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <p className="text-sm font-semibold text-red-900 dark:text-red-100 truncate">{title}</p>
                {isFetching && <span className="text-xs text-red-700/80 dark:text-red-200/70">syncing...</span>}
              </div>
              <p className="text-xs text-red-800/90 dark:text-red-200/80">
                Fail-Closed mode activated after a bypass attempt (VPN / Encrypted DNS / proxy / Tor). Restore access after you disable the bypass.
              </p>
              <div className="mt-1 text-xs">
                <a
                  href="/help?guide=guide-parental-controls"
                  className="underline underline-offset-2 text-red-800 hover:text-red-950 dark:text-red-200 dark:hover:text-white"
                >
                  How this works
                </a>
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="shrink-0 inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-medium bg-white/60 hover:bg-white/80 dark:bg-black/10 dark:hover:bg-black/20 text-red-900 dark:text-red-100 border border-red-200/70 dark:border-red-900/40"
          >
            <AlertTriangle className="h-4 w-4" />
            {expanded ? 'Hide' : 'Details'}
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </div>

        {expanded && (
          <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2">
            {devices.map((d) => (
              <div
                key={d.ip}
                className="flex items-start justify-between gap-3 rounded-lg border border-red-200/70 dark:border-red-900/40 bg-white/60 dark:bg-black/10 px-3 py-2"
              >
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-red-950 dark:text-red-100 truncate">{d.name || d.ip}</div>
                  <div className="text-xs font-mono text-red-900/80 dark:text-red-200/70">{d.ip}</div>
                  {(d.domain || d.group_label || d.triggered_at) && (
                    <div className="mt-1 text-xs text-red-900/80 dark:text-red-200/80">
                      {d.group_label ? <span className="font-medium">{d.group_label}</span> : <span className="font-medium">Bypass</span>}
                      {d.domain ? <span className="ml-2 font-mono">{d.domain}</span> : null}
                      {d.triggered_at ? <span className="ml-2 opacity-80">{new Date(d.triggered_at).toLocaleString()}</span> : null}
                    </div>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => restoreMutation.mutate(d.ip)}
                  disabled={restoreMutation.isPending}
                  className="shrink-0 inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold bg-green-600 hover:bg-green-700 text-white disabled:opacity-50"
                  title="Restore Internet"
                >
                  <Globe className="h-4 w-4" />
                  Restore
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
