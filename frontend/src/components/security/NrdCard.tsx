import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { ShieldCheck, RefreshCw } from 'lucide-react'
import { getNrdStatus, setNrdConfig, refreshNrdFeed } from '../../api/nrd'

export default function NrdCard() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['nrd-status'], queryFn: getNrdStatus, refetchInterval: 30000 })
  const enabled = !!data?.enabled
  const ageWindow = data?.max_age_days ?? 14
  const feed = data?.feed_domains ?? 0

  const cfg = useMutation({
    mutationFn: setNrdConfig,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nrd-status'] })
      toast.success('NRD settings updated (NetProtection restarting…)')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed to update NRD'),
  })
  const refresh = useMutation({
    mutationFn: refreshNrdFeed,
    onSuccess: (r: any) => {
      qc.invalidateQueries({ queryKey: ['nrd-status'] })
      toast[r?.success ? 'success' : 'error'](r?.message || 'Feed refresh done')
    },
    onError: () => toast.error('Feed refresh failed'),
  })

  return (
    <div className="rounded-lg border border-rose-200 dark:border-rose-900/40 bg-white dark:bg-dark-900 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <ShieldCheck className="h-5 w-5 shrink-0 text-rose-500" />
        <div className="min-w-0">
          <div className="text-sm font-semibold text-gray-900 dark:text-white">
            🆕 Block newly-registered domains (NRD)
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            Catches fresh phishing/scam before it reaches blocklists. Feed: {feed.toLocaleString()} domains
            {data?.feed_updated_at
              ? ` · updated ${new Date(data.feed_updated_at).toLocaleDateString()}`
              : ' · not downloaded yet'}
          </div>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <select
            value={ageWindow}
            disabled={cfg.isPending}
            onChange={(e) => cfg.mutate({ max_age_days: Number(e.target.value) })}
            className="rounded-md border border-gray-300 dark:border-dark-700 bg-white dark:bg-dark-800 px-2 py-1 text-xs text-gray-900 dark:text-white disabled:opacity-50"
            title="Age window (days)"
          >
            <option value={7}>≤ 7 days</option>
            <option value={14}>≤ 14 days</option>
            <option value={30}>≤ 30 days</option>
          </select>
          <button
            onClick={() => refresh.mutate()}
            disabled={refresh.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-gray-300 dark:border-dark-700 px-2 py-1 text-xs text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-800 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refresh.isPending ? 'animate-spin' : ''}`} />
            Update feed
          </button>
          <button
            onClick={() => cfg.mutate({ enabled: !enabled })}
            disabled={cfg.isPending}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition ${enabled ? 'bg-rose-500' : 'bg-gray-300 dark:bg-gray-600'}`}
            title={enabled ? 'Disable NRD blocking' : 'Enable NRD blocking'}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${enabled ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>
      </div>
      {enabled && feed === 0 && (
        <div className="mt-2 text-xs text-amber-600 dark:text-amber-400">
          ⚠️ NRD is on but the feed is empty — click “Update feed” to download the list, otherwise nothing is blocked.
        </div>
      )}
    </div>
  )
}
