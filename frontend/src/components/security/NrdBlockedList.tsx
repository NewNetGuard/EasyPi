import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Check, ExternalLink, ShieldOff, RefreshCw } from 'lucide-react'
import { getNrdBlocked } from '../../api/nrd'
import { addToWhitelist } from '../../api/guardSecurity'

export default function NrdBlockedList() {
  const { data, isFetching, refetch } = useQuery({
    queryKey: ['nrd-blocked'],
    queryFn: () => getNrdBlocked(60),
    refetchInterval: 8000,
  })
  const [allowed, setAllowed] = useState<Set<string>>(new Set())
  const domains = data?.domains ?? []

  const allow = useMutation({
    mutationFn: (domain: string) =>
      addToWhitelist({ domain, type: 'exact', comment: 'Allowed from New-Domain Guard' } as any),
    onSuccess: (_r, domain) => {
      setAllowed((prev) => new Set(prev).add(domain))
      toast.success(`${domain} allowed`)
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed to allow'),
  })

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-700">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Recently blocked as newly-registered</h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Fresh domains a device tried to reach. Look one up (↗ whois) and allow any you trust.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="p-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 shrink-0"
          title="Refresh"
        >
          <RefreshCw className={`w-4 h-4 text-gray-500 ${isFetching ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {domains.length === 0 ? (
        <div className="px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400">
          No newly-registered domains blocked yet. Turn NRD on and update the feed — blocks will appear here.
        </div>
      ) : (
        <div className="divide-y divide-gray-100 dark:divide-gray-700/60 max-h-[420px] overflow-y-auto">
          {domains.map((d) => {
            const isAllowed = allowed.has(d.domain)
            return (
              <div key={d.domain} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                <span className="rounded-full bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300 text-[11px] px-1.5 py-0.5">
                  🆕 New
                </span>
                <span className="font-mono text-sm text-gray-900 dark:text-white truncate max-w-[240px]" title={d.domain}>
                  {d.domain}
                </span>
                <a
                  href={`https://who.is/whois/${encodeURIComponent(d.domain)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-gray-400 hover:text-blue-500"
                  title="Look up registration (whois)"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
                <div className="ml-auto flex items-center gap-3">
                  <span className="hidden text-xs text-gray-400 sm:inline">
                    {d.client || ''}
                    {d.time ? ` · ${new Date(d.time).toLocaleTimeString()}` : ''}
                  </span>
                  {isAllowed ? (
                    <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                      <Check className="w-3.5 h-3.5" />
                      Allowed
                    </span>
                  ) : (
                    <button
                      onClick={() => allow.mutate(d.domain)}
                      disabled={allow.isPending}
                      className="inline-flex items-center gap-1 rounded-md border border-emerald-300 dark:border-emerald-800 px-2 py-1 text-xs text-emerald-700 dark:text-emerald-300 hover:bg-emerald-50 dark:hover:bg-emerald-900/20 disabled:opacity-50"
                      title="Allow this domain (add to allowlist)"
                    >
                      <ShieldOff className="w-3.5 h-3.5" />
                      Allow
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
