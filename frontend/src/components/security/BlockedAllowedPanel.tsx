import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Ban, CheckCircle2, Globe, Info, Loader2, Radio, RefreshCw, ShieldCheck } from 'lucide-react'
import {
  getBlockedOverview,
  setDomainDecision,
  type AllowedDomain,
  type BlockedDomain,
  type BlockedPeriod,
  type ClassificationBasis,
} from '../../api/blockedOverview'
import { getAnalytics } from '../../api/analytics'
import { blockSourceStyle } from './blockSourceStyles'

const BASIS_HINT: Record<ClassificationBasis, string> = {
  reason: 'Sorted by the reason it was blocked',
  name: 'Sorted by its name',
  behavior: 'Sorted by when it was requested: on its own (opened) or right after another site (loaded by that page)',
}

const formatTime = (value: string) => {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function SourceBadge({ sourceKey, label }: { sourceKey: string; label: string }) {
  const style = blockSourceStyle(sourceKey)
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full ${style.color}`}>
      {style.emoji} {label}
    </span>
  )
}

function Section({
  title,
  subtitle,
  icon,
  count,
  children,
}: {
  title: string
  subtitle: string
  icon: React.ReactNode
  count: number
  children: React.ReactNode
}) {
  return (
    <section className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
      <header className="flex items-start gap-3 px-4 py-3 border-b border-gray-200 dark:border-gray-700">
        <div className="mt-0.5 shrink-0">{icon}</div>
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
            {title} <span className="text-gray-500 dark:text-gray-400 font-normal">({count})</span>
          </h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">{subtitle}</p>
        </div>
      </header>
      {children}
    </section>
  )
}

function Empty({ text }: { text: string }) {
  return <div className="px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400">{text}</div>
}

function BlockedRows({
  items,
  pending,
  onUnblock,
}: {
  items: BlockedDomain[]
  pending: string | null
  onUnblock: (domain: string) => void
}) {
  return (
    <div className="divide-y divide-gray-100 dark:divide-gray-700/60 max-h-[520px] overflow-y-auto">
      {items.map((item) => (
        <div key={item.domain} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
          <div className="min-w-0 flex-1">
            <div className="font-mono text-sm text-gray-900 dark:text-white truncate" title={item.domain}>
              {item.domain}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500 dark:text-gray-400">
              <SourceBadge sourceKey={item.source_key} label={item.source_label} />
              <span>
                {item.count}× · last {formatTime(item.last_seen)}
              </span>
              {item.devices.length > 0 && <span>· {item.devices.join(', ')}</span>}
              <span title={BASIS_HINT[item.basis]} className="inline-flex items-center gap-0.5 cursor-help">
                <Info className="w-3 h-3" />
              </span>
            </div>
          </div>
          <button
            onClick={() => onUnblock(item.domain)}
            disabled={pending === item.domain}
            className="inline-flex items-center gap-1 rounded-md bg-green-600 hover:bg-green-700 disabled:opacity-60 text-white text-xs font-medium px-2.5 py-1.5"
          >
            {pending === item.domain ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
            Unblock
          </button>
        </div>
      ))}
    </div>
  )
}

function AllowedRows({
  items,
  pending,
  onBlock,
}: {
  items: AllowedDomain[]
  pending: string | null
  onBlock: (domain: string) => void
}) {
  return (
    <div className="divide-y divide-gray-100 dark:divide-gray-700/60 max-h-[520px] overflow-y-auto">
      {items.map((item) => (
        <div key={item.domain} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
          <div className="min-w-0 flex-1">
            <div className="font-mono text-sm text-gray-900 dark:text-white truncate" title={item.domain}>
              {item.domain}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500 dark:text-gray-400">
              <span className="inline-flex items-center gap-1 px-2 py-0.5 font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300">
                ✅ Allowed in {item.source_label}
              </span>
              {item.added_at && <span>since {formatTime(item.added_at)}</span>}
            </div>
          </div>
          <button
            onClick={() => onBlock(item.domain)}
            disabled={pending === item.domain}
            className="inline-flex items-center gap-1 rounded-md bg-red-600 hover:bg-red-700 disabled:opacity-60 text-white text-xs font-medium px-2.5 py-1.5"
          >
            {pending === item.domain ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />}
            Block again
          </button>
        </div>
      ))}
    </div>
  )
}

export default function BlockedAllowedPanel() {
  const queryClient = useQueryClient()
  const [period, setPeriod] = useState<BlockedPeriod>('24h')
  const [clientId, setClientId] = useState('')
  const [pending, setPending] = useState<string | null>(null)

  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['blocked-overview', period, clientId],
    queryFn: () => getBlockedOverview(period, clientId || undefined),
    refetchInterval: 30000,
  })
  const { data: analytics } = useQuery({
    queryKey: ['blocked-overview-devices', period],
    queryFn: () => getAnalytics(period),
    staleTime: 60000,
  })

  const decide = useMutation({
    mutationFn: ({ domain, decision }: { domain: string; decision: 'allow' | 'block' }) =>
      setDomainDecision(domain, decision),
    onMutate: ({ domain }) => setPending(domain),
    onSuccess: (_result, { domain, decision }) => {
      toast.success(decision === 'allow' ? `${domain} unblocked` : `${domain} blocked again`)
      queryClient.invalidateQueries({ queryKey: ['blocked-overview'] })
    },
    onError: (error: any) => toast.error(error?.response?.data?.detail || 'The change could not be saved'),
    onSettled: () => setPending(null),
  })

  const unblock = (domain: string) => decide.mutate({ domain, decision: 'allow' })
  const blockAgain = (domain: string) => decide.mutate({ domain, decision: 'block' })

  return (
    <div className="space-y-4">
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 text-sm text-blue-800 dark:text-blue-200">
        Everything the network-wide protection blocked, sorted into sites someone tried to open and trackers that
        pages and apps load in the background. <strong>Unblock</strong> adds the exact host to your allowlist, which
        overrides every network-wide block. Parental controls, schedules and other device restrictions are not shown
        here and are never overridden.
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="inline-flex rounded-md border border-gray-200 dark:border-gray-700 overflow-hidden">
          {(['24h', '7d'] as BlockedPeriod[]).map((value) => (
            <button
              key={value}
              onClick={() => setPeriod(value)}
              className={`px-3 py-1.5 text-sm ${
                period === value
                  ? 'bg-blue-600 text-white'
                  : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
              }`}
            >
              {value}
            </button>
          ))}
        </div>
        <select
          value={clientId}
          onChange={(event) => setClientId(event.target.value)}
          className="rounded-md border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm text-gray-700 dark:text-gray-300 px-2 py-1.5"
        >
          <option value="">All devices</option>
          {(analytics?.devices ?? []).map((device) => (
            <option key={device.client_id} value={device.client_id}>
              {device.name}
            </option>
          ))}
        </select>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="p-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
          title="Refresh"
        >
          <RefreshCw className={`w-4 h-4 text-gray-500 ${isFetching ? 'animate-spin' : ''}`} />
        </button>
        {data?.truncated && (
          <span className="text-xs text-amber-600 dark:text-amber-400">
            Showing the newest {data.scanned_rows.toLocaleString()} requests of this period.
          </span>
        )}
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-gray-400" />
        </div>
      ) : isError ? (
        <Empty text="Blocked domains could not be loaded. Check that NetProtection is running." />
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Section
            title="Blocked sites"
            subtitle="Pages someone tried to open."
            icon={<Globe className="w-5 h-5 text-red-500" />}
            count={data?.sites.length ?? 0}
          >
            {data?.sites.length ? (
              <BlockedRows items={data.sites} pending={pending} onUnblock={unblock} />
            ) : (
              <Empty text="No sites were blocked in this period." />
            )}
          </Section>

          <Section
            title="Blocked trackers & background"
            subtitle="Ads, trackers and services that pages and apps load on their own — nothing to open."
            icon={<Radio className="w-5 h-5 text-fuchsia-500" />}
            count={data?.trackers.length ?? 0}
          >
            {data?.trackers.length ? (
              <BlockedRows items={data.trackers} pending={pending} onUnblock={unblock} />
            ) : (
              <Empty text="No trackers were blocked in this period." />
            )}
          </Section>

          <div className="xl:col-span-2">
            <Section
              title="Allowed by you"
              subtitle="Domains you allowed. They are never blocked by the network-wide protection."
              icon={<ShieldCheck className="w-5 h-5 text-green-500" />}
              count={data?.allowed.length ?? 0}
            >
              {data?.allowed.length ? (
                <AllowedRows items={data.allowed} pending={pending} onBlock={blockAgain} />
              ) : (
                <Empty text="You have not allowed any domains yet." />
              )}
            </Section>
          </div>
        </div>
      )}
    </div>
  )
}
