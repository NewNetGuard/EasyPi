import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import clsx from 'clsx'
import {
  AlertTriangle,
  BellRing,
  CheckCircle2,
  ClipboardList,
  ExternalLink,
  Eye,
  RefreshCw,
  Send,
  ShieldAlert,
} from 'lucide-react'

import Badge from '../components/common/Badge'
import Button from '../components/common/Button'
import Card from '../components/common/Card'
import OverviewStat from '../components/common/OverviewStat'
import { listInbox, type InboxItem, type InboxSeverity } from '../api/inbox'

type InboxFilter = 'all' | 'attention' | 'jobs' | 'security' | 'push' | 'watchdog'

const severityBadge: Record<
  InboxSeverity,
  { label: string; color: 'primary' | 'success' | 'warning' | 'danger' | 'gray'; dot?: boolean }
> = {
  critical: { label: 'Critical', color: 'danger', dot: true },
  warning: { label: 'Warning', color: 'warning', dot: true },
  success: { label: 'Resolved', color: 'success' },
  info: { label: 'Info', color: 'primary', dot: true },
}

const severityAccent: Record<InboxSeverity, string> = {
  critical: 'border-l-red-500',
  warning: 'border-l-amber-500',
  success: 'border-l-emerald-500',
  info: 'border-l-sky-500',
}

const sourceMeta: Record<InboxItem['source'], { label: string; icon: typeof ClipboardList }> = {
  jobs: { label: 'Jobs Center', icon: ClipboardList },
  security: { label: 'Security', icon: ShieldAlert },
  push: { label: 'Push Notifications', icon: Send },
  watchdog: { label: 'Watchdog', icon: Eye },
}

const formatRelativeDate = (date: Date) => {
  const delta = Date.now() - date.getTime()
  const minutes = Math.round(delta / 60000)
  if (minutes < 1) {
    return 'just now'
  }
  if (minutes < 60) {
    return `${minutes}m ago`
  }
  const hours = Math.round(minutes / 60)
  if (hours < 24) {
    return `${hours}h ago`
  }
  const days = Math.round(hours / 24)
  return `${days}d ago`
}

const formatTimestamp = (value?: string | null) => {
  if (!value) {
    return 'Unknown'
  }
  const isoDate = new Date(value)
  if (!Number.isNaN(isoDate.getTime())) {
    return isoDate.toLocaleString()
  }
  return value
}

const relativeTime = (value?: string | null) => {
  if (!value) {
    return null
  }

  const isoDate = new Date(value)
  if (!Number.isNaN(isoDate.getTime())) {
    return formatRelativeDate(isoDate)
  }

  const parsed = new Date(`${new Date().getFullYear()} ${value}`)
  if (!Number.isNaN(parsed.getTime())) {
    return formatRelativeDate(parsed)
  }

  return null
}

export default function Notifications() {
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedFilter = searchParams.get('tab')
  const filter: InboxFilter = ['attention', 'jobs', 'security', 'push', 'watchdog'].includes(requestedFilter || '')
    ? requestedFilter as InboxFilter
    : 'all'
  const setFilter = (nextFilter: InboxFilter) => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', nextFilter)
    setSearchParams(next, { replace: true })
  }
  const {
    data,
    isLoading,
    isFetching,
    error,
    refetch,
  } = useQuery({
    queryKey: ['notification-inbox'],
    queryFn: () => listInbox(80),
    refetchInterval: 10000,
  })

  const summary = data?.summary ?? {
    total: 0,
    action_required: 0,
    critical: 0,
    warning: 0,
    success: 0,
    info: 0,
    jobs: 0,
    security: 0,
    push: 0,
    watchdog: 0,
  }

  const items = useMemo(() => data?.items ?? [], [data?.items])

  const filteredItems = useMemo(() => {
    switch (filter) {
      case 'attention':
        return items.filter((item) => item.severity === 'critical' || item.severity === 'warning')
      case 'jobs':
        return items.filter((item) => item.source === 'jobs')
      case 'security':
        return items.filter((item) => item.source === 'security')
      case 'push':
        return items.filter((item) => item.source === 'push')
      case 'watchdog':
        return items.filter((item) => item.source === 'watchdog')
      default:
        return items
    }
  }, [filter, items])

  const filterChips: Array<{ id: InboxFilter; label: string; count: number }> = [
    { id: 'all', label: 'All', count: summary.total },
    { id: 'attention', label: 'Needs attention', count: summary.action_required },
    { id: 'jobs', label: 'Jobs', count: summary.jobs },
    { id: 'security', label: 'Security', count: summary.security },
    { id: 'watchdog', label: 'Watchdog', count: summary.watchdog },
    { id: 'push', label: 'Push', count: summary.push },
  ]

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-2xl bg-primary-100 p-3 dark:bg-primary-900/30">
            <BellRing className="h-6 w-6 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Notification Inbox</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              A calmer view of jobs, security signals, rollback activity, and push delivery history.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Link to="/settings?tab=notifications">
            <Button variant="outline" size="sm">Notification Settings</Button>
          </Link>
          <Button
            variant="outline"
            size="sm"
            icon={<RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />}
            onClick={() => refetch()}
            loading={isFetching && !isLoading}
          >
            Refresh
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <OverviewStat label="Total events" value={summary.total} hint="Recent activity" tone="primary" icon={BellRing} />
        <OverviewStat
          label="Needs attention"
          value={summary.action_required}
          hint="Critical or warning items"
          tone="danger"
          icon={AlertTriangle}
        />
        <OverviewStat label="Jobs & services" value={summary.jobs} hint="Operational events" tone="warning" icon={ClipboardList} />
        <OverviewStat label="Security" value={summary.security} hint="Audit and protection" tone="success" icon={ShieldAlert} />
      </div>

      <Card
        title="Inbox Feed"
        subtitle="Recent signals from jobs, security, rollback activity, and delivery status."
      >
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 animate-spin text-primary-500" />
          </div>
        ) : error ? (
          <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-900/10 dark:text-red-300">
            Failed to load Notification Inbox.
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap gap-2">
                {filterChips.map((chip) => (
                  <button
                    key={chip.id}
                    type="button"
                    onClick={() => setFilter(chip.id)}
                    className={`rounded-full px-3 py-1.5 text-sm font-medium transition ${
                      filter === chip.id
                        ? 'bg-primary-600 text-white'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-800 dark:text-gray-300 dark:hover:bg-dark-700'
                    }`}
                  >
                    {chip.label} <span className="ml-1 opacity-80">{chip.count}</span>
                  </button>
                ))}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Showing {filteredItems.length} of {items.length}
              </div>
            </div>

            {filteredItems.length === 0 ? (
              <div className="rounded-xl border border-dashed border-gray-300 p-10 text-center dark:border-dark-700">
                <BellRing className="mx-auto h-10 w-10 text-gray-300 dark:text-gray-600" />
                <h2 className="mt-3 text-lg font-semibold text-gray-900 dark:text-white">Inbox is quiet</h2>
                <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                  When jobs, admin actions, snapshots, security events, or push deliveries happen, they will appear here.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {filteredItems.map((item) => {
                  const badge = severityBadge[item.severity]
                  const source = sourceMeta[item.source] ?? {
                    label: item.source_label || item.source,
                    icon: BellRing,
                  }
                  const SourceIcon = source.icon
                  const when = relativeTime(item.timestamp)

                  return (
                    <div
                      key={item.event_id}
                      className={clsx(
                        'rounded-2xl border border-gray-200 border-l-4 bg-white p-5 shadow-sm dark:border-dark-700 dark:bg-dark-900',
                        severityAccent[item.severity]
                      )}
                    >
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <SourceIcon className="h-4 w-4 text-gray-500 dark:text-gray-400" />
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{item.title}</h3>
                            <Badge color={badge.color} dot={badge.dot}>
                              {badge.label}
                            </Badge>
                            <Badge color="gray">{item.source_label || source.label}</Badge>
                          </div>
                          <p className="mt-3 text-sm leading-6 text-gray-600 dark:text-gray-300">{item.message}</p>
                        </div>

                        {item.route && (
                          <Link
                            to={item.route}
                            className="inline-flex items-center gap-2 rounded-xl border border-gray-200 px-3 py-2 text-sm font-medium text-gray-700 transition hover:bg-gray-50 dark:border-dark-700 dark:text-gray-300 dark:hover:bg-dark-800"
                          >
                            Open Section
                            <ExternalLink className="h-4 w-4" />
                          </Link>
                        )}
                      </div>

                      <div className="mt-4 flex flex-wrap items-center gap-3 text-sm text-gray-500 dark:text-gray-400">
                        <span>{formatTimestamp(item.timestamp)}</span>
                        {when && <span>• {when}</span>}
                        {(item.severity === 'critical' || item.severity === 'warning') && (
                          <span className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-300">
                            <AlertTriangle className="h-4 w-4" />
                            Review recommended
                          </span>
                        )}
                        {item.severity === 'success' && (
                          <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-300">
                            <CheckCircle2 className="h-4 w-4" />
                            Resolved
                          </span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
