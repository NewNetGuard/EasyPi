import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  Clock3,
  ExternalLink,
  RefreshCw,
} from 'lucide-react'

import Badge from '../components/common/Badge'
import Button from '../components/common/Button'
import Card from '../components/common/Card'
import OverviewStat from '../components/common/OverviewStat'
import ProgressBar from '../components/common/ProgressBar'
import { listJobs, type JobRecord, type JobStatus } from '../api/jobs'

type JobFilter = 'all' | 'active' | 'attention' | 'completed'

const statusBadge: Record<
  JobStatus,
  { label: string; color: 'primary' | 'success' | 'warning' | 'danger' | 'gray'; dot?: boolean }
> = {
  queued: { label: 'Queued', color: 'gray', dot: true },
  running: { label: 'Running', color: 'warning', dot: true },
  success: { label: 'Completed', color: 'success' },
  failed: { label: 'Failed', color: 'danger' },
  cancelled: { label: 'Cancelled', color: 'gray' },
  unknown: { label: 'Unknown', color: 'gray' },
}

const sourceLabel: Record<JobRecord['source'], string> = {
  installer: 'Installer job',
  backup: 'Backup job',
  rollback: 'Safe snapshot',
  action: 'Admin action',
}

const formatTimestamp = (value?: string | null) => {
  if (!value) {
    return 'Unknown'
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString()
}

const relativeTime = (value?: string | null) => {
  if (!value) {
    return null
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return null
  }
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

export default function Jobs() {
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedFilter = searchParams.get('tab')
  const filter: JobFilter = ['active', 'attention', 'completed'].includes(requestedFilter || '')
    ? requestedFilter as JobFilter
    : 'all'
  const setFilter = (nextFilter: JobFilter) => {
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
    queryKey: ['jobs-center'],
    queryFn: () => listJobs(50),
    refetchInterval: 8000,
  })

  const jobs = useMemo(() => data?.jobs ?? [], [data?.jobs])
  const summary = data?.summary ?? {
    total: 0,
    running: 0,
    queued: 0,
    success: 0,
    failed: 0,
    cancelled: 0,
    unknown: 0,
  }

  const activeJobs = useMemo(
    () => jobs.filter((job) => job.status === 'running' || job.status === 'queued'),
    [jobs]
  )

  const filteredJobs = useMemo(() => {
    switch (filter) {
      case 'active':
        return jobs.filter((job) => job.status === 'running' || job.status === 'queued')
      case 'attention':
        return jobs.filter(
          (job) => job.status === 'failed' || job.status === 'cancelled' || job.status === 'unknown'
        )
      case 'completed':
        return jobs.filter((job) => job.status === 'success')
      default:
        return jobs
    }
  }, [filter, jobs])

  const filterChips: Array<{ id: JobFilter; label: string; count: number }> = [
    { id: 'all', label: 'All', count: summary.total },
    { id: 'active', label: 'Active', count: summary.running + summary.queued },
    {
      id: 'attention',
      label: 'Needs attention',
      count: summary.failed + summary.cancelled + summary.unknown,
    },
    { id: 'completed', label: 'Completed', count: summary.success },
  ]

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-2xl bg-primary-100 p-3 dark:bg-primary-900/30">
            <ClipboardList className="h-6 w-6 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Jobs Center</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Follow installs, updates, backups, snapshots, and admin actions from one place.
            </p>
          </div>
        </div>

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

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <OverviewStat label="Total jobs" value={summary.total} hint="Recorded by EasyPi" tone="primary" icon={ClipboardList} />
        <OverviewStat
          label="Active"
          value={summary.running + summary.queued}
          hint="Still running or queued"
          tone="warning"
          icon={Clock3}
        />
        <OverviewStat label="Completed" value={summary.success} hint="Finished successfully" tone="success" icon={CheckCircle2} />
        <OverviewStat
          label="Needs attention"
          value={summary.failed + summary.cancelled + summary.unknown}
          hint="Failed, cancelled, or unclear"
          tone="danger"
          icon={AlertTriangle}
        />
      </div>

      <Card
        title="Background Operations"
        subtitle="Track what EasyPi is doing now, then jump directly to the affected section when needed."
      >
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 animate-spin text-primary-500" />
          </div>
        ) : error ? (
          <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-900/10 dark:text-red-300">
            Failed to load Jobs Center.
          </div>
        ) : jobs.length === 0 ? (
          <div className="rounded-xl border border-dashed border-gray-300 p-10 text-center dark:border-dark-700">
            <ClipboardList className="mx-auto h-10 w-10 text-gray-300 dark:text-gray-600" />
            <h2 className="mt-3 text-lg font-semibold text-gray-900 dark:text-white">No jobs yet</h2>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              When EasyPi runs an installer, backup, snapshot, or important admin action, it will show up here.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {activeJobs.length > 0 && (
              <div className="rounded-2xl border border-primary-200 bg-primary-50/70 p-4 dark:border-primary-900/40 dark:bg-primary-900/10">
                <div className="flex items-center gap-2 text-sm font-semibold text-primary-700 dark:text-primary-300">
                  <Clock3 className="h-4 w-4" />
                  {activeJobs.length} active {activeJobs.length === 1 ? 'job' : 'jobs'}
                </div>
                <p className="mt-1 text-sm text-primary-700/80 dark:text-primary-300/80">
                  This list refreshes automatically while background work is still in progress.
                </p>
              </div>
            )}

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
                Showing {filteredJobs.length} of {jobs.length}
              </div>
            </div>

            {filteredJobs.length === 0 ? (
              <div className="rounded-xl border border-dashed border-gray-300 p-10 text-center dark:border-dark-700">
                <ClipboardList className="mx-auto h-10 w-10 text-gray-300 dark:text-gray-600" />
                <h2 className="mt-3 text-lg font-semibold text-gray-900 dark:text-white">Nothing in this view</h2>
                <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                  Try another filter to see active work, completed jobs, or items that need attention.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {filteredJobs.map((job) => {
                  const badge = statusBadge[job.status]
                  const showProgress =
                    typeof job.progress === 'number' && job.progress > 0 && job.status === 'running'
                  const lastUpdated = relativeTime(job.updated_at)

                  return (
                    <div
                      key={job.job_id}
                      className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm dark:border-dark-700 dark:bg-dark-900"
                    >
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{job.title}</h3>
                            <Badge color={badge.color} dot={badge.dot}>
                              {badge.label}
                            </Badge>
                            <Badge color="gray">{sourceLabel[job.source]}</Badge>
                          </div>
                          {job.subtitle && (
                            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">{job.subtitle}</p>
                          )}
                        </div>

                        {job.route && (
                          <Link
                            to={job.route}
                            className="inline-flex items-center gap-2 rounded-xl border border-gray-200 px-3 py-2 text-sm font-medium text-gray-700 transition hover:bg-gray-50 dark:border-dark-700 dark:text-gray-300 dark:hover:bg-dark-800"
                          >
                            Open Section
                            <ExternalLink className="h-4 w-4" />
                          </Link>
                        )}
                      </div>

                      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                        <div className="rounded-xl bg-gray-50 p-3 text-sm dark:bg-dark-800">
                          <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Started</div>
                          <div className="mt-1 font-medium text-gray-900 dark:text-white">
                            {formatTimestamp(job.started_at)}
                          </div>
                        </div>
                        <div className="rounded-xl bg-gray-50 p-3 text-sm dark:bg-dark-800">
                          <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Updated</div>
                          <div className="mt-1 font-medium text-gray-900 dark:text-white">
                            {lastUpdated
                              ? `${formatTimestamp(job.updated_at)} (${lastUpdated})`
                              : formatTimestamp(job.updated_at)}
                          </div>
                        </div>
                        <div className="rounded-xl bg-gray-50 p-3 text-sm dark:bg-dark-800 xl:col-span-1 md:col-span-2">
                          <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Job ID</div>
                          <div className="mt-1 break-all font-mono text-xs text-gray-900 dark:text-white">
                            {job.job_id}
                          </div>
                        </div>
                      </div>

                      {job.message && (
                        <div className="mt-4 flex items-start gap-2 rounded-xl border border-gray-200 bg-gray-50 p-3 text-sm text-gray-700 dark:border-dark-700 dark:bg-dark-800 dark:text-gray-300">
                          {job.status === 'failed' || job.status === 'unknown' ? (
                            <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-500" />
                          ) : (
                            <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-primary-500" />
                          )}
                          <span>{job.message}</span>
                        </div>
                      )}

                      {showProgress && (
                        <div className="mt-4">
                          <ProgressBar
                            progress={job.progress ?? 0}
                            label="Reported progress"
                            showPercentage
                            color="warning"
                          />
                        </div>
                      )}

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
