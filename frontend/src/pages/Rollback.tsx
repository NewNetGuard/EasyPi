import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  Download,
  Info,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { toast } from 'react-hot-toast'

import Badge from '../components/common/Badge'
import Button from '../components/common/Button'
import Card from '../components/common/Card'
import Input from '../components/common/Input'
import Modal from '../components/common/Modal'
import OverviewStat from '../components/common/OverviewStat'
import ActionPreviewPanel from '../features/actions/ActionPreviewPanel'
import { getActionPreview } from '../api/actionPreview'
import {
  createRollbackSnapshot,
  deleteRollbackSnapshot,
  getRollbackDownloadUrl,
  listRollbackSnapshots,
  restoreRollbackSnapshot,
  type RollbackSnapshotRecord,
  type RollbackStatus,
} from '../api/rollback'

const statusBadge: Record<
  RollbackStatus,
  { label: string; color: 'primary' | 'success' | 'warning' | 'danger' | 'gray'; dot?: boolean }
> = {
  creating: { label: 'Creating', color: 'warning', dot: true },
  ready: { label: 'Ready', color: 'success' },
  failed: { label: 'Failed', color: 'danger' },
  restoring: { label: 'Restoring', color: 'warning', dot: true },
  'restore-failed': { label: 'Restore failed', color: 'danger' },
}

const formatDate = (value?: string | null) => {
  if (!value) {
    return 'Unknown'
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString()
}

const formatSize = (size?: number | null) => {
  if (!size) {
    return 'Unknown'
  }
  const units = ['B', 'KB', 'MB', 'GB']
  let index = 0
  let current = size
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024
    index += 1
  }
  return `${current.toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

export default function Rollback() {
  const queryClient = useQueryClient()
  const [snapshotName, setSnapshotName] = useState('')
  const [snapshotReason, setSnapshotReason] = useState('')
  const [restoreTarget, setRestoreTarget] = useState<RollbackSnapshotRecord | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<RollbackSnapshotRecord | null>(null)

  const {
    data,
    isLoading,
    isFetching,
    error,
    refetch,
  } = useQuery({
    queryKey: ['rollback-snapshots'],
    queryFn: () => listRollbackSnapshots(50),
    refetchInterval: 10000,
  })

  const snapshots = useMemo(() => data?.snapshots ?? [], [data?.snapshots])
  const summary = data?.summary ?? {
    total: 0,
    ready: 0,
    active: 0,
    failed: 0,
  }

  const createMutation = useMutation({
    mutationFn: createRollbackSnapshot,
    onSuccess: (response) => {
      toast.success(response.message || 'Safe snapshot started')
      setSnapshotName('')
      setSnapshotReason('')
      queryClient.invalidateQueries({ queryKey: ['rollback-snapshots'] })
      queryClient.invalidateQueries({ queryKey: ['notification-inbox'] })
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to create safe snapshot')
    },
  })

  const restoreMutation = useMutation({
    mutationFn: restoreRollbackSnapshot,
    onSuccess: (response) => {
      toast.success(response.message || 'Rollback restore started')
      setRestoreTarget(null)
      queryClient.invalidateQueries({ queryKey: ['rollback-snapshots'] })
      queryClient.invalidateQueries({ queryKey: ['notification-inbox'] })
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to start rollback restore')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deleteRollbackSnapshot,
    onSuccess: (response) => {
      toast.success(response.message || 'Snapshot deleted')
      setDeleteTarget(null)
      queryClient.invalidateQueries({ queryKey: ['rollback-snapshots'] })
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to delete snapshot')
    },
  })

  const activeSnapshots = useMemo(
    () => snapshots.filter((snapshot) => snapshot.status === 'creating' || snapshot.status === 'restoring'),
    [snapshots]
  )

  const restorePreviewQuery = useQuery({
    queryKey: ['action-preview', 'rollback.restore', restoreTarget?.snapshot_id],
    queryFn: () => getActionPreview('rollback.restore', restoreTarget?.snapshot_id ?? ''),
    enabled: Boolean(restoreTarget?.snapshot_id),
  })

  const deletePreviewQuery = useQuery({
    queryKey: ['action-preview', 'rollback.delete', deleteTarget?.snapshot_id],
    queryFn: () => getActionPreview('rollback.delete', deleteTarget?.snapshot_id ?? ''),
    enabled: Boolean(deleteTarget?.snapshot_id),
  })

  const handleCreateSnapshot = () => {
    const trimmedName = snapshotName.trim()
    const trimmedReason = snapshotReason.trim()
    createMutation.mutate({
      name: trimmedName || undefined,
      reason: trimmedReason || undefined,
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-2xl bg-primary-100 p-3 dark:bg-primary-900/30">
            <RotateCcw className="h-6 w-6 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Rollback Center</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Create clean restore points before risky changes, then roll back with confidence if needed.
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
        <OverviewStat label="Total snapshots" value={summary.total} hint="Saved restore points" tone="primary" icon={RotateCcw} />
        <OverviewStat label="Ready" value={summary.ready} hint="Available to restore or download" tone="success" icon={ShieldCheck} />
        <OverviewStat label="Active" value={summary.active} hint="Still creating or restoring" tone="warning" icon={RefreshCw} />
        <OverviewStat label="Failed" value={summary.failed} hint="Needs review before reuse" tone="danger" icon={AlertTriangle} />
      </div>

      <Card
        title="Create Safe Snapshot"
        subtitle="Capture the current EasyPi configuration before you change DNS, VPN, security, or other system settings."
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Input
            label="Snapshot name (optional)"
            placeholder="Example: Before VPN changes"
            value={snapshotName}
            onChange={(event) => setSnapshotName(event.target.value)}
            helperText="Letters, numbers, spaces, underscores, and dashes only."
          />
          <Input
            label="Reason (optional)"
            placeholder="Example: Before changing Personal DNS"
            value={snapshotReason}
            onChange={(event) => setSnapshotReason(event.target.value)}
            helperText="This helps you remember why the snapshot exists."
          />
          <div className="flex items-end">
            <Button
              className="w-full"
              icon={<ShieldCheck className="h-4 w-4" />}
              onClick={handleCreateSnapshot}
              loading={createMutation.isPending}
            >
              Create Safe Snapshot
            </Button>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
          <div className="rounded-xl border border-blue-200 bg-blue-50 p-3 text-sm text-blue-900 dark:border-blue-900/40 dark:bg-blue-900/10 dark:text-blue-100">
            <div className="flex items-start gap-2">
              <Info className="mt-0.5 h-4 w-4 flex-shrink-0" />
              <div>
                <div className="font-semibold">Why create one now?</div>
                <div className="mt-1 text-blue-900/90 dark:text-blue-100/90">
                  A safe snapshot gives you a known-good point before making a change that could affect access or services.
                </div>
              </div>
            </div>
          </div>
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900/40 dark:bg-amber-900/10 dark:text-amber-100">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
              <div>
                <div className="font-semibold">Restore carefully</div>
                <div className="mt-1 text-amber-900/90 dark:text-amber-100/90">
                  Restoring a snapshot overwrites current configuration files, so use it only when you really want to roll back.
                </div>
              </div>
            </div>
          </div>
        </div>
      </Card>

      <Card
        title="Available Snapshots"
        subtitle="Restore a known-good config state or download a copy for safekeeping."
      >
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 animate-spin text-primary-500" />
          </div>
        ) : error ? (
          <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-900/10 dark:text-red-300">
            Failed to load Rollback Center.
          </div>
        ) : snapshots.length === 0 ? (
          <div className="rounded-xl border border-dashed border-gray-300 p-10 text-center dark:border-dark-700">
            <RotateCcw className="mx-auto h-10 w-10 text-gray-300 dark:text-gray-600" />
            <h2 className="mt-3 text-lg font-semibold text-gray-900 dark:text-white">No snapshots yet</h2>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              Create your first safe snapshot before making a risky configuration change.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {activeSnapshots.length > 0 && (
              <div className="rounded-2xl border border-primary-200 bg-primary-50/70 p-4 dark:border-primary-900/40 dark:bg-primary-900/10">
                <div className="flex items-center gap-2 text-sm font-semibold text-primary-700 dark:text-primary-300">
                  <RotateCcw className="h-4 w-4" />
                  {activeSnapshots.length} active{' '}
                  {activeSnapshots.length === 1 ? 'snapshot operation' : 'snapshot operations'}
                </div>
                <p className="mt-1 text-sm text-primary-700/80 dark:text-primary-300/80">
                  This list refreshes automatically while snapshot work is still running.
                </p>
              </div>
            )}

            {snapshots.map((snapshot) => {
              const badge = statusBadge[snapshot.status]
              const busy = snapshot.status === 'creating' || snapshot.status === 'restoring'
              return (
                <div
                  key={snapshot.snapshot_id}
                  className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm dark:border-dark-700 dark:bg-dark-900"
                >
                  <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{snapshot.name}</h3>
                        <Badge color={badge.color} dot={badge.dot}>
                          {badge.label}
                        </Badge>
                      </div>
                      {snapshot.reason && (
                        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">{snapshot.reason}</p>
                      )}
                    </div>

                    <div className="flex flex-wrap gap-2">
                      {snapshot.archive_path && (
                        <a href={getRollbackDownloadUrl(snapshot.snapshot_id)} download>
                          <Button variant="outline" size="sm" icon={<Download className="h-4 w-4" />}>
                            Download
                          </Button>
                        </a>
                      )}
                      <Button
                        variant="outline"
                        size="sm"
                        icon={<RotateCcw className="h-4 w-4" />}
                        onClick={() => setRestoreTarget(snapshot)}
                        disabled={busy || !snapshot.archive_path}
                      >
                        Restore
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        icon={<Trash2 className="h-4 w-4" />}
                        onClick={() => setDeleteTarget(snapshot)}
                        disabled={busy}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-xl bg-gray-50 p-3 text-sm dark:bg-dark-800">
                      <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Created</div>
                      <div className="mt-1 font-medium text-gray-900 dark:text-white">{formatDate(snapshot.created_at)}</div>
                    </div>
                    <div className="rounded-xl bg-gray-50 p-3 text-sm dark:bg-dark-800">
                      <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Updated</div>
                      <div className="mt-1 font-medium text-gray-900 dark:text-white">{formatDate(snapshot.updated_at)}</div>
                    </div>
                    <div className="rounded-xl bg-gray-50 p-3 text-sm dark:bg-dark-800">
                      <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Archive size</div>
                      <div className="mt-1 font-medium text-gray-900 dark:text-white">{formatSize(snapshot.size_bytes)}</div>
                    </div>
                    <div className="rounded-xl bg-gray-50 p-3 text-sm dark:bg-dark-800">
                      <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Last restored</div>
                      <div className="mt-1 font-medium text-gray-900 dark:text-white">
                        {snapshot.last_restored_at ? formatDate(snapshot.last_restored_at) : 'Never'}
                      </div>
                    </div>
                  </div>

                  {snapshot.error_message && (
                    <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-900/10 dark:text-red-300">
                      {snapshot.error_message}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </Card>

      <Modal
        isOpen={Boolean(restoreTarget)}
        onClose={() => setRestoreTarget(null)}
        title="Restore Safe Snapshot"
        footer={
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setRestoreTarget(null)}>Cancel</Button>
            <Button
              variant="danger"
              icon={<RotateCcw className="h-4 w-4" />}
              onClick={() => restoreTarget && restoreMutation.mutate(restoreTarget.snapshot_id)}
              loading={restoreMutation.isPending}
            >
              Restore Snapshot
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Restore <span className="font-semibold text-gray-900 dark:text-white">{restoreTarget?.name}</span> to overwrite
            the current config with this saved state.
          </p>
          <ActionPreviewPanel
            preview={restorePreviewQuery.data}
            isLoading={restorePreviewQuery.isLoading || restorePreviewQuery.isFetching}
            errorMessage={restorePreviewQuery.error instanceof Error ? restorePreviewQuery.error.message : null}
          />
        </div>
      </Modal>

      <Modal
        isOpen={Boolean(deleteTarget)}
        onClose={() => setDeleteTarget(null)}
        title="Delete Safe Snapshot"
        footer={
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button
              variant="danger"
              icon={<Trash2 className="h-4 w-4" />}
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.snapshot_id)}
              loading={deleteMutation.isPending}
            >
              Delete Snapshot
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Delete <span className="font-semibold text-gray-900 dark:text-white">{deleteTarget?.name}</span> and its archive.
          </p>
          <ActionPreviewPanel
            preview={deletePreviewQuery.data}
            isLoading={deletePreviewQuery.isLoading || deletePreviewQuery.isFetching}
            errorMessage={deletePreviewQuery.error instanceof Error ? deletePreviewQuery.error.message : null}
          />
        </div>
      </Modal>
    </div>
  )
}
