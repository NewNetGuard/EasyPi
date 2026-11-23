import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Database, Download, Info, KeyRound, RefreshCw, RotateCcw, Trash2, Upload, XCircle } from 'lucide-react'
import { toast } from 'react-hot-toast'

import Badge from '../components/common/Badge'
import Button from '../components/common/Button'
import Card from '../components/common/Card'
import Input from '../components/common/Input'
import Modal from '../components/common/Modal'
import Select from '../components/common/Select'

import {
  cancelBackup,
  createBackup,
  deleteBackup,
  exportRecoveryKey,
  getBackupRestoreStatus,
  getBackupDownloadUrl,
  importBackupArchive,
  importRecoveryKey,
  listBackups,
  restoreBackup,
} from '../api/backup'
import type { BackupRecord, BackupType } from '../types/backup'
import ActionPreviewPanel from '../features/actions/ActionPreviewPanel'
import { getActionPreview } from '../api/actionPreview'

const backupTypeOptions = [
  { value: 'full', label: 'Full system backup' },
  { value: 'config', label: 'Config-only backup' },
]

const RECOVERY_KEY_MAGIC = 'EASYPIKEY1'
const BACKUP_ARCHIVE_MAGIC = 'EASYPIBK1'
const MAX_RECOVERY_KEY_PACKAGE_BYTES = 4096
const MAX_BACKUP_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
const MIN_RECOVERY_KEY_PASSPHRASE_LENGTH = 12

const Backup = () => {
  const queryClient = useQueryClient()
  const [backupType, setBackupType] = useState<BackupType>('full')
  const [backupName, setBackupName] = useState('')
  const [restoreTarget, setRestoreTarget] = useState<BackupRecord | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<BackupRecord | null>(null)
  const [exportRecoveryOpen, setExportRecoveryOpen] = useState(false)
  const [importRecoveryOpen, setImportRecoveryOpen] = useState(false)
  const [importArchiveOpen, setImportArchiveOpen] = useState(false)
  const [exportCurrentPassword, setExportCurrentPassword] = useState('')
  const [exportPassphrase, setExportPassphrase] = useState('')
  const [exportPassphraseConfirm, setExportPassphraseConfirm] = useState('')
  const [exportTotp, setExportTotp] = useState('')
  const [importPackage, setImportPackage] = useState<File | null>(null)
  const [importCurrentPassword, setImportCurrentPassword] = useState('')
  const [importPassphrase, setImportPassphrase] = useState('')
  const [importTotp, setImportTotp] = useState('')
  const [archiveFile, setArchiveFile] = useState<File | null>(null)
  const [archiveCurrentPassword, setArchiveCurrentPassword] = useState('')
  const [archiveTotp, setArchiveTotp] = useState('')

  const {
    data: backups = [],
    isLoading,
    isFetching,
    error,
    refetch,
  } = useQuery({
    queryKey: ['backups'],
    queryFn: listBackups,
    refetchInterval: 10000,
  })

  const { data: restoreStatus } = useQuery({
    queryKey: ['backup-restore-status'],
    queryFn: getBackupRestoreStatus,
    refetchInterval: 5000,
    retry: 1,
  })

  const createMutation = useMutation({
    mutationFn: createBackup,
    onSuccess: (response) => {
      toast.success(response.message || 'Backup started')
      setBackupName('')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to start backup')
    },
  })

  const restoreMutation = useMutation({
    mutationFn: restoreBackup,
    onSuccess: (response) => {
      toast.success(response.message || 'Restore started')
      setRestoreTarget(null)
      queryClient.invalidateQueries({ queryKey: ['backup-restore-status'] })
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to restore backup')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deleteBackup,
    onSuccess: (response) => {
      toast.success(response.message || 'Backup deleted')
      setDeleteTarget(null)
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to delete backup')
    },
  })

  const cancelMutation = useMutation({
    mutationFn: cancelBackup,
    onSuccess: (response) => {
      toast.success(response.message || 'Backup cancelled')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to cancel backup')
    },
  })

  const clearExportSecrets = () => {
    setExportCurrentPassword('')
    setExportPassphrase('')
    setExportPassphraseConfirm('')
    setExportTotp('')
  }

  const clearImportSecrets = () => {
    setImportPackage(null)
    setImportCurrentPassword('')
    setImportPassphrase('')
    setImportTotp('')
  }

  const exportRecoveryMutation = useMutation({
    mutationFn: exportRecoveryKey,
    onSuccess: (blob) => {
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      try {
        anchor.href = url
        anchor.download = 'easypi-recovery-key-v1.epikey'
        document.body.appendChild(anchor)
        anchor.click()
      } finally {
        anchor.remove()
        window.setTimeout(() => URL.revokeObjectURL(url), 0)
      }
      toast.success('Protected recovery-key package downloaded')
      setExportRecoveryOpen(false)
      clearExportSecrets()
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to export recovery key')
    },
  })

  const importRecoveryMutation = useMutation({
    mutationFn: importRecoveryKey,
    onSuccess: (response) => {
      toast.success(response.message || 'Recovery key imported')
      setImportRecoveryOpen(false)
      clearImportSecrets()
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to import recovery key')
    },
  })

  const importArchiveMutation = useMutation({
    mutationFn: importBackupArchive,
    onSuccess: (response) => {
      toast.success(response.message || 'Backup archive imported')
      setImportArchiveOpen(false)
      setArchiveFile(null)
      setArchiveCurrentPassword('')
      setArchiveTotp('')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to import backup archive')
    },
  })

  const closeExportRecovery = () => {
    if (exportRecoveryMutation.isPending) return
    setExportRecoveryOpen(false)
    clearExportSecrets()
  }

  const closeImportRecovery = () => {
    if (importRecoveryMutation.isPending) return
    setImportRecoveryOpen(false)
    clearImportSecrets()
  }

  const closeImportArchive = () => {
    if (importArchiveMutation.isPending) return
    setImportArchiveOpen(false)
    setArchiveFile(null)
    setArchiveCurrentPassword('')
    setArchiveTotp('')
  }

  const validateTotp = (value: string) => !value || /^\d{6}$/.test(value)

  const handleExportRecovery = () => {
    const totpCode = exportTotp.trim()
    if (!exportCurrentPassword) {
      toast.error('Enter your current EasyPi password')
      return
    }
    if (exportPassphrase.length < MIN_RECOVERY_KEY_PASSPHRASE_LENGTH) {
      toast.error(`Use a recovery-key passphrase of at least ${MIN_RECOVERY_KEY_PASSPHRASE_LENGTH} characters`)
      return
    }
    if (exportPassphrase !== exportPassphraseConfirm) {
      toast.error('Recovery-key passphrases do not match')
      return
    }
    if (!validateTotp(totpCode)) {
      toast.error('The authenticator code must contain 6 digits')
      return
    }
    exportRecoveryMutation.mutate({
      current_password: exportCurrentPassword,
      package_passphrase: exportPassphrase,
      totp_code: totpCode || undefined,
    })
  }

  const handleImportRecovery = async () => {
    const totpCode = importTotp.trim()
    if (!importPackage) {
      toast.error('Choose an EasyPi .epikey package')
      return
    }
    if (importPackage.size > MAX_RECOVERY_KEY_PACKAGE_BYTES) {
      toast.error('The recovery-key package is too large')
      return
    }
    if (!importCurrentPassword) {
      toast.error('Enter your current EasyPi password')
      return
    }
    if (importPassphrase.length < MIN_RECOVERY_KEY_PASSPHRASE_LENGTH) {
      toast.error('Enter the passphrase used when this recovery key was exported')
      return
    }
    if (!validateTotp(totpCode)) {
      toast.error('The authenticator code must contain 6 digits')
      return
    }

    let magic = ''
    try {
      magic = await importPackage.slice(0, RECOVERY_KEY_MAGIC.length).text()
    } catch {
      toast.error('The recovery-key package could not be read')
      return
    }
    if (magic !== RECOVERY_KEY_MAGIC) {
      toast.error('This is not a valid EasyPi recovery-key package')
      return
    }

    importRecoveryMutation.mutate({
      package: importPackage,
      currentPassword: importCurrentPassword,
      packagePassphrase: importPassphrase,
      totpCode: totpCode || undefined,
    })
  }

  const handleImportArchive = async () => {
    const totpCode = archiveTotp.trim()
    if (!archiveFile) {
      toast.error('Choose an EasyPi .epibak archive')
      return
    }
    if (archiveFile.size > MAX_BACKUP_ARCHIVE_BYTES) {
      toast.error('The backup archive is too large')
      return
    }
    if (!/^(config|full|pre-restore)-\d{4}(?:-\d{2}){4,5}\.epibak$/.test(archiveFile.name)) {
      toast.error('The backup archive name is not valid')
      return
    }
    if (!archiveCurrentPassword) {
      toast.error('Enter your current EasyPi password')
      return
    }
    if (!validateTotp(totpCode)) {
      toast.error('The authenticator code must contain 6 digits')
      return
    }
    let magic = ''
    try {
      magic = await archiveFile.slice(0, BACKUP_ARCHIVE_MAGIC.length).text()
    } catch {
      toast.error('The backup archive could not be read')
      return
    }
    if (magic !== BACKUP_ARCHIVE_MAGIC) {
      toast.error('This is not an encrypted EasyPi backup archive')
      return
    }
    importArchiveMutation.mutate({
      archive: archiveFile,
      currentPassword: archiveCurrentPassword,
      totpCode: totpCode || undefined,
    })
  }

  const statusStyles = useMemo(
    () => ({
      running: { label: 'Running', color: 'warning' as const },
      completed: { label: 'Completed', color: 'success' as const },
      failed: { label: 'Failed', color: 'danger' as const },
    }),
    []
  )

  const handleCreateBackup = () => {
    const trimmedName = backupName.trim()
    if (trimmedName && !/^[\w\s-]+$/.test(trimmedName)) {
      toast.error('Name contains invalid characters')
      return
    }
    createMutation.mutate({
      type: backupType,
      name: trimmedName ? trimmedName : undefined,
    })
  }

  const formatDate = (value: string) => {
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) {
      return value
    }
    return date.toLocaleString()
  }

  const restorePreviewQuery = useQuery({
    queryKey: ['action-preview', 'backup.restore', restoreTarget?.id],
    queryFn: () => getActionPreview('backup.restore', restoreTarget?.id ?? ''),
    enabled: Boolean(restoreTarget?.id),
  })
  const deletePreviewQuery = useQuery({
    queryKey: ['action-preview', 'backup.delete', deleteTarget?.id],
    queryFn: () => getActionPreview('backup.delete', deleteTarget?.id ?? ''),
    enabled: Boolean(deleteTarget?.id),
  })
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
            <Database className="h-6 w-6 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">System Backup</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Create, restore, and download system backups, and protect their recovery key.
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

      {restoreStatus && restoreStatus.status !== 'idle' && (
        <div
          className={`rounded-xl border p-4 ${
            restoreStatus.status === 'success'
              ? 'border-green-200 bg-green-50 dark:border-green-900/60 dark:bg-green-950/30'
              : restoreStatus.status === 'failed'
                ? 'border-red-200 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30'
                : 'border-amber-200 bg-amber-50 dark:border-amber-900/60 dark:bg-amber-950/30'
          }`}
        >
          <div className="flex items-start gap-3">
            {restoreStatus.status === 'running' ? (
              <RefreshCw className="mt-0.5 h-5 w-5 shrink-0 animate-spin text-amber-600 dark:text-amber-300" />
            ) : restoreStatus.status === 'success' ? (
              <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-green-600 dark:text-green-300" />
            ) : (
              <AlertTriangle
                className={`mt-0.5 h-5 w-5 shrink-0 ${
                  restoreStatus.status === 'failed'
                    ? 'text-red-600 dark:text-red-300'
                    : 'text-amber-600 dark:text-amber-300'
                }`}
              />
            )}
            <div className="min-w-0">
              <p className="font-medium text-gray-900 dark:text-white">
                {restoreStatus.status === 'running' && 'Backup restore is running'}
                {restoreStatus.status === 'success' && 'Last backup restore completed'}
                {restoreStatus.status === 'failed-rolled-back' &&
                  'Restore failed; the safety snapshot was reapplied'}
                {restoreStatus.status === 'failed' &&
                  'Restore failed and automatic recovery did not complete'}
              </p>
              <p className="mt-1 break-all text-xs text-gray-600 dark:text-gray-300">
                {restoreStatus.archive}
                {restoreStatus.updated_at && ` • ${formatDate(restoreStatus.updated_at)}`}
              </p>
            </div>
          </div>
        </div>
      )}

      <Card
        title="Create Backup"
        subtitle="Start a full system backup or a lightweight configuration backup."
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Select
            label="Backup type"
            options={backupTypeOptions}
            value={backupType}
            onChange={(value) => setBackupType(value as BackupType)}
          />
          <Input
            label="Backup name (optional)"
            placeholder="Example: Pre-upgrade backup"
            value={backupName}
            onChange={(event) => setBackupName(event.target.value)}
            helperText="Letters, numbers, spaces, underscores, and dashes only."
          />
          <div className="flex items-end">
            <Button
              className="w-full"
              icon={<Database className="h-4 w-4" />}
              onClick={handleCreateBackup}
              loading={createMutation.isPending}
            >
              Start Backup
            </Button>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
          <AlertTriangle className="h-4 w-4 text-amber-500" />
          Restores will overwrite existing data. Download a backup before major changes.
        </div>
        <div className="mt-2 flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400">
          <Info className="h-4 w-4" />
          Backups are created only when you start them here.
        </div>
      </Card>

      <Card
        title="Backup Recovery Key"
        subtitle="Keep encrypted backups recoverable if this EasyPi device is lost or replaced."
      >
        <div className="grid gap-4 lg:grid-cols-[1fr_auto] lg:items-center">
          <div className="space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-300">
              EasyPi backup archives are encrypted with a key stored on this device. Export a
              passphrase-protected <code className="font-mono text-xs">.epikey</code> package and
              store it separately from your <code className="font-mono text-xs">.epibak</code>{' '}
              archives.
            </p>
            <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700/50 dark:bg-amber-900/20 dark:text-amber-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                Keep the package and its passphrase in separate secure locations. Neither one can
                recover a backup by itself.
              </span>
            </div>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row lg:flex-col">
            <Button
              variant="outline"
              icon={<Upload className="h-4 w-4" />}
              onClick={() => setImportArchiveOpen(true)}
              disabled={importRecoveryMutation.isPending || exportRecoveryMutation.isPending}
            >
              Import Backup Archive
            </Button>
            <Button
              icon={<KeyRound className="h-4 w-4" />}
              onClick={() => setExportRecoveryOpen(true)}
              disabled={importRecoveryMutation.isPending}
            >
              Export Recovery Key
            </Button>
            <Button
              variant="outline"
              icon={<Upload className="h-4 w-4" />}
              onClick={() => setImportRecoveryOpen(true)}
              disabled={exportRecoveryMutation.isPending}
            >
              Import Recovery Key
            </Button>
          </div>
        </div>
      </Card>

      <div className="bg-white dark:bg-dark-800 rounded-xl shadow-sm border border-gray-200 dark:border-dark-700 overflow-hidden">
        <div className="flex flex-col gap-2 px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-dark-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Existing Backups</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Restore or download completed backups. Running jobs can be cancelled.
          </p>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 text-primary-500 animate-spin" />
          </div>
        ) : error ? (
          <div className="px-6 py-8 text-sm text-red-600 dark:text-red-400">
            Failed to load backups.
          </div>
        ) : backups.length === 0 ? (
          <div className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
            No backups yet. Start one above.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-dark-700">
                <tr>
                  <th className="px-4 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-4 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider hidden md:table-cell">
                    Type
                  </th>
                  <th className="px-4 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider hidden lg:table-cell">
                    Size
                  </th>
                  <th className="px-4 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider hidden lg:table-cell">
                    Created
                  </th>
                  <th className="px-4 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 sm:px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-dark-700">
                {backups.map((backup) => {
                  const status = statusStyles[backup.status as keyof typeof statusStyles]
                  const statusLabel = status?.label || backup.status
                  const statusColor = status?.color || 'gray'
                  const isRunning = backup.status === 'running'
                  const isCompleted = backup.status === 'completed'

                  return (
                    <tr key={backup.id} className="hover:bg-gray-50 dark:hover:bg-dark-700/50">
                      <td className="px-4 sm:px-6 py-4">
                        <div className="font-medium text-gray-900 dark:text-white">{backup.name}</div>
                        {backup.error_message && (
                          <div className="text-xs text-red-600 dark:text-red-400 mt-1">
                            {backup.error_message}
                          </div>
                        )}
                        {isRunning && (
                          <div className="mt-2 flex max-w-xs items-center gap-2 text-xs text-amber-700 dark:text-amber-300">
                            <RefreshCw className="h-3.5 w-3.5 shrink-0 animate-spin" />
                            <span>Backup is running; exact progress is not reported.</span>
                          </div>
                        )}
                        <div className="text-xs text-gray-500 dark:text-gray-400 mt-1 lg:hidden">
                          {backup.type} • {backup.size} • {formatDate(backup.created_at)}
                        </div>
                      </td>
                      <td className="px-4 sm:px-6 py-4 text-sm text-gray-600 dark:text-gray-300 hidden md:table-cell">
                        {backup.type}
                      </td>
                      <td className="px-4 sm:px-6 py-4 text-sm text-gray-600 dark:text-gray-300 hidden lg:table-cell">
                        {backup.size}
                      </td>
                      <td className="px-4 sm:px-6 py-4 text-sm text-gray-600 dark:text-gray-300 hidden lg:table-cell">
                        {formatDate(backup.created_at)}
                      </td>
                      <td className="px-4 sm:px-6 py-4">
                        <Badge color={statusColor} dot={isRunning}>
                          {statusLabel}
                        </Badge>
                      </td>
                      <td className="px-4 sm:px-6 py-4">
                        <div className="flex flex-wrap items-center justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            icon={<Download className="h-4 w-4" />}
                            onClick={() => window.open(getBackupDownloadUrl(backup.id), '_blank')}
                            disabled={!isCompleted}
                          >
                            Download
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            icon={<RotateCcw className="h-4 w-4" />}
                            onClick={() => setRestoreTarget(backup)}
                            disabled={!isCompleted}
                          >
                            Restore
                          </Button>
                          {isRunning ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              icon={<XCircle className="h-4 w-4" />}
                              onClick={() => cancelMutation.mutate(backup.id)}
                              loading={cancelMutation.isPending}
                            >
                              Cancel
                            </Button>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              icon={<Trash2 className="h-4 w-4" />}
                              onClick={() => setDeleteTarget(backup)}
                            >
                              Delete
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Modal
        isOpen={restoreTarget !== null}
        onClose={() => setRestoreTarget(null)}
        title="Restore Backup"
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setRestoreTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => restoreTarget && restoreMutation.mutate(restoreTarget.id)}
              loading={restoreMutation.isPending}
            >
              Restore
            </Button>
          </div>
        }
      >
        <div className="space-y-3 text-sm text-gray-600 dark:text-gray-300">
          <p>
            Restoring will overwrite current data and configurations. Make sure you have a recent backup before
            continuing.
          </p>
          <ActionPreviewPanel
            preview={restorePreviewQuery.data}
            isLoading={restorePreviewQuery.isLoading || restorePreviewQuery.isFetching}
            errorMessage={restorePreviewQuery.error instanceof Error ? restorePreviewQuery.error.message : null}
          />
          {restoreTarget && (
            <div className="rounded-lg border border-amber-200 dark:border-amber-700/50 bg-amber-50 dark:bg-amber-900/20 p-3 text-amber-900 dark:text-amber-200">
              Restore backup <strong>{restoreTarget.name}</strong> created on {formatDate(restoreTarget.created_at)}.
            </div>
          )}
        </div>
      </Modal>

      <Modal
        isOpen={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title="Delete Backup"
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
              loading={deleteMutation.isPending}
            >
              Delete
            </Button>
          </div>
        }
      >
        <div className="space-y-3 text-sm text-gray-600 dark:text-gray-300">
          <p>This backup will be permanently removed. This action cannot be undone.</p>
          <ActionPreviewPanel
            preview={deletePreviewQuery.data}
            isLoading={deletePreviewQuery.isLoading || deletePreviewQuery.isFetching}
            errorMessage={deletePreviewQuery.error instanceof Error ? deletePreviewQuery.error.message : null}
          />
          {deleteTarget && (
            <div className="rounded-lg border border-red-200 dark:border-red-700/50 bg-red-50 dark:bg-red-900/20 p-3 text-red-900 dark:text-red-200">
              Delete backup <strong>{deleteTarget.name}</strong>.
            </div>
          )}
        </div>
      </Modal>

      <Modal
        isOpen={exportRecoveryOpen}
        onClose={closeExportRecovery}
        title="Export Backup Recovery Key"
        closeOnOutsideClick={!exportRecoveryMutation.isPending}
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              onClick={closeExportRecovery}
              disabled={exportRecoveryMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              form="export-recovery-key-form"
              icon={<Download className="h-4 w-4" />}
              loading={exportRecoveryMutation.isPending}
              disabled={
                !exportCurrentPassword ||
                exportPassphrase.length < MIN_RECOVERY_KEY_PASSPHRASE_LENGTH ||
                exportPassphrase !== exportPassphraseConfirm
              }
            >
              Export Protected Key
            </Button>
          </div>
        }
      >
        <form
          id="export-recovery-key-form"
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            handleExportRecovery()
          }}
        >
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-3 text-sm text-blue-900 dark:border-blue-700/50 dark:bg-blue-900/20 dark:text-blue-200">
            The downloaded package contains sensitive key material encrypted by the passphrase you
            choose below. EasyPi cannot recover a forgotten passphrase.
          </div>
          <Input
            label="Current EasyPi password"
            type="password"
            autoComplete="current-password"
            maxLength={256}
            value={exportCurrentPassword}
            onChange={(event) => setExportCurrentPassword(event.target.value)}
            required
          />
          <Input
            label="Recovery-key passphrase"
            type="password"
            autoComplete="new-password"
            minLength={MIN_RECOVERY_KEY_PASSPHRASE_LENGTH}
            maxLength={1024}
            value={exportPassphrase}
            onChange={(event) => setExportPassphrase(event.target.value)}
            helperText={`At least ${MIN_RECOVERY_KEY_PASSPHRASE_LENGTH} characters. Store it separately from the package.`}
            required
          />
          <Input
            label="Confirm recovery-key passphrase"
            type="password"
            autoComplete="new-password"
            minLength={MIN_RECOVERY_KEY_PASSPHRASE_LENGTH}
            maxLength={1024}
            value={exportPassphraseConfirm}
            onChange={(event) => setExportPassphraseConfirm(event.target.value)}
            error={
              exportPassphraseConfirm && exportPassphrase !== exportPassphraseConfirm
                ? 'Passphrases do not match'
                : undefined
            }
            required
          />
          <Input
            label="Authenticator code (if 2FA is enabled)"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="000000"
            value={exportTotp}
            onChange={(event) => setExportTotp(event.target.value.replace(/\D/g, '').slice(0, 6))}
            helperText="Enter the current 6-digit code only if your account uses two-factor authentication."
          />
        </form>
      </Modal>

      <Modal
        isOpen={importRecoveryOpen}
        onClose={closeImportRecovery}
        title="Import Backup Recovery Key"
        closeOnOutsideClick={!importRecoveryMutation.isPending}
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              onClick={closeImportRecovery}
              disabled={importRecoveryMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              form="import-recovery-key-form"
              icon={<Upload className="h-4 w-4" />}
              loading={importRecoveryMutation.isPending}
              disabled={
                !importPackage ||
                !importCurrentPassword ||
                importPassphrase.length < MIN_RECOVERY_KEY_PASSPHRASE_LENGTH
              }
            >
              Import Key
            </Button>
          </div>
        }
      >
        <form
          id="import-recovery-key-form"
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            void handleImportRecovery()
          }}
        >
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-3 text-sm text-blue-900 dark:border-blue-700/50 dark:bg-blue-900/20 dark:text-blue-200">
            Importing adds a decryption key for backups from another EasyPi installation. It does
            not replace this device&apos;s active backup key.
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
              Recovery-key package <span className="text-red-500">*</span>
            </label>
            <input
              type="file"
              accept=".epikey,application/octet-stream"
              className="input block w-full file:mr-4 file:rounded-md file:border-0 file:bg-primary-50 file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-primary-700 hover:file:bg-primary-100 dark:file:bg-primary-900/30 dark:file:text-primary-300"
              onChange={(event) => {
                const selected = event.target.files?.[0] ?? null
                if (selected && selected.size > MAX_RECOVERY_KEY_PACKAGE_BYTES) {
                  toast.error('The recovery-key package is too large')
                  event.target.value = ''
                  setImportPackage(null)
                  return
                }
                setImportPackage(selected)
              }}
              required
            />
            <p className="mt-1.5 text-sm text-gray-500 dark:text-gray-400">
              Select the <code className="font-mono text-xs">.epikey</code> file exported from the
              installation that created your backup.
            </p>
          </div>
          <Input
            label="Current EasyPi password"
            type="password"
            autoComplete="current-password"
            maxLength={256}
            value={importCurrentPassword}
            onChange={(event) => setImportCurrentPassword(event.target.value)}
            required
          />
          <Input
            label="Recovery-key package passphrase"
            type="password"
            autoComplete="off"
            minLength={MIN_RECOVERY_KEY_PASSPHRASE_LENGTH}
            maxLength={1024}
            value={importPassphrase}
            onChange={(event) => setImportPassphrase(event.target.value)}
            helperText="Use the passphrase chosen when the package was exported."
            required
          />
          <Input
            label="Authenticator code (if 2FA is enabled)"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="000000"
            value={importTotp}
            onChange={(event) => setImportTotp(event.target.value.replace(/\D/g, '').slice(0, 6))}
            helperText="Enter the current 6-digit code only if your account uses two-factor authentication."
          />
        </form>
      </Modal>

      <Modal
        isOpen={importArchiveOpen}
        onClose={closeImportArchive}
        title="Import Encrypted Backup"
        closeOnOutsideClick={!importArchiveMutation.isPending}
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              onClick={closeImportArchive}
              disabled={importArchiveMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              form="import-backup-archive-form"
              icon={<Upload className="h-4 w-4" />}
              loading={importArchiveMutation.isPending}
              disabled={!archiveFile || !archiveCurrentPassword}
            >
              Validate and Import
            </Button>
          </div>
        }
      >
        <form
          id="import-backup-archive-form"
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            void handleImportArchive()
          }}
        >
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-3 text-sm text-blue-900 dark:border-blue-700/50 dark:bg-blue-900/20 dark:text-blue-200">
            Import the <code className="font-mono text-xs">.epikey</code> recovery key first when
            this archive was created by another EasyPi installation. The archive is authenticated
            and inspected before it appears in the restore list.
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
              Backup archive <span className="text-red-500">*</span>
            </label>
            <input
              type="file"
              accept=".epibak,application/octet-stream"
              className="input block w-full file:mr-4 file:rounded-md file:border-0 file:bg-primary-50 file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-primary-700 hover:file:bg-primary-100 dark:file:bg-primary-900/30 dark:file:text-primary-300"
              onChange={(event) => {
                const selected = event.target.files?.[0] ?? null
                if (selected && selected.size > MAX_BACKUP_ARCHIVE_BYTES) {
                  toast.error('The backup archive is too large')
                  event.target.value = ''
                  setArchiveFile(null)
                  return
                }
                setArchiveFile(selected)
              }}
              required
            />
          </div>
          <Input
            label="Current EasyPi password"
            type="password"
            autoComplete="current-password"
            maxLength={256}
            value={archiveCurrentPassword}
            onChange={(event) => setArchiveCurrentPassword(event.target.value)}
            required
          />
          <Input
            label="Authenticator code (if 2FA is enabled)"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="000000"
            value={archiveTotp}
            onChange={(event) => setArchiveTotp(event.target.value.replace(/\D/g, '').slice(0, 6))}
          />
        </form>
      </Modal>
    </div>
  )
}

export default Backup
