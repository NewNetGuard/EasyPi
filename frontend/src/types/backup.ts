export type BackupType = 'full' | 'config'
export type BackupStatus = 'running' | 'completed' | 'failed'

export interface BackupRecord {
  id: number
  name: string
  type: BackupType | string
  size: string
  size_bytes: number
  created_at: string
  status: BackupStatus | string
  error_message?: string | null
}

export interface BackupCreatePayload {
  type: BackupType
  name?: string
}

export interface BackupActionResponse {
  status: string
  message: string
  id?: number
}

export interface BackupArchiveImportPayload {
  archive: File
  currentPassword: string
  totpCode?: string
}

export interface BackupStatusResponse {
  id: number
  status: BackupStatus
  progress: number
  error_message?: string | null
}

export type BackupRestoreState = 'idle' | 'running' | 'success' | 'failed-rolled-back' | 'failed'

export interface BackupRestoreStatusResponse {
  status: BackupRestoreState
  archive?: string | null
  updated_at?: string | null
}

export interface RecoveryKeyExportPayload {
  current_password: string
  package_passphrase: string
  totp_code?: string
}

export interface RecoveryKeyImportPayload {
  package: File
  currentPassword: string
  packagePassphrase: string
  totpCode?: string
}

export interface RecoveryKeyImportResponse {
  status: 'imported' | 'already_present'
  message: string
  fingerprint: string
}
