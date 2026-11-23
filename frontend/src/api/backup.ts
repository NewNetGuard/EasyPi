import axios from 'axios'
import api from './client'
import { getApiV1BaseUrl } from '../utils/apiBase'
import type {
  BackupActionResponse,
  BackupArchiveImportPayload,
  BackupCreatePayload,
  BackupRecord,
  BackupRestoreStatusResponse,
  BackupStatusResponse,
  RecoveryKeyExportPayload,
  RecoveryKeyImportPayload,
  RecoveryKeyImportResponse,
} from '../types/backup'

const client = api

const handleError = (error: unknown) => {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (detail) {
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    }
  }
  throw error
}

const handleBlobError = async (error: unknown): Promise<never> => {
  if (axios.isAxiosError(error) && error.response?.data instanceof Blob) {
    try {
      const payload = JSON.parse(await error.response.data.text()) as { detail?: unknown }
      if (payload.detail !== undefined) {
        throw new Error(
          typeof payload.detail === 'string' ? payload.detail : JSON.stringify(payload.detail)
        )
      }
    } catch (parseError) {
      if (parseError instanceof Error && !(parseError instanceof SyntaxError)) {
        throw parseError
      }
    }
  }
  return handleError(error)
}

export const listBackups = async (): Promise<BackupRecord[]> => {
  try {
    const res = await client.get<BackupRecord[]>('/backup/list')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const createBackup = async (payload: BackupCreatePayload): Promise<BackupActionResponse> => {
  try {
    const res = await client.post<BackupActionResponse>('/backup/create', payload)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const restoreBackup = async (backupId: number): Promise<BackupActionResponse> => {
  try {
    const res = await client.post<BackupActionResponse>(`/backup/restore/${backupId}`)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getBackupRestoreStatus = async (): Promise<BackupRestoreStatusResponse> => {
  try {
    const res = await client.get<BackupRestoreStatusResponse>('/backup/restore-status')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const cancelBackup = async (backupId: number): Promise<BackupActionResponse> => {
  try {
    const res = await client.post<BackupActionResponse>(`/backup/cancel/${backupId}`)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const deleteBackup = async (backupId: number): Promise<BackupActionResponse> => {
  try {
    const res = await client.delete<BackupActionResponse>(`/backup/${backupId}`)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getBackupStatus = async (backupId: number): Promise<BackupStatusResponse> => {
  try {
    const res = await client.get<BackupStatusResponse>(`/backup/status/${backupId}`)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getBackupDownloadUrl = (backupId: number): string =>
  `${getApiV1BaseUrl()}/backup/download/${backupId}`

export const exportRecoveryKey = async (payload: RecoveryKeyExportPayload): Promise<Blob> => {
  try {
    const res = await client.post<Blob>('/backup/recovery-key/export', payload, {
      responseType: 'blob',
    })
    if (await res.data.slice(0, 10).text() !== 'EASYPIKEY1') {
      throw new Error('The server returned an invalid recovery-key package')
    }
    return res.data
  } catch (error) {
    return handleBlobError(error)
  }
}

export const importRecoveryKey = async (
  payload: RecoveryKeyImportPayload
): Promise<RecoveryKeyImportResponse> => {
  const body = new FormData()
  body.append('package', payload.package)
  body.append('current_password', payload.currentPassword)
  body.append('package_passphrase', payload.packagePassphrase)
  if (payload.totpCode) body.append('totp_code', payload.totpCode)
  try {
    const res = await client.post<RecoveryKeyImportResponse>('/backup/recovery-key/import', body)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const importBackupArchive = async (
  payload: BackupArchiveImportPayload
): Promise<BackupActionResponse> => {
  const body = new FormData()
  body.append('archive', payload.archive)
  body.append('current_password', payload.currentPassword)
  if (payload.totpCode) body.append('totp_code', payload.totpCode)
  try {
    const res = await client.post<BackupActionResponse>('/backup/import', body)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}
