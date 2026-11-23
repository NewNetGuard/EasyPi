import axios from 'axios'

import apiClient from './client'
import { getApiV1BaseUrl } from '../utils/apiBase'

export type RollbackStatus = 'creating' | 'ready' | 'failed' | 'restoring' | 'restore-failed'

export interface RollbackSummary {
  total: number
  ready: number
  active: number
  failed: number
}

export interface RollbackSnapshotRecord {
  snapshot_id: string
  name: string
  reason?: string | null
  status: RollbackStatus
  created_at: string
  updated_at: string
  archive_path?: string | null
  size_bytes?: number | null
  error_message?: string | null
  last_restored_at?: string | null
  last_restore_status?: string | null
}

export interface RollbackListResponse {
  generated_at: string
  summary: RollbackSummary
  snapshots: RollbackSnapshotRecord[]
}

export interface RollbackActionResponse {
  snapshot_id: string
  status: string
  message: string
}

export interface RollbackCreatePayload {
  name?: string
  reason?: string
}

const handleError = (error: unknown) => {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (detail) {
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    }
  }
  throw error
}

export const listRollbackSnapshots = async (limit = 50): Promise<RollbackListResponse> => {
  try {
    const response = await apiClient.get<RollbackListResponse>('/rollback/snapshots', { params: { limit } })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const createRollbackSnapshot = async (payload: RollbackCreatePayload): Promise<RollbackActionResponse> => {
  try {
    const response = await apiClient.post<RollbackActionResponse>('/rollback/snapshots', payload)
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const restoreRollbackSnapshot = async (snapshotId: string): Promise<RollbackActionResponse> => {
  try {
    const response = await apiClient.post<RollbackActionResponse>(`/rollback/snapshots/${snapshotId}/restore`)
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const deleteRollbackSnapshot = async (snapshotId: string): Promise<RollbackActionResponse> => {
  try {
    const response = await apiClient.delete<RollbackActionResponse>(`/rollback/snapshots/${snapshotId}`)
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getRollbackDownloadUrl = (snapshotId: string): string =>
  `${getApiV1BaseUrl()}/rollback/snapshots/${snapshotId}/download`
