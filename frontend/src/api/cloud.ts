import axios from 'axios'
import api from './client'
import { getApiV1BaseUrl } from '../utils/apiBase'
import type {
  PiCloudFile,
  FileListResponse,
  StorageStats,
  UsageByType,
  ShareLink,
  UploadResponse,
  TrashItem,
  FileMetadata,
  Folder,
  FolderTree,
  ActivityItem,
  DuplicateGroup,
  BulkOperationResult,
  TelegramBotConfig,
  TelegramBotStatus,
  TelegramUpload,
  FileCategory,
  ColorLabel,
  SortField,
  SortOrder,
} from '../types/cloud'

// Use the shared api client with auth interceptor
const client = api

const handleError = (error: any) => {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (detail) throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  throw error
}

export const encodeFileIdPath = (fileId: string): string =>
  fileId
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/')

// === Files ===

export const listFiles = async (
  path: string,
  options?: {
    category?: FileCategory
    favoriteOnly?: boolean
    sortBy?: SortField
    sortOrder?: SortOrder
    offset?: number
    limit?: number
    search?: string
  }
): Promise<FileListResponse> => {
  try {
    const res = await client.get<FileListResponse>('/picloud/files', {
      params: { path, ...options },
    })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const uploadFiles = async (path: string, files: File[]): Promise<UploadResponse> => {
  const formData = new FormData()
  formData.append('path', path)
  files.forEach((file) => formData.append('files', file))
  try {
    const res = await client.post<UploadResponse>('/picloud/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const uploadFile = async (
  path: string,
  file: File,
  onProgress?: (progress: number) => void
): Promise<PiCloudFile> => {
  const formData = new FormData()
  formData.append('path', path)
  formData.append('files', file)
  
  try {
    const res = await client.post<UploadResponse>('/picloud/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      },
    })
    return res.data.uploaded[0]
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const deleteFile = async (fileId: string): Promise<void> => {
  try {
    await client.delete('/picloud/file', { params: { file_id: fileId } })
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const deleteFilePermanently = async (fileId: string): Promise<void> => {
  try {
    await client.delete('/picloud/file', {
      params: { file_id: fileId, permanent: true },
    })
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const renameOrMove = async (fileId: string, newPath: string): Promise<PiCloudFile> => {
  try {
    const res = await client.put<PiCloudFile>(
      `/picloud/file/${encodeFileIdPath(fileId)}`,
      null,
      { params: { new_path: newPath } }
    )
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const copyFile = async (fileId: string, newPath: string): Promise<PiCloudFile> => {
  try {
    const res = await client.post<PiCloudFile>(
      `/picloud/copy/${encodeFileIdPath(fileId)}`,
      null,
      { params: { new_path: newPath } }
    )
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const createFolder = async (path: string): Promise<PiCloudFile> => {
  try {
    const res = await client.post<PiCloudFile>('/picloud/folder', null, { params: { path } })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const searchFiles = async (
  query: string,
  options?: {
    category?: FileCategory
    tags?: string[]
    favoriteOnly?: boolean
    sortBy?: SortField
    sortOrder?: SortOrder
    offset?: number
    limit?: number
  }
): Promise<PiCloudFile[]> => {
  try {
    const res = await client.get<PiCloudFile[]>('/picloud/search', {
      params: { q: query, ...options },
    })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getFileMetadata = async (fileId: string): Promise<FileMetadata> => {
  try {
    const res = await client.get<FileMetadata>(`/picloud/metadata/${encodeFileIdPath(fileId)}`)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const buildDownloadUrl = (fileId: string): string => 
  `${getApiV1BaseUrl()}/picloud/file/${encodeFileIdPath(fileId)}/download`

export const buildVideoUrl = (fileId: string): string =>
  `${getApiV1BaseUrl()}/picloud/video/${encodeFileIdPath(fileId)}`

export const buildThumbnailUrl = (fileId: string): string =>
  `${getApiV1BaseUrl()}/picloud/thumbnail/${encodeFileIdPath(fileId)}`

/**
 * Fetch file content once with the authenticated same-origin API client.
 * Callers that need to inspect or decrypt content should operate on this Blob
 * directly instead of fetching a blob: URL, which is intentionally excluded
 * from the application's strict connect-src policy.
 */
export const fetchAuthenticatedBlob = async (fileId: string): Promise<Blob> => {
  try {
    const response = await client.get(`/picloud/file/${encodeFileIdPath(fileId)}/download`, {
      responseType: 'blob'
    })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const fetchAuthenticatedThumbnailBlob = async (fileId: string): Promise<Blob> => {
  try {
    const response = await client.get(`/picloud/thumbnail/${encodeFileIdPath(fileId)}`, {
      responseType: 'blob'
    })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

/**
 * Revoke blob URL to free memory
 */
export const revokeBlobUrl = (url: string): void => {
  if (url.startsWith('blob:')) {
    URL.revokeObjectURL(url)
  }
}

// === Storage ===

export const getStorageStats = async (): Promise<StorageStats> => {
  try {
    const res = await client.get<StorageStats>('/picloud/storage/stats')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getUsageByType = async (): Promise<UsageByType> => {
  try {
    const res = await client.get<UsageByType>('/picloud/storage/usage')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Favorites ===

export const getRecentFiles = async (limit = 20): Promise<PiCloudFile[]> => {
  try {
    const res = await client.get<PiCloudFile[]>('/picloud/recent', { params: { limit } })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getFavorites = async (): Promise<PiCloudFile[]> => {
  try {
    const res = await client.get<PiCloudFile[]>('/picloud/favorites')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const toggleFavorite = async (fileId: string, value: boolean): Promise<void> => {
  try {
    await client.post(`/picloud/favorite/${encodeFileIdPath(fileId)}`, null, {
      params: { value },
    })
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Tags ===

export const getTags = async (fileId: string): Promise<string[]> => {
  try {
    const res = await client.get<string[]>(`/picloud/tags/${encodeFileIdPath(fileId)}`)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const setTags = async (fileId: string, tags: string[]): Promise<string[]> => {
  try {
    const res = await client.post<string[]>(`/picloud/tags/${encodeFileIdPath(fileId)}`, tags)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Color Labels ===

export const setColorLabel = async (fileId: string, color: ColorLabel): Promise<void> => {
  try {
    await client.post(`/picloud/color-label/${encodeFileIdPath(fileId)}`, null, {
      params: { color },
    })
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Folders ===

export const listFolders = async (path: string): Promise<Folder[]> => {
  try {
    const res = await client.get<Folder[]>('/picloud/folders', { params: { path } })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getFolderTree = async (): Promise<FolderTree[]> => {
  try {
    const res = await client.get<FolderTree[]>('/picloud/folder-tree')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Sharing ===

export const createShareLink = async (
  fileId: string,
  options?: {
    hours?: number
    password?: string
  }
): Promise<ShareLink> => {
  try {
    const res = await client.post<ShareLink>('/picloud/share', {
      file_id: fileId,
      ...options,
    })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getShareInfo = async (shareId: string): Promise<ShareLink> => {
  try {
    const res = await client.get<ShareLink>(`/picloud/share/${shareId}/info`)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const deleteShare = async (shareId: string): Promise<void> => {
  try {
    await client.delete(`/picloud/share/${shareId}`)
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const listShares = async (): Promise<ShareLink[]> => {
  try {
    const res = await client.get<ShareLink[]>('/picloud/shares')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Trash ===

export const listTrash = async (): Promise<TrashItem[]> => {
  try {
    const res = await client.get<TrashItem[]>('/picloud/trash')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const restoreFromTrash = async (trashId: string): Promise<void> => {
  try {
    await client.post(`/picloud/trash/${trashId}/restore`)
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const deleteFromTrash = async (trashId: string): Promise<void> => {
  try {
    await client.delete(`/picloud/trash/${trashId}`)
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const emptyTrash = async (): Promise<void> => {
  try {
    await client.delete('/picloud/trash/empty')
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Activity ===

export const getActivity = async (limit = 50): Promise<ActivityItem[]> => {
  try {
    const res = await client.get<ActivityItem[]>('/picloud/activity', { params: { limit } })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Duplicates ===

export const findDuplicates = async (): Promise<DuplicateGroup[]> => {
  try {
    const res = await client.get<DuplicateGroup[]>('/picloud/duplicates')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Bulk Operations ===

export const bulkDelete = async (fileIds: string[]): Promise<BulkOperationResult> => {
  try {
    const res = await client.post<BulkOperationResult>('/picloud/bulk/delete', { file_ids: fileIds })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const bulkMove = async (fileIds: string[], targetPath: string): Promise<BulkOperationResult> => {
  try {
    const res = await client.post<BulkOperationResult>('/picloud/bulk/move', {
      file_ids: fileIds,
      target_path: targetPath,
    })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const bulkCopy = async (fileIds: string[], targetPath: string): Promise<BulkOperationResult> => {
  try {
    const res = await client.post<BulkOperationResult>('/picloud/bulk/copy', {
      file_ids: fileIds,
      target_path: targetPath,
    })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const bulkFavorite = async (fileIds: string[], value: boolean): Promise<BulkOperationResult> => {
  try {
    const res = await client.post<BulkOperationResult>('/picloud/bulk/favorite', {
      file_ids: fileIds,
      value,
    })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// === Telegram Bot ===

export const getTelegramStatus = async (): Promise<TelegramBotStatus> => {
  try {
    const res = await client.get<TelegramBotStatus>('/picloud/telegram/status')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const configureTelegramBot = async (config: TelegramBotConfig): Promise<TelegramBotStatus> => {
  try {
    const res = await client.post<TelegramBotStatus>('/picloud/telegram/config', config)
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const startTelegramBot = async (): Promise<void> => {
  try {
    await client.post('/picloud/telegram/start')
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const stopTelegramBot = async (): Promise<void> => {
  try {
    await client.post('/picloud/telegram/stop')
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const testTelegramBot = async (): Promise<{ success: boolean; message: string }> => {
  try {
    const res = await client.post('/picloud/telegram/test')
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getTelegramUploads = async (limit = 20): Promise<TelegramUpload[]> => {
  try {
    const res = await client.get<TelegramUpload[]>('/picloud/telegram/uploads', { params: { limit } })
    return res.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const removeTelegramUser = async (userId: number): Promise<void> => {
  try {
    await client.delete(`/picloud/telegram/user/${userId}`)
  } catch (error) {
    handleError(error)
    throw error
  }
}
