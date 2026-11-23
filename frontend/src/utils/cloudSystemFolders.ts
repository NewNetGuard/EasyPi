import type { PiCloudFile } from '../types/cloud'

const SYSTEM_CLOUD_ROOT_FOLDERS = new Set([
  'Videos',
  'Music',
  'Documents',
  'Encrypt',
  'Encrypted',
  'Photos',
  'Files',
])

const normalizeCloudId = (fileId: string): string =>
  fileId.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '')

export const isSystemCloudFolderId = (fileId: string): boolean => {
  const normalized = normalizeCloudId(fileId)
  if (normalized.startsWith('_category_')) return true
  return !normalized.includes('/') && SYSTEM_CLOUD_ROOT_FOLDERS.has(normalized)
}

export const isSystemCloudFolder = (file: PiCloudFile): boolean =>
  file.type === 'folder' && isSystemCloudFolderId(file.id)
