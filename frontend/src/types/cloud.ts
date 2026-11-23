// File types
export type FileCategory = 'all' | 'photos' | 'videos' | 'documents' | 'audio' | 'archives' | 'encrypted' | 'other'

// Color labels
export type ColorLabel = 'none' | 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'purple' | 'gray'

// Access levels
export type AccessLevel = 'private' | 'public' | 'password'

// Sorting
export type SortField = 'name' | 'size' | 'modified' | 'type'
export type SortOrder = 'asc' | 'desc'

export interface PiCloudFile {
  id: string
  name: string
  path: string
  mime?: string | null
  type: 'folder' | 'file'
  size: number
  modified: string
  created?: string
  extension?: string | null
  favorite?: boolean
  tags?: string[]
  colorLabel?: ColorLabel
  thumbnail?: boolean
  thumbnailUrl?: string | null
  category?: FileCategory
  // For media files
  width?: number | null
  height?: number | null
  duration?: number | null // for video/audio in seconds
  // Telegram
  uploadedViaTelegram?: boolean
  telegramUserId?: number | null
}

export interface FileListResponse {
  path: string
  items: PiCloudFile[]
  totalCount: number
  hasMore: boolean
}

export interface StorageStats {
  total: number
  used: number
  free: number
  percent: number
  fileCount: number
  folderCount: number
}

export interface UsageByType {
  photos: number
  videos: number
  documents: number
  audio: number
  archives: number
  other: number
}

export interface ShareLink {
  id: string
  url: string
  fileId: string
  fileName: string
  expiresAt?: string | null
  password?: string | null
  accessCount: number
  maxAccess?: number | null
  qrBase64?: string | null
  embedCode?: string | null
  createdAt: string
}

export interface UploadProgress {
  fileId: string
  fileName: string
  fileSize: number
  progress: number // 0-100
  status: 'queued' | 'uploading' | 'processing' | 'completed' | 'error'
  error?: string
  speed?: number // bytes per second
  eta?: number // seconds remaining
}

export interface UploadResponse {
  uploaded: PiCloudFile[]
  failed: Array<{ name: string; error: string }>
}

export interface TrashItem {
  id: string
  original: string
  deleted_at: string
}

export interface FileMetadata {
  name: string
  path: string
  size: number
  mime?: string | null
  modified: string
  created?: string
  width?: number | null
  height?: number | null
  duration?: number | null
  // EXIF data for photos
  exif?: {
    camera?: string
    lens?: string
    aperture?: string
    shutterSpeed?: string
    iso?: string
    focalLength?: string
    dateTaken?: string
    gps?: {
      latitude: number
      longitude: number
      altitude?: number
    }
    [key: string]: any
  } | null
  // Audio metadata
  audio?: {
    title?: string
    artist?: string
    album?: string
    year?: string
    genre?: string
    bitrate?: number
    sampleRate?: number
  } | null
  // Video metadata
  video?: {
    codec?: string
    bitrate?: number
    fps?: number
    audioCodec?: string
    audioBitrate?: number
  } | null
}

export interface Folder {
  id: string
  name: string
  path: string
  parentPath: string
  itemCount: number
  size: number
  modified: string
  created: string
  colorLabel?: ColorLabel
}

export interface FolderTree {
  id: string
  name: string
  path: string
  children: FolderTree[]
  itemCount: number
}

// Telegram Bot
export interface TelegramBotConfig {
  token: string
  allowedUserIds: number[]
  autoOrganize: boolean
  notifyOnUpload: boolean
  maxFileSize: number // in bytes
  uploadFolder: string
}

export interface TelegramBotStatus {
  enabled: boolean
  configured: boolean
  connected: boolean
  botUsername?: string
  lastActivity?: string
  totalUploads: number
  storageUsed: number
  message?: string
  authorizedUsers: Array<{
    id: number
    username?: string
    firstName?: string
    lastUpload?: string
    uploadCount: number
  }>
}

export interface TelegramUpload {
  id: string
  fileId: string
  fileName: string
  fileSize: number
  telegramUserId: number
  telegramUsername?: string
  uploadedAt: string
  storagePath: string
}

// Activity/History
export interface ActivityItem {
  id: string
  action: 'upload' | 'download' | 'delete' | 'move' | 'rename' | 'share' | 'favorite' | 'tag'
  fileId?: string
  fileName: string
  filePath?: string
  details?: string
  timestamp: string
  source: 'web' | 'telegram' | 'api'
}

// Bulk operations
export interface BulkOperationResult {
  success: string[]
  failed: Array<{ id: string; error: string }>
}

// Duplicate detection
export interface DuplicateGroup {
  hash: string
  size: number
  files: PiCloudFile[]
}
