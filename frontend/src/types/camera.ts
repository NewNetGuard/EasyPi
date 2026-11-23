export interface Camera {
  id: string
  name: string
  ip: string
  port: number
  username: string
  hasAuth: boolean // password not exposed
  hasPtzAuth?: boolean // dedicated PTZ/ONVIF credentials configured (secret not exposed)
  ptzUsername?: string
  rtspPath: string // e.g. /stream1
  brand?: string
  model?: string
  location?: string
  status: 'online' | 'offline' | 'recording' | 'error'
  lastSeen?: string
  createdAt: string
  updatedAt: string
}

export interface CameraStatus {
  cameraId: string
  recording: boolean
  since?: string
  fileSize?: string
  status: 'active' | 'inactive' | 'failed'
  lastFrame?: string
  health: CameraHealth
}

export interface CameraHealth {
  status: 'healthy' | 'degraded' | 'unhealthy'
  checks: {
    network: 'ok' | 'error'
    rtspStream: 'ok' | 'error'
    recordingService: 'active' | 'inactive' | 'failed'
    diskSpace: 'ok' | 'warning' | 'critical'
    lastFrame: string
  }
}

export interface Recording {
  id: string
  cameraId: string
  cameraName: string
  startTime: string
  endTime: string
  duration: number // seconds
  fileSize: number // bytes
  hasMotion: boolean
  locked?: boolean // user "kept" it -> excluded from auto-cleanup
  thumbnail?: string
  events: RecordingEvent[]
}

export interface RecordingEvent {
  id: string
  type: 'motion' | 'offline' | 'online' | 'manual'
  timestamp: string
  metadata?: Record<string, any>
}

export interface CameraEvent {
  id: string
  cameraId: string
  cameraName: string
  type: 'motion' | 'offline' | 'online' | 'storage_full' | 'recording_started' | 'recording_stopped'
  timestamp: string
  message: string
  metadata?: Record<string, any>
  notified: boolean
  snapshot?: string
}

export interface CameraStats {
  totalCameras: number
  online: number
  offline: number
  recording: number
  storage: {
    total: string
    used: string
    free: string
    percent: number
  }
  recordings: {
    total: number
    today: number
    size: string
  }
  eventsToday: {
    motion: number
    offline: number
    online: number
  }
}

export interface CameraSettings {
  storageLocation: string
  retentionDays: number
  autoCleanup: boolean
  motionDetection: {
    enabled: boolean
    sensitivity: number
    notifyEmail: boolean
    notifyTelegram: boolean
    notifyBrowser: boolean
    cooldownMinutes: number
  }
  offlineNotify: {
    enabled: boolean
    retryAttempts: number
  }
  storageFull: {
    enabled: boolean
    thresholdPercent: number
    autoCleanup: boolean
  }
}

export interface AddCameraPayload {
  name: string
  ip: string
  port: number
  username: string
  password: string
  rtspPath: string
  brand?: string
  model?: string
  location?: string
  ptzUsername?: string
  ptzPassword?: string
  onvifPort?: number
}

export interface UpdateCameraPayload {
  name?: string
  ip?: string
  port?: number
  username?: string
  password?: string // only if changed
  rtspPath?: string
  brand?: string
  model?: string
  location?: string
  ptzUsername?: string
  ptzPassword?: string // only if changed
}

export interface RecordingsFilter {
  cameraId?: string
  date?: string
  startTime?: string
  endTime?: string
  eventsOnly?: boolean
  sort?: 'newest' | 'oldest'
  limit?: number
  offset?: number
}
