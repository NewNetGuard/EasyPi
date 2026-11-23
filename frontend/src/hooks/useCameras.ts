import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../api/client'
import type {
  Camera,
  CameraStatus,
  CameraHealth,
  Recording,
  CameraEvent,
  CameraStats,
  CameraSettings,
  AddCameraPayload,
  UpdateCameraPayload,
  RecordingsFilter
} from '../types/camera'

const API_BASE = '/cameras'

// ============================================================================
// Cameras CRUD
// ============================================================================

export const useCameras = () => {
  return useQuery({
    queryKey: ['cameras'],
    queryFn: async (): Promise<Camera[]> => {
      const { data } = await api.get(API_BASE)
      return data
    },
    refetchInterval: 10000 // Refresh every 10 seconds
  })
}

export const useCamera = (id: string) => {
  return useQuery({
    queryKey: ['cameras', id],
    queryFn: async (): Promise<Camera> => {
      const { data } = await api.get(`${API_BASE}/${id}`)
      return data
    },
    enabled: !!id
  })
}

export const useAddCamera = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: AddCameraPayload): Promise<Camera> => {
      const { data } = await api.post(API_BASE, payload)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cameras'] })
      queryClient.invalidateQueries({ queryKey: ['camera-stats'] })
    }
  })
}

export const useUpdateCamera = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, payload }: { id: string; payload: UpdateCameraPayload }): Promise<Camera> => {
      const { data } = await api.patch(`${API_BASE}/${id}`, payload)
      return data
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['cameras'] })
      queryClient.invalidateQueries({ queryKey: ['cameras', variables.id] })
    }
  })
}

export const useDeleteCamera = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await api.delete(`${API_BASE}/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cameras'] })
      queryClient.invalidateQueries({ queryKey: ['camera-stats'] })
    }
  })
}

// ============================================================================
// Camera Status & Health
// ============================================================================

export const useCameraStatus = (id: string) => {
  return useQuery({
    queryKey: ['cameras', id, 'status'],
    queryFn: async (): Promise<CameraStatus> => {
      const { data } = await api.get(`${API_BASE}/${id}/status`)
      return data
    },
    enabled: !!id,
    refetchInterval: 5000 // Refresh every 5 seconds
  })
}

export const useCameraHealth = (id: string) => {
  return useQuery({
    queryKey: ['cameras', id, 'health'],
    queryFn: async (): Promise<CameraHealth> => {
      const { data } = await api.get(`${API_BASE}/${id}/health`)
      return data
    },
    enabled: !!id,
    refetchInterval: 30000 // Every 30 seconds
  })
}

// ============================================================================
// Service Control
// ============================================================================

export const useStartRecording = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await api.post(`${API_BASE}/${id}/service/start`)
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['cameras', id, 'status'] })
    }
  })
}

export const useStopRecording = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await api.post(`${API_BASE}/${id}/service/stop`)
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['cameras', id, 'status'] })
    }
  })
}

export const useRestartRecording = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await api.post(`${API_BASE}/${id}/service/restart`)
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['cameras', id, 'status'] })
    }
  })
}

// ============================================================================
// Snapshot
// ============================================================================

export const useCameraSnapshot = (id: string, isOnline: boolean = true) => {
  return useQuery({
    queryKey: ['cameras', id, 'snapshot'],
    queryFn: async (): Promise<string> => {
      const { data } = await api.get(`${API_BASE}/${id}/snapshot`, {
        responseType: 'blob'
      })
      return URL.createObjectURL(data)
    },
    // Only fetch if camera is online
    enabled: !!id && isOnline,
    refetchInterval: false,
    staleTime: 60000, // 1 minute
    // go2rtc may still be opening its listeners immediately after a camera is
    // added or edited. Retry a bounded number of times instead of leaving the
    // card permanently on "No Preview" after one transient 503 response.
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(1000 * (2 ** attemptIndex), 4000),
    retryOnMount: true
  })
}

// ============================================================================
// Recordings
// ============================================================================

export const useRecordings = (filter?: RecordingsFilter) => {
  return useQuery({
    queryKey: ['recordings', filter],
    queryFn: async (): Promise<Recording[]> => {
      const { data } = await api.get(`${API_BASE}/recordings`, { params: filter })
      return data
    }
  })
}

export const useRecording = (id: string) => {
  return useQuery({
    queryKey: ['recordings', id],
    queryFn: async (): Promise<Recording> => {
      const { data } = await api.get(`${API_BASE}/recordings/${id}`)
      return data
    },
    enabled: !!id
  })
}

export const useDeleteRecording = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await api.delete(`${API_BASE}/recordings/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['recordings'] })
      queryClient.invalidateQueries({ queryKey: ['camera-stats'] })
    }
  })
}

export interface RecordingsStorage {
  used_pct: number
  free_pct: number
  min_free_pct: number
  guard_enabled: boolean
  warning: boolean
  total_bytes: number
  free_bytes: number
  recordings_bytes: number
  recordings_count: number
  protected_count: number
  retention_days: number
}

export const useRecordingsStorage = () => {
  return useQuery({
    queryKey: ['recordings-storage'],
    queryFn: async (): Promise<RecordingsStorage> => {
      const { data } = await api.get(`${API_BASE}/recordings/storage`)
      return data
    },
    refetchInterval: 60_000,
  })
}

// Lock ("keep") or unlock a recording so auto-cleanup never / can delete it.
export const useSetRecordingProtected = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, locked }: { id: string; locked: boolean }): Promise<void> => {
      if (locked) await api.post(`${API_BASE}/recordings/${id}/protect`)
      else await api.delete(`${API_BASE}/recordings/${id}/protect`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['recordings'] })
      queryClient.invalidateQueries({ queryKey: ['recordings-storage'] })
    },
  })
}

// ============================================================================
// Events
// ============================================================================

export const useCameraEvents = (cameraId?: string) => {
  return useQuery({
    queryKey: cameraId ? ['cameras', cameraId, 'events'] : ['camera-events'],
    queryFn: async (): Promise<CameraEvent[]> => {
      const url = cameraId ? `${API_BASE}/${cameraId}/events` : `${API_BASE}/events`
      const { data } = await api.get(url)
      return data
    },
    refetchInterval: 15000 // Every 15 seconds
  })
}

export const useClearEvents = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (cameraId?: string): Promise<void> => {
      const url = cameraId ? `${API_BASE}/${cameraId}/events/clear` : `${API_BASE}/events/clear`
      await api.post(url)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera-events'] })
      queryClient.invalidateQueries({ queryKey: ['cameras'] })
    }
  })
}

// ============================================================================
// Stats & Settings
// ============================================================================

export const useCameraStats = () => {
  return useQuery({
    queryKey: ['camera-stats'],
    queryFn: async (): Promise<CameraStats> => {
      const { data } = await api.get(`${API_BASE}/stats`)
      return data
    },
    refetchInterval: 30000 // Every 30 seconds
  })
}

export const useCameraSettings = () => {
  return useQuery({
    queryKey: ['camera-settings'],
    queryFn: async (): Promise<CameraSettings> => {
      const { data } = await api.get(`${API_BASE}/settings`)
      return data
    }
  })
}

export const useUpdateCameraSettings = () => {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (settings: Partial<CameraSettings>): Promise<CameraSettings> => {
      const { data } = await api.patch(`${API_BASE}/settings`, settings)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera-settings'] })
    }
  })
}
