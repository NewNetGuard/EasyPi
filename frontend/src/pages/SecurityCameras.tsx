import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Camera as CameraIcon, Plus, Activity, HardDrive, AlertTriangle, Video, Grid } from 'lucide-react'
import { useCameras, useAddCamera, useUpdateCamera, useDeleteCamera, useStartRecording, useStopRecording, useCameraStats } from '../hooks/useCameras'
import { Camera } from '../types/camera'
import CamerasGrid from '../components/cameras/CamerasGrid'
import LiveViewModal from '../components/cameras/LiveViewModal'
import AddCameraModal from '../components/cameras/AddCameraModal'
import EditCameraModal from '../components/cameras/EditCameraModal'
import RecordingsPanel from '../components/cameras/RecordingsPanel'
import Button from '../components/common/Button'
import type { AddCameraPayload } from '../types/camera'

const cameraMutationError = (error: unknown): string | null => {
  if (!error || typeof error !== 'object') return null
  const response = (error as { response?: { data?: unknown } }).response
  if (!response?.data || typeof response.data !== 'object') return 'Failed to add camera.'
  const detail = (response.data as { detail?: unknown }).detail
  if (typeof detail === 'string' && detail.trim()) return detail
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0]
    if (first && typeof first === 'object' && 'msg' in first) return String(first.msg)
  }
  return 'Failed to add camera.'
}

const SecurityCameras = () => {
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedCamera, setSelectedCamera] = useState<Camera | null>(null)
  const [liveViewOpen, setLiveViewOpen] = useState(false)
  const [liveViewSession, setLiveViewSession] = useState(0)
  const [addModalOpen, setAddModalOpen] = useState(false)
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [editingCamera, setEditingCamera] = useState<Camera | null>(null)
  const activeTab: 'cameras' | 'recordings' = searchParams.get('tab') === 'recordings' ? 'recordings' : 'cameras'
  const setActiveTab = (tab: 'cameras' | 'recordings') => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', tab)
    setSearchParams(next, { replace: true })
  }

  const { data: cameras = [], isLoading } = useCameras()
  const { data: stats } = useCameraStats()
  const addCamera = useAddCamera()
  const updateCamera = useUpdateCamera()
  const deleteCamera = useDeleteCamera()
  const startRecording = useStartRecording()
  const stopRecording = useStopRecording()

  const handleView = (camera: Camera) => {
    setSelectedCamera(camera)
    setLiveViewSession((current) => current + 1)
    setLiveViewOpen(true)
  }

  const handleEdit = (camera: Camera) => {
    setEditingCamera(camera)
    setEditModalOpen(true)
  }

  const handleDelete = (camera: Camera) => {
    if (confirm(`Are you sure you want to delete ${camera.name}?`)) {
      deleteCamera.mutate(camera.id)
    }
  }

  const handleToggleRecording = (camera: Camera, start: boolean) => {
    if (start) {
      startRecording.mutate(camera.id)
    } else {
      stopRecording.mutate(camera.id)
    }
  }

  const handleAddCamera = (payload: AddCameraPayload) => {
    addCamera.mutate(payload, {
      onSuccess: () => {
        setAddModalOpen(false)
      }
    })
  }

  const handleUpdateCamera = (id: string, payload: any) => {
    updateCamera.mutate({ id, payload }, {
      onSuccess: () => {
        setEditModalOpen(false)
        setEditingCamera(null)
      }
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
            <Video className="h-6 w-6 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Security Cameras</h1>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Monitor and record your IP cameras in real-time</p>
          </div>
        </div>
        <Button variant="primary" icon={<Plus className="h-4 w-4" />} onClick={() => { addCamera.reset(); setAddModalOpen(true) }}>
          Add Camera
        </Button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {/* Total Cameras */}
          <div className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Total Cameras</p>
                <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-white">{stats.totalCameras}</p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary-50 dark:bg-primary-900/20">
                <CameraIcon className="h-6 w-6 text-primary-600 dark:text-primary-400" />
              </div>
            </div>
          </div>

          {/* Online/Offline */}
          <div className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Status</p>
                <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.online}/{stats.totalCameras}
                </p>
                <p className="text-xs text-gray-400">{stats.offline} offline</p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-green-50 dark:bg-green-900/20">
                <Activity className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
            </div>
          </div>

          {/* Recording */}
          <div className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Recording</p>
                <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-white">{stats.recording}</p>
                <p className="text-xs text-gray-400">{stats.recordings.today} today</p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-50 dark:bg-red-900/20">
                <div className="h-3 w-3 animate-pulse rounded-full bg-red-600" />
              </div>
            </div>
          </div>

          {/* Storage */}
          <div className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Storage Used</p>
                <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-white">{stats.storage.percent}%</p>
                <p className="text-xs text-gray-400">
                  {stats.storage.used} / {stats.storage.total}
                </p>
              </div>
              <div
                className={`flex h-12 w-12 items-center justify-center rounded-xl ${
                  stats.storage.percent > 90
                    ? 'bg-red-50 dark:bg-red-900/20'
                    : stats.storage.percent > 70
                    ? 'bg-amber-50 dark:bg-amber-900/20'
                    : 'bg-blue-50 dark:bg-blue-900/20'
                }`}
              >
                {stats.storage.percent > 90 ? (
                  <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
                ) : (
                  <HardDrive className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-gray-200 dark:border-dark-700">
        <button
          onClick={() => setActiveTab('cameras')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'cameras'
              ? 'border-primary-500 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
          }`}
        >
          <Grid className="h-4 w-4" />
          Cameras
        </button>
        <button
          onClick={() => setActiveTab('recordings')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'recordings'
              ? 'border-primary-500 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
          }`}
        >
          <Video className="h-4 w-4" />
          Recordings
        </button>
      </div>

      {/* Content */}
      {activeTab === 'cameras' ? (
        /* Cameras Grid */
        isLoading ? (
          <div className="flex h-64 items-center justify-center">
            <div className="text-center">
              <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
              <p className="mt-4 text-sm text-gray-500">Loading cameras...</p>
            </div>
          </div>
        ) : (
          <CamerasGrid
            cameras={cameras}
            onView={handleView}
            onEdit={handleEdit}
            onDelete={handleDelete}
            onToggleRecording={handleToggleRecording}
          />
        )
      ) : (
        /* Recordings Panel */
        <RecordingsPanel />
      )}

      {/* Modals */}
      <LiveViewModal
        key={`${selectedCamera?.id ?? 'none'}-${liveViewSession}`}
        camera={selectedCamera}
        isOpen={liveViewOpen}
        onClose={() => setLiveViewOpen(false)}
      />
      <AddCameraModal
        isOpen={addModalOpen}
        onClose={() => setAddModalOpen(false)}
        onSubmit={handleAddCamera}
        isLoading={addCamera.isPending}
        submitError={cameraMutationError(addCamera.error)}
      />
      <EditCameraModal
        camera={editingCamera}
        isOpen={editModalOpen}
        onClose={() => {
          setEditModalOpen(false)
          setEditingCamera(null)
        }}
        onSubmit={handleUpdateCamera}
        isLoading={updateCamera.isPending}
      />
    </div>
  )
}

export default SecurityCameras
