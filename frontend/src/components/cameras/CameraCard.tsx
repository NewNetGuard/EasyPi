import { Camera } from '../../types/camera'
import { Video, Circle, Wifi, WifiOff, MoreVertical, Play, Pause, X } from 'lucide-react'
import { useCameraStatus, useCameraSnapshot } from '../../hooks/useCameras'
import { useState } from 'react'

interface CameraCardProps {
  camera: Camera
  onView: (camera: Camera) => void
  onEdit: (camera: Camera) => void
  onDelete: (camera: Camera) => void
  onToggleRecording: (camera: Camera, start: boolean) => void
}

const CameraCard = ({ camera, onView, onEdit, onDelete, onToggleRecording }: CameraCardProps) => {
  const [menuOpen, setMenuOpen] = useState(false)
  const { data: status } = useCameraStatus(camera.id)
  
  const isOnline = camera.status === 'online' || camera.status === 'recording'
  const isRecording = status?.recording || camera.status === 'recording'
  
  // Only fetch snapshot for online cameras
  const { data: snapshotUrl, isLoading: snapshotLoading } = useCameraSnapshot(camera.id, isOnline)

  return (
    <div className="group relative rounded-2xl border border-gray-200 bg-white shadow-sm transition hover:shadow-md dark:border-dark-700 dark:bg-dark-900">
      {/* Превью */}
      <div className="relative aspect-video cursor-pointer overflow-hidden rounded-t-2xl bg-gray-900" onClick={() => onView(camera)}>
        {snapshotUrl ? (
          <img src={snapshotUrl} alt={camera.name} className="h-full w-full object-cover" />
        ) : (
          <div className="flex h-full flex-col items-center justify-center gap-2">
            {!isOnline ? (
              <>
                <WifiOff className="h-12 w-12 text-gray-600" />
                <span className="text-sm text-gray-500">Camera Offline</span>
              </>
            ) : snapshotLoading ? (
              <>
                <Video className="h-12 w-12 animate-pulse text-gray-600" />
                <span className="text-sm text-gray-500">Loading...</span>
              </>
            ) : (
              <>
                <Video className="h-12 w-12 text-gray-600" />
                <span className="text-sm text-gray-500">No Preview</span>
              </>
            )}
          </div>
        )}

        {/* Статус overlay */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent opacity-0 transition group-hover:opacity-100" />

        {/* Recording индикатор */}
        {isRecording && (
          <div className="absolute left-3 top-3 flex items-center gap-2 rounded-full bg-red-500 px-3 py-1 text-xs font-semibold text-white">
            <Circle className="h-2 w-2 animate-pulse fill-current" />
            REC
          </div>
        )}

        {/* Online/Offline badge */}
        <div className="absolute right-3 top-3">
          {isOnline ? (
            <div className="flex items-center gap-1 rounded-full bg-green-500 px-2 py-1 text-xs font-semibold text-white">
              <Wifi className="h-3 w-3" />
              Online
            </div>
          ) : (
            <div className="flex items-center gap-1 rounded-full bg-gray-500 px-2 py-1 text-xs font-semibold text-white">
              <WifiOff className="h-3 w-3" />
              Offline
            </div>
          )}
        </div>

        {/* Play button overlay */}
        <div className="absolute inset-0 flex items-center justify-center opacity-0 transition group-hover:opacity-100">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-white/90 shadow-lg">
            <Play className="h-8 w-8 text-gray-900" />
          </div>
        </div>
      </div>

      {/* Инфо */}
      <div className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <h3 className="font-semibold text-gray-900 dark:text-white truncate">{camera.name}</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {camera.ip}:{camera.port}
            </p>
            {camera.location && <p className="mt-1 text-xs text-gray-400 truncate">{camera.location}</p>}
          </div>

          {/* Menu */}
          <div className="relative flex-shrink-0 ml-2">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="rounded-lg p-2 hover:bg-gray-100 dark:hover:bg-dark-800"
            >
              <MoreVertical className="h-5 w-5 text-gray-500" />
            </button>

            {menuOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setMenuOpen(false)} />
                <div className="absolute right-0 bottom-full mb-2 z-50 w-48 rounded-xl border border-gray-200 bg-white py-2 shadow-xl dark:border-dark-700 dark:bg-dark-800">
                  <button
                    onClick={() => {
                      onView(camera)
                      setMenuOpen(false)
                    }}
                    className="w-full px-4 py-2.5 text-left text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 flex items-center gap-2"
                  >
                    <Play className="h-4 w-4" />
                    View Live
                  </button>
                  <button
                    onClick={() => {
                      onToggleRecording(camera, !isRecording)
                      setMenuOpen(false)
                    }}
                    className="w-full px-4 py-2.5 text-left text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 flex items-center gap-2"
                  >
                    {isRecording ? (
                      <>
                        <Pause className="h-4 w-4" />
                        Stop Recording
                      </>
                    ) : (
                      <>
                        <Circle className="h-4 w-4 text-red-500" />
                        Start Recording
                      </>
                    )}
                  </button>
                  <button
                    onClick={() => {
                      onEdit(camera)
                      setMenuOpen(false)
                    }}
                    className="w-full px-4 py-2.5 text-left text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 flex items-center gap-2"
                  >
                    <MoreVertical className="h-4 w-4" />
                    Edit Settings
                  </button>
                  <div className="my-1 border-t border-gray-200 dark:border-dark-700" />
                  <button
                    onClick={() => {
                      onDelete(camera)
                      setMenuOpen(false)
                    }}
                    className="w-full px-4 py-2.5 text-left text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center gap-2"
                  >
                    <X className="h-4 w-4" />
                    Delete Camera
                  </button>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Recording status */}
        {status && isRecording && (
          <div className="mt-3 rounded-lg bg-gray-50 p-2 text-xs dark:bg-dark-800">
            <div className="flex justify-between">
              <span className="text-gray-500">Recording since:</span>
              <span className="font-semibold text-gray-900 dark:text-white">
                {status.since ? new Date(status.since).toLocaleTimeString() : 'N/A'}
              </span>
            </div>
            {status.fileSize && (
              <div className="mt-1 flex justify-between">
                <span className="text-gray-500">Current file:</span>
                <span className="font-semibold text-gray-900 dark:text-white">{status.fileSize}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default CameraCard
