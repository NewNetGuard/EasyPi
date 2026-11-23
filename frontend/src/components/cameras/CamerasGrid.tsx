import { Camera } from '../../types/camera'
import CameraCard from './CameraCard'

interface CamerasGridProps {
  cameras: Camera[]
  onView: (camera: Camera) => void
  onEdit: (camera: Camera) => void
  onDelete: (camera: Camera) => void
  onToggleRecording: (camera: Camera, start: boolean) => void
}

const CamerasGrid = ({ cameras, onView, onEdit, onDelete, onToggleRecording }: CamerasGridProps) => {
  if (cameras.length === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-gray-300 bg-gray-50 p-12 text-center dark:border-dark-700 dark:bg-dark-800">
        <p className="text-lg font-semibold text-gray-900 dark:text-white">No cameras yet</p>
        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
          Add your first IP camera to start monitoring and recording
        </p>
      </div>
    )
  }

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
      {cameras.map((camera) => (
        <CameraCard
          key={camera.id}
          camera={camera}
          onView={onView}
          onEdit={onEdit}
          onDelete={onDelete}
          onToggleRecording={onToggleRecording}
        />
      ))}
    </div>
  )
}

export default CamerasGrid
