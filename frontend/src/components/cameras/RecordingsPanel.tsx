import { useState, useEffect } from 'react'
import { Video, Play, Trash2, Calendar, HardDrive, X, Download, Lock, Unlock, AlertTriangle } from 'lucide-react'
import {
  useRecordings,
  useDeleteRecording,
  useRecordingsStorage,
  useSetRecordingProtected,
} from '../../hooks/useCameras'
import { Recording } from '../../types/camera'
import Button from '../common/Button'

interface RecordingsPanelProps {
  cameraId?: string
}

const formatDuration = (seconds: number): string => {
  const hrs = Math.floor(seconds / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60
  if (hrs > 0) {
    return `${hrs}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`
  }
  return `${mins}:${secs.toString().padStart(2, '0')}`
}

const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

const formatDate = (isoString: string): string => {
  const date = new Date(isoString)
  return date.toLocaleDateString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  })
}

const formatTime = (isoString: string): string => {
  const date = new Date(isoString)
  return date.toLocaleTimeString('ru-RU', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

const RecordingsPanel = ({ cameraId }: RecordingsPanelProps) => {
  const [selectedRecording, setSelectedRecording] = useState<Recording | null>(null)
  const [videoModalOpen, setVideoModalOpen] = useState(false)
  
  const { data: recordings = [], isLoading, refetch } = useRecordings(
    cameraId ? { cameraId } : undefined
  )
  const deleteRecording = useDeleteRecording()
  const { data: storage } = useRecordingsStorage()
  const setProtected = useSetRecordingProtected()

  // Auto-refresh recordings when component mounts (tab becomes active)
  useEffect(() => {
    refetch()
  }, [refetch])

  const handleToggleLock = async (rec: Recording) => {
    await setProtected.mutateAsync({ id: rec.id, locked: !rec.locked })
    refetch()
  }

  const handleDownload = (rec: Recording) => {
    // The stream endpoint carries the session, so a plain anchor download works
    // and lets the browser stream large files instead of buffering them.
    const a = document.createElement('a')
    a.href = getStreamUrl(rec.id)
    a.download = `${rec.cameraName}_${rec.startTime}.mp4`.replace(/[^\w.-]+/g, '_')
    document.body.appendChild(a)
    a.click()
    a.remove()
  }

  const handlePlay = (recording: Recording) => {
    setSelectedRecording(recording)
    setVideoModalOpen(true)
  }

  const handleDelete = async (recording: Recording) => {
    if (confirm(`Delete recording from ${recording.cameraName} on ${formatDate(recording.startTime)}?`)) {
      await deleteRecording.mutateAsync(recording.id)
      refetch()
    }
  }

  const getStreamUrl = (recordingId: string) => {
    return `/api/v1/cameras/recordings/${recordingId}/stream`
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-500 border-t-transparent" />
      </div>
    )
  }

  if (recordings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-gray-500">
        <Video className="h-12 w-12 mb-4" />
        <p>No recordings yet</p>
      </div>
    )
  }

  // Group by date
  const groupedByDate: Record<string, Recording[]> = {}
  for (const rec of recordings) {
    const date = formatDate(rec.startTime)
    if (!groupedByDate[date]) {
      groupedByDate[date] = []
    }
    groupedByDate[date].push(rec)
  }

  return (
    <div className="space-y-6">
      {/* Storage warning banner */}
      {storage?.warning && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-800/50 dark:bg-amber-900/20">
          <AlertTriangle className="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-500" />
          <div>
            <p className="font-medium text-amber-800 dark:text-amber-300">Storage {Math.round(storage.used_pct)}% full</p>
            <p className="text-amber-700 dark:text-amber-400/90">
              The oldest <span className="font-medium">unlocked</span> recordings will be auto-deleted to keep about {Math.round(storage.min_free_pct)}% of the disk free.
              Press <span className="font-medium">Keep</span> or download any you want to save.
            </p>
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-gray-500">
        <span className="flex items-center gap-1">
          <Video className="h-4 w-4" />
          {recordings.length} recordings
        </span>
        <span className="flex items-center gap-1">
          <HardDrive className="h-4 w-4" />
          {formatFileSize(recordings.reduce((sum, r) => sum + r.fileSize, 0))}
        </span>
        {storage && (
          <span title="Auto-cleanup keeps a free margin so recordings never fill the disk">
            Disk {Math.round(storage.used_pct)}% used · {Math.round(storage.free_pct)}% free
          </span>
        )}
        {storage && storage.protected_count > 0 && (
          <span className="flex items-center gap-1 text-primary-600 dark:text-primary-400">
            <Lock className="h-3.5 w-3.5" />
            {storage.protected_count} kept
          </span>
        )}
      </div>

      {/* Recordings list grouped by date */}
      {Object.entries(groupedByDate).map(([date, recs]) => (
        <div key={date} className="space-y-3">
          <h3 className="flex items-center gap-2 text-sm font-medium text-gray-600 dark:text-gray-400">
            <Calendar className="h-4 w-4" />
            {date}
          </h3>
          <div className="space-y-2">
            {recs.map((rec) => (
              <div
                key={rec.id}
                className="flex items-center justify-between rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900"
              >
                <div className="flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gray-100 dark:bg-dark-800">
                    <Video className="h-6 w-6 text-gray-500" />
                  </div>
                  <div>
                    <p className="flex items-center gap-1.5 font-medium text-gray-900 dark:text-white">
                      {rec.cameraName}
                      {rec.locked && (
                        <span className="inline-flex items-center gap-0.5 rounded bg-primary-100 px-1.5 py-0.5 text-[10px] font-medium text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">
                          <Lock className="h-3 w-3" /> Kept
                        </span>
                      )}
                    </p>
                    <p className="text-sm text-gray-500">
                      {formatTime(rec.startTime)} • {formatDuration(rec.duration)} • {formatFileSize(rec.fileSize)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    icon={<Play className="h-4 w-4" />}
                    onClick={() => handlePlay(rec)}
                  >
                    Watch
                  </Button>
                  <Button
                    variant={rec.locked ? 'primary' : 'ghost'}
                    size="sm"
                    title={rec.locked ? 'Unlock — allow auto-cleanup to delete it' : 'Keep — never auto-delete this recording'}
                    icon={rec.locked ? <Lock className="h-4 w-4" /> : <Unlock className="h-4 w-4" />}
                    onClick={() => handleToggleLock(rec)}
                  >
                    {rec.locked ? 'Kept' : 'Keep'}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    title="Download to your device"
                    icon={<Download className="h-4 w-4" />}
                    onClick={() => handleDownload(rec)}
                  >
                    {' '}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20"
                    icon={<Trash2 className="h-4 w-4" />}
                    onClick={() => handleDelete(rec)}
                  >
                    {' '}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Video Modal */}
      {videoModalOpen && selectedRecording && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
          <div className="relative w-full max-w-4xl mx-4">
            <button
              onClick={() => {
                setVideoModalOpen(false)
                setSelectedRecording(null)
              }}
              className="absolute -top-12 right-0 text-white hover:text-gray-300"
            >
              <X className="h-8 w-8" />
            </button>
            <div className="rounded-2xl overflow-hidden bg-black">
              <video
                src={getStreamUrl(selectedRecording.id)}
                controls
                autoPlay
                className="w-full aspect-video"
              />
              <div className="p-4 bg-gray-900 text-white">
                <h3 className="font-medium">{selectedRecording.cameraName}</h3>
                <p className="text-sm text-gray-400">
                  {formatDate(selectedRecording.startTime)} {formatTime(selectedRecording.startTime)} • 
                  {formatDuration(selectedRecording.duration)} • 
                  {formatFileSize(selectedRecording.fileSize)}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default RecordingsPanel
