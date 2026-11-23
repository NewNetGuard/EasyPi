import { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { useQueryClient } from '@tanstack/react-query'
import { Upload, X, CheckCircle, AlertCircle, Loader2, FolderOpen } from 'lucide-react'
import Modal from '../common/Modal'
import Button from '../common/Button'
import ProgressBar from '../common/ProgressBar'
import { uploadFile } from '../../api/cloud'
import { useCloudStore } from '../../stores/cloudStore'
import clsx from 'clsx'

interface UploadModalProps {
  isOpen: boolean
  onClose: () => void
}

interface UploadItem {
  id: string
  file: File
  status: 'queued' | 'uploading' | 'completed' | 'error'
  progress: number
  error?: string
}

const UploadModal = ({ isOpen, onClose }: UploadModalProps) => {
  const queryClient = useQueryClient()
  const { currentPath } = useCloudStore()
  const [uploads, setUploads] = useState<UploadItem[]>([])
  const [targetPath, setTargetPath] = useState(currentPath)
  const [autoOrganize, setAutoOrganize] = useState(true)
  
  const onDrop = useCallback((acceptedFiles: File[]) => {
    const newUploads: UploadItem[] = acceptedFiles.map((file) => ({
      id: `${Date.now()}-${file.name}`,
      file,
      status: 'queued',
      progress: 0,
    }))
    setUploads((prev) => [...prev, ...newUploads])
  }, [])
  
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxSize: 2 * 1024 * 1024 * 1024, // 2GB
  })
  
  const removeUpload = (id: string) => {
    setUploads((prev) => prev.filter((u) => u.id !== id))
  }
  
  const startUpload = async (uploadItem: UploadItem) => {
    setUploads((prev) =>
      prev.map((u) => (u.id === uploadItem.id ? { ...u, status: 'uploading' as const } : u))
    )
    
    try {
      await uploadFile(targetPath, uploadItem.file, (progress) => {
        setUploads((prev) =>
          prev.map((u) => (u.id === uploadItem.id ? { ...u, progress } : u))
        )
      })
      
      setUploads((prev) =>
        prev.map((u) =>
          u.id === uploadItem.id ? { ...u, status: 'completed' as const, progress: 100 } : u
        )
      )
      
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-stats'] })
    } catch (error) {
      setUploads((prev) =>
        prev.map((u) =>
          u.id === uploadItem.id
            ? { ...u, status: 'error' as const, error: (error as Error).message }
            : u
        )
      )
    }
  }
  
  const startAllUploads = async () => {
    const queuedUploads = uploads.filter((u) => u.status === 'queued')
    for (const upload of queuedUploads) {
      await startUpload(upload)
    }
  }
  
  const clearCompleted = () => {
    setUploads((prev) => prev.filter((u) => u.status !== 'completed'))
  }
  
  const formatSize = (bytes: number) => {
    const k = 1024
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${['B', 'KB', 'MB', 'GB'][i]}`
  }
  
  const totalSize = uploads.reduce((acc, u) => acc + u.file.size, 0)
  const queuedCount = uploads.filter((u) => u.status === 'queued').length
  const uploadingCount = uploads.filter((u) => u.status === 'uploading').length
  const completedCount = uploads.filter((u) => u.status === 'completed').length
  // const errorCount = uploads.filter((u) => u.status === 'error').length
  
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Upload Files"
      size="xl"
      footer={
        <div className="flex items-center justify-between w-full">
          <div className="text-sm text-gray-600 dark:text-gray-400">
            {uploads.length > 0 && (
              <span>
                {completedCount}/{uploads.length} completed • {formatSize(totalSize)} total
              </span>
            )}
          </div>
          <div className="flex gap-2">
            {completedCount > 0 && (
              <Button variant="ghost" onClick={clearCompleted}>
                Clear Completed
              </Button>
            )}
            {queuedCount > 0 && (
              <Button onClick={startAllUploads} loading={uploadingCount > 0}>
                Upload {queuedCount} {queuedCount === 1 ? 'File' : 'Files'}
              </Button>
            )}
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      }
    >
      <div className="space-y-4">
        {/* Drop zone */}
        <div
          {...getRootProps()}
          className={clsx(
            'rounded-lg border-2 border-dashed p-8 text-center transition-colors cursor-pointer',
            isDragActive
              ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/10'
              : 'border-gray-300 dark:border-dark-700 hover:border-gray-400'
          )}
        >
          <input {...getInputProps()} />
          <Upload className="mx-auto h-12 w-12 text-gray-400 mb-3" />
          {isDragActive ? (
            <p className="text-base font-medium text-primary-600 dark:text-primary-400">
              Drop files here...
            </p>
          ) : (
            <div>
              <p className="text-base font-medium text-gray-900 dark:text-white mb-1">
                Drag & drop files here
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                or click to browse
              </p>
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-3">
                Any file type: APK, archives, documents, media, and more • Max 2GB per file
              </p>
            </div>
          )}
        </div>
        
        {/* Upload options */}
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
              <FolderOpen className="inline h-4 w-4 mr-1" />
              Upload to:
            </label>
            <input
              type="text"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              className="input w-full"
              placeholder="/path/to/folder"
            />
          </div>
          <div className="flex items-center gap-2 pt-6">
            <input
              type="checkbox"
              id="auto-organize"
              checked={autoOrganize}
              onChange={(e) => setAutoOrganize(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
            />
            <label htmlFor="auto-organize" className="text-sm text-gray-700 dark:text-gray-300">
              Auto-organize
            </label>
          </div>
        </div>
        
        {/* Upload list */}
        {uploads.length > 0 && (
          <div className="max-h-96 space-y-2 overflow-y-auto rounded-lg border border-gray-200 dark:border-dark-700 p-3">
            {uploads.map((upload) => (
              <div
                key={upload.id}
                className="flex items-center gap-3 rounded-lg bg-gray-50 dark:bg-dark-800 p-3"
              >
                {/* Status icon */}
                <div className="flex-shrink-0">
                  {upload.status === 'queued' && (
                    <div className="h-8 w-8 rounded-full bg-gray-200 dark:bg-dark-700 flex items-center justify-center">
                      <Upload className="h-4 w-4 text-gray-500" />
                    </div>
                  )}
                  {upload.status === 'uploading' && (
                    <div className="h-8 w-8 rounded-full bg-primary-100 dark:bg-primary-900/20 flex items-center justify-center">
                      <Loader2 className="h-4 w-4 text-primary-600 animate-spin" />
                    </div>
                  )}
                  {upload.status === 'completed' && (
                    <div className="h-8 w-8 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
                      <CheckCircle className="h-4 w-4 text-green-600" />
                    </div>
                  )}
                  {upload.status === 'error' && (
                    <div className="h-8 w-8 rounded-full bg-red-100 dark:bg-red-900/20 flex items-center justify-center">
                      <AlertCircle className="h-4 w-4 text-red-600" />
                    </div>
                  )}
                </div>
                
                {/* File info */}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between">
                    <p className="truncate text-sm font-medium text-gray-900 dark:text-white">
                      {upload.file.name}
                    </p>
                    <span className="ml-2 text-xs text-gray-500">
                      {formatSize(upload.file.size)}
                    </span>
                  </div>
                  
                  {upload.status === 'uploading' && (
                    <div className="mt-1">
                      <ProgressBar progress={upload.progress} size="sm" />
                    </div>
                  )}
                  
                  {upload.status === 'error' && upload.error && (
                    <p className="mt-1 text-xs text-red-600">{upload.error}</p>
                  )}
                </div>
                
                {/* Remove button */}
                {upload.status !== 'uploading' && (
                  <button
                    onClick={() => removeUpload(upload.id)}
                    className="flex-shrink-0 rounded p-1 text-gray-400 hover:bg-gray-200 hover:text-gray-600 dark:hover:bg-dark-700"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </Modal>
  )
}

export default UploadModal
