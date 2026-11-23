import { Suspense, lazy, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, FolderPlus, RefreshCw, FolderInput, FolderLock, Eye, EyeOff, Menu, Search, X, Box, Tag } from 'lucide-react'
import { toast } from 'react-hot-toast'

// Components
import Sidebar from '../components/picloud/Sidebar'
import BreadcrumbNav from '../components/picloud/BreadcrumbNav'
import FilterBar from '../components/picloud/FilterBar'
import FileGrid from '../components/picloud/FileGrid'
import FileList from '../components/picloud/FileList'
import UploadModal from '../components/picloud/UploadModal'
import ContextMenu from '../components/picloud/ContextMenu'
import FolderPickerModal from '../components/picloud/FolderPickerModal'
import Button from '../components/common/Button'
import Card from '../components/common/Card'
import Modal from '../components/common/Modal'

// API & Store
import { useCloudStore } from '../stores/cloudStore'
import {
  listFiles,
  deleteFile,
  bulkDelete,
  toggleFavorite,
  createFolder,
  renameOrMove,
  copyFile,
  uploadFile,
  setColorLabel,
  setTags,
  fetchAuthenticatedBlob,
  buildVideoUrl,
  fetchAuthenticatedThumbnailBlob,
  revokeBlobUrl,
} from '../api/cloud'
import type { PiCloudFile, ColorLabel } from '../types/cloud'
import { 
  decryptFileWithMetadata,
  isEncryptedFile,
} from '../utils/encryption'
import { isSystemCloudFolder, isSystemCloudFolderId } from '../utils/cloudSystemFolders'
import { getCloudPreviewKind, isCloudFilePreviewable } from '../utils/cloudPreview'

const ShareModal = lazy(() => import('../components/picloud/ShareModal'))
const TelegramBotView = lazy(() => import('../components/picloud/TelegramBotView'))
const TrashView = lazy(() => import('../components/picloud/TrashView'))
const ImageViewer = lazy(() => import('../components/picloud/viewers/ImageViewer'))
const VideoPlayer = lazy(() => import('../components/picloud/viewers/VideoPlayer'))
const AudioPlayer = lazy(() => import('../components/picloud/viewers/AudioPlayer'))
const DocumentViewer = lazy(() => import('../components/picloud/viewers/DocumentViewer'))
const EncryptFileModal = lazy(() => import('../components/picloud/EncryptFileModal'))

const CloudDeferredFallback = ({ label = 'Loading...' }: { label?: string }) => (
  <div className="flex min-h-[12rem] items-center justify-center text-sm text-gray-500 dark:text-gray-400">
    {label}
  </div>
)

const legacyDecryptedName = (name: string): string => {
  if (name.endsWith('.encrypted')) return name.slice(0, -10)
  if (name.endsWith('.epec')) return name.slice(0, -5) || 'decrypted-file'
  return `${name}.decrypted`
}

const safeDecryptedName = (name: string | null, fallback: string): string => {
  const leaf = name?.replace(/\\/g, '/').split('/').pop()?.trim()
  return leaf && leaf !== '.' && leaf !== '..' ? leaf : fallback
}

const safeCloudRestorePath = (path: string | null, fallback: string): string => {
  if (!path) return fallback
  const normalized = path.replace(/\\/g, '/').replace(/\/+/g, '/')
  if (!normalized.startsWith('/')) return fallback
  const parts = normalized.split('/').filter(Boolean)
  if (parts.some((part) => part === '.' || part === '..')) return fallback
  return parts.length ? `/${parts.join('/')}` : '/'
}

const cloudChildPath = (parent: string, name: string): string => {
  const normalizedParent = parent.replace(/\\/g, '/').replace(/\/+$/g, '')
  return `${normalizedParent}/${name}`.replace(/\/{2,}/g, '/')
}

const copyName = (file: PiCloudFile): string => {
  if (file.type === 'folder') return `${file.name} copy`
  const dot = file.name.lastIndexOf('.')
  if (dot <= 0) return `${file.name} copy`
  return `${file.name.slice(0, dot)} copy${file.name.slice(dot)}`
}

const PiCloud = () => {
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const {
    currentPath,
    category,
    searchQuery,
    sortBy,
    sortOrder,
    viewMode,
    uploadModalOpen,
    openUploadModal,
    closeUploadModal,
    selectedFiles,
    clearSelection,
  } = useCloudStore()
  
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [previewFile, setPreviewFile] = useState<PiCloudFile | null>(null)
  const [previewBlobUrl, setPreviewBlobUrl] = useState<string | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewText, setPreviewText] = useState<string | null>(null)
  const [previewKind, setPreviewKind] = useState<'file' | 'text' | 'markdown' | 'document-image'>('file')
  const [shareFile, setShareFile] = useState<PiCloudFile | null>(null)
  const [tagFile, setTagFile] = useState<PiCloudFile | null>(null)
  const [tagInput, setTagInput] = useState('')
  const [folderPickerOpen, setFolderPickerOpen] = useState(false)
  const [contextMenu, setContextMenu] = useState<{
    file: PiCloudFile
    x: number
    y: number
  } | null>(null)
  const [encryptionModalOpen, setEncryptionModalOpen] = useState(false)
  const [decryptPrompt, setDecryptPrompt] = useState<{
    file: PiCloudFile
    action: 'preview' | 'download' | 'decrypt'
  } | null>(null)
  const [decryptPassword, setDecryptPassword] = useState('')
  const [decryptError, setDecryptError] = useState<string | null>(null)
  const [decryptWorking, setDecryptWorking] = useState(false)
  const [showDecryptPassword, setShowDecryptPassword] = useState(false)

  useEffect(() => {
    const activeSection = currentPath === '/telegram'
      ? 'telegram'
      : currentPath === '/.trash'
        ? 'trash'
        : currentPath === '/recent'
          ? 'recent'
          : category === 'all'
            ? 'files'
            : category
    if (searchParams.get('tab') === activeSection) return
    const next = new URLSearchParams(searchParams)
    next.set('tab', activeSection)
    setSearchParams(next, { replace: true })
  }, [category, currentPath, searchParams, setSearchParams])
  
  // Fetch files from server with auto-refresh every 10 seconds
  const { data: filesData, isLoading, isFetching, refetch, error } = useQuery({
    queryKey: ['picloud-files', currentPath, category, sortBy, sortOrder],
    queryFn: () => listFiles(currentPath, {
      category: category,
      sortBy,
      sortOrder,
    }),
    refetchInterval: 10000, // Auto-refresh every 10 seconds
    refetchIntervalInBackground: false, // Don't refresh when tab is not active
  })

  const handleRefresh = async () => {
    try {
      const [filesResult] = await Promise.all([
        refetch(),
        queryClient.refetchQueries({ queryKey: ['picloud-stats'], type: 'active' }),
        queryClient.refetchQueries({ queryKey: ['picloud-folder-tree'], type: 'active' }),
      ])

      if (filesResult.error) throw filesResult.error
    } catch (refreshError) {
      console.error('Failed to refresh cloud data:', refreshError)
      toast.error('Failed to refresh Cloud')
    }
  }
  
  // Client-side search filtering
  const filteredItems = useMemo(() => {
    if (!filesData?.items) return []
    if (!searchQuery.trim()) return filesData.items
    
    const query = searchQuery.toLowerCase().trim()
    return filesData.items.filter(file => 
      file.name.toLowerCase().includes(query)
    )
  }, [filesData?.items, searchQuery])
  
  // Mutations
  const deleteMutation = useMutation({
    mutationFn: deleteFile,
    onSuccess: () => {
      toast.success('File deleted')
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-stats'] })
    },
    onError: () => toast.error('Failed to delete file'),
  })
  
  const bulkDeleteMutation = useMutation({
    mutationFn: bulkDelete,
    onSuccess: ({ success, failed }) => {
      success.forEach(useCloudStore.getState().deselectFile)
      if (success.length) toast.success(`${success.length} items moved to Trash`)
      if (failed.length) toast.error(`Could not delete ${failed.length} items`)
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-stats'] })
    },
    onError: () => toast.error('Failed to delete selected items'),
  })

  const favoriteMutation = useMutation({
    mutationFn: ({ id, value }: { id: string; value: boolean }) => toggleFavorite(id, value),
    onSuccess: () => {
      toast.success('Favorite updated')
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
    },
    onError: () => toast.error('Failed to update favorite'),
  })
  
  const createFolderMutation = useMutation({
    mutationFn: createFolder,
    onSuccess: () => {
      toast.success('Folder created')
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-folder-tree'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-stats'] })
    },
    onError: () => toast.error('Failed to create folder'),
  })
  
  const renameMutation = useMutation({
    mutationFn: ({ id, newPath }: { id: string; newPath: string }) => renameOrMove(id, newPath),
    onSuccess: () => {
      toast.success('File renamed')
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
    },
    onError: () => toast.error('Failed to rename file'),
  })
  
  const moveMutation = useMutation({
    mutationFn: ({ id, newPath }: { id: string; newPath: string }) => renameOrMove(id, newPath),
    onSuccess: () => {
      toast.success('File moved')
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
    },
    onError: () => toast.error('Failed to move file'),
  })
  
  const copyMutation = useMutation({
    mutationFn: ({ id, newPath }: { id: string; newPath: string }) => copyFile(id, newPath),
    onSuccess: () => {
      toast.success('File copied')
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
    },
    onError: () => toast.error('Failed to copy file'),
  })
  
  const colorLabelMutation = useMutation({
    mutationFn: ({ id, color }: { id: string; color: ColorLabel }) => setColorLabel(id, color),
    onSuccess: () => {
      toast.success('Color label updated')
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
    },
    onError: () => toast.error('Failed to update color label'),
  })

  const tagMutation = useMutation({
    mutationFn: ({ id, tags }: { id: string; tags: string[] }) => setTags(id, tags),
    onSuccess: () => {
      toast.success('Tags updated')
      setTagFile(null)
      setTagInput('')
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
    },
    onError: () => toast.error('Failed to update tags'),
  })
  
  // Handlers
  const isEncryptedName = (file: PiCloudFile): boolean =>
    file.extension === '.encrypted' || file.extension === '.epec' ||
    file.name.endsWith('.encrypted') || file.name.endsWith('.epec')

  const openDecryptPrompt = (file: PiCloudFile, action: 'preview' | 'download' | 'decrypt') => {
    setDecryptPassword('')
    setDecryptError(null)
    setShowDecryptPassword(false)
    setDecryptPrompt({ file, action })
  }

  const closeDecryptPrompt = () => {
    setDecryptPrompt(null)
    setDecryptPassword('')
    setDecryptError(null)
    setShowDecryptPassword(false)
    setDecryptWorking(false)
  }

  const performEncryptedPreview = async (file: PiCloudFile, password: string) => {
    if (previewBlobUrl) {
      revokeBlobUrl(previewBlobUrl)
      setPreviewBlobUrl(null)
    }

    setPreviewLoading(true)

    try {
      const blob = await fetchAuthenticatedBlob(file.id)
      const { blob: decryptedBlob, metadata } = await decryptFileWithMetadata(
        blob, file.mime || 'application/octet-stream', password,
      )
      const recoveredName = safeDecryptedName(metadata.originalName, legacyDecryptedName(file.name))
      const recoveredFile = {
        ...file,
        name: recoveredName,
        mime: metadata.originalMime,
        extension: recoveredName.includes('.') ? `.${recoveredName.split('.').pop()?.toLowerCase()}` : null,
      }
      setPreviewFile(recoveredFile)
      setPreviewKind(getCloudPreviewKind(recoveredFile))
      const decryptedUrl = URL.createObjectURL(decryptedBlob)
      setPreviewBlobUrl(decryptedUrl)
    } catch (error) {
      console.error('Decryption failed:', error)
      setPreviewFile(null)
      throw error
    } finally {
      setPreviewLoading(false)
    }
  }

  const performEncryptedDownload = async (file: PiCloudFile, password: string) => {
    try {
      const blob = await fetchAuthenticatedBlob(file.id)
      const { blob: downloadBlob, metadata } = await decryptFileWithMetadata(
        blob, file.mime || 'application/octet-stream', password,
      )
      const downloadName = safeDecryptedName(metadata.originalName, legacyDecryptedName(file.name))

      const downloadUrl = URL.createObjectURL(downloadBlob)
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = downloadName
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)

      setTimeout(() => {
        URL.revokeObjectURL(downloadUrl)
      }, 1000)
    } catch (error) {
      console.error('Decryption failed:', error)
      throw error
    }
  }

  const performDecryptToCloud = async (file: PiCloudFile, password: string) => {
    toast.loading('Decrypting file...', { id: 'decrypt-progress' })

    try {
      const blob = await fetchAuthenticatedBlob(file.id)
      const { blob: decryptedBlob, metadata } = await decryptFileWithMetadata(
        blob, file.mime || 'application/octet-stream', password,
      )
      const decryptedName = safeDecryptedName(metadata.originalName, legacyDecryptedName(file.name))
      const uploadPath = safeCloudRestorePath(metadata.originalParentPath, getParentPath(file.id))
      const decryptedFile = new File([decryptedBlob], decryptedName, {
        type: metadata.originalMime || decryptedBlob.type || 'application/octet-stream',
      })

      await uploadFile(uploadPath, decryptedFile)
      toast.success('Decrypted copy saved', { id: 'decrypt-progress' })
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-stats'] })
    } catch (error) {
      console.error('Decrypt to cloud failed:', error)
      toast.dismiss('decrypt-progress')
      throw error
    }
  }

  const handlePreview = async (file: PiCloudFile) => {
    if (!isCloudFilePreviewable(file)) return

    if (isEncryptedName(file)) {
      openDecryptPrompt(file, 'preview')
      return
    }
    
    // Clean up previous blob URL if exists
    if (previewBlobUrl) {
      revokeBlobUrl(previewBlobUrl)
      setPreviewBlobUrl(null)
    }
    
    setPreviewFile(file)
    setPreviewLoading(true)
    setPreviewText(null)
    const nextPreviewKind = getCloudPreviewKind(file)
    setPreviewKind(nextPreviewKind)

    if (file.category === 'videos' || file.mime?.startsWith('video/')) {
      setPreviewBlobUrl(buildVideoUrl(file.id))
      setPreviewLoading(false)
      return
    }
    
    try {
      // Fetch once through the authenticated same-origin API. Inspect the Blob
      // before creating its display URL so strict CSP remains unchanged.
      const blob = nextPreviewKind === 'document-image'
        ? await fetchAuthenticatedThumbnailBlob(file.id)
        : await fetchAuthenticatedBlob(file.id)

      if (nextPreviewKind === 'document-image') {
        setPreviewBlobUrl(URL.createObjectURL(blob))
        return
      }
      
      if (await isEncryptedFile(blob)) {
        openDecryptPrompt(file, 'preview')
        return
      }
      if (nextPreviewKind === 'text' || nextPreviewKind === 'markdown') {
        const previewBytes = blob.slice(0, 2 * 1024 * 1024)
        const text = await previewBytes.text()
        setPreviewText(blob.size > previewBytes.size ? `${text}\n\n[Preview truncated]` : text)
      } else {
        setPreviewBlobUrl(URL.createObjectURL(blob))
      }
    } catch (error) {
      console.error('Failed to load file preview:', error)
      toast.error('Failed to load file preview')
      setPreviewFile(null)
    } finally {
      setPreviewLoading(false)
    }
  }
  
  const handleFavorite = (file: PiCloudFile) => {
    favoriteMutation.mutate({ id: file.id, value: !file.favorite })
  }
  
  const handleShare = (file: PiCloudFile) => {
    setShareFile(file)
  }
  
  const handleDelete = (file: PiCloudFile) => {
    if (isSystemCloudFolder(file)) {
      toast.error('System folders cannot be deleted')
      return
    }
    if (confirm(`Delete "${file.name}"?`)) {
      deleteMutation.mutate(file.id)
    }
  }
  
  const handleContextMenu = (file: PiCloudFile, e: React.MouseEvent) => {
    e.preventDefault()
    setContextMenu({ file, x: e.clientX, y: e.clientY })
  }
  
  const handleRename = (file: PiCloudFile) => {
    const newName = prompt('New name:', file.name)
    if (newName && newName !== file.name) {
      // Build new path with the new name
      const pathParts = file.id.split('/')
      pathParts[pathParts.length - 1] = newName
      const newPath = pathParts.join('/')
      renameMutation.mutate({ id: file.id, newPath })
    }
  }
  
  const handleMove = (file: PiCloudFile) => {
    const newPath = prompt('Move to full path:', cloudChildPath(currentPath, file.name))
    if (newPath && newPath !== file.id) {
      moveMutation.mutate({ id: file.id, newPath })
    }
  }
  
  const handleCopy = (file: PiCloudFile) => {
    const newPath = prompt('Copy to full path:', cloudChildPath(currentPath, copyName(file)))
    if (newPath) {
      copyMutation.mutate({ id: file.id, newPath })
    }
  }
  
  const handleColorLabel = (file: PiCloudFile, color: ColorLabel) => {
    colorLabelMutation.mutate({ id: file.id, color })
  }
  
  const handleTag = (file: PiCloudFile) => {
    setTagFile(file)
    setTagInput((file.tags || []).join(', '))
  }

  const saveTags = () => {
    if (!tagFile) return
    const tags = Array.from(new Set(
      tagInput
        .split(',')
        .map((tag) => tag.trim().replace(/\s+/g, ' '))
        .filter(Boolean),
    ))
    if (tags.length > 20) {
      toast.error('A file can have at most 20 tags')
      return
    }
    if (tags.some((tag) => tag.length > 32)) {
      toast.error('Each tag must be 32 characters or fewer')
      return
    }
    tagMutation.mutate({ id: tagFile.id, tags })
  }
  
  const handleDownload = async (file: PiCloudFile) => {
    if (isEncryptedName(file)) {
      openDecryptPrompt(file, 'download')
      return
    }

    try {
      const blob = await fetchAuthenticatedBlob(file.id)
      
      if (await isEncryptedFile(blob)) {
        openDecryptPrompt(file, 'download')
        return
      }
      
      // Create download link
      const downloadUrl = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = file.name
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      
      // Clean up blob URLs
      setTimeout(() => {
        URL.revokeObjectURL(downloadUrl)
      }, 1000)
    } catch (error) {
      console.error('Download failed:', error)
      toast.error('Failed to download file')
    }
  }

  const handleDownloadEncrypted = async (file: PiCloudFile) => {
    try {
      const blob = await fetchAuthenticatedBlob(file.id)

      if (!(await isEncryptedFile(blob))) {
        toast.error('This file is not encrypted')
        return
      }

      const downloadUrl = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = isEncryptedName(file) ? file.name : `${file.name}.encrypted`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)

      setTimeout(() => {
        URL.revokeObjectURL(downloadUrl)
      }, 1000)
    } catch (error) {
      console.error('Encrypted download failed:', error)
      toast.error('Failed to download encrypted file')
    }
  }

  const getParentPath = (fileId: string): string => {
    const parts = fileId.split('/').filter(Boolean)
    if (parts.length <= 1) {
      return '/'
    }
    return `/${parts.slice(0, -1).join('/')}`
  }

  const handleDecryptInCloud = async (file: PiCloudFile) => {
    if (file.type === 'folder') return
    if (isEncryptedName(file)) {
      openDecryptPrompt(file, 'decrypt')
      return
    }

    toast.error('This file is not encrypted')
  }
  
  const handleCreateFolder = () => {
    const name = prompt('Folder name:')
    if (name) {
      const path = `${currentPath}/${name}`.replace('//', '/')
      createFolderMutation.mutate(path)
    }
  }
  
  const handleBulkDelete = () => {
    const deletableIds = Array.from(selectedFiles).filter((fileId) => !isSystemCloudFolderId(fileId))
    if (deletableIds.length === 0 || bulkDeleteMutation.isPending) return
    if (confirm(`Delete ${deletableIds.length} files?`)) {
      bulkDeleteMutation.mutate(deletableIds)
    }
  }
  
  const handleBulkMove = (targetPath: string) => {
    if (selectedFiles.size === 0) return
    Array.from(selectedFiles).forEach((fileId) => {
      // Get just the filename from the file ID
      const fileName = fileId.split('/').pop() || ''
      // Normalize target path - remove trailing slash if any
      const normalizedTarget = targetPath.endsWith('/') && targetPath !== '/' 
        ? targetPath.slice(0, -1) 
        : targetPath
      // Build new path properly
      const newPath = normalizedTarget === '/' 
        ? `/${fileName}` 
        : `${normalizedTarget}/${fileName}`
      
      moveMutation.mutate({ id: fileId, newPath })
    })
    clearSelection()
    setFolderPickerOpen(false)
  }
  
  // Preview modal
  const closePreview = () => {
    // Clean up blob URL when closing preview
    if (previewBlobUrl) {
      revokeBlobUrl(previewBlobUrl)
      setPreviewBlobUrl(null)
    }
    setPreviewFile(null)
    setPreviewLoading(false)
    setPreviewText(null)
    setPreviewKind('file')
  }
  
  const renderPreview = () => {
    if (!previewFile) return null
    
    // Show loading state while fetching authenticated blob
    if (previewLoading) {
      return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
          <div className="text-center text-white">
            <div className="animate-spin rounded-full h-12 w-12 border-4 border-white border-t-transparent mx-auto mb-4" />
            <p>Loading preview...</p>
          </div>
          <button
            onClick={closePreview}
            className="absolute top-4 right-4 text-white hover:text-gray-300"
          >
            <X className="h-6 w-6" />
          </button>
        </div>
      )
    }
    
    if ((previewKind === 'text' || previewKind === 'markdown') && previewText !== null) {
      return (
        <Suspense fallback={<CloudDeferredFallback label="Loading document viewer..." />}>
          <DocumentViewer
            type={previewKind === 'markdown' ? 'markdown' : 'text'}
            src=""
            content={previewText}
            onClose={closePreview}
          />
        </Suspense>
      )
    }

    // Use authenticated blob URL instead of direct URL
    if (!previewBlobUrl) return null

    if (previewKind === 'document-image') {
      return (
        <Suspense fallback={<CloudDeferredFallback label="Loading document viewer..." />}>
          <DocumentViewer type="image" src={previewBlobUrl} onClose={closePreview} />
        </Suspense>
      )
    }
    
    const effectiveName = previewFile.name.endsWith('.encrypted')
      ? previewFile.name.slice(0, -10)
      : previewFile.name
    const ext = effectiveName.includes('.')
      ? `.${effectiveName.split('.').pop()?.toLowerCase() || ''}`
      : (previewFile.extension || '').toLowerCase()

    const imageExts = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'])
    const videoExts = new Set(['.mp4', '.webm', '.mov', '.mkv', '.avi'])
    const audioExts = new Set(['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.opus'])

    if (previewFile.category === 'photos' || imageExts.has(ext)) {
      return (
        <Suspense fallback={<CloudDeferredFallback label="Loading image viewer..." />}>
          <ImageViewer images={[previewBlobUrl]} onClose={closePreview} />
        </Suspense>
      )
    } else if (previewFile.category === 'videos' || previewFile.mime?.startsWith('video/') || videoExts.has(ext)) {
      return (
        <Suspense fallback={<CloudDeferredFallback label="Loading video player..." />}>
          <VideoPlayer src={previewBlobUrl} onClose={closePreview} />
        </Suspense>
      )
    } else if (previewFile.category === 'audio' || audioExts.has(ext)) {
      return (
        <Suspense fallback={<CloudDeferredFallback label="Loading audio player..." />}>
          <AudioPlayer src={previewBlobUrl} onClose={closePreview} />
        </Suspense>
      )
    } else if (previewFile.mime === 'application/pdf' || ext === '.pdf') {
      return (
        <Suspense fallback={<CloudDeferredFallback label="Loading document viewer..." />}>
          <DocumentViewer type="pdf" src={previewBlobUrl} onClose={closePreview} />
        </Suspense>
      )
    } else if (ext === '.md') {
      return (
        <Suspense fallback={<CloudDeferredFallback label="Loading document viewer..." />}>
          <DocumentViewer type="markdown" src={previewBlobUrl} onClose={closePreview} />
        </Suspense>
      )
    } else if (previewFile.category === 'documents' || ext === '.txt') {
      return (
        <Suspense fallback={<CloudDeferredFallback label="Loading document viewer..." />}>
          <DocumentViewer type="text" src={previewBlobUrl} onClose={closePreview} />
        </Suspense>
      )
    }
    
    return null
  }
  
  return (
    <div className="flex h-screen overflow-hidden bg-gray-50 dark:bg-dark-950">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      
      {/* Sidebar */}
      <div className={`
        fixed lg:static inset-y-0 left-0 z-50 
        transform transition-transform duration-300 ease-in-out
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        <Sidebar onItemClick={() => setSidebarOpen(false)} />
      </div>
      
      {/* Main Content */}
      <main className="flex flex-1 flex-col overflow-hidden">
        {/* Show Telegram Bot View if path is /telegram */}
        {currentPath === '/telegram' ? (
          <div className="flex-1 overflow-auto">
            <Suspense fallback={<CloudDeferredFallback label="Loading Telegram view..." />}>
              <TelegramBotView />
            </Suspense>
          </div>
        ) : currentPath === '/.trash' ? (
          <div className="flex-1 overflow-auto">
            <Suspense fallback={<CloudDeferredFallback label="Loading trash..." />}>
              <TrashView />
            </Suspense>
          </div>
        ) : (
          <>
            {/* Header */}
            <header className="border-b border-gray-200 dark:border-dark-800 bg-white dark:bg-dark-900 px-3 sm:px-6 py-3 sm:py-4">
              {/* Mobile menu button */}
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="lg:hidden p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-800 mb-3"
              >
                {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
              </button>
              
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
                    <Box className="h-6 w-6 text-primary-600 dark:text-primary-400" />
                  </div>
                  <div>
                    <h1 className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white">Cloud</h1>
                    <p className="text-xs sm:text-sm text-gray-500 dark:text-gray-400">Personal cloud storage</p>
                  </div>
                </div>
                
                <div className="flex items-center gap-2 flex-wrap">
                  {selectedFiles.size > 0 && (
                    <>
                      <span className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">
                        {selectedFiles.size} selected
                      </span>
                      <Button 
                        variant="outline" 
                        size="sm" 
                        icon={<FolderInput className="h-4 w-4" />}
                        onClick={() => setFolderPickerOpen(true)}
                      >
                        <span className="hidden sm:inline">Move to</span>
                      </Button>
                      <Button variant="danger" size="sm" onClick={handleBulkDelete} disabled={bulkDeleteMutation.isPending}>
                        Delete
                      </Button>
                      <Button variant="outline" size="sm" onClick={clearSelection}>
                        Clear
                      </Button>
                    </>
                  )}
                  
                  <Button
                    variant="outline"
                    size="sm"
                    icon={<RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />}
                    onClick={() => void handleRefresh()}
                    disabled={isFetching}
                    aria-label="Refresh Cloud"
                  >
                    <span className="hidden sm:inline">{isFetching ? 'Refreshing...' : 'Refresh'}</span>
                  </Button>
                  
                  <Button
                    variant="outline"
                    size="sm"
                    icon={<FolderLock className="h-4 w-4" />}
                    onClick={() => setEncryptionModalOpen(true)}
                    title="Encrypt a file"
                  >
                    <span className="hidden md:inline">Encrypt</span>
                  </Button>
                  
                  <Button
                    variant="outline"
                    size="sm"
                    icon={<FolderPlus className="h-4 w-4" />}
                    onClick={handleCreateFolder}
                  >
                    <span className="hidden md:inline">New Folder</span>
                  </Button>
                  
                  <Button icon={<Upload className="h-4 w-4" />} onClick={openUploadModal}>
                    <span className="hidden sm:inline">Upload</span>
                  </Button>
                </div>
              </div>
              
              <BreadcrumbNav />
            </header>
            
            {/* Filter Bar */}
            <div className="border-b border-gray-200 dark:border-dark-800 bg-white dark:bg-dark-900 px-3 sm:px-6 py-3">
              <FilterBar />
            </div>
            
            {/* Files Content */}
            <div className="flex-1 overflow-y-auto p-3 sm:p-6">
              {isLoading ? (
                <Card className="flex items-center justify-center h-64">
                  <div className="text-center">
                    <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent mb-4"></div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Loading files...</p>
                  </div>
                </Card>
          ) : filteredItems.length > 0 ? (
            viewMode === 'grid' ? (
              <FileGrid
                files={filteredItems}
                onPreview={handlePreview}
                onFavorite={handleFavorite}
                onShare={handleShare}
                onDelete={handleDelete}
                onContextMenu={handleContextMenu}
              />
            ) : (
              <FileList
                files={filteredItems}
                onPreview={handlePreview}
                onFavorite={handleFavorite}
                onShare={handleShare}
                onDelete={handleDelete}
                onContextMenu={handleContextMenu}
              />
            )
          ) : (
            <Card className="flex items-center justify-center h-64">
              <div className="text-center">
                <div className="mb-4 flex justify-center">
                  {searchQuery ? (
                    <Search className="h-12 w-12 text-gray-300 dark:text-gray-600" />
                  ) : category === 'encrypted' ? (
                    <FolderLock className="h-12 w-12 text-gray-300 dark:text-gray-600" />
                  ) : (
                    <FolderPlus className="h-12 w-12 text-gray-300 dark:text-gray-600" />
                  )}
                </div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  {searchQuery
                    ? 'No matching files'
                    : category === 'encrypted'
                      ? 'No encrypted files yet'
                      : 'No files found'}
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                  {searchQuery
                    ? `No files match "${searchQuery}"`
                    : category === 'encrypted'
                      ? 'Use "Encrypt File" to add encrypted files to this section'
                      : 'Get started by uploading some files'}
                </p>
                {!searchQuery && category !== 'encrypted' && (
                  <Button icon={<Upload className="h-4 w-4" />} onClick={openUploadModal}>
                    Upload Files
                  </Button>
                )}
              </div>
            </Card>
          )}
          
          {/* Pagination info */}
          {filesData && filesData.totalCount > 0 && (
            <div className="mt-6 text-center text-sm text-gray-500 dark:text-gray-400">
              Showing {filesData.items.length} of {filesData.totalCount} files
              {filesData.hasMore && (
                <button className="ml-2 text-primary-600 hover:underline">Load more</button>
              )}
            </div>
          )}
        </div>
          </>
        )}
      </main>
      
      {/* Modals */}
      <UploadModal isOpen={uploadModalOpen} onClose={closeUploadModal} />
      
      <Suspense fallback={null}>
        <ShareModal file={shareFile} isOpen={shareFile !== null} onClose={() => setShareFile(null)} />
      </Suspense>

      <Modal
        isOpen={tagFile !== null}
        onClose={() => {
          setTagFile(null)
          setTagInput('')
        }}
        title="Manage Tags"
        size="sm"
        footer={(
          <div className="flex justify-end gap-3">
            <Button
              variant="outline"
              onClick={() => {
                setTagFile(null)
                setTagInput('')
              }}
            >
              Cancel
            </Button>
            <Button loading={tagMutation.isPending} onClick={saveTags}>Save Tags</Button>
          </div>
        )}
      >
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-sm font-medium text-gray-900 dark:text-white">
            <Tag className="h-4 w-4" />
            <span>{tagFile?.name}</span>
          </div>
          <label htmlFor="cloud-file-tags" className="block text-sm text-gray-600 dark:text-gray-300">
            Separate tags with commas
          </label>
          <input
            id="cloud-file-tags"
            value={tagInput}
            onChange={(event) => setTagInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') saveTags()
            }}
            maxLength={679}
            autoFocus
            className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 outline-none focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 dark:border-dark-700 dark:bg-dark-800 dark:text-white"
            placeholder="work, invoices, important"
          />
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Up to 20 tags; each tag can contain up to 32 characters.
          </p>
        </div>
      </Modal>
      
      <FolderPickerModal
        isOpen={folderPickerOpen}
        onClose={() => setFolderPickerOpen(false)}
        onSelect={handleBulkMove}
        title={`Move ${selectedFiles.size} selected ${selectedFiles.size === 1 ? 'item' : 'items'}`}
      />
      
      <Suspense fallback={null}>
        <EncryptFileModal
          isOpen={encryptionModalOpen}
          onClose={() => setEncryptionModalOpen(false)}
        />
      </Suspense>

      <Modal
        isOpen={decryptPrompt !== null}
        onClose={closeDecryptPrompt}
        title={decryptPrompt ? `Decrypt "${decryptPrompt.file.name}"` : 'Decrypt file'}
        size="sm"
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={closeDecryptPrompt} disabled={decryptWorking}>
              Cancel
            </Button>
            <Button
              onClick={async () => {
                if (!decryptPrompt) return
                if (!decryptPassword.trim()) {
                  setDecryptError('Password is required')
                  return
                }
                setDecryptWorking(true)
                setDecryptError(null)
                try {
                  if (decryptPrompt.action === 'preview') {
                    await performEncryptedPreview(decryptPrompt.file, decryptPassword)
                  } else if (decryptPrompt.action === 'download') {
                    await performEncryptedDownload(decryptPrompt.file, decryptPassword)
                  } else {
                    await performDecryptToCloud(decryptPrompt.file, decryptPassword)
                  }
                  closeDecryptPrompt()
                } catch (error) {
                  console.error('Decrypt action failed:', error)
                  setDecryptError('Wrong password or corrupted file')
                } finally {
                  setDecryptWorking(false)
                }
              }}
              loading={decryptWorking}
            >
              Decrypt
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Password
          </label>
          <div className="relative">
            <input
              type={showDecryptPassword ? 'text' : 'password'}
              value={decryptPassword}
              onChange={(e) => setDecryptPassword(e.target.value)}
              className="w-full px-3 py-2 pr-10 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-800 text-gray-900 dark:text-white"
              placeholder="Enter password"
              autoFocus
            />
            <button
              type="button"
              onClick={() => setShowDecryptPassword(!showDecryptPassword)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500"
            >
              {showDecryptPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          {decryptError && (
            <p className="text-sm text-red-600">{decryptError}</p>
          )}
        </div>
      </Modal>
      
      {contextMenu && (
        <ContextMenu
          file={contextMenu.file}
          position={{ x: contextMenu.x, y: contextMenu.y }}
          onClose={() => setContextMenu(null)}
          onPreview={() => handlePreview(contextMenu.file)}
          onDownload={() => handleDownload(contextMenu.file)}
          onDownloadEncrypted={() => handleDownloadEncrypted(contextMenu.file)}
          onDecrypt={() => handleDecryptInCloud(contextMenu.file)}
          onShare={() => handleShare(contextMenu.file)}
          onRename={() => handleRename(contextMenu.file)}
          onMove={() => handleMove(contextMenu.file)}
          onCopy={() => handleCopy(contextMenu.file)}
          onFavorite={() => handleFavorite(contextMenu.file)}
          onColorLabel={(color) => handleColorLabel(contextMenu.file, color)}
          onTag={() => handleTag(contextMenu.file)}
          onDelete={() => handleDelete(contextMenu.file)}
          deletable={!isSystemCloudFolder(contextMenu.file)}
          previewable={isCloudFilePreviewable(contextMenu.file)}
          isEncrypted={
            contextMenu.file.extension === '.encrypted' ||
            contextMenu.file.extension === '.epec' ||
            contextMenu.file.name.endsWith('.encrypted') ||
            contextMenu.file.name.endsWith('.epec')
          }
        />
      )}
      
      {renderPreview()}
    </div>
  )
}

export default PiCloud
