import { useState } from 'react'
import {
  File, 
  FileText,
  Folder, 
  Image,
  Music4,
  Star, 
  Download, 
  Share2, 
  MoreVertical,
  Video,
  Eye,
} from 'lucide-react'
import clsx from 'clsx'
import { format } from 'date-fns'
import type { PiCloudFile } from '../../types/cloud'
import { useAuthenticatedUrl, fetchAuthenticatedFileUrl, revokeAuthenticatedUrl } from '../../hooks/useAuthenticatedUrl'
import Badge from '../common/Badge'
import { getCloudFormatLabel, isCloudFilePreviewable, showsCloudCardMedia } from '../../utils/cloudPreview'

interface FileCardProps {
  file: PiCloudFile
  isSelected?: boolean
  onSelect?: () => void
  onToggleSelection?: () => void
  selectable?: boolean
  onPreview: () => void
  onShare: () => void
  onContextMenu: (e: React.MouseEvent) => void
}

const FileCard = ({
  file,
  isSelected,
  onSelect,
  onToggleSelection,
  selectable = true,
  onPreview,
  onShare,
  onContextMenu,
}: FileCardProps) => {
  const [previewError, setPreviewError] = useState(false)
  const [showActions, setShowActions] = useState(false)
  
  const isFolder = file.type === 'folder'
  const showsMedia = showsCloudCardMedia(file)
  const isNameCard = file.type === 'file' && !showsMedia
  const usePreview = !isFolder && showsMedia

  const { url: previewUrl, loading: previewLoading } = useAuthenticatedUrl(
    usePreview ? file.id : null,
    'thumbnail'
  )
  const resolvedUrl = previewUrl
  const resolvedLoading = previewLoading
  
  const formatSize = (bytes: number) => {
    if (!bytes) return '0 B'
    const k = 1024
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${['B', 'KB', 'MB', 'GB', 'TB'][i]}`
  }
  
  const getFileIcon = () => {
    if (file.type === 'folder') {
      return <Folder className="h-12 w-12 text-blue-500" />
    }
    
    if (file.category === 'photos') {
      return <Image className="h-12 w-12 text-emerald-500" />
    } else if (file.category === 'videos') {
      return <Video className="h-12 w-12 text-rose-500" />
    } else if (file.category === 'audio') {
      return <Music4 className="h-12 w-12 text-violet-500" />
    } else if (file.category === 'documents') {
      return <FileText className="h-12 w-12 text-sky-500" />
    }
    
    return <File className="h-12 w-12 text-gray-400" />
  }
  
  const colorLabelColors = {
    none: '',
    red: 'border-red-500',
    orange: 'border-orange-500',
    yellow: 'border-yellow-500',
    green: 'border-green-500',
    blue: 'border-blue-500',
    purple: 'border-purple-500',
    gray: 'border-gray-500',
  }

  const getFallbackLabel = () => {
    if (file.type === 'folder') {
      return null
    }
    return isNameCard ? file.name : getCloudFormatLabel(file)
  }
  
  return (
    <div
      className={clsx(
        'group relative rounded-lg border-2 bg-white dark:bg-dark-800 shadow-sm transition-all hover:shadow-md cursor-pointer',
        isSelected 
          ? 'border-primary-500 ring-2 ring-primary-200 dark:ring-primary-900' 
          : 'border-gray-200 dark:border-dark-700 hover:border-gray-300',
        file.colorLabel && file.colorLabel !== 'none' && colorLabelColors[file.colorLabel]
      )}
      onClick={onSelect}
      onContextMenu={onContextMenu}
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
    >
      {/* Selection checkbox */}
      {selectable && onToggleSelection && (
        <div className="absolute left-2 top-2 z-10">
          <input
            type="checkbox"
            checked={isSelected}
            onChange={onToggleSelection}
            onClick={(e) => e.stopPropagation()}
            aria-label={`Select ${file.name}`}
            className="h-5 w-5 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
          />
        </div>
      )}
      
      {/* Favorite star */}
      {file.favorite && (
        <div className="absolute right-2 top-2 z-10">
          <Star className="h-5 w-5 fill-amber-400 text-amber-400" />
        </div>
      )}
      
      {/* Thumbnail/Icon */}
      <div className={clsx(
        'relative aspect-square overflow-hidden rounded-t-lg',
        isNameCard ? 'bg-white dark:bg-dark-800' : 'bg-gray-50 dark:bg-dark-900'
      )}>
        {resolvedUrl && !previewError ? (
          <img
            src={resolvedUrl}
            alt={file.name}
            className="h-full w-full object-cover"
            onError={() => setPreviewError(true)}
          />
        ) : resolvedLoading ? (
          <div className="flex h-full w-full items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-2 border-primary-500 border-t-transparent" />
          </div>
        ) : (
          <div className="flex h-full w-full items-center justify-center">
            {file.type === 'folder' ? (
              getFileIcon()
            ) : (
              <div
                title={isNameCard ? file.name : undefined}
                className={clsx(
                  isNameCard
                    ? 'mx-4 max-w-[85%] text-center text-sm font-bold leading-snug text-gray-900 dark:text-white'
                    : 'rounded-md bg-gray-200 px-3 py-2 text-xs font-bold text-gray-700 dark:bg-dark-700 dark:text-gray-200'
                )}
              >
                <span className={clsx(isNameCard && 'line-clamp-3 break-all')}>
                  {getFallbackLabel()}
                </span>
              </div>
            )}
          </div>
        )}
        
        {/* Quick actions overlay - only for files */}
        {showActions && file.type !== 'folder' && (
          <div className="absolute inset-0 flex items-center justify-center gap-2 bg-black/50 opacity-0 transition-opacity group-hover:opacity-100">
            {isCloudFilePreviewable(file) && (
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onPreview?.()
                }}
                className="rounded-full bg-white/90 p-2 text-gray-700 hover:bg-white"
                title="Preview"
              >
                <Eye className="h-4 w-4" />
              </button>
            )}
            <button
              onClick={(e) => {
                e.stopPropagation()
                onShare?.()
              }}
              className="rounded-full bg-white/90 p-2 text-gray-700 hover:bg-white"
              title="Share"
            >
              <Share2 className="h-4 w-4" />
            </button>
            <button
              onClick={async (e) => {
                e.stopPropagation()
                try {
                  const blobUrl = await fetchAuthenticatedFileUrl(file.id, 'download')
                  const link = document.createElement('a')
                  link.href = blobUrl
                  link.download = file.name
                  document.body.appendChild(link)
                  link.click()
                  document.body.removeChild(link)
                  setTimeout(() => revokeAuthenticatedUrl(blobUrl), 1000)
                } catch (err) {
                  console.error('Download failed:', err)
                }
              }}
              className="rounded-full bg-white/90 p-2 text-gray-700 hover:bg-white"
              title="Download"
            >
              <Download className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
      
      {/* File info */}
      <div className="p-3">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-2">
              <h3
                className="truncate text-sm font-medium text-gray-900 dark:text-white"
                title={isNameCard ? getCloudFormatLabel(file) : file.name}
              >
                {isNameCard ? getCloudFormatLabel(file) : file.name}
              </h3>
            </div>
            <div className="mt-1 flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
              <span>{formatSize(file.size)}</span>
              {file.modified && (
                <>
                  <span>•</span>
                  <span>{format(new Date(file.modified), 'MMM d, yyyy')}</span>
                </>
              )}
            </div>
          </div>
          
          {/* More actions - only for files */}
          {file.type !== 'folder' && (
            <button
              onClick={(e) => {
                e.stopPropagation()
                onContextMenu?.(e)
              }}
              className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600 dark:hover:bg-dark-700"
            >
              <MoreVertical className="h-4 w-4" />
            </button>
          )}
        </div>
        
        {/* Tags */}
        {file.tags && file.tags.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {file.tags.slice(0, 2).map((tag) => (
              <Badge key={tag} color="gray" size="sm">
                {tag}
              </Badge>
            ))}
            {file.tags.length > 3 && (
              <Badge color="gray" size="sm">
                +{file.tags.length - 3}
              </Badge>
            )}
          </div>
        )}
        
        {/* Telegram indicator */}
        {file.uploadedViaTelegram && (
          <div className="mt-2">
            <Badge color="primary" size="sm">
              Telegram
            </Badge>
          </div>
        )}
      </div>
    </div>
  )
}

export default FileCard
