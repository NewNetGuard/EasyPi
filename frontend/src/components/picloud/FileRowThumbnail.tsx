import { useAuthenticatedUrl } from '../../hooks/useAuthenticatedUrl'
import { showsCloudCardMedia } from '../../utils/cloudPreview'
import type { PiCloudFile } from '../../types/cloud'

interface FileRowThumbnailProps {
  fileId: string
  fileName: string
  hasThumbnail: boolean
  category?: PiCloudFile['category'] | null
  mime?: string | null
  extension?: string | null
}

/**
 * Thumbnail component for file list rows
 * Fetches thumbnail with authentication
 */
const FileRowThumbnail = ({ fileId, fileName, category, mime, extension }: FileRowThumbnailProps) => {
  const showsMedia = showsCloudCardMedia({
    type: 'file',
    name: fileName,
    extension,
    mime,
    category: category || undefined,
  })

  const { url: previewUrl, loading: previewLoading } = useAuthenticatedUrl(
    showsMedia ? fileId : null,
    'thumbnail'
  )
  const resolvedUrl = previewUrl
  const loading = previewLoading
  
  if (!showsMedia) {
    return (
      <div
        title={fileName}
        className="flex h-8 w-20 items-center justify-center rounded bg-black px-1.5 text-[9px] font-bold text-white"
      >
        <span className="max-w-full truncate">{fileName}</span>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="h-8 w-8 rounded bg-gray-200 dark:bg-dark-700 animate-pulse" />
    )
  }
  
  if (resolvedUrl) {
    return (
      <img
        src={resolvedUrl}
        alt={fileName}
        className="h-8 w-8 rounded object-cover"
      />
    )
  }
  
  // Fallback to file icon if thumbnail fails to load
  return (
    <div className="flex h-8 w-20 items-center justify-center rounded bg-black px-1.5 text-[9px] font-bold text-white">
      <span className="max-w-full truncate">{fileName}</span>
    </div>
  )
}

export default FileRowThumbnail
