import { Download, File, Folder, MoreVertical, Share2, Star } from 'lucide-react'

import { formatBytes, formatDate } from '../../utils/format'
import { useCloudStore } from '../../stores/cloudStore'
import type { ColorLabel, FileCategory, PiCloudFile } from '../../types/cloud'
import Badge from '../common/Badge'
import FileRowThumbnail from './FileRowThumbnail'
import { isSystemCloudFolder } from '../../utils/cloudSystemFolders'

interface FileListProps {
  files: PiCloudFile[]
  onPreview: (file: PiCloudFile) => void
  onFavorite: (file: PiCloudFile) => void
  onShare: (file: PiCloudFile) => void
  onDelete?: (file: PiCloudFile) => void
  onContextMenu: (file: PiCloudFile, e: React.MouseEvent) => void
}

const colorLabelStyles: Record<ColorLabel, string> = {
  none: '',
  red: 'border-l-4 border-red-500',
  orange: 'border-l-4 border-orange-500',
  yellow: 'border-l-4 border-yellow-500',
  green: 'border-l-4 border-green-500',
  blue: 'border-l-4 border-blue-500',
  purple: 'border-l-4 border-purple-500',
  gray: 'border-l-4 border-gray-500',
}

const FileList = ({
  files,
  onPreview,
  onFavorite,
  onShare,
  onContextMenu,
}: FileListProps) => {
  const { setPath, setCategory, selectedFiles, toggleFileSelection, selectionMode } = useCloudStore()

  const handleRowClick = (file: PiCloudFile, e: React.MouseEvent) => {
    if ((e.ctrlKey || e.metaKey || selectionMode === 'multiple') && !isSystemCloudFolder(file)) {
      toggleFileSelection(file.id, true)
    } else if (file.type === 'folder') {
      if (file.id.startsWith('_category_')) {
        setCategory(file.id.replace('_category_', '') as FileCategory)
      } else {
        setPath(file.path)
      }
    } else {
      onPreview(file)
    }
  }

  const handleCheckboxChange = (file: PiCloudFile) => {
    toggleFileSelection(file.id, true)
  }

  if (files.length === 0) {
    return (
      <div className="py-12 text-center text-gray-500 dark:text-gray-400">
        <Folder className="mx-auto mb-3 h-12 w-12 opacity-50" />
        <p>No files found</p>
      </div>
    )
  }

  return (
    <div className="overflow-hidden rounded-lg bg-white shadow dark:bg-dark-900">
      <table className="w-full">
        <thead className="hidden border-b border-gray-200 bg-gray-50 md:table-header-group dark:border-dark-700 dark:bg-dark-800">
          <tr>
            <th className="w-8 px-4 py-3" />
            <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">
              Name
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">
              Type
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">
              Size
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">
              Modified
            </th>
            <th className="w-24 px-4 py-3" />
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-dark-700">
          {files.map((file) => {
            const selected = selectedFiles.has(file.id)
            const showActions = selected || file.type !== 'folder'
            const selectable = !isSystemCloudFolder(file)

            return (
              <tr
                key={file.id}
                onContextMenu={(e) => onContextMenu(file, e)}
                className={`cursor-pointer transition-colors ${
                  selected
                    ? 'bg-primary-50 dark:bg-primary-900/20'
                    : 'hover:bg-gray-50 dark:hover:bg-dark-800'
                } ${file.colorLabel ? colorLabelStyles[file.colorLabel] : ''}`}
              >
                <td className="px-4 py-3">
                  {selectable && (
                    <input
                      type="checkbox"
                      checked={selected}
                      onChange={() => handleCheckboxChange(file)}
                      onClick={(e) => e.stopPropagation()}
                      aria-label={`Select ${file.name}`}
                      className="rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-dark-600"
                    />
                  )}
                </td>

                <td className="px-4 py-3" onClick={(e) => handleRowClick(file, e)}>
                  <div className="flex items-center gap-3">
                    <div className="flex-shrink-0">
                      {file.type === 'folder' ? (
                        <Folder className="h-8 w-8 text-yellow-500" />
                      ) : (
                        <FileRowThumbnail
                          fileId={file.id}
                          fileName={file.name}
                          hasThumbnail={!!file.thumbnail}
                          category={file.category}
                          mime={file.mime}
                          extension={file.extension}
                        />
                      )}
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 items-center gap-2">
                        <span className="truncate text-sm font-medium text-gray-900 dark:text-white">
                          {file.name}
                        </span>
                        {file.favorite && (
                          <Star className="h-4 w-4 flex-shrink-0 fill-yellow-500 text-yellow-500" />
                        )}
                        {file.uploadedViaTelegram && (
                          <Badge color="primary" size="sm">
                            Telegram
                          </Badge>
                        )}
                      </div>

                      {file.tags && file.tags.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {file.tags.slice(0, 3).map((tag: string) => (
                            <Badge key={tag} size="sm" color="gray">
                              {tag}
                            </Badge>
                          ))}
                          {file.tags.length > 3 && (
                            <Badge size="sm" color="gray">
                              +{file.tags.length - 3}
                            </Badge>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </td>

                <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                  {file.type === 'folder' ? 'Folder' : file.mime}
                </td>

                <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                  {file.type === 'folder' ? '-' : formatBytes(file.size)}
                </td>

                <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                  {formatDate(file.modified)}
                </td>

                <td className="px-4 py-3">
                  {showActions && file.type !== 'folder' && (
                    <div className="flex items-center gap-1">
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          onFavorite(file)
                        }}
                        className="rounded p-1.5 transition-colors hover:bg-gray-200 dark:hover:bg-dark-700"
                        title="Favorite"
                      >
                        <Star
                          className={`h-4 w-4 ${
                            file.favorite ? 'fill-yellow-500 text-yellow-500' : 'text-gray-400'
                          }`}
                        />
                      </button>

                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          onShare(file)
                        }}
                        className="rounded p-1.5 transition-colors hover:bg-gray-200 dark:hover:bg-dark-700"
                        title="Share"
                      >
                        <Share2 className="h-4 w-4 text-gray-400" />
                      </button>

                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          window.open(`/api/v1/picloud/file/${encodeURIComponent(file.id)}/download`, '_blank')
                        }}
                        className="rounded p-1.5 transition-colors hover:bg-gray-200 dark:hover:bg-dark-700"
                        title="Download"
                      >
                        <Download className="h-4 w-4 text-gray-400" />
                      </button>

                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          onContextMenu(file, e)
                        }}
                        className="rounded p-1.5 transition-colors hover:bg-gray-200 dark:hover:bg-dark-700"
                        title="More"
                      >
                        <MoreVertical className="h-4 w-4 text-gray-400" />
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export default FileList
