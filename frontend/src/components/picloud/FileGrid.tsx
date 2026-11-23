import { useCloudStore } from '../../stores/cloudStore'
import FileCard from './FileCard'
import type { PiCloudFile } from '../../types/cloud'
import clsx from 'clsx'
import { isSystemCloudFolder } from '../../utils/cloudSystemFolders'

interface FileGridProps {
  files: PiCloudFile[]
  onPreview: (file: PiCloudFile) => void
  onFavorite: (file: PiCloudFile) => void
  onShare: (file: PiCloudFile) => void
  onDelete: (file: PiCloudFile) => void
  onContextMenu: (file: PiCloudFile, e: React.MouseEvent) => void
}

const FileGrid = ({ files, onPreview, onShare, onContextMenu }: FileGridProps) => {
  const { 
    toggleFileSelection, 
    isFileSelected, 
    setPath,
    setCategory
  } = useCloudStore()
  
  const handleFileClick = (file: PiCloudFile) => {
    if (file.type === 'folder') {
      // Handle virtual category folders
      if (file.id.startsWith('_category_')) {
        const categoryId = file.id.replace('_category_', '')
        setCategory(categoryId as any)
      } else {
        setPath(file.path)
      }
    } else {
      toggleFileSelection(file.id)
    }
  }
  
  if (files.length === 0) {
    return (
      <div className="flex h-64 flex-col items-center justify-center rounded-lg border-2 border-dashed border-gray-300 dark:border-dark-700 text-center p-8">
        <div className="text-5xl mb-4">📂</div>
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          No files found
        </h3>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          This folder is empty or your search didn't match any files
        </p>
      </div>
    )
  }
  
  return (
    <div className={clsx(
      'grid gap-4',
      'grid-cols-2',
      'md:grid-cols-3',
      'lg:grid-cols-4',
      'xl:grid-cols-5',
      '2xl:grid-cols-6'
    )}>
      {files.map((file) => (
        <FileCard
          key={file.id}
          file={file}
          isSelected={isFileSelected(file.id)}
          onSelect={() => handleFileClick(file)}
          onToggleSelection={() => toggleFileSelection(file.id, true)}
          selectable={!isSystemCloudFolder(file)}
          onPreview={() => onPreview(file)}
          onShare={() => onShare(file)}
          onContextMenu={(e) => onContextMenu(file, e)}
        />
      ))}
    </div>
  )
}

export default FileGrid
