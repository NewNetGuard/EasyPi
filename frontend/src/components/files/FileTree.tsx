import { FolderIcon, FileIcon, ChevronRightIcon, ChevronDownIcon } from 'lucide-react'
import { useState } from 'react'

interface FileItem {
  name: string
  path: string
  type: 'file' | 'directory'
  size?: number
  size_formatted?: string
  modified?: string
}

interface FileTreeProps {
  files: FileItem[]
  onSelect: (path: string, type: string) => void
  selectedFile: string | null
}

const FileTree = ({ files, onSelect, selectedFile }: FileTreeProps) => {
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set())

  const toggleFolder = (path: string) => {
    const newExpanded = new Set(expandedFolders)
    if (newExpanded.has(path)) {
      newExpanded.delete(path)
    } else {
      newExpanded.add(path)
    }
    setExpandedFolders(newExpanded)
  }

  const handleItemClick = (item: FileItem) => {
    if (item.type === 'directory') {
      toggleFolder(item.path)
      onSelect(item.path, item.type)
    } else {
      onSelect(item.path, item.type)
    }
  }

  if (files.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500 dark:text-gray-400 text-sm">
        Empty directory
      </div>
    )
  }

  return (
    <div className="space-y-1">
      {files.map((item) => {
        const isSelected = selectedFile === item.path
        const isExpanded = expandedFolders.has(item.path)
        const isDirectory = item.type === 'directory'

        return (
          <div key={item.path}>
            <button
              onClick={() => handleItemClick(item)}
              className={`
                w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm
                transition-colors duration-150
                ${
                  isSelected
                    ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300'
                    : 'hover:bg-gray-100 dark:hover:bg-dark-700 text-gray-700 dark:text-gray-300'
                }
              `}
            >
              {isDirectory && (
                <span className="flex-shrink-0">
                  {isExpanded ? (
                    <ChevronDownIcon className="h-4 w-4" />
                  ) : (
                    <ChevronRightIcon className="h-4 w-4" />
                  )}
                </span>
              )}
              
              {isDirectory ? (
                <FolderIcon className="h-4 w-4 flex-shrink-0 text-yellow-500" />
              ) : (
                <FileIcon className="h-4 w-4 flex-shrink-0 text-gray-400" />
              )}
              
              <span className="truncate flex-1 text-left">{item.name}</span>
              
              {item.size_formatted && (
                <span className="text-xs text-gray-500 dark:text-gray-400 flex-shrink-0">
                  {item.size_formatted}
                </span>
              )}
            </button>
          </div>
        )
      })}
    </div>
  )
}

export default FileTree
