import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Folder, FolderOpen, ChevronRight, ChevronDown, Home, Plus } from 'lucide-react'
import clsx from 'clsx'

import Modal from '../common/Modal'
import Button from '../common/Button'
import Input from '../common/Input'
import { getFolderTree, listFiles } from '../../api/cloud'
import type { FolderTree } from '../../types/cloud'

interface FolderPickerModalProps {
  isOpen: boolean
  onClose: () => void
  onSelect: (path: string) => void
  title?: string
}

const FolderPickerModal = ({ 
  isOpen, 
  onClose, 
  onSelect, 
  title = 'Выберите папку',
}: FolderPickerModalProps) => {
  const [selectedPath, setSelectedPath] = useState<string>('/')
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set(['/']))
  const [newFolderName, setNewFolderName] = useState('')
  const [showNewFolder, setShowNewFolder] = useState(false)
  
  // Try to get folder tree first
  const { data: folderTree } = useQuery({
    queryKey: ['picloud-folder-tree-picker'],
    queryFn: getFolderTree,
    enabled: isOpen,
  })
  
  // Fallback: get folders from root listing
  const { data: rootFiles } = useQuery({
    queryKey: ['picloud-files-root-folders'],
    queryFn: () => listFiles('/'),
    enabled: isOpen,
  })
  
  // Extract folders from file listing
  const foldersFromFiles = rootFiles?.items?.filter(f => f.type === 'folder') || []
  
  const toggleExpand = (path: string) => {
    const newSet = new Set(expandedFolders)
    if (newSet.has(path)) {
      newSet.delete(path)
    } else {
      newSet.add(path)
    }
    setExpandedFolders(newSet)
  }
  
  const handleSelect = () => {
    if (selectedPath) {
      onSelect(selectedPath)
      onClose()
    }
  }
  
  const handleCreateFolder = () => {
    if (newFolderName.trim()) {
      const newPath = selectedPath === '/' 
        ? `/${newFolderName.trim()}` 
        : `${selectedPath}/${newFolderName.trim()}`
      onSelect(newPath)
      onClose()
    }
  }
  
  // Render folder tree item recursively
  const renderFolderTreeItem = (folder: FolderTree, level: number = 0) => {
    const isExpanded = expandedFolders.has(folder.path)
    const isSelected = selectedPath === folder.path
    const hasChildren = folder.children && folder.children.length > 0
    
    return (
      <div key={folder.path || folder.id}>
        <div
          className={clsx(
            'flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer transition-colors',
            isSelected
              ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400'
              : 'hover:bg-gray-100 dark:hover:bg-dark-800 text-gray-700 dark:text-gray-300'
          )}
          style={{ paddingLeft: `${level * 16 + 12}px` }}
          onClick={() => setSelectedPath(folder.path)}
        >
          {hasChildren ? (
            <button
              onClick={(e) => {
                e.stopPropagation()
                toggleExpand(folder.path)
              }}
              className="p-0.5 hover:bg-gray-200 dark:hover:bg-dark-700 rounded"
            >
              {isExpanded ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
            </button>
          ) : (
            <span className="w-5" />
          )}
          
          {isExpanded && hasChildren ? (
            <FolderOpen className="h-5 w-5 text-blue-500" />
          ) : (
            <Folder className="h-5 w-5 text-blue-500" />
          )}
          
          <span className="truncate font-medium">{folder.name}</span>
          {folder.itemCount > 0 && (
            <span className="ml-auto text-xs text-gray-500">{folder.itemCount}</span>
          )}
        </div>
        
        {isExpanded && hasChildren && (
          <div>
            {folder.children.map((child) => renderFolderTreeItem(child, level + 1))}
          </div>
        )}
      </div>
    )
  }
  
  // Render simple folder from file listing
  const renderSimpleFolder = (folder: { id: string; name: string; path: string }, level: number = 1) => {
    const isSelected = selectedPath === folder.path
    
    return (
      <div
        key={folder.id}
        className={clsx(
          'flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer transition-colors',
          isSelected
            ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400'
            : 'hover:bg-gray-100 dark:hover:bg-dark-800 text-gray-700 dark:text-gray-300'
        )}
        style={{ paddingLeft: `${level * 16 + 12}px` }}
        onClick={() => setSelectedPath(folder.path)}
      >
        <span className="w-5" />
        <Folder className="h-5 w-5 text-blue-500" />
        <span className="truncate font-medium">{folder.name}</span>
      </div>
    )
  }
  
  // Determine what folders to show
  const hasFolderTree = folderTree && Array.isArray(folderTree) && folderTree.length > 0
  const hasFoldersFromFiles = foldersFromFiles.length > 0
  
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title} size="md">
      <div className="space-y-4">
        {/* Folder Tree */}
        <div className="border border-gray-200 dark:border-dark-700 rounded-lg max-h-80 overflow-y-auto">
          <div className="p-2">
            {/* Root folder - always shown */}
            <div
              className={clsx(
                'flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer transition-colors',
                selectedPath === '/'
                  ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400'
                  : 'hover:bg-gray-100 dark:hover:bg-dark-800 text-gray-700 dark:text-gray-300'
              )}
              onClick={() => setSelectedPath('/')}
            >
              <Home className="h-5 w-5 text-gray-500" />
              <span className="font-medium">Корневая папка</span>
            </div>
            
            {/* Show folder tree if available */}
            {hasFolderTree && folderTree.map((folder) => renderFolderTreeItem(folder, 1))}
            
            {/* Fallback: show folders from file listing */}
            {!hasFolderTree && hasFoldersFromFiles && foldersFromFiles.map((folder) => 
              renderSimpleFolder({ id: folder.id, name: folder.name, path: folder.path }, 1)
            )}
            
            {/* No folders message */}
            {!hasFolderTree && !hasFoldersFromFiles && (
              <div className="text-center py-4 text-gray-500 text-sm">
                Папок пока нет. Вы можете создать новую.
              </div>
            )}
          </div>
        </div>
        
        {/* Selected path display */}
        <div className="bg-gray-50 dark:bg-dark-800 rounded-lg px-4 py-3">
          <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">Выбранный путь:</div>
          <div className="font-mono text-sm text-gray-900 dark:text-white">{selectedPath}</div>
        </div>
        
        {/* New folder option */}
        {showNewFolder ? (
          <div className="flex gap-2">
            <Input
              placeholder="Название новой папки"
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              className="flex-1"
            />
            <Button variant="primary" size="sm" onClick={handleCreateFolder}>
              Создать
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowNewFolder(false)}>
              Отмена
            </Button>
          </div>
        ) : (
          <Button
            variant="outline"
            size="sm"
            icon={<Plus className="h-4 w-4" />}
            onClick={() => setShowNewFolder(true)}
          >
            Создать новую папку
          </Button>
        )}
        
        {/* Actions */}
        <div className="flex justify-end gap-2 pt-4 border-t border-gray-200 dark:border-dark-700">
          <Button variant="outline" onClick={onClose}>
            Отмена
          </Button>
          <Button onClick={handleSelect}>
            Переместить сюда
          </Button>
        </div>
      </div>
    </Modal>
  )
}

export default FolderPickerModal
