import { useState, useEffect, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import { FolderIcon, FolderOpenIcon, FileIcon, PlusIcon, UploadIcon, RefreshCwIcon, ArrowUpIcon, HomeIcon, TrashIcon, SearchIcon, XIcon } from 'lucide-react'
import FileTree from '../../components/files/FileTree'
import FileEditor from '../../components/files/FileEditor'
import Button from '../../components/common/Button'
import Input from '../../components/common/Input'
import Modal from '../../components/common/Modal'
import Select from '../../components/common/Select'
import OverviewStat from '../../components/common/OverviewStat'
import { toast } from 'react-hot-toast'
import { createFile, createFolder, uploadFile, listDirectory, deleteFile, searchFiles, FileSearchResult } from '../../api/files'

interface FileItem {
  name: string
  path: string
  type: 'file' | 'directory'
  size?: number
  size_formatted?: string
  modified?: string
}

// File Manager is scoped to the EasyPi installation tree. The backend enforces
// this too (ALLOWED_ROOTS); the constant keeps the UI's root/floor in sync.
const FM_ROOT = '/opt/EasyPi'
const ROOT_PATHS = [
  { value: FM_ROOT, label: 'EasyPi' },
]

const FileManager = () => {
  const [currentPath, setCurrentPath] = useState(FM_ROOT)
  const [files, setFiles] = useState<FileItem[]>([])
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [selectedRoot, setSelectedRoot] = useState(FM_ROOT)
  const location = useLocation()
  
  // Search state
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<FileSearchResult[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [showSearchResults, setShowSearchResults] = useState(false)
  
  // Modals
  const [newFileModal, setNewFileModal] = useState(false)
  const [newFolderModal, setNewFolderModal] = useState(false)
  const [newFileName, setNewFileName] = useState('')
  const [newFolderName, setNewFolderName] = useState('')
  const fileCount = files.filter((item) => item.type === 'file').length
  const folderCount = files.filter((item) => item.type === 'directory').length
  const currentRootLabel = ROOT_PATHS.find((root) => root.value === selectedRoot)?.label || selectedRoot

  // Debounced search
  const debounce = <T extends (...args: Parameters<T>) => void>(fn: T, delay: number) => {
    let timeoutId: ReturnType<typeof setTimeout>
    return (...args: Parameters<T>) => {
      clearTimeout(timeoutId)
      timeoutId = setTimeout(() => fn(...args), delay)
    }
  }

  const performSearch = useCallback(async (query: string) => {
    if (!query.trim()) {
      setSearchResults([])
      setShowSearchResults(false)
      return
    }
    
    setIsSearching(true)
    setShowSearchResults(true)
    
    try {
      const results = await searchFiles(query, selectedRoot, 50)
      setSearchResults(results)
    } catch (error: any) {
      console.error('Search failed:', error)
      setSearchResults([])
    } finally {
      setIsSearching(false)
    }
  }, [selectedRoot])

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const debouncedSearch = useCallback(debounce(performSearch, 300), [performSearch])

  useEffect(() => {
    debouncedSearch(searchQuery)
  }, [searchQuery, debouncedSearch])

  const handleSearchResultClick = (result: FileSearchResult) => {
    if (result.type === 'directory') {
      loadDirectory(result.path)
    } else {
      // Navigate to parent directory and select the file
      loadDirectory(result.parent)
      setSelectedFile(result.path)
    }
    setSearchQuery('')
    setShowSearchResults(false)
  }

  const clearSearch = () => {
    setSearchQuery('')
    setSearchResults([])
    setShowSearchResults(false)
  }

  const loadDirectory = useCallback(async (path: string) => {
    setLoading(true)
    try {
      const items = await listDirectory(path)
      setFiles(items)
      setCurrentPath(path)
    } catch (error: any) {
      toast.error(error.message || 'Failed to load directory')
    } finally {
      setLoading(false)
    }
  }, [])

  const findRootPath = (path: string) => {
    let best = FM_ROOT
    for (const root of ROOT_PATHS) {
      if (path === root.value || path.startsWith(`${root.value}/`)) {
        if (root.value.length > best.length) {
          best = root.value
        }
      }
    }
    return best
  }

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const raw = params.get('path')
    if (!raw) {
      loadDirectory(FM_ROOT)
      return
    }
    const decoded = decodeURIComponent(raw)
    // Only honor a ?path= that is inside the EasyPi tree; otherwise fall back.
    if (decoded !== FM_ROOT && !decoded.startsWith(`${FM_ROOT}/`)) {
      loadDirectory(FM_ROOT)
      return
    }
    setSelectedRoot(findRootPath(decoded))
    loadDirectory(decoded)
  }, [location.search, loadDirectory])

  const handleFileSelect = (path: string, type: string) => {
    if (type === 'file') {
      setSelectedFile(path)
    } else {
      loadDirectory(path)
    }
  }

  const handleCreateFile = async () => {
    if (!newFileName.trim()) {
      toast.error('File name is required')
      return
    }

    const filePath = currentPath === '/' 
      ? `/${newFileName}` 
      : `${currentPath}/${newFileName}`
    
    try {
      await createFile(filePath)
      toast.success('File created successfully')
      setNewFileModal(false)
      setNewFileName('')
      loadDirectory(currentPath)
    } catch (error: any) {
      toast.error(error.message || 'Failed to create file')
    }
  }

  const handleCreateFolder = async () => {
    if (!newFolderName.trim()) {
      toast.error('Folder name is required')
      return
    }

    const folderPath = currentPath === '/' 
      ? `/${newFolderName}` 
      : `${currentPath}/${newFolderName}`
    
    try {
      await createFolder(folderPath)
      toast.success('Folder created successfully')
      setNewFolderModal(false)
      setNewFolderName('')
      loadDirectory(currentPath)
    } catch (error: any) {
      toast.error(error.message || 'Failed to create folder')
    }
  }

  const handleUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const filePath = currentPath === '/' 
      ? `/${file.name}` 
      : `${currentPath}/${file.name}`
    
    try {
      await uploadFile(file, filePath)
      toast.success('File uploaded successfully')
      loadDirectory(currentPath)
    } catch (error: any) {
      toast.error(error.message || 'Failed to upload file')
    }
    
    // Reset input
    event.target.value = ''
  }

  const handleRefresh = () => {
    loadDirectory(currentPath)
    if (selectedFile) {
      // Trigger re-fetch in FileEditor
      setSelectedFile(null)
      setTimeout(() => setSelectedFile(selectedFile), 0)
    }
  }

  const handleDelete = async (path: string, type: string) => {
    const itemType = type === 'directory' ? 'folder' : 'file'
    
    if (!confirm(`Are you sure you want to delete this ${itemType}?\n\n${path}\n\nThis action cannot be undone.`)) {
      return
    }
    
    try {
      await deleteFile(path)
      toast.success(`${itemType.charAt(0).toUpperCase() + itemType.slice(1)} deleted successfully`)
      
      // If we deleted the current directory, go up one level
      if (type === 'directory' && path === currentPath) {
        handleGoUp()
      } else {
        loadDirectory(currentPath)
      }
      
      // Clear selection if we deleted the selected file
      if (selectedFile === path) {
        setSelectedFile(null)
      }
    } catch (error: any) {
      toast.error(error.message || 'Failed to delete')
    }
  }
  
  const handleDeleteCurrent = () => {
    if (selectedFile) {
      // Delete selected file
      const type = files.find(f => f.path === selectedFile)?.type || 'file'
      handleDelete(selectedFile, type)
    } else {
      // Delete current folder
      if (currentPath === FM_ROOT) {
        toast.error('Cannot delete the EasyPi root directory')
        return
      }
      handleDelete(currentPath, 'directory')
    }
  }

  const handleGoUp = () => {
    if (currentPath === FM_ROOT) return

    const parentPath = currentPath.split('/').slice(0, -1).join('/') || '/'
    // Never navigate above the EasyPi root.
    if (parentPath !== FM_ROOT && !parentPath.startsWith(FM_ROOT + '/')) return
    loadDirectory(parentPath)
    setSelectedFile(null)
  }

  const handleRootChange = (value: string) => {
    setSelectedRoot(value)
    loadDirectory(value)
    setSelectedFile(null)
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
              <FolderOpenIcon className="h-6 w-6 text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">File Manager</h1>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Browse, search, and edit files on your Raspberry Pi.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              loading={loading}
              icon={<RefreshCwIcon className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />}
            >
              {loading ? 'Refreshing...' : 'Refresh'}
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setNewFolderModal(true)}
              icon={<FolderIcon className="h-4 w-4" />}
            >
              New Folder
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setNewFileModal(true)}
              icon={<PlusIcon className="h-4 w-4" />}
            >
              New File
            </Button>

            <label className="cursor-pointer">
              <input
                type="file"
                className="hidden"
                onChange={handleUpload}
                onClick={(e) => {
                  e.currentTarget.value = ''
                }}
              />
              <span className="inline-flex items-center gap-2 rounded-md border border-primary-600 bg-primary-600 px-3 py-2 text-sm font-medium text-white transition-colors duration-200 hover:border-primary-700 hover:bg-primary-700">
                <UploadIcon className="h-4 w-4" />
                Upload
              </span>
            </label>

            <Button
              variant="outline"
              size="sm"
              onClick={handleDeleteCurrent}
              disabled={!selectedFile && currentPath === FM_ROOT}
              icon={<TrashIcon className="h-4 w-4" />}
              className="text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20"
            >
              Delete
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <OverviewStat label="Current root" value={currentRootLabel} hint="Quick jump area" tone="primary" icon={HomeIcon} valueClassName="text-base font-medium" />
          <OverviewStat label="Current path" value={currentPath} hint="Directory in focus" tone="gray" icon={FolderIcon} valueClassName="text-base font-medium" />
          <OverviewStat label="Folders" value={folderCount} hint="Visible here right now" tone="warning" icon={FolderIcon} />
          <OverviewStat
            label="Files"
            value={fileCount}
            hint={selectedFile ? 'One file currently selected' : 'Select a file to open the editor'}
            tone="success"
            icon={FileIcon}
          />
        </div>

        <div className="grid grid-cols-1 gap-3 xl:grid-cols-[260px_minmax(0,1fr)]">
          <div className="min-w-0">
            <Select
              options={ROOT_PATHS}
              value={selectedRoot}
              onChange={handleRootChange}
            />
          </div>

          <div className="relative min-w-0">
            <div className="relative">
              <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search files..."
                className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-10 pr-10 text-sm text-gray-900 placeholder-gray-400 focus:border-transparent focus:ring-2 focus:ring-primary-500 dark:border-dark-600 dark:bg-dark-800 dark:text-white"
              />
              {searchQuery && (
                <button
                  onClick={clearSearch}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  <XIcon className="h-4 w-4" />
                </button>
              )}
            </div>

            {showSearchResults && (
              <div className="absolute z-50 mt-1 max-h-80 w-full overflow-y-auto rounded-lg border border-gray-200 bg-white shadow-lg dark:border-dark-600 dark:bg-dark-800">
                {isSearching ? (
                  <div className="flex items-center justify-center py-4">
                    <div className="h-5 w-5 animate-spin rounded-full border-b-2 border-primary-500" />
                    <span className="ml-2 text-sm text-gray-500">Searching...</span>
                  </div>
                ) : searchResults.length === 0 ? (
                  <div className="px-3 py-4 text-center text-sm text-gray-500">
                    No files found
                  </div>
                ) : (
                  <ul className="py-1">
                    {searchResults.map((result, index) => (
                      <li key={index}>
                        <button
                          onClick={() => handleSearchResultClick(result)}
                          className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-gray-100 dark:hover:bg-dark-700"
                        >
                          {result.type === 'directory' ? (
                            <FolderIcon className="h-4 w-4 flex-shrink-0 text-yellow-500" />
                          ) : (
                            <FileIcon className="h-4 w-4 flex-shrink-0 text-gray-400" />
                          )}
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-sm font-medium text-gray-900 dark:text-white">
                              {result.name}
                            </p>
                            <p className="truncate text-xs text-gray-500 dark:text-gray-400">
                              {result.parent}
                            </p>
                          </div>
                          {result.size_formatted && (
                            <span className="flex-shrink-0 text-xs text-gray-400">
                              {result.size_formatted}
                            </span>
                          )}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* File Tree */}
        <div className="lg:col-span-1">
          <div className="bg-white dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700 p-4">
            <div className="mb-3 pb-3 border-b border-gray-200 dark:border-dark-700">
              <div className="flex items-center justify-between gap-2 mb-2">
                <p className="text-sm font-medium text-gray-700 dark:text-gray-300 truncate" title={currentPath}>
                  {currentPath}
                </p>
                
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => {
                      loadDirectory(FM_ROOT)
                      setSelectedRoot(FM_ROOT)
                    }}
                    disabled={currentPath === FM_ROOT}
                    className="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-dark-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    title="Go to EasyPi root"
                  >
                    <HomeIcon className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                  </button>
                  
                  <button
                    onClick={handleGoUp}
                    disabled={currentPath === FM_ROOT}
                    className="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-dark-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    title="Go up one level"
                  >
                    <ArrowUpIcon className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                  </button>
                </div>
              </div>
            </div>
            
            {loading ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
              </div>
            ) : (
              <FileTree
                files={files}
                onSelect={handleFileSelect}
                selectedFile={selectedFile}
              />
            )}
          </div>
        </div>

        {/* File Editor */}
        <div className="lg:col-span-2">
          {selectedFile ? (
            <FileEditor
              filePath={selectedFile}
              onSave={handleRefresh}
            />
          ) : (
            <div className="bg-white dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700 p-12">
              <div className="text-center">
                <FileIcon className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-white">
                  No file selected
                </h3>
                <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                  Select a file from the tree to view and edit its contents
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* New File Modal */}
      <Modal
        isOpen={newFileModal}
        onClose={() => {
          setNewFileModal(false)
          setNewFileName('')
        }}
        title="Create New File"
      >
        <div className="space-y-4">
          <Input
            label="File Name"
            value={newFileName}
            onChange={(e) => setNewFileName(e.target.value)}
            placeholder="example.txt"
            autoFocus
          />
          
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              onClick={() => {
                setNewFileModal(false)
                setNewFileName('')
              }}
            >
              Cancel
            </Button>
            <Button variant="primary" onClick={handleCreateFile}>
              Create
            </Button>
          </div>
        </div>
      </Modal>

      {/* New Folder Modal */}
      <Modal
        isOpen={newFolderModal}
        onClose={() => {
          setNewFolderModal(false)
          setNewFolderName('')
        }}
        title="Create New Folder"
      >
        <div className="space-y-4">
          <Input
            label="Folder Name"
            value={newFolderName}
            onChange={(e) => setNewFolderName(e.target.value)}
            placeholder="my-folder"
            autoFocus
          />
          
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              onClick={() => {
                setNewFolderModal(false)
                setNewFolderName('')
              }}
            >
              Cancel
            </Button>
            <Button variant="primary" onClick={handleCreateFolder}>
              Create
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default FileManager
