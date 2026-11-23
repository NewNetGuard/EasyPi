import { useState, useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { 
  Lock, 
  Eye, 
  EyeOff, 
  File,
  Check,
  Loader2,
  FolderLock
} from 'lucide-react'
import Button from '../common/Button'
import {
  encryptFile,
  encryptedBlobsEqual,
  encryptedFileNameFor,
} from '../../utils/encryption'
import {
  listFiles,
  uploadFile,
  deleteFile,
  deleteFilePermanently,
  createFolder,
  fetchAuthenticatedBlob,
} from '../../api/cloud'
import type { PiCloudFile, FileCategory } from '../../types/cloud'
import { toast } from 'react-hot-toast'

interface EncryptFileModalProps {
  isOpen: boolean
  onClose: () => void
  preSelectedFile?: PiCloudFile | null
}

const ENCRYPTED_FOLDER = '/Encrypted'

const getParentPath = (fileId: string): string => {
  const parts = fileId.replace(/\\/g, '/').split('/').filter(Boolean)
  return parts.length <= 1 ? '/' : `/${parts.slice(0, -1).join('/')}`
}

type EncryptSource = 'cloud' | 'local'

const EncryptFileModal = ({ isOpen, onClose, preSelectedFile }: EncryptFileModalProps) => {
  const queryClient = useQueryClient()
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [encrypting, setEncrypting] = useState(false)
  const [mode, setMode] = useState<'select' | 'encrypting'>('select')
  const [selectedFile, setSelectedFile] = useState<PiCloudFile | null>(null)
  const [localFile, setLocalFile] = useState<File | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<FileCategory>('all')
  const [source, setSource] = useState<EncryptSource>('cloud')
  
  // Fetch files for selection
  const { data: filesData } = useQuery({
    queryKey: ['picloud-files-for-encrypt', '/', selectedCategory, searchQuery],
    queryFn: async () => {
      const trimmedSearch = searchQuery.trim()
      const baseOptions = {
        limit: 200,
        sortBy: 'name' as const,
        sortOrder: 'asc' as const,
      }

      if (trimmedSearch) {
        return listFiles('/', {
          ...baseOptions,
          category: selectedCategory !== 'all' ? selectedCategory : undefined,
          search: trimmedSearch,
        })
      }

      if (selectedCategory !== 'all') {
        return listFiles('/', { ...baseOptions, category: selectedCategory })
      }

      const categories: FileCategory[] = ['photos', 'videos', 'documents', 'audio', 'other']
      const responses = await Promise.all(
        categories.map((category) => listFiles('/', { ...baseOptions, category }))
      )
      const merged = new Map<string, PiCloudFile>()
      responses.forEach((res) => {
        res.items.forEach((file) => {
          if (!merged.has(file.id)) {
            merged.set(file.id, file)
          }
        })
      })
      const items = Array.from(merged.values()).sort((a, b) =>
        a.name.localeCompare(b.name)
      )
      return {
        path: '/',
        items,
        totalCount: items.length,
        hasMore: false,
      }
    },
    enabled: isOpen && mode === 'select' && source === 'cloud',
  })
  
  useEffect(() => {
    if (isOpen) {
      setMode('select')
      if (preSelectedFile) {
        setSelectedFile(preSelectedFile)
        setSource('cloud')
      }
      if (preSelectedFile?.category && preSelectedFile.category !== 'encrypted') {
        setSelectedCategory(preSelectedFile.category)
      } else {
        setSelectedCategory('all')
      }
    } else {
      // Reset state when closing
      setMode('select')
      setSelectedFile(null)
      setLocalFile(null)
      setSearchQuery('')
      setSelectedCategory('all')
      setPassword('')
      setConfirmPassword('')
    }
  }, [isOpen, preSelectedFile])
  
  const handleEncryptFile = async () => {
    if (password.length < 8) {
      toast.error('Password must be at least 8 characters')
      return
    }
    if (password !== confirmPassword) {
      toast.error('Passwords do not match')
      return
    }
    if (source === 'cloud' && !selectedFile) {
      toast.error('Please select a file to encrypt')
      return
    }
    if (source === 'local' && !localFile) {
      toast.error('Please choose a file to encrypt')
      return
    }
    
    setEncrypting(true)
    setMode('encrypting')
    
    try {
      let originalFile: File
      let originalParentPath = '/'

      if (source === 'cloud' && selectedFile) {
        // 1. Download the original file
        toast.loading('Downloading file...', { id: 'encrypt-progress' })
        const originalBlob = await fetchAuthenticatedBlob(selectedFile.id)
        originalFile = new window.File([originalBlob], selectedFile.name, {
          type: selectedFile.mime || 'application/octet-stream',
        })
        originalParentPath = getParentPath(selectedFile.id)
      } else if (localFile) {
        originalFile = localFile
      } else {
        throw new Error('No file selected')
      }
      
      // 2. Encrypt the file
      toast.loading('Encrypting file...', { id: 'encrypt-progress' })
      const encryptedBlob = await encryptFile(originalFile, password, {
        originalName: originalFile.name,
        originalMime: originalFile.type || 'application/octet-stream',
        originalParentPath,
      })
      const encryptedFileName = encryptedFileNameFor(originalFile.name)
      
      // 3. Create encrypted folder if it doesn't exist
      try {
        await createFolder(ENCRYPTED_FOLDER)
      } catch {
        // Folder might already exist, ignore error
      }
      
      // 4. Upload encrypted file to the Encrypted folder
      toast.loading('Uploading encrypted file...', { id: 'encrypt-progress' })
      const encryptedFile = new window.File([encryptedBlob], encryptedFileName, { type: 'application/octet-stream' })
      
      const uploadedFile = await uploadFile(ENCRYPTED_FOLDER, encryptedFile, () => {})

      // 5. Read the uploaded bytes back before the original is removed. A
      // successful HTTP response alone does not prove that the complete file
      // reached storage intact.
      toast.loading('Verifying encrypted upload...', { id: 'encrypt-progress' })
      const uploadedBlob = await fetchAuthenticatedBlob(uploadedFile.id)
      if (!(await encryptedBlobsEqual(encryptedBlob, uploadedBlob))) {
        try {
          await deleteFile(uploadedFile.id)
        } catch (cleanupError) {
          console.error('Failed to remove invalid encrypted upload:', cleanupError)
        }
        throw new Error('Encrypted upload verification failed; the original file was kept')
      }
      
      // 6. Delete original file (cloud source only), after verification.
      let originalRemoved = true
      if (source === 'cloud' && selectedFile) {
        toast.loading('Removing unencrypted original...', { id: 'encrypt-progress' })
        try {
          await deleteFilePermanently(selectedFile.id)
        } catch (error) {
          console.error('Failed to remove original file:', error)
          originalRemoved = false
        }
      }
      
      // 7. Success!
      if (originalRemoved) {
        toast.success('Encrypted file verified and saved', { id: 'encrypt-progress' })
      } else {
        toast('Encrypted file verified, but the unencrypted original could not be removed and was kept', {
          id: 'encrypt-progress',
        })
      }
      
      // Refresh file lists
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-files-for-encrypt'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-folder-tree'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-stats'] })
      
      // Close modal
      onClose()
      
    } catch (error) {
      console.error('Encryption failed:', error)
      toast.error(error instanceof Error ? error.message : 'Failed to encrypt file', { id: 'encrypt-progress' })
      setMode('select')
    } finally {
      setEncrypting(false)
    }
  }
  
  // Filter files (exclude folders and already encrypted files)
  const availableFiles = (filesData?.items || []).filter((f: PiCloudFile) => 
    f.type !== 'folder' && 
    !f.name.endsWith('.encrypted') &&
    !f.name.endsWith('.epec')
  ) || []

  const categoryOptions: { value: FileCategory; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'photos', label: 'Photos' },
    { value: 'videos', label: 'Videos' },
    { value: 'documents', label: 'Documents' },
    { value: 'audio', label: 'Audio' },
    { value: 'other', label: 'Files' },
  ]
  
  if (!isOpen) return null
  
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white dark:bg-dark-900 rounded-xl shadow-xl max-w-lg w-full mx-4 max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center gap-3 p-4 border-b border-gray-200 dark:border-dark-700">
          <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
            <FolderLock className="h-5 w-5 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Encrypt File
            </h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {mode === 'encrypting' ? 'Encrypting...' : 'Select a file to encrypt'}
            </p>
          </div>
        </div>
        
        {/* Content */}
        <div className="p-4 flex-1 overflow-y-auto">
          {mode === 'select' && (
            <div className="space-y-4">
              {/* Source selector */}
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setSource('cloud')
                    setLocalFile(null)
                  }}
                  className={`flex-1 rounded-lg border px-3 py-2 text-sm font-medium ${
                    source === 'cloud'
                      ? 'border-primary-600 bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'
                      : 'border-gray-200 bg-white text-gray-700 dark:border-dark-700 dark:bg-dark-800 dark:text-gray-300'
                  }`}
                >
                  From Cloud
                </button>
                <button
                  onClick={() => {
                    setSource('local')
                    setSelectedFile(null)
                  }}
                  className={`flex-1 rounded-lg border px-3 py-2 text-sm font-medium ${
                    source === 'local'
                      ? 'border-primary-600 bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'
                      : 'border-gray-200 bg-white text-gray-700 dark:border-dark-700 dark:bg-dark-800 dark:text-gray-300'
                  }`}
                >
                  From Computer
                </button>
              </div>

              {source === 'cloud' && (
                <>
              {/* Categories */}
              <div className="flex flex-wrap gap-2">
                {categoryOptions.map((option) => (
                  <button
                    key={option.value}
                    onClick={() => setSelectedCategory(option.value)}
                    className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-colors ${
                      selectedCategory === option.value
                        ? 'bg-primary-600 text-white border-primary-600'
                        : 'bg-white dark:bg-dark-800 text-gray-700 dark:text-gray-300 border-gray-200 dark:border-dark-700 hover:bg-gray-50 dark:hover:bg-dark-700'
                    }`}
                  >
                    {option.label}
                  </button>
                ))}
              </div>

              {/* Search */}
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-800 text-gray-900 dark:text-white"
                placeholder="Search files..."
              />
              
              {/* Selected file indicator */}
              {selectedFile && (
                <div className="flex items-center gap-2 p-3 bg-primary-50 dark:bg-primary-900/20 rounded-lg">
                  <Lock className="h-4 w-4 text-primary-600" />
                  <span className="text-sm font-medium text-primary-700 dark:text-primary-300 truncate">
                    {selectedFile.name}
                  </span>
                  <span className="text-xs text-primary-600 dark:text-primary-400 ml-auto">Selected</span>
                </div>
              )}
              
              {/* File list */}
              <div className="border border-gray-200 dark:border-dark-700 rounded-lg max-h-64 overflow-y-auto">
                {availableFiles.length === 0 ? (
                  <div className="p-4 text-center text-gray-500 dark:text-gray-400">
                    No files available to encrypt
                  </div>
                ) : (
                  availableFiles.map((file) => (
                    <button
                      key={file.id}
                      onClick={() => setSelectedFile(file)}
                      className={`w-full flex items-center gap-3 p-3 text-left hover:bg-gray-50 dark:hover:bg-dark-800 transition-colors ${
                        selectedFile?.id === file.id 
                          ? 'bg-primary-50 dark:bg-primary-900/20' 
                          : ''
                      }`}
                    >
                      <File className="h-5 w-5 text-gray-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                          {file.name}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {file.size ? `${(file.size / 1024).toFixed(1)} KB` : 'Unknown size'}
                        </p>
                      </div>
                      {selectedFile?.id === file.id && (
                        <Check className="h-5 w-5 text-primary-600 flex-shrink-0" />
                      )}
                    </button>
                  ))
                )}
              </div>
                </>
              )}

              {source === 'local' && (
                <div className="space-y-3">
                  <input
                    type="file"
                    onChange={(e) => {
                      const file = e.target.files?.[0] || null
                      setLocalFile(file)
                    }}
                    className="w-full text-sm text-gray-700 dark:text-gray-300"
                  />
                  {localFile && (
                    <div className="flex items-center gap-2 p-3 bg-primary-50 dark:bg-primary-900/20 rounded-lg">
                      <File className="h-4 w-4 text-primary-600" />
                      <span className="text-sm font-medium text-primary-700 dark:text-primary-300 truncate">
                        {localFile.name}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* Password */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Encryption password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-3 py-2 pr-10 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-800 text-gray-900 dark:text-white"
                    placeholder="Min 8 characters"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Confirm password
                </label>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-800 text-gray-900 dark:text-white"
                  placeholder="Re-enter password"
                />
              </div>

              <div className="text-xs text-gray-500 dark:text-gray-400 flex items-start gap-2">
                <Lock className="h-4 w-4 flex-shrink-0" />
                <span>
                  The file will be encrypted with AES-256-GCM and saved to the "Encrypted Files" section.
                  {source === 'cloud' ? ' The unencrypted original will be permanently deleted only after the encrypted upload is verified.' : ''}
                  {' '}The password is not stored and cannot be recovered.
                </span>
              </div>
            </div>
          )}
          
          {mode === 'encrypting' && (
            <div className="flex flex-col items-center justify-center py-8">
              <Loader2 className="h-12 w-12 text-primary-600 animate-spin mb-4" />
              <p className="text-gray-700 dark:text-gray-300 font-medium">
                Encrypting file...
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Please don't close this window
              </p>
            </div>
          )}
        </div>
        
        {/* Footer */}
        {mode === 'select' && (
          <div className="flex justify-end gap-2 p-4 border-t border-gray-200 dark:border-dark-700">
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button 
              onClick={handleEncryptFile} 
              disabled={(source === 'cloud' ? !selectedFile : !localFile) || encrypting}
              icon={<Lock className="h-4 w-4" />}
            >
              Encrypt File
            </Button>
          </div>
        )}
      </div>
    </div>
  )
}

export default EncryptFileModal
