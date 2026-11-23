import { useState, useEffect } from 'react'
import { SaveIcon, AlertCircleIcon, ImageIcon, FileIcon as FileIconLucide } from 'lucide-react'
import Button from '../common/Button'
import { toast } from 'react-hot-toast'
import { readFile, writeFile, getFileType, getImageUrl } from '../../api/files'

interface FileEditorProps {
  filePath: string
  onSave?: () => void
}

const FileEditor = ({ filePath, onSave }: FileEditorProps) => {
  const [content, setContent] = useState('')
  const [originalContent, setOriginalContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [fileInfo, setFileInfo] = useState<any>(null)
  const [hasChanges, setHasChanges] = useState(false)
  const [fileType, setFileType] = useState<string>('text')

  useEffect(() => {
    let active = true

    const loadFile = async () => {
      setLoading(true)
      try {
        const typeInfo = await getFileType(filePath)
        if (!active) return
        setFileType(typeInfo.category)

        if (typeInfo.category === 'text') {
          const data = await readFile(filePath)
          if (!active) return
          setContent(data.content)
          setOriginalContent(data.content)
          setFileInfo(data)
        } else {
          setFileInfo({ path: filePath, mime_type: typeInfo.mime_type })
        }
      } catch (error: any) {
        if (active) toast.error(error.message || 'Failed to load file')
      } finally {
        if (active) setLoading(false)
      }
    }

    void loadFile()
    return () => {
      active = false
    }
  }, [filePath])

  useEffect(() => {
    setHasChanges(content !== originalContent)
  }, [content, originalContent])

  const handleSave = async () => {
    setSaving(true)
    try {
      await writeFile(filePath, content)
      setOriginalContent(content)
      toast.success('File saved successfully')
      onSave?.()
    } catch (error: any) {
      toast.error(error.message || 'Failed to save file')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="bg-white dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700 p-12">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-white dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-dark-700">
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-medium text-gray-900 dark:text-white truncate" title={filePath}>
            {filePath}
          </h3>
          {fileInfo && (
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {fileInfo.size_formatted} • Modified {new Date(fileInfo.modified).toLocaleString()}
            </p>
          )}
        </div>

        <div className="flex items-center gap-2 ml-4">
          {fileType === 'text' && (
            <Button
              variant="primary"
              size="sm"
              onClick={handleSave}
              icon={<SaveIcon className="h-4 w-4" />}
              disabled={!hasChanges || saving}
              loading={saving}
            >
              {saving ? 'Saving...' : 'Save'}
            </Button>
          )}
        </div>
      </div>

      {/* Changes Warning */}
      {hasChanges && (
        <div className="px-4 py-2 bg-yellow-50 dark:bg-yellow-900/20 border-b border-yellow-200 dark:border-yellow-800">
          <div className="flex items-center gap-2 text-sm text-yellow-800 dark:text-yellow-200">
            <AlertCircleIcon className="h-4 w-4" />
            <span>You have unsaved changes</span>
          </div>
        </div>
      )}

      {/* Content */}
      <div className="p-4">
        {fileType === 'image' ? (
          /* Image Preview */
          <div className="flex items-center justify-center bg-gray-50 dark:bg-dark-900 rounded-md border border-gray-300 dark:border-dark-600 p-8">
            <div className="text-center">
              <img
                src={getImageUrl(filePath)}
                alt={filePath.split('/').pop()}
                className="max-w-full max-h-[600px] object-contain rounded-lg shadow-lg"
                onError={(e) => {
                  e.currentTarget.style.display = 'none'
                  e.currentTarget.nextElementSibling?.classList.remove('hidden')
                }}
              />
              <div className="hidden">
                <ImageIcon className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500 dark:text-gray-400">Failed to load image</p>
              </div>
            </div>
          </div>
        ) : fileType === 'text' ? (
          /* Text Editor */
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="
              w-full h-[600px] px-4 py-3 rounded-md
              bg-gray-50 dark:bg-dark-900
              border border-gray-300 dark:border-dark-600
              text-gray-900 dark:text-white
              font-mono text-sm
              focus:outline-none focus:ring-2 focus:ring-primary-500
              resize-none
            "
            spellCheck={false}
          />
        ) : (
          /* Binary File */
          <div className="flex items-center justify-center bg-gray-50 dark:bg-dark-900 rounded-md border border-gray-300 dark:border-dark-600 h-[600px]">
            <div className="text-center">
              <FileIconLucide className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                Binary File
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                This file type cannot be edited in the browser
              </p>
              {fileInfo?.mime_type && (
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-2">
                  {fileInfo.mime_type}
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default FileEditor
