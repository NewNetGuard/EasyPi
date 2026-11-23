import { useEffect, useRef, useState } from 'react'
import {
  Eye,
  Download,
  Share2,
  Edit3,
  FolderInput,
  Copy,
  Unlock,
  Star,
  Palette,
  Tag,
  Trash2,
} from 'lucide-react'
import type { PiCloudFile, ColorLabel } from '../../types/cloud'

interface MenuItem {
  icon: React.ReactNode
  label: string
  onClick: () => void
  danger?: boolean
  divider?: boolean
}

interface ContextMenuProps {
  file: PiCloudFile
  position: { x: number; y: number }
  onClose: () => void
  onPreview: () => void
  onDownload: () => void
  onShare: () => void
  onRename: () => void
  onMove: () => void
  onCopy: () => void
  onFavorite: () => void
  onColorLabel: (color: ColorLabel) => void
  onTag: () => void
  onDelete: () => void
  deletable?: boolean
  previewable?: boolean
  isEncrypted?: boolean
  onDownloadEncrypted?: () => void
  onDecrypt?: () => void
}

const colorLabels: { value: ColorLabel; label: string; color: string }[] = [
  { value: 'none', label: 'None', color: 'transparent' },
  { value: 'red', label: 'Red', color: '#ef4444' },
  { value: 'orange', label: 'Orange', color: '#f97316' },
  { value: 'yellow', label: 'Yellow', color: '#eab308' },
  { value: 'green', label: 'Green', color: '#22c55e' },
  { value: 'blue', label: 'Blue', color: '#3b82f6' },
  { value: 'purple', label: 'Purple', color: '#a855f7' },
  { value: 'gray', label: 'Gray', color: '#6b7280' },
]

const ContextMenu = ({
  file,
  position,
  onClose,
  onPreview,
  onDownload,
  onShare,
  onRename,
  onMove,
  onCopy,
  onFavorite,
  onColorLabel,
  onTag,
  onDelete,
  deletable = true,
  previewable = true,
  isEncrypted = false,
  onDownloadEncrypted,
  onDecrypt,
}: ContextMenuProps) => {
  const menuRef = useRef<HTMLDivElement>(null)
  const [showColorSubmenu, setShowColorSubmenu] = useState(false)
  
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
      }
    }
    
    document.addEventListener('mousedown', handleClickOutside)
    document.addEventListener('keydown', handleEscape)
    
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [onClose])
  
  // Adjust position if menu goes off screen
  useEffect(() => {
    if (menuRef.current) {
      const rect = menuRef.current.getBoundingClientRect()
      const viewportWidth = window.innerWidth
      const viewportHeight = window.innerHeight
      
      let { x, y } = position
      
      if (x + rect.width > viewportWidth) {
        x = viewportWidth - rect.width - 10
      }
      if (y + rect.height > viewportHeight) {
        y = viewportHeight - rect.height - 10
      }
      
      menuRef.current.style.left = `${x}px`
      menuRef.current.style.top = `${y}px`
    }
  }, [position])
  
  const menuItems: MenuItem[] = [
    ...(previewable
      ? [
          {
            icon: <Eye className="h-4 w-4" />,
            label: 'Preview',
            onClick: onPreview,
          },
        ]
      : []),
    {
      icon: <Download className="h-4 w-4" />,
      label: 'Download',
      onClick: onDownload,
    },
    ...(isEncrypted && onDownloadEncrypted
      ? [
          {
            icon: <Download className="h-4 w-4" />,
            label: 'Download encrypted',
            onClick: onDownloadEncrypted,
          },
        ]
      : []),
    ...(isEncrypted && onDecrypt
      ? [
          {
            icon: <Unlock className="h-4 w-4" />,
            label: 'Decrypt to Cloud',
            onClick: onDecrypt,
          },
        ]
      : []),
    {
      icon: <Share2 className="h-4 w-4" />,
      label: 'Share',
      onClick: onShare,
      divider: true,
    },
    {
      icon: <Edit3 className="h-4 w-4" />,
      label: 'Rename',
      onClick: onRename,
    },
    {
      icon: <FolderInput className="h-4 w-4" />,
      label: 'Move',
      onClick: onMove,
    },
    {
      icon: <Copy className="h-4 w-4" />,
      label: 'Copy',
      onClick: onCopy,
      divider: true,
    },
    {
      icon: <Star className="h-4 w-4" />,
      label: file.favorite ? 'Remove from Favorites' : 'Add to Favorites',
      onClick: onFavorite,
    },
    {
      icon: <Tag className="h-4 w-4" />,
      label: 'Manage Tags',
      onClick: onTag,
      divider: true,
    },
    ...(deletable
      ? [
          {
            icon: <Trash2 className="h-4 w-4" />,
            label: 'Delete',
            onClick: onDelete,
            danger: true,
          },
        ]
      : []),
  ]
  
  return (
    <>
      <div
        ref={menuRef}
        className="fixed z-50 w-56 bg-white dark:bg-dark-800 rounded-lg shadow-lg border border-gray-200 dark:border-dark-700 py-1"
        style={{ left: position.x, top: position.y }}
      >
        {menuItems.map((item, index) => (
          <div key={index}>
            <button
              onClick={() => {
                item.onClick()
                onClose()
              }}
              className={`w-full flex items-center gap-3 px-4 py-2 text-sm text-left transition-colors ${
                item.danger
                  ? 'text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20'
                  : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-700'
              }`}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
            
            {item.divider && <div className="my-1 border-t border-gray-200 dark:border-dark-700" />}
          </div>
        ))}
        
        {/* Color Label Submenu */}
        <div className="relative">
          <button
            onClick={() => setShowColorSubmenu(!showColorSubmenu)}
            className="w-full flex items-center gap-3 px-4 py-2 text-sm text-left text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors"
          >
            <Palette className="h-4 w-4" />
            <span>Color Label</span>
            <span className="ml-auto text-gray-400">›</span>
          </button>
          
          {showColorSubmenu && (
            <div className="absolute left-full top-0 ml-1 w-40 bg-white dark:bg-dark-800 rounded-lg shadow-lg border border-gray-200 dark:border-dark-700 py-1">
              {colorLabels.map((colorItem) => (
                <button
                  key={colorItem.value}
                  onClick={() => {
                    onColorLabel(colorItem.value)
                    onClose()
                  }}
                  className="w-full flex items-center gap-3 px-4 py-2 text-sm text-left text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors"
                >
                  <div
                    className="w-4 h-4 rounded-full border-2 border-gray-300 dark:border-dark-600"
                    style={{ backgroundColor: colorItem.color }}
                  />
                  <span>{colorItem.label}</span>
                  {file.colorLabel === colorItem.value && (
                    <span className="ml-auto text-primary-600">✓</span>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  )
}

export default ContextMenu
