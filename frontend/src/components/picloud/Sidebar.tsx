import { useQuery } from '@tanstack/react-query'
import {
  Bot,
  Clock,
  File,
  FileSearch,
  FileText,
  FolderOpen,
  HardDrive,
  Home,
  Image,
  Lock,
  Music4,
  Trash2,
  Video,
} from 'lucide-react'
import clsx from 'clsx'

import type { FileCategory } from '../../types/cloud'
import { useCloudStore } from '../../stores/cloudStore'
import { getFolderTree, getStorageStats } from '../../api/cloud'
import Card from '../common/Card'
import ProgressBar from '../common/ProgressBar'

interface SidebarProps {
  className?: string
  onItemClick?: () => void
}

const Sidebar = ({ className, onItemClick }: SidebarProps) => {
  const {
    currentPath,
    setPath,
    category,
    setCategory,
    favoriteOnly,
    setFavoriteOnly,
  } = useCloudStore()

  const { data: stats } = useQuery({
    queryKey: ['picloud-stats'],
    queryFn: getStorageStats,
    refetchInterval: 30000,
  })

  const { data: folderTree } = useQuery({
    queryKey: ['picloud-folder-tree'],
    queryFn: getFolderTree,
  })

  const formatSize = (bytes: number) => {
    if (!bytes) return '0 B'
    const k = 1024
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${['B', 'KB', 'MB', 'GB', 'TB'][i]}`
  }

  const navItems = [
    { id: 'files', label: 'My Files', icon: Home, action: () => { setPath('/'); setFavoriteOnly(false); setCategory('all') } },
    { id: 'recent', label: 'Recent', icon: Clock, action: () => { setPath('/recent'); setFavoriteOnly(false); setCategory('all') } },
    { id: 'trash', label: 'Trash', icon: Trash2, action: () => { setPath('/.trash'); setFavoriteOnly(false); setCategory('all') } },
    { id: 'telegram', label: 'Telegram Bot', icon: Bot, action: () => { setPath('/telegram'); setFavoriteOnly(false); setCategory('all') } },
  ]

  const categoryItems = [
    { id: 'all', label: 'All Files', icon: FileSearch },
    { id: 'photos', label: 'Photos', icon: Image },
    { id: 'videos', label: 'Videos', icon: Video },
    { id: 'documents', label: 'Documents', icon: FileText },
    { id: 'audio', label: 'Music', icon: Music4 },
    { id: 'other', label: 'Files', icon: File },
    { id: 'encrypted', label: 'Encrypted Files', icon: Lock },
  ]

  const isNavItemActive = (itemId: string) => {
    if (itemId === 'files') return currentPath === '/' && !favoriteOnly
    if (itemId === 'recent') return currentPath === '/recent'
    if (itemId === 'trash') return currentPath === '/.trash'
    if (itemId === 'telegram') return currentPath === '/telegram'
    return false
  }

  return (
    <aside className={clsx('flex h-full w-64 flex-col gap-4 overflow-y-auto bg-gray-50 p-4 dark:bg-dark-900', className)}>
      <Card noPadding>
        <nav className="py-2">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => { item.action(); onItemClick?.() }}
              className={clsx(
                'flex w-full items-center gap-3 px-4 py-2.5 text-sm font-medium transition-colors',
                isNavItemActive(item.id)
                  ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-400'
                  : 'text-gray-700 hover:bg-gray-50 dark:text-gray-300 dark:hover:bg-dark-800'
              )}
            >
              <item.icon className="h-5 w-5" />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
      </Card>

      <Card title="Categories" noPadding>
        <nav className="py-2">
          {categoryItems.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setPath('/')
                setCategory(item.id as FileCategory)
                setFavoriteOnly(false)
                onItemClick?.()
              }}
              className={clsx(
                'flex w-full items-center gap-3 px-4 py-2.5 text-sm font-medium transition-colors',
                category === item.id
                  ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-400'
                  : 'text-gray-700 hover:bg-gray-50 dark:text-gray-300 dark:hover:bg-dark-800'
              )}
            >
              <item.icon className="h-5 w-5" />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
      </Card>

      {stats && (
        <Card title="Storage" className="flex-shrink-0">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <HardDrive className="h-4 w-4 text-gray-500" />
              <span className="text-gray-600 dark:text-gray-400">
                {formatSize(stats.used)} / {formatSize(stats.total)}
              </span>
            </div>

            <ProgressBar progress={stats.percent} size="sm" showPercentage />

            <div className="grid grid-cols-2 gap-2 text-xs text-gray-500">
              <div>
                <div className="font-medium text-gray-900 dark:text-white">{stats.fileCount}</div>
                <div>Files</div>
              </div>
              <div>
                <div className="font-medium text-gray-900 dark:text-white">{stats.folderCount}</div>
                <div>Folders</div>
              </div>
            </div>
          </div>
        </Card>
      )}

      {Array.isArray(folderTree) && folderTree.length > 0 && (
        <Card title="Folders" noPadding className="flex-1 overflow-hidden">
          <div className="max-h-64 overflow-y-auto p-2">
            {folderTree.slice(0, 10).map((folder: any) => (
              <button
                key={folder.id}
                onClick={() => setPath(folder.path)}
                className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-dark-800"
              >
                <FolderOpen className="h-4 w-4 text-blue-500" />
                <span className="truncate">{folder.name}</span>
                {folder.itemCount > 0 && (
                  <span className="ml-auto text-xs text-gray-500">{folder.itemCount}</span>
                )}
              </button>
            ))}
          </div>
        </Card>
      )}
    </aside>
  )
}

export default Sidebar
