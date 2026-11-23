import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, RotateCcw, AlertTriangle } from 'lucide-react'
import { toast } from 'react-hot-toast'

import Card from '../common/Card'
import Button from '../common/Button'
import { listTrash, restoreFromTrash, deleteFromTrash, emptyTrash } from '../../api/cloud'
import type { TrashItem } from '../../types/cloud'

const TrashView = () => {
  const queryClient = useQueryClient()
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set())

  const { data: trashItems, isLoading, error } = useQuery({
    queryKey: ['picloud-trash'],
    queryFn: listTrash,
  })

  const restoreMutation = useMutation({
    mutationFn: restoreFromTrash,
    onSuccess: () => {
      toast.success('File restored')
      queryClient.invalidateQueries({ queryKey: ['picloud-trash'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-files'] })
    },
    onError: () => toast.error('Failed to restore file'),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteFromTrash,
    onSuccess: () => {
      toast.success('File permanently deleted')
      queryClient.invalidateQueries({ queryKey: ['picloud-trash'] })
    },
    onError: () => toast.error('Failed to delete file'),
  })

  const emptyMutation = useMutation({
    mutationFn: emptyTrash,
    onSuccess: () => {
      toast.success('Trash emptied')
      queryClient.invalidateQueries({ queryKey: ['picloud-trash'] })
      queryClient.invalidateQueries({ queryKey: ['picloud-stats'] })
      setSelectedItems(new Set())
    },
    onError: () => toast.error('Failed to empty trash'),
  })

  const handleSelectItem = (id: string) => {
    setSelectedItems(prev => {
      const newSet = new Set(prev)
      if (newSet.has(id)) {
        newSet.delete(id)
      } else {
        newSet.add(id)
      }
      return newSet
    })
  }

  const handleSelectAll = () => {
    if (trashItems) {
      if (selectedItems.size === trashItems.length) {
        setSelectedItems(new Set())
      } else {
        setSelectedItems(new Set(trashItems.map(item => item.id)))
      }
    }
  }

  const handleRestoreSelected = () => {
    selectedItems.forEach(id => restoreMutation.mutate(id))
    setSelectedItems(new Set())
  }

  const handleDeleteSelected = () => {
    if (confirm(`Permanently delete ${selectedItems.size} items? This cannot be undone.`)) {
      selectedItems.forEach(id => deleteMutation.mutate(id))
      setSelectedItems(new Set())
    }
  }

  const handleEmptyTrash = () => {
    if (confirm('Empty trash? This will permanently delete all items and cannot be undone.')) {
      emptyMutation.mutate()
    }
  }

  const formatDate = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleString()
    } catch {
      return dateStr
    }
  }

  if (isLoading) {
    return (
      <Card className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent mb-4"></div>
          <p className="text-sm text-gray-600 dark:text-gray-400">Loading trash...</p>
        </div>
      </Card>
    )
  }

  if (error) {
    return (
      <Card className="flex items-center justify-center h-64">
        <div className="text-center text-red-500">
          <AlertTriangle className="h-8 w-8 mx-auto mb-2" />
          <p>Failed to load trash</p>
        </div>
      </Card>
    )
  }

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Trash2 className="h-8 w-8 text-gray-500" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Trash</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {trashItems?.length || 0} items in trash
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {selectedItems.size > 0 && (
            <>
              <span className="text-sm text-gray-600 dark:text-gray-400">
                {selectedItems.size} selected
              </span>
              <Button
                variant="outline"
                size="sm"
                icon={<RotateCcw className="h-4 w-4" />}
                onClick={handleRestoreSelected}
              >
                Restore
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleDeleteSelected}
              >
                Delete Permanently
              </Button>
            </>
          )}
          
          {trashItems && trashItems.length > 0 && (
            <Button
              variant="danger"
              size="sm"
              icon={<Trash2 className="h-4 w-4" />}
              onClick={handleEmptyTrash}
            >
              Empty Trash
            </Button>
          )}
        </div>
      </div>

      {/* Trash List */}
      {!trashItems || trashItems.length === 0 ? (
        <Card className="flex flex-col items-center justify-center h-64 text-center">
          <Trash2 className="h-16 w-16 text-gray-300 dark:text-gray-600 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            Trash is empty
          </h3>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Deleted files will appear here
          </p>
        </Card>
      ) : (
        <Card noPadding>
          <table className="w-full">
            <thead className="border-b border-gray-200 dark:border-dark-700">
              <tr>
                <th className="px-4 py-3 text-left">
                  <input
                    type="checkbox"
                    checked={selectedItems.size === trashItems.length}
                    onChange={handleSelectAll}
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-300">
                  Original Location
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-300">
                  Deleted At
                </th>
                <th className="px-4 py-3 text-right text-sm font-medium text-gray-700 dark:text-gray-300">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-dark-700">
              {trashItems.map((item) => (
                <tr
                  key={item.id}
                  className={`hover:bg-gray-50 dark:hover:bg-dark-800 ${
                    selectedItems.has(item.id) ? 'bg-primary-50 dark:bg-primary-900/20' : ''
                  }`}
                >
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectedItems.has(item.id)}
                      onChange={() => handleSelectItem(item.id)}
                      className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Trash2 className="h-5 w-5 text-gray-400" />
                      <span className="text-sm text-gray-900 dark:text-white">
                        {item.original}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                    {formatDate(item.deleted_at)}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        icon={<RotateCcw className="h-4 w-4" />}
                        onClick={() => restoreMutation.mutate(item.id)}
                        disabled={restoreMutation.isPending}
                      >
                        Restore
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => {
                          if (confirm(`Permanently delete "${item.original}"?`)) {
                            deleteMutation.mutate(item.id)
                          }
                        }}
                        disabled={deleteMutation.isPending}
                      >
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  )
}

export default TrashView
