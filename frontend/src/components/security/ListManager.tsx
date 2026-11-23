import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Plus, Trash2, Edit2, CheckCircle, XCircle, Search, List } from 'lucide-react'
import {
  getWhitelist,
  getBlacklist,
  addToWhitelist,
  addToBlacklist,
  removeFromWhitelist,
  removeFromBlacklist,
} from '../../api/guardSecurity'
import type { DomainEntry } from '../../types/security'

export default function ListManager() {
  const [activeTab, setActiveTab] = useState<'whitelist' | 'blacklist'>('whitelist')
  const [searchQuery, setSearchQuery] = useState('')
  const [showAddModal, setShowAddModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [editingEntry, setEditingEntry] = useState<DomainEntry | null>(null)
  const [newDomain, setNewDomain] = useState('')
  const [newComment, setNewComment] = useState('')
  const queryClient = useQueryClient()

  const { data: whitelistData, isLoading: _whitelistLoading } = useQuery({
    queryKey: ['whitelist'],
    queryFn: getWhitelist,
    staleTime: 0,
    refetchOnMount: true,
  })

  const { data: blacklistData, isLoading: _blacklistLoading } = useQuery({
    queryKey: ['blacklist'],
    queryFn: getBlacklist,
    staleTime: 0,
    refetchOnMount: true,
  })

  const addMutation = useMutation({
    mutationFn: (payload: Omit<DomainEntry, 'id' | 'addedAt' | 'hits'>) =>
      activeTab === 'whitelist' ? addToWhitelist(payload) : addToBlacklist(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [activeTab] })
      setShowAddModal(false)
      setNewDomain('')
      setNewComment('')
    },
    onError: (error: any) => toast.error(error?.response?.data?.detail || 'The domain could not be added'),
  })

  const removeMutation = useMutation({
    mutationFn: (id: string) => (activeTab === 'whitelist' ? removeFromWhitelist(id) : removeFromBlacklist(id)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [activeTab] })
    },
  })

  // Edit: only remove-then-add when the domain itself changed; editing just the
  // comment updates the entry in place so hits / addedAt are preserved.
  const editMutation = useMutation({
    mutationFn: async ({ oldEntry, newDomain: domain }: { oldEntry: DomainEntry; newDomain: string }) => {
      // Add the new name first: if the server refuses it, the old entry stays.
      // The server normalizes names ("Example.com" -> "example.com"), so only
      // drop the old entry when the stored name really changed.
      const domainChanged = domain !== oldEntry.domain
      if (activeTab === 'whitelist') {
        const result = await addToWhitelist({ domain, type: 'exact', enabled: true, comment: newComment })
        if (domainChanged && result?.domain !== oldEntry.domain) await removeFromWhitelist(oldEntry.id)
        return result
      } else {
        const result = await addToBlacklist({ domain, type: 'exact', enabled: true, comment: newComment })
        if (domainChanged && result?.domain !== oldEntry.domain) await removeFromBlacklist(oldEntry.id)
        return result
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [activeTab] })
      setShowEditModal(false)
      setEditingEntry(null)
      setNewDomain('')
      setNewComment('')
    },
    onError: (error: any) => toast.error(error?.response?.data?.detail || 'The change could not be saved'),
  })

  const currentList = useMemo(
    () => (activeTab === 'whitelist' ? whitelistData || [] : blacklistData || []),
    [activeTab, whitelistData, blacklistData],
  )

  const filteredList = currentList.filter(entry =>
    entry.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
    entry.comment?.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const handleAddDomain = () => {
    addMutation.mutate({
      domain: newDomain,
      type: 'exact',
      enabled: true,
      comment: newComment,
    })
  }

  const handleEditClick = (entry: DomainEntry) => {
    setEditingEntry(entry)
    setNewDomain(entry.domain)
    setNewComment(entry.comment || '')
    setShowEditModal(true)
  }

  const handleEditSave = () => {
    if (editingEntry && newDomain.trim()) {
      editMutation.mutate({ oldEntry: editingEntry, newDomain: newDomain.trim() })
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 sm:gap-4">
            <List className="w-10 h-10 sm:w-16 sm:h-16 text-gray-600 dark:text-gray-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">Domain Lists</h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Manage whitelist and blacklist domains
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors w-full sm:w-auto"
          >
            <Plus className="w-4 h-4" />
            Add Domain
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 sm:gap-2 border-b border-gray-200 dark:border-gray-700">
        <button
          onClick={() => setActiveTab('whitelist')}
          className={`px-3 sm:px-6 py-2 sm:py-3 font-medium transition-colors border-b-2 text-sm sm:text-base ${
            activeTab === 'whitelist'
              ? 'border-green-500 text-green-600 dark:text-green-400'
              : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
          }`}
        >
          <div className="flex items-center gap-1 sm:gap-2">
            <CheckCircle className="w-4 h-4" />
            <span className="hidden sm:inline">Whitelist</span> ({(whitelistData || []).length})
          </div>
        </button>
        <button
          onClick={() => setActiveTab('blacklist')}
          className={`px-3 sm:px-6 py-2 sm:py-3 font-medium transition-colors border-b-2 text-sm sm:text-base ${
            activeTab === 'blacklist'
              ? 'border-red-500 text-red-600 dark:text-red-400'
              : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
          }`}
        >
          <div className="flex items-center gap-1 sm:gap-2">
            <XCircle className="w-4 h-4" />
            <span className="hidden sm:inline">Blacklist</span> ({(blacklistData || []).length})
          </div>
        </button>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search domains..."
          className="w-full pl-10 pr-4 py-2 sm:py-3 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
        />
      </div>

      {/* Domains Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="px-3 sm:px-6 py-2 sm:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Domain
                </th>
                <th className="px-3 sm:px-6 py-2 sm:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase hidden md:table-cell">
                  Comment
                </th>
                <th className="px-3 sm:px-6 py-2 sm:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase hidden sm:table-cell">
                  Hits
                </th>
                <th className="px-3 sm:px-6 py-2 sm:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredList.map((entry) => (
                <tr key={entry.id} className="hover:bg-gray-50 dark:hover:bg-gray-900/50">
                  <td className="px-3 sm:px-6 py-3 sm:py-4">
                    <div className="text-sm font-mono font-medium text-gray-900 dark:text-white truncate max-w-[150px] sm:max-w-none">
                      {entry.domain}
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 sm:hidden">
                      {entry.hits.toLocaleString()} hits
                    </div>
                  </td>
                  <td className="px-3 sm:px-6 py-3 sm:py-4 hidden md:table-cell">
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                      {entry.comment || '-'}
                    </span>
                  </td>
                  <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap hidden sm:table-cell">
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {entry.hits.toLocaleString()}
                    </span>
                  </td>
                  <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap">
                    <div className="flex items-center gap-1 sm:gap-2">
                      <button
                        onClick={() => handleEditClick(entry)}
                        className="p-1.5 sm:p-2 text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-500/10 rounded-lg transition-colors"
                        title="Edit"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => removeMutation.mutate(entry.id)}
                        className="p-1.5 sm:p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Domain Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
              Add Domain to {activeTab === 'whitelist' ? 'Whitelist' : 'Blacklist'}
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Domain
                </label>
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                />
                <p className="text-xs text-gray-500 mt-1">Applies to the domain and all its subdomains.</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Comment (optional)
                </label>
                <input
                  type="text"
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  placeholder="Reason for adding..."
                  className="w-full px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                />
              </div>
              <div className="flex gap-3 pt-4">
                <button
                  onClick={handleAddDomain}
                  disabled={addMutation.isPending || !newDomain.trim()}
                  className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 text-white rounded-lg transition-colors"
                >
                  Add
                </button>
                <button
                  onClick={() => setShowAddModal(false)}
                  className="flex-1 px-4 py-2 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit Domain Modal */}
      {showEditModal && editingEntry && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
              Edit Domain
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Domain
                </label>
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Comment (optional)
                </label>
                <input
                  type="text"
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  placeholder="Reason for adding..."
                  className="w-full px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                />
              </div>
              <div className="flex gap-3 pt-4">
                <button
                  onClick={handleEditSave}
                  disabled={editMutation.isPending}
                  className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-400 text-white rounded-lg transition-colors"
                >
                  {editMutation.isPending ? 'Saving...' : 'Save'}
                </button>
                <button
                  onClick={() => {
                    setShowEditModal(false)
                    setEditingEntry(null)
                    setNewDomain('')
                    setNewComment('')
                  }}
                  className="flex-1 px-4 py-2 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
