import { create } from 'zustand'
import type { PiCloudFile, FileCategory, SortField, SortOrder } from '../types/cloud'
import { isSystemCloudFolder, isSystemCloudFolderId } from '../utils/cloudSystemFolders'

export type ViewMode = 'grid' | 'list'
export type SelectionMode = 'single' | 'multiple'

interface CloudState {
  // Navigation
  currentPath: string
  pathHistory: string[]
  
  // View
  viewMode: ViewMode
  selectionMode: SelectionMode
  
  // Filters & Sorting
  category: FileCategory
  favoriteOnly: boolean
  searchQuery: string
  sortBy: SortField
  sortOrder: SortOrder
  
  // Selection
  selectedFiles: Set<string>
  
  // UI State
  uploadModalOpen: boolean
  shareModalOpen: boolean
  telegramModalOpen: boolean
  previewFile: PiCloudFile | null
  contextMenuFile: PiCloudFile | null
  contextMenuPosition: { x: number; y: number } | null
  
  // Special views
  activeView: 'files' | 'activity' | 'duplicates'
  
  // Actions - Navigation
  setPath: (path: string) => void
  goBack: () => void
  goForward: () => void
  navigateToParent: () => void
  
  // Actions - View
  setViewMode: (mode: ViewMode) => void
  setSelectionMode: (mode: SelectionMode) => void
  
  // Actions - Filters
  setCategory: (category: FileCategory) => void
  setFavoriteOnly: (value: boolean) => void
  setSearchQuery: (query: string) => void
  setSortBy: (field: SortField) => void
  setSortOrder: (order: SortOrder) => void
  toggleSortOrder: () => void
  clearFilters: () => void
  
  // Actions - Selection
  selectFile: (fileId: string) => void
  deselectFile: (fileId: string) => void
  toggleFileSelection: (fileId: string, additive?: boolean) => void
  selectAll: (files: PiCloudFile[]) => void
  clearSelection: () => void
  isFileSelected: (fileId: string) => boolean
  
  // Actions - UI
  openUploadModal: () => void
  closeUploadModal: () => void
  openShareModal: () => void
  closeShareModal: () => void
  openTelegramModal: () => void
  closeTelegramModal: () => void
  setPreviewFile: (file: PiCloudFile | null) => void
  openContextMenu: (file: PiCloudFile, x: number, y: number) => void
  closeContextMenu: () => void
  setActiveView: (view: 'files' | 'activity' | 'duplicates') => void
}

export const useCloudStore = create<CloudState>((set, get) => ({
  // Initial state
  currentPath: '/',
  pathHistory: ['/'],
  viewMode: 'grid',
  selectionMode: 'single',
  category: 'all',
  favoriteOnly: false,
  searchQuery: '',
  sortBy: 'modified',
  sortOrder: 'desc',
  selectedFiles: new Set(),
  uploadModalOpen: false,
  shareModalOpen: false,
  telegramModalOpen: false,
  previewFile: null,
  contextMenuFile: null,
  contextMenuPosition: null,
  activeView: 'files',
  
  // Navigation
  setPath: (path) => set((state) => ({
    currentPath: path,
    pathHistory: [...state.pathHistory, path],
    selectedFiles: new Set(),
  })),
  
  goBack: () => set((state) => {
    if (state.pathHistory.length > 1) {
      const newHistory = [...state.pathHistory]
      newHistory.pop()
      return {
        pathHistory: newHistory,
        currentPath: newHistory[newHistory.length - 1],
        selectedFiles: new Set(),
      }
    }
    return state
  }),
  
  goForward: () => set((state) => {
    // Implementation would require forward history
    return state
  }),
  
  navigateToParent: () => set((state) => {
    if (state.currentPath === '/') return state
    const parts = state.currentPath.split('/').filter(Boolean)
    parts.pop()
    const parentPath = '/' + parts.join('/')
    return {
      currentPath: parentPath,
      pathHistory: [...state.pathHistory, parentPath],
      selectedFiles: new Set(),
    }
  }),
  
  // View
  setViewMode: (mode) => set({ viewMode: mode }),
  setSelectionMode: (mode) => set({ selectionMode: mode, selectedFiles: new Set() }),
  
  // Filters
  setCategory: (category) => set({ category, selectedFiles: new Set() }),
  setFavoriteOnly: (value) => set({ favoriteOnly: value, selectedFiles: new Set() }),
  setSearchQuery: (query) => set({ searchQuery: query, selectedFiles: new Set() }),
  setSortBy: (field) => set({ sortBy: field }),
  setSortOrder: (order) => set({ sortOrder: order }),
  toggleSortOrder: () => set((state) => ({ sortOrder: state.sortOrder === 'asc' ? 'desc' : 'asc' })),
  clearFilters: () => set({
    category: 'all',
    favoriteOnly: false,
    searchQuery: '',
    sortBy: 'modified',
    sortOrder: 'desc',
  }),
  
  // Selection
  selectFile: (fileId) => set((state) => {
    if (isSystemCloudFolderId(fileId)) return state
    const newSet = new Set(state.selectedFiles)
    newSet.add(fileId)
    return { selectedFiles: newSet }
  }),
  
  deselectFile: (fileId) => set((state) => {
    const newSet = new Set(state.selectedFiles)
    newSet.delete(fileId)
    return { selectedFiles: newSet }
  }),
  
  toggleFileSelection: (fileId, additive = false) => set((state) => {
    if (isSystemCloudFolderId(fileId)) return state
    const newSet = new Set(state.selectedFiles)
    if (newSet.has(fileId)) {
      newSet.delete(fileId)
    } else {
      if (state.selectionMode === 'single' && !additive) {
        newSet.clear()
      }
      newSet.add(fileId)
    }
    return { selectedFiles: newSet }
  }),
  
  selectAll: (files) => set({
    selectedFiles: new Set(files.filter((file) => !isSystemCloudFolder(file)).map((file) => file.id)),
  }),
  
  clearSelection: () => set({ selectedFiles: new Set() }),
  
  isFileSelected: (fileId) => get().selectedFiles.has(fileId),
  
  // UI
  openUploadModal: () => set({ uploadModalOpen: true }),
  closeUploadModal: () => set({ uploadModalOpen: false }),
  openShareModal: () => set({ shareModalOpen: true }),
  closeShareModal: () => set({ shareModalOpen: false }),
  openTelegramModal: () => set({ telegramModalOpen: true }),
  closeTelegramModal: () => set({ telegramModalOpen: false }),
  setPreviewFile: (file) => set({ previewFile: file }),
  openContextMenu: (file, x, y) => set({
    contextMenuFile: file,
    contextMenuPosition: { x, y },
  }),
  closeContextMenu: () => set({
    contextMenuFile: null,
    contextMenuPosition: null,
  }),
  setActiveView: (view) => set({ activeView: view }),
}))
