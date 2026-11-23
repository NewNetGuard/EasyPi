import { Grid, List, ArrowUpDown, Search, X, Filter, ChevronDown } from 'lucide-react'
import { useCloudStore } from '../../stores/cloudStore'
import Input from '../common/Input'
import Select from '../common/Select'
import Button from '../common/Button'
import clsx from 'clsx'
import { useState } from 'react'

const FilterBar = () => {
  const {
    viewMode,
    setViewMode,
    searchQuery,
    setSearchQuery,
    sortBy,
    setSortBy,
    sortOrder,
    toggleSortOrder,
    clearFilters,
  } = useCloudStore()
  
  const [isExpanded, setIsExpanded] = useState(false)
  const hasActiveFilters = searchQuery || sortBy !== 'name' || sortOrder !== 'asc'
  
  return (
    <div className="rounded-lg border border-gray-200 dark:border-dark-700 bg-white dark:bg-dark-800">
      {/* Toggle Button */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-3 py-2 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
      >
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
          {isExpanded ? 'Hide' : 'Show'} Search & Filters
        </span>
        <ChevronDown
          className={`h-4 w-4 text-gray-500 transition-transform ${
            isExpanded ? 'rotate-180' : ''
          }`}
        />
      </button>
      
      {/* Filter Content */}
      {isExpanded && (
        <div className="flex flex-wrap items-center gap-3 p-3 border-t border-gray-200 dark:border-dark-700">
      {/* Search - instant filtering */}
      <div className="flex-1 min-w-[200px]">
        <Input
          leftIcon={<Search className="h-4 w-4" />}
          rightIcon={
            searchQuery ? (
              <button onClick={() => setSearchQuery('')} className="text-gray-400 hover:text-gray-600">
                <X className="h-4 w-4" />
              </button>
            ) : undefined
          }
          placeholder="Search files..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>
      
      {/* Sort */}
      <Select
        options={[
          { value: 'name', label: 'Name' },
          { value: 'size', label: 'Size' },
          { value: 'modified', label: 'Modified' },
          { value: 'type', label: 'Type' },
        ]}
        value={sortBy}
        onChange={(value) => setSortBy(value as any)}
        className="w-32"
      />
      
      {/* Sort order */}
      <Button
        variant="outline"
        size="sm"
        icon={<ArrowUpDown className="h-4 w-4" />}
        onClick={toggleSortOrder}
      >
        {sortOrder === 'asc' ? '↑' : '↓'}
      </Button>
      
      {/* View mode */}
      <div className="flex rounded-lg border border-gray-200 dark:border-dark-700">
        <button
          onClick={() => setViewMode('grid')}
          className={clsx(
            'p-2 transition-colors',
            viewMode === 'grid'
              ? 'bg-primary-50 text-primary-600 dark:bg-primary-900/20 dark:text-primary-400'
              : 'text-gray-600 hover:bg-gray-50 dark:text-gray-400 dark:hover:bg-dark-800'
          )}
          title="Grid view"
        >
          <Grid className="h-4 w-4" />
        </button>
        <button
          onClick={() => setViewMode('list')}
          className={clsx(
            'p-2 transition-colors border-l border-gray-200 dark:border-dark-700',
            viewMode === 'list'
              ? 'bg-primary-50 text-primary-600 dark:bg-primary-900/20 dark:text-primary-400'
              : 'text-gray-600 hover:bg-gray-50 dark:text-gray-400 dark:hover:bg-dark-800'
          )}
          title="List view"
        >
          <List className="h-4 w-4" />
        </button>
      </div>
      
      {/* Clear filters */}
      {hasActiveFilters && (
        <Button variant="ghost" size="sm" icon={<Filter className="h-4 w-4" />} onClick={clearFilters}>
          Clear
        </Button>
      )}
        </div>
      )}
    </div>
  )
}

export default FilterBar
