import React from 'react'
import { ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react'

export interface Column<T extends object> {
  key: keyof T | string
  header: string
  width?: string
  render?: (value: any, row: T) => React.ReactNode
  sortable?: boolean
}

interface DataTableProps<T extends object> {
  data: T[]
  columns: Column<T>[]
  keyExtractor: (row: T) => string
  onRowClick?: (row: T) => void
  emptyMessage?: string
  sortBy?: string
  sortDirection?: 'asc' | 'desc'
  onSort?: (key: string) => void
}

export function DataTable<T extends object>({
  data,
  columns,
  keyExtractor,
  onRowClick,
  emptyMessage = 'No data',
  sortBy,
  sortDirection,
  onSort,
}: DataTableProps<T>) {
  const handleSort = (key: string, sortable?: boolean) => {
    if (sortable && onSort) {
      onSort(key)
    }
  }

  const getSortIcon = (key: string, sortable?: boolean) => {
    if (!sortable) return null
    
    if (sortBy !== key) {
      return <ArrowUpDown className="w-4 h-4 opacity-40" />
    }
    
    return sortDirection === 'asc' ? (
      <ArrowUp className="w-4 h-4 text-blue-400" />
    ) : (
      <ArrowDown className="w-4 h-4 text-blue-400" />
    )
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-gray-500 dark:text-gray-400">
        {emptyMessage}
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-gray-200 dark:border-gray-700">
            {columns.map((column) => (
              <th
                key={String(column.key)}
                className={`px-4 py-3 text-left text-xs font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider ${
                  column.width || ''
                } ${column.sortable ? 'cursor-pointer hover:text-gray-900 dark:hover:text-gray-300' : ''}`}
                onClick={() => handleSort(String(column.key), column.sortable)}
              >
                <div className="flex items-center gap-2">
                  {column.header}
                  {getSortIcon(String(column.key), column.sortable)}
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr
              key={keyExtractor(row)}
              className={`border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-white/5 transition-colors ${
                onRowClick ? 'cursor-pointer' : ''
              }`}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map((column) => {
                const value = column.key in row ? row[column.key as keyof T] : null
                return (
                  <td key={String(column.key)} className="px-4 py-3 text-sm text-gray-700 dark:text-gray-300">
                    {column.render ? column.render(value, row) : String(value || '-')}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
