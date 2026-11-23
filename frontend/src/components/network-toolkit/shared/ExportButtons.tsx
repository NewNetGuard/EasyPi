import { FileJson, FileSpreadsheet, FileCode } from 'lucide-react'
import type { ExportFormat } from '../../../types/network'

interface ExportButtonsProps {
  data: any
  filename: string
  formats?: ExportFormat[]
}

export function ExportButtons({ data, filename, formats = ['json', 'csv'] }: ExportButtonsProps) {
  const exportData = (format: ExportFormat) => {
    let content: string
    let mimeType: string
    let extension: string

    switch (format) {
      case 'json':
        content = JSON.stringify(data, null, 2)
        mimeType = 'application/json'
        extension = 'json'
        break
      case 'csv':
        content = convertToCSV(data)
        mimeType = 'text/csv'
        extension = 'csv'
        break
      case 'xml':
        content = convertToXML(data)
        mimeType = 'application/xml'
        extension = 'xml'
        break
      default:
        return
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${filename}.${extension}`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  const convertToCSV = (data: any): string => {
    if (Array.isArray(data) && data.length > 0) {
      const headers = Object.keys(data[0])
      const rows = data.map((row) => headers.map((header) => JSON.stringify(row[header] || '')).join(','))
      return [headers.join(','), ...rows].join('\n')
    }
    return ''
  }

  const convertToXML = (data: any, rootName = 'root'): string => {
    const toXML = (obj: any, name: string): string => {
      if (Array.isArray(obj)) {
        return obj.map((item) => toXML(item, 'item')).join('')
      }
      if (typeof obj === 'object' && obj !== null) {
        const content = Object.entries(obj)
          .map(([key, value]) => toXML(value, key))
          .join('')
        return `<${name}>${content}</${name}>`
      }
      return `<${name}>${obj}</${name}>`
    }
    return `<?xml version="1.0" encoding="UTF-8"?>${toXML(data, rootName)}`
  }

  const getIcon = (format: ExportFormat) => {
    switch (format) {
      case 'json':
        return <FileJson className="w-4 h-4" />
      case 'csv':
        return <FileSpreadsheet className="w-4 h-4" />
      case 'xml':
        return <FileCode className="w-4 h-4" />
    }
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-gray-600 dark:text-gray-400">Export:</span>
      {formats.map((format) => (
        <button
          key={format}
          onClick={() => exportData(format)}
          className="flex items-center gap-2 px-3 py-1.5 bg-gray-100 hover:bg-gray-200 dark:bg-white/5 dark:hover:bg-white/10 border border-gray-200 dark:border-white/10 rounded-lg text-sm text-gray-700 dark:text-gray-300 transition-colors"
        >
          {getIcon(format)}
          {format.toUpperCase()}
        </button>
      ))}
    </div>
  )
}
