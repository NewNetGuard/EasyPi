import { ChevronRight, Home, ArrowLeft } from 'lucide-react'
import { useCloudStore } from '../../stores/cloudStore'
import clsx from 'clsx'

const BreadcrumbNav = () => {
  const { currentPath, setPath } = useCloudStore()
  
  const pathParts = currentPath.split('/').filter(Boolean)
  
  const paths: { label: string; path: string }[] = [
    { label: 'Home', path: '/' },
    ...pathParts.map((part, index) => ({
      label: part,
      path: '/' + pathParts.slice(0, index + 1).join('/'),
    })),
  ]
  
  // Get parent path for back button
  const parentPath = pathParts.length > 0 
    ? pathParts.length === 1 
      ? '/' 
      : '/' + pathParts.slice(0, -1).join('/')
    : null
  
  return (
    <nav className="flex items-center gap-2 overflow-x-auto py-2">
      {/* Back button - show only if not in root */}
      {parentPath && (
        <button
          onClick={() => setPath(parentPath)}
          className="flex items-center gap-1 rounded px-2 py-1 text-sm font-medium text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-dark-800 dark:hover:text-white transition-colors lg:hidden"
          title="Back"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
      )}
      
      {paths.map((item, index) => (
        <div key={item.path} className="flex items-center gap-1">
          <button
            onClick={() => setPath(item.path)}
            className={clsx(
              'flex items-center gap-1 rounded px-2 py-1 text-sm font-medium transition-colors',
              index === paths.length - 1
                ? 'text-primary-600 dark:text-primary-400'
                : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-dark-800 dark:hover:text-white'
            )}
          >
            {index === 0 && <Home className="h-4 w-4" />}
            <span>{item.label}</span>
          </button>
          {index < paths.length - 1 && (
            <ChevronRight className="h-4 w-4 text-gray-400" />
          )}
        </div>
      ))}
    </nav>
  )
}

export default BreadcrumbNav
