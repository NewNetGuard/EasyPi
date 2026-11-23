import { ArrowUpRight, Clock3, User } from 'lucide-react'
import Card from '../common/Card'
import Button from '../common/Button'
import Badge from '../common/Badge'

interface PluginCardProps {
  plugin: {
    id: string
    name: string
    author: string
    description: string
    icon: React.ReactNode
    category: string
    status: 'planned' | 'preview'
    note: string
  }
}

const PluginCard: React.FC<PluginCardProps> = ({ plugin }) => {
  return (
    <Card hover noPadding>
      <div className="p-6">
        <div className="flex items-start gap-4 mb-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gray-100 dark:bg-dark-800 text-2xl">
            {plugin.icon}
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="font-semibold text-gray-900 dark:text-white truncate">
              {plugin.name}
            </h3>
            <div className="flex items-center gap-2 mt-1">
              <User className="h-3 w-3 text-gray-400" />
              <span className="text-xs text-gray-500 dark:text-gray-400">
                {plugin.author}
              </span>
            </div>
          </div>
        </div>

        <p className="text-sm text-gray-600 dark:text-gray-400 mb-4 line-clamp-2">
          {plugin.description}
        </p>

        <div className="flex items-center justify-end mb-4">
          <Badge color="primary" size="sm">{plugin.category}</Badge>
        </div>

        <div className="flex items-center justify-between gap-3">
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {plugin.note}
          </div>
          <Badge color={plugin.status === 'preview' ? 'warning' : 'gray'} size="sm">
            {plugin.status === 'preview' ? 'Preview' : 'Planned'}
          </Badge>
        </div>

        <div className="mt-4">
          <Button
            variant="outline"
            size="sm"
            className="w-full"
            disabled
            icon={plugin.status === 'preview' ? <ArrowUpRight className="h-4 w-4" /> : <Clock3 className="h-4 w-4" />}
          >
            {plugin.status === 'preview' ? 'Not Yet Installable' : 'Planned For Later'}
          </Button>
        </div>
      </div>
    </Card>
  )
}

export default PluginCard
