import { Bell, Cloud, HardDrive, Search, Shield, ShoppingBag, Waves } from 'lucide-react'
import { useMemo, useState } from 'react'

import Badge from '../common/Badge'
import Card from '../common/Card'
import Input from '../common/Input'
import Select from '../common/Select'
import PluginCard from './PluginCard'

const plugins = [
  {
    id: '1',
    name: 'Advanced Monitoring',
    author: 'Community',
    description: 'Enhanced monitoring with custom dashboards and alert views.',
    icon: <Waves className="h-6 w-6 text-blue-600 dark:text-blue-400" />,
    category: 'monitoring',
    status: 'preview' as const,
    note: 'Planned as an optional package, not wired to install yet.',
  },
  {
    id: '2',
    name: 'Auto Backup to Cloud',
    author: 'NewNetGuard',
    description: 'Scheduled exports to external storage providers and archive targets.',
    icon: <Cloud className="h-6 w-6 text-sky-600 dark:text-sky-400" />,
    category: 'backup',
    status: 'planned' as const,
    note: 'Needs a real package registry, signatures, and rollback support first.',
  },
  {
    id: '3',
    name: 'Discord Notifications',
    author: 'Community',
    description: 'Deliver important alerts and summaries to a Discord server.',
    icon: <Bell className="h-6 w-6 text-fuchsia-600 dark:text-fuchsia-400" />,
    category: 'notifications',
    status: 'planned' as const,
    note: 'Provider integration is not exposed in production yet.',
  },
  {
    id: '4',
    name: 'Security Hardening Pack',
    author: 'EasyPi',
    description: 'Preset hardening checks, guided remediation, and safe previews.',
    icon: <Shield className="h-6 w-6 text-emerald-600 dark:text-emerald-400" />,
    category: 'security',
    status: 'preview' as const,
    note: 'Designed, but not yet shipped as a separate package.',
  },
  {
    id: '5',
    name: 'Cold Storage Export',
    author: 'Community',
    description: 'Archive selected files and snapshots to external disks with integrity checks.',
    icon: <HardDrive className="h-6 w-6 text-amber-600 dark:text-amber-400" />,
    category: 'backup',
    status: 'planned' as const,
    note: 'Waiting for a real install lifecycle rather than a mock button.',
  },
]

const Marketplace = () => {
  const [searchQuery, setSearchQuery] = useState('')
  const [category, setCategory] = useState('all')

  const filteredPlugins = useMemo(() => {
    const query = searchQuery.trim().toLowerCase()
    return plugins.filter((plugin) => {
      const matchesQuery =
        query.length === 0 ||
        plugin.name.toLowerCase().includes(query) ||
        plugin.description.toLowerCase().includes(query) ||
        plugin.author.toLowerCase().includes(query)

      const matchesCategory = category === 'all' || plugin.category === category
      return matchesQuery && matchesCategory
    })
  }, [category, searchQuery])

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
            <ShoppingBag className="h-6 w-6 text-primary-600 dark:text-primary-400" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Marketplace</h1>
          <Badge color="warning" size="sm">Preview</Badge>
        </div>
        <p className="max-w-3xl text-sm text-gray-500 dark:text-gray-400">
          This section is currently a curated preview of package ideas, not a live installer.
          It stays visible so users can see what is planned next without a fake install flow.
        </p>
      </div>

      <Card
        title="Current State"
        subtitle="Marketplace is intentionally read-only right now."
      >
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-800/80">
            <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Live Registry</div>
            <div className="mt-2 text-lg font-semibold text-gray-900 dark:text-white">Not populated yet</div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              There is no production package catalog wired to installation yet.
            </p>
          </div>
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-800/80">
            <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Install Flow</div>
            <div className="mt-2 text-lg font-semibold text-gray-900 dark:text-white">Disabled on purpose</div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              It is better to be honest here than to show buttons that do not do real work.
            </p>
          </div>
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-800/80">
            <div className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Needed First</div>
            <div className="mt-2 text-lg font-semibold text-gray-900 dark:text-white">Package lifecycle</div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              Registry, signatures, jobs, action preview, and rollback need to exist first.
            </p>
          </div>
        </div>
      </Card>

      <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
        <Input
          placeholder="Search planned packages..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          leftIcon={<Search className="h-4 w-4" />}
          className="flex-1"
        />
        <Select
          options={[
            { value: 'all', label: 'All Categories' },
            { value: 'monitoring', label: 'Monitoring' },
            { value: 'backup', label: 'Backup' },
            { value: 'notifications', label: 'Notifications' },
            { value: 'security', label: 'Security' },
          ]}
          value={category}
          onChange={setCategory}
          className="sm:w-48"
        />
      </div>

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {filteredPlugins.map((plugin) => (
          <PluginCard key={plugin.id} plugin={plugin} />
        ))}
      </div>

      {filteredPlugins.length === 0 && (
        <div className="rounded-2xl border border-dashed border-gray-300 p-10 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-gray-400">
          Nothing matched this filter. Try another category or a simpler search query.
        </div>
      )}
    </div>
  )
}

export default Marketplace
