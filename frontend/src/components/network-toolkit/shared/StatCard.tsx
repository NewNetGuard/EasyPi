import { LucideIcon } from 'lucide-react'

interface StatCardProps {
  icon: LucideIcon
  label: string
  value: string | number
  unit?: string
  trend?: {
    value: number
    direction: 'up' | 'down'
  }
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple'
}

const colorClasses = {
  blue: {
    bg: 'from-blue-500/30 to-cyan-500/30 dark:from-blue-500/20 dark:to-cyan-500/20',
    icon: 'text-blue-600 dark:text-blue-400',
    border: 'border-blue-500/30 dark:border-white/10',
  },
  green: {
    bg: 'from-green-500/30 to-emerald-500/30 dark:from-green-500/20 dark:to-emerald-500/20',
    icon: 'text-green-600 dark:text-green-400',
    border: 'border-green-500/30 dark:border-white/10',
  },
  yellow: {
    bg: 'from-yellow-500/30 to-orange-500/30 dark:from-yellow-500/20 dark:to-orange-500/20',
    icon: 'text-yellow-600 dark:text-yellow-400',
    border: 'border-yellow-500/30 dark:border-white/10',
  },
  red: {
    bg: 'from-red-500/30 to-pink-500/30 dark:from-red-500/20 dark:to-pink-500/20',
    icon: 'text-red-600 dark:text-red-400',
    border: 'border-red-500/30 dark:border-white/10',
  },
  purple: {
    bg: 'from-purple-500/30 to-pink-500/30 dark:from-purple-500/20 dark:to-pink-500/20',
    icon: 'text-purple-600 dark:text-purple-400',
    border: 'border-purple-500/30 dark:border-white/10',
  },
}

export function StatCard({ icon: Icon, label, value, unit, trend, color = 'blue' }: StatCardProps) {
  const colors = colorClasses[color]
  
  return (
    <div className={`bg-gradient-to-br ${colors.bg} rounded-xl p-4 backdrop-blur-sm border ${colors.border} overflow-hidden`}>
      <div className="flex items-center justify-between mb-2">
        <Icon className={`w-5 h-5 ${colors.icon} flex-shrink-0`} />
        {trend && (
          <span
            className={`text-xs font-medium flex-shrink-0 ${
              trend.direction === 'up' ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'
            }`}
          >
            {trend.direction === 'up' ? '↑' : '↓'} {Math.abs(trend.value)}%
          </span>
        )}
      </div>
      <div className="space-y-1 min-w-0">
        <p className="text-2xl font-bold text-gray-900 dark:text-white break-words">
          {value}
          {unit && <span className="text-lg ml-1 text-gray-500 dark:text-gray-400">{unit}</span>}
        </p>
        <p className="text-xs text-gray-600 dark:text-gray-400 truncate">{label}</p>
      </div>
    </div>
  )
}
