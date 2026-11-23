import { Shield, AlertTriangle, AlertCircle, Skull } from 'lucide-react'
import type { RiskLevel } from '../../../types/network'

interface RiskBadgeProps {
  level: RiskLevel
  showIcon?: boolean
  size?: 'sm' | 'md' | 'lg'
}

const riskConfig = {
  low: {
    icon: Shield,
    label: 'Low',
    color: 'text-green-400',
    bgClass: 'bg-green-500/10',
    borderClass: 'border-green-500/20',
  },
  medium: {
    icon: AlertTriangle,
    label: 'Medium',
    color: 'text-yellow-400',
    bgClass: 'bg-yellow-500/10',
    borderClass: 'border-yellow-500/20',
  },
  high: {
    icon: AlertCircle,
    label: 'High',
    color: 'text-orange-400',
    bgClass: 'bg-orange-500/10',
    borderClass: 'border-orange-500/20',
  },
  critical: {
    icon: Skull,
    label: 'Critical',
    color: 'text-red-400',
    bgClass: 'bg-red-500/10',
    borderClass: 'border-red-500/20',
  },
}

const sizeClasses = {
  sm: 'px-2 py-1 text-xs',
  md: 'px-3 py-1.5 text-sm',
  lg: 'px-4 py-2 text-base',
}

const iconSizes = {
  sm: 'w-3 h-3',
  md: 'w-4 h-4',
  lg: 'w-5 h-5',
}

export function RiskBadge({ level, showIcon = true, size = 'md' }: RiskBadgeProps) {
  const config = riskConfig[level]
  const Icon = config.icon

  return (
    <span
      className={`inline-flex items-center gap-1.5 ${sizeClasses[size]} ${config.bgClass} ${config.color} ${config.borderClass} border rounded-lg font-medium`}
    >
      {showIcon && <Icon className={iconSizes[size]} />}
      {config.label}
    </span>
  )
}
