interface StatusBadgeProps {
  status: 'online' | 'offline' | 'limited' | 'open' | 'closed' | 'filtered' | 'success' | 'error' | 'warning' | 'info'
  label?: string
  size?: 'sm' | 'md' | 'lg'
}

const statusConfig = {
  online: { color: 'bg-green-500', text: 'text-green-400', bgClass: 'bg-green-500/10', label: 'Online' },
  offline: { color: 'bg-gray-500', text: 'text-gray-400', bgClass: 'bg-gray-500/10', label: 'Offline' },
  limited: { color: 'bg-yellow-500', text: 'text-yellow-400', bgClass: 'bg-yellow-500/10', label: 'Limited' },
  open: { color: 'bg-green-500', text: 'text-green-400', bgClass: 'bg-green-500/10', label: 'Open' },
  closed: { color: 'bg-red-500', text: 'text-red-400', bgClass: 'bg-red-500/10', label: 'Closed' },
  filtered: { color: 'bg-yellow-500', text: 'text-yellow-400', bgClass: 'bg-yellow-500/10', label: 'Filtered' },
  success: { color: 'bg-green-500', text: 'text-green-400', bgClass: 'bg-green-500/10', label: 'Success' },
  error: { color: 'bg-red-500', text: 'text-red-400', bgClass: 'bg-red-500/10', label: 'Error' },
  warning: { color: 'bg-yellow-500', text: 'text-yellow-400', bgClass: 'bg-yellow-500/10', label: 'Warning' },
  info: { color: 'bg-blue-500', text: 'text-blue-400', bgClass: 'bg-blue-500/10', label: 'Info' },
}

const sizeClasses = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-sm',
  lg: 'px-3 py-1.5 text-base',
}

export function StatusBadge({ status, label, size = 'sm' }: StatusBadgeProps) {
  const config = statusConfig[status]
  const displayLabel = label || config.label

  return (
    <span
      className={`inline-flex items-center gap-1.5 ${sizeClasses[size]} ${config.bgClass} ${config.text} rounded-full font-medium`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.color}`} />
      {displayLabel}
    </span>
  )
}
