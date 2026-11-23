import React from 'react'
import clsx from 'clsx'

interface ProgressBarProps {
  progress: number // 0-100
  color?: 'primary' | 'success' | 'warning' | 'danger'
  size?: 'sm' | 'md' | 'lg'
  showPercentage?: boolean
  label?: string
  className?: string
}

const ProgressBar: React.FC<ProgressBarProps> = ({
  progress,
  color = 'primary',
  size = 'md',
  showPercentage = false,
  label,
  className,
}) => {
  const clampedProgress = Math.min(Math.max(progress, 0), 100)

  const colors = {
    primary: 'bg-primary-600',
    success: 'bg-green-600',
    warning: 'bg-yellow-600',
    danger: 'bg-red-600',
  }

  const sizes = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
  }

  return (
    <div className={clsx('w-full', className)}>
      {(label || showPercentage) && (
        <div className="mb-1 flex items-center justify-between text-sm">
          {label && <span className="text-gray-700 dark:text-gray-300">{label}</span>}
          {showPercentage && (
            <span className="font-medium text-gray-900 dark:text-white">
              {Math.round(clampedProgress)}%
            </span>
          )}
        </div>
      )}
      
      <div className={clsx('w-full overflow-hidden rounded-full bg-gray-200 dark:bg-dark-800', sizes[size])}>
        <div
          className={clsx('h-full rounded-full transition-all duration-500 ease-out', colors[color])}
          style={{ width: `${clampedProgress}%` }}
        />
      </div>
    </div>
  )
}

export default ProgressBar
