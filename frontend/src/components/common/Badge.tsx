import React from 'react'
import clsx from 'clsx'

interface BadgeProps {
  children: React.ReactNode
  color?: 'primary' | 'success' | 'warning' | 'danger' | 'gray'
  size?: 'sm' | 'md' | 'lg'
  dot?: boolean
  className?: string
}

const Badge: React.FC<BadgeProps> = ({
  children,
  color = 'gray',
  size = 'md',
  dot = false,
  className,
}) => {
  const colors = {
    primary: 'bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-300',
    success: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
    warning: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
    danger: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
    gray: 'bg-gray-100 text-gray-800 dark:bg-dark-800 dark:text-gray-300',
  }

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-0.5 text-xs',
    lg: 'px-3 py-1 text-sm',
  }

  const dotColors = {
    primary: 'bg-primary-500',
    success: 'bg-green-500',
    warning: 'bg-yellow-500',
    danger: 'bg-red-500',
    gray: 'bg-gray-500',
  }

  return (
    <span className={clsx('badge inline-flex items-center gap-1.5 font-medium rounded-full', colors[color], sizes[size], className)}>
      {dot && <span className={clsx('h-1.5 w-1.5 rounded-full', dotColors[color])} />}
      {children}
    </span>
  )
}

export default Badge
