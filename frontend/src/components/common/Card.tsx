import React from 'react'
import clsx from 'clsx'

interface CardProps {
  title?: string | React.ReactNode
  subtitle?: string
  children: React.ReactNode
  footer?: React.ReactNode
  className?: string
  hover?: boolean
  noPadding?: boolean
}

const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  children,
  footer,
  className,
  hover = false,
  noPadding = false,
}) => {
  return (
    <div
      className={clsx(
        'card',
        hover && 'card-hover cursor-pointer',
        className
      )}
    >
      {(title || subtitle) && (
        <div className="border-b border-gray-200 dark:border-dark-800 px-4 sm:px-6 py-3 sm:py-4">
          {title && (
            <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white">
              {title}
            </h3>
          )}
          {subtitle && (
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {subtitle}
            </p>
          )}
        </div>
      )}
      
      <div className={clsx(!noPadding && 'p-4 sm:p-6')}>
        {children}
      </div>
      
      {footer && (
        <div className="border-t border-gray-200 dark:border-dark-800 px-4 sm:px-6 py-3 sm:py-4">
          {footer}
        </div>
      )}
    </div>
  )
}

export default Card