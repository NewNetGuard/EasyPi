import React from 'react'
import clsx from 'clsx'

type OverviewTone = 'primary' | 'success' | 'warning' | 'danger' | 'gray'

interface OverviewStatProps {
  label: string
  value: React.ReactNode
  hint?: string
  tone?: OverviewTone
  icon?: React.ComponentType<{ className?: string }>
  className?: string
  /** Override the value's size/weight classes (defaults to the large bold stat style). */
  valueClassName?: string
}

const toneClasses: Record<
  OverviewTone,
  {
    container: string
    label: string
    value: string
    hint: string
    iconWrap: string
    icon: string
  }
> = {
  primary: {
    container: 'border-sky-200/80 bg-white dark:border-sky-900/40 dark:bg-dark-900',
    label: 'text-sky-700 dark:text-sky-300',
    value: 'text-slate-900 dark:text-white',
    hint: 'text-slate-500 dark:text-slate-400',
    iconWrap: 'bg-sky-100 dark:bg-sky-900/20',
    icon: 'text-sky-600 dark:text-sky-300',
  },
  success: {
    container: 'border-emerald-200/80 bg-white dark:border-emerald-900/40 dark:bg-dark-900',
    label: 'text-emerald-700 dark:text-emerald-300',
    value: 'text-slate-900 dark:text-white',
    hint: 'text-slate-500 dark:text-slate-400',
    iconWrap: 'bg-emerald-100 dark:bg-emerald-900/20',
    icon: 'text-emerald-600 dark:text-emerald-300',
  },
  warning: {
    container: 'border-amber-200/80 bg-white dark:border-amber-900/40 dark:bg-dark-900',
    label: 'text-amber-700 dark:text-amber-300',
    value: 'text-slate-900 dark:text-white',
    hint: 'text-slate-500 dark:text-slate-400',
    iconWrap: 'bg-amber-100 dark:bg-amber-900/20',
    icon: 'text-amber-600 dark:text-amber-300',
  },
  danger: {
    container: 'border-red-200/80 bg-white dark:border-red-900/40 dark:bg-dark-900',
    label: 'text-red-700 dark:text-red-300',
    value: 'text-slate-900 dark:text-white',
    hint: 'text-slate-500 dark:text-slate-400',
    iconWrap: 'bg-red-100 dark:bg-red-900/20',
    icon: 'text-red-600 dark:text-red-300',
  },
  gray: {
    container: 'border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-900',
    label: 'text-slate-600 dark:text-slate-300',
    value: 'text-slate-900 dark:text-white',
    hint: 'text-slate-500 dark:text-slate-400',
    iconWrap: 'bg-gray-100 dark:bg-dark-800',
    icon: 'text-slate-500 dark:text-slate-300',
  },
}

const OverviewStat: React.FC<OverviewStatProps> = ({
  label,
  value,
  hint,
  tone = 'gray',
  icon: Icon,
  className,
  valueClassName,
}) => {
  const palette = toneClasses[tone]

  return (
    <div
      className={clsx(
        'rounded-2xl border p-4 shadow-sm transition-colors',
        palette.container,
        className
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div
            className={clsx(
              'text-[11px] font-semibold uppercase tracking-[0.18em]',
              palette.label
            )}
          >
            {label}
          </div>
          <div
            className={clsx(
              'mt-2 break-words',
              valueClassName ?? 'text-2xl font-bold sm:text-3xl',
              palette.value
            )}
          >
            {value}
          </div>
          {hint && <div className={clsx('mt-1 text-sm', palette.hint)}>{hint}</div>}
        </div>

        {Icon && (
          <div className={clsx('rounded-xl p-2.5', palette.iconWrap)}>
            <Icon className={clsx('h-4 w-4', palette.icon)} />
          </div>
        )}
      </div>
    </div>
  )
}

export default OverviewStat
