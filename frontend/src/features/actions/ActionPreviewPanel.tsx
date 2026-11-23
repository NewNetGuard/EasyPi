import { AlertTriangle, CheckCircle2, RefreshCw, RotateCcw, ShieldAlert } from 'lucide-react'

import Badge from '../../components/common/Badge'
import type { ActionPreviewResponse, ActionPreviewRisk } from '../../api/actionPreview'

const riskBadge: Record<
  ActionPreviewRisk,
  { label: string; color: 'success' | 'warning' | 'danger' | 'gray' | 'primary'; dot?: boolean }
> = {
  low: { label: 'Low risk', color: 'success' },
  medium: { label: 'Medium risk', color: 'warning', dot: true },
  high: { label: 'High risk', color: 'danger', dot: true },
  critical: { label: 'Critical risk', color: 'danger', dot: true },
}

interface ActionPreviewPanelProps {
  preview?: ActionPreviewResponse
  isLoading?: boolean
  errorMessage?: string | null
}

interface PreviewListSectionProps {
  title: string
  items: string[]
  icon: typeof ShieldAlert
  iconClassName: string
}

function PreviewListSection({
  title,
  items,
  icon: Icon,
  iconClassName,
}: PreviewListSectionProps) {
  if (items.length === 0) {
    return null
  }

  return (
    <div className="rounded-xl border border-gray-200 bg-white p-3.5 dark:border-dark-700 dark:bg-dark-900">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-gray-900 dark:text-white">
        <Icon className={`h-4 w-4 ${iconClassName}`} />
        {title}
      </div>
      <ul className="space-y-2">
        {items.map((item) => (
          <li key={item} className="flex items-start gap-2 text-sm text-gray-600 dark:text-gray-300">
            <span className="mt-[7px] h-1.5 w-1.5 flex-shrink-0 rounded-full bg-current opacity-60" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function ActionPreviewPanel({
  preview,
  isLoading = false,
  errorMessage,
}: ActionPreviewPanelProps) {
  if (isLoading) {
    return (
      <div className="rounded-2xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-800">
        <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
          <RefreshCw className="h-4 w-4 animate-spin text-primary-500" />
          Loading action preview...
        </div>
      </div>
    )
  }

  if (errorMessage) {
    return (
      <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800 dark:border-amber-900/40 dark:bg-amber-900/10 dark:text-amber-200">
        <div className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <div>
            <div className="font-semibold">Action preview is unavailable right now</div>
            <div className="mt-1">{errorMessage}</div>
          </div>
        </div>
      </div>
    )
  }

  if (!preview) {
    return null
  }

  const badge = riskBadge[preview.risk_level]
  const impactCount = preview.affects.length + preview.service_impact.length

  return (
    <div className="space-y-4 rounded-2xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-800">
      <div className="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900">
        <div className="flex flex-wrap items-center gap-2">
          <h4 className="text-sm font-semibold text-gray-900 dark:text-white">
            {preview.title || 'Action Preview'}
          </h4>
          <Badge color={badge.color} dot={badge.dot}>
            {badge.label}
          </Badge>
          {preview.destructive && (
            <Badge color="danger" dot>
              Destructive
            </Badge>
          )}
          {preview.target_label && <Badge color="gray">{preview.target_label}</Badge>}
        </div>
        <p className="mt-3 text-sm leading-6 text-gray-600 dark:text-gray-300">{preview.summary}</p>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <div className="rounded-xl border border-gray-200 bg-white p-3.5 dark:border-dark-700 dark:bg-dark-900">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 dark:text-gray-400">
            Rollback path
          </div>
          <div className="mt-2 text-sm font-semibold text-gray-900 dark:text-white">
            {preview.rollback_available ? 'Available' : 'Not automatic'}
          </div>
          {preview.rollback_hint && (
            <div className="mt-2 text-sm text-gray-500 dark:text-gray-400">{preview.rollback_hint}</div>
          )}
        </div>

        <div className="rounded-xl border border-gray-200 bg-white p-3.5 dark:border-dark-700 dark:bg-dark-900">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 dark:text-gray-400">
            Confirmation
          </div>
          <div className="mt-2 text-sm font-semibold text-gray-900 dark:text-white">
            {preview.requires_confirmation ? 'Required before running' : 'Can run directly'}
          </div>
          <div className="mt-2 text-sm text-gray-500 dark:text-gray-400">
            {preview.destructive
              ? 'This action will change existing state.'
              : 'This action should not overwrite existing state.'}
          </div>
        </div>

        <div className="rounded-xl border border-gray-200 bg-white p-3.5 dark:border-dark-700 dark:bg-dark-900">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 dark:text-gray-400">
            Scope
          </div>
          <div className="mt-2 text-sm font-semibold text-gray-900 dark:text-white">
            {impactCount > 0
              ? `${impactCount} ${impactCount === 1 ? 'known impact' : 'known impacts'}`
              : 'No broad impact detected'}
          </div>
          <div className="mt-2 text-sm text-gray-500 dark:text-gray-400">
            {preview.service_impact.length > 0
              ? `${preview.service_impact.length} service-related ${
                  preview.service_impact.length === 1 ? 'change' : 'changes'
                }`
              : 'No service restart or interruption reported.'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <PreviewListSection
          title="What this will affect"
          items={preview.affects}
          icon={ShieldAlert}
          iconClassName="text-amber-500"
        />
        <PreviewListSection
          title="Service impact"
          items={preview.service_impact}
          icon={RefreshCw}
          iconClassName="text-primary-500"
        />
      </div>

      {preview.recommended_checks.length > 0 && (
        <div className="rounded-xl border border-blue-200 bg-blue-50 p-3.5 dark:border-blue-900/40 dark:bg-blue-900/10">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-blue-900 dark:text-blue-100">
            <CheckCircle2 className="h-4 w-4" />
            Recommended checks before continuing
          </div>
          <ul className="space-y-2">
            {preview.recommended_checks.map((item) => (
              <li key={item} className="flex items-start gap-2 text-sm text-blue-900/90 dark:text-blue-100/90">
                <span className="mt-[7px] h-1.5 w-1.5 flex-shrink-0 rounded-full bg-current opacity-70" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex items-start gap-2 rounded-xl border border-dashed border-gray-200 px-3 py-2 text-xs text-gray-500 dark:border-dark-700 dark:text-gray-400">
        <RotateCcw className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
        EasyPi shows this preview before higher-impact actions so you can confirm the scope first.
      </div>
    </div>
  )
}
