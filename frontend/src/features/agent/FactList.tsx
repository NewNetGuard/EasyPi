import type { DiagnosticFact } from '../../api/ai'

interface FactListProps {
  facts: DiagnosticFact[]
}

const severityClasses: Record<DiagnosticFact['severity'], string> = {
  info: 'border-slate-200 bg-white text-slate-700 dark:border-dark-700 dark:bg-dark-900 dark:text-slate-200',
  warning: 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/40 dark:bg-amber-900/20 dark:text-amber-300',
  critical: 'border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-900/40 dark:bg-rose-900/20 dark:text-rose-300',
}

export default function FactList({ facts }: FactListProps) {
  if (facts.length === 0) {
    return null
  }

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
        Facts
      </h4>
      <div className="grid gap-2">
        {facts.map((fact, index) => (
          <div
            key={`${fact.label}-${index}`}
            className={`rounded-xl border px-3 py-2 ${severityClasses[fact.severity]}`}
          >
            <div className="text-[11px] font-semibold uppercase tracking-wide opacity-70">
              {fact.label}
            </div>
            <div className="mt-1 text-sm font-medium break-words">
              {fact.value}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
