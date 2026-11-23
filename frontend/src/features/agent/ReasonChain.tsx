interface ReasonChainProps {
  steps: string[]
}

export default function ReasonChain({ steps }: ReasonChainProps) {
  if (steps.length === 0) {
    return null
  }

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
        Reasoning
      </h4>
      <ol className="space-y-2">
        {steps.map((step, index) => (
          <li
            key={`${index}-${step}`}
            className="flex gap-3 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700 dark:border-dark-700 dark:bg-dark-900 dark:text-slate-200"
          >
            <span className="mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[11px] font-semibold text-white dark:bg-slate-100 dark:text-slate-900">
              {index + 1}
            </span>
            <span>{step}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}
