interface RecommendationsProps {
  items: string[]
}

export default function Recommendations({ items }: RecommendationsProps) {
  if (items.length === 0) {
    return null
  }

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
        Recommended next steps
      </h4>
      <div className="grid gap-2">
        {items.map((item, index) => (
          <div
            key={`${index}-${item}`}
            className="rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-900/40 dark:bg-emerald-900/20 dark:text-emerald-300"
          >
            {item}
          </div>
        ))}
      </div>
    </div>
  )
}
