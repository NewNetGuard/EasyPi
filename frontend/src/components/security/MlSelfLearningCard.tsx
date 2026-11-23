import type { ReactNode } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Brain, GraduationCap, RefreshCw, ShieldCheck, Crosshair } from 'lucide-react'
import { getMlStatus, retrainMl } from '../../api/ml'

function timeAgo(iso?: string | null): string {
  if (!iso) return 'never'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return 'unknown'
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000))
  if (s < 90) return 'just now'
  const m = Math.floor(s / 60)
  if (m < 90) return `${m} min ago`
  const h = Math.floor(m / 60)
  if (h < 36) return `${h} h ago`
  return `${Math.floor(h / 24)} d ago`
}

// One quality gauge: a big percentage over a colored bar with a plain caption.
function Gauge({
  icon,
  label,
  caption,
  pct,
  tone,
}: {
  icon: ReactNode
  label: string
  caption: string
  pct: number | null | undefined
  tone: 'green' | 'purple'
}) {
  const has = typeof pct === 'number'
  const bar = tone === 'green' ? 'bg-emerald-500' : 'bg-purple-500'
  const text = tone === 'green' ? 'text-emerald-600 dark:text-emerald-400' : 'text-purple-600 dark:text-purple-400'
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
      <div className="flex items-center gap-2">
        {icon}
        <span className="text-sm font-medium text-gray-800 dark:text-gray-200">{label}</span>
      </div>
      <div className={`mt-2 text-3xl font-bold ${text}`}>{has ? `${pct}%` : '—'}</div>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-gray-100 dark:bg-gray-700">
        <div className={`h-full ${bar} transition-all`} style={{ width: `${has ? Math.min(100, Math.max(0, pct!)) : 0}%` }} />
      </div>
      <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">{caption}</p>
    </div>
  )
}

export default function MlSelfLearningCard() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['ml-status'],
    queryFn: getMlStatus,
    refetchInterval: 60000,
  })

  const retrain = useMutation({
    mutationFn: retrainMl,
    onSuccess: (r) => {
      if (r.success) {
        toast.success(
          `Model retrained on your data${r.gibberish_caught ? ` · gate ${r.gibberish_caught}` : ''}`
        )
      } else {
        // Gate kept the previous model — this is a safe, expected outcome.
        toast(r.message || 'Not enough new data yet — kept the current model', { icon: 'ℹ️' })
      }
      refetch()
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Retrain failed'),
  })

  const model = data?.model
  const q = data?.quality
  const available = !!model?.available

  return (
    <div className="rounded-lg border border-purple-200 bg-purple-50 p-4 dark:border-purple-800 dark:bg-purple-900/20 sm:p-5">
      {/* Header + reassurance */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3">
          <Brain className="mt-0.5 h-5 w-5 flex-shrink-0 text-purple-600 dark:text-purple-400" />
          <div className="text-sm">
            <p className="font-medium text-purple-900 dark:text-purple-100">
              Self-learning models — they get smarter about your network
            </p>
            <p className="mt-0.5 text-purple-700 dark:text-purple-300">
              The domain-language level retrains automatically on the names this network visits
              {data?.auto_retrain?.interval_hours ? ` (every ${data.auto_retrain.interval_hours} h)` : ''}.
              The flow-behavior level learns continuously from encrypted connection metadata.
              Everything stays on this device.
            </p>
          </div>
        </div>
        <button
          onClick={() => retrain.mutate()}
          disabled={retrain.isPending}
          className="inline-flex flex-shrink-0 items-center gap-2 self-start rounded-lg bg-purple-600 px-3 py-2 text-sm font-medium text-white hover:bg-purple-700 disabled:opacity-50"
          title="Retrain the domain-language model on your network's own data now"
        >
          <RefreshCw className={`h-4 w-4 ${retrain.isPending ? 'animate-spin' : ''}`} />
          {retrain.isPending ? 'Retraining…' : 'Retrain domain model'}
        </button>
      </div>

      {/* Quality metrics */}
      {isLoading ? (
        <div className="mt-4 text-sm text-purple-700 dark:text-purple-300">Loading model status…</div>
      ) : !available ? (
        <div className="mt-4 rounded-lg border border-purple-200 bg-white/60 px-4 py-3 text-sm text-purple-800 dark:border-purple-800 dark:bg-gray-800/40 dark:text-purple-200">
          The model is still warming up — it trains automatically about 10 minutes after start,
          once some traffic has been seen. You can also click “Retrain on my data”.
        </div>
      ) : (
        <>
          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Gauge
              icon={<ShieldCheck className="h-4 w-4 text-emerald-500" />}
              label="Real sites left alone"
              caption={
                q?.benign_tested
                  ? `No false alarms on ${q.benign_tested.toLocaleString()} domains your network ${
                      q.benign_from_traffic ? 'actually visited' : '(well-known brands)'
                    }`
                  : 'How often it avoids false alarms on real sites'
              }
              pct={q?.clean_pass_rate}
              tone="green"
            />
            <Gauge
              icon={<Crosshair className="h-4 w-4 text-purple-500" />}
              label="Gibberish & DGA caught"
              caption={
                q?.gibberish_tested
                  ? `Flagged ${q.gibberish_caught?.toLocaleString()} of ${q.gibberish_tested.toLocaleString()} machine-generated names`
                  : 'How often it catches machine-generated junk'
              }
              pct={q?.detection_rate}
              tone="purple"
            />
          </div>

          {/* Model facts */}
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-purple-700 dark:text-purple-300">
            <span className="inline-flex items-center gap-1">
              <GraduationCap className="h-3.5 w-3.5" />
              Learned from {(model?.n_benign ?? 0).toLocaleString()} real domain names
            </span>
            <span>· Last trained {timeAgo(model?.trained_at)}</span>
            {model?.gibberish_total ? (
              <span>· Gate {model.gibberish_caught}/{model.gibberish_total}</span>
            ) : null}
            {model?.vocab_size ? <span>· {model.vocab_size.toLocaleString()} learned patterns</span> : null}
          </div>
        </>
      )}

      {/* Level 2: learned encrypted-flow shape. It remains gated by Ad-Genesis. */}
      <div className="mt-4 rounded-lg border border-purple-200 bg-white/70 px-4 py-3 dark:border-purple-800 dark:bg-gray-800/40">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-sm font-medium text-purple-900 dark:text-purple-100">
            Level 2 · Flow behavior
          </span>
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${
            data?.behavior_model?.available
              ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300'
              : 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300'
          }`}>
            {data?.behavior_model?.available ? 'Active' : 'Learning'}
          </span>
        </div>
        <p className="mt-1 text-xs text-purple-700 dark:text-purple-300">
          Learns flow count, byte shape, beacon/media ratio, TCP/QUIC mix, PRISM TLS timing and session context.
          It cannot block by itself: navigation, cross-site, co-occurrence, CDN and allowlist safety gates still apply.
        </p>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-purple-700 dark:text-purple-300">
          <span>Ad examples {(data?.behavior_model?.ad_samples ?? 0).toLocaleString()}</span>
          <span>· Clean examples {(data?.behavior_model?.clean_samples ?? 0).toLocaleString()}</span>
          <span>· Ready at {data?.behavior_model?.min_class_samples ?? 20} per class</span>
          {data?.behavior_model?.updated_at ? (
            <span>· Updated {timeAgo(data.behavior_model.updated_at)}</span>
          ) : null}
        </div>
      </div>
    </div>
  )
}
