import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Rocket, CheckCircle2, Circle, AlertTriangle, X, ArrowRight, Sparkles, Loader2 } from 'lucide-react'
import { getOnboarding, startProtection, type OnboardingStep } from '../../api/onboarding'

const DISMISS_KEY = 'easypi_guard_onboarding_dismissed'

// Agent-led first-run guide (protection → DNS → gateway → profiles). Reads live state,
// shows each step's status (green ✓ / amber ⚠ for a missing required step) plus the
// agent's plain-language next step, and links to the tool that does it.
//
//  variant="dashboard" — dismissible; auto-hides once everything is set up (no nagging).
//  variant="setup"     — permanent status panel in the Setup page; always visible, and
//                        shows all-green when everything is done.
export default function OnboardingCard({ variant = 'dashboard' }: { variant?: 'dashboard' | 'setup' }) {
  const isSetup = variant === 'setup'
  const navigate = useNavigate()
  const [dismissed, setDismissed] = useState<boolean>(() => !isSetup && localStorage.getItem(DISMISS_KEY) === '1')
  const { data } = useQuery({
    queryKey: ['guard-onboarding'],
    queryFn: getOnboarding,
    staleTime: 5_000,
    refetchInterval: 5_000,
  })
  const qc = useQueryClient()
  const [busyKey, setBusyKey] = useState<string | null>(null)
  const [actError, setActError] = useState<string | null>(null)

  if (!data || (data.totalCount ?? 0) === 0) return null
  if (!isSetup && (dismissed || data.allDone)) return null // dashboard: hide when done/dismissed

  const next = data.steps.find((s) => !s.done)
  const act = async (step: OnboardingStep) => {
    setActError(null)
    if (step.key === 'protection') {
      // "The DNS filter isn't running" — actually start it in one click, instead
      // of dumping the user on a page to hunt for the switch themselves.
      setBusyKey(step.key)
      try {
        const res = await startProtection()
        if (!res.success) setActError(res.error || 'Could not start the DNS filter.')
        await qc.invalidateQueries({ queryKey: ['guard-onboarding'] })
      } finally {
        setBusyKey(null)
      }
      return
    }
    if (step.key === 'dns' || step.key === 'gateway') {
      // DNS + gateway are handled by the "Network Protection" card on the Dashboard.
      if (isSetup) navigate('/dashboard')
      else document.getElementById('network-protection')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    } else {
      navigate(step.link)
    }
  }
  const dismiss = () => { localStorage.setItem(DISMISS_KEY, '1'); setDismissed(true) }

  return (
    <div className="relative rounded-xl border border-indigo-200 dark:border-indigo-800 bg-gradient-to-br from-indigo-50 via-white to-white dark:from-indigo-950/40 dark:via-gray-800/40 dark:to-gray-800/40 p-4 sm:p-5">
      {!isSetup && (
        <button onClick={dismiss} title="Hide guide"
          className="absolute top-3 right-3 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
          <X className="w-4 h-4" />
        </button>
      )}

      <div className="flex items-center gap-3 mb-3">
        <div className="p-2 rounded-lg bg-indigo-500 shadow-lg shadow-indigo-500/30"><Rocket className="w-5 h-5 text-white" /></div>
        <div>
          <h3 className="font-semibold text-gray-900 dark:text-white">{isSetup ? 'Setup checklist' : 'Getting Started'}</h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">{data.completedCount} of {data.totalCount} steps done</p>
        </div>
        <div className={`ml-auto ${isSetup ? '' : 'mr-6'} hidden sm:flex items-center gap-1.5`}>
          {data.steps.map((s) => (
            <span key={s.key} className={`h-1.5 w-8 rounded-full ${s.done ? 'bg-emerald-400' : 'bg-gray-200 dark:bg-gray-700'}`} />
          ))}
        </div>
      </div>

      {data.narrative && (
        <div className="mb-3 flex items-start gap-2 rounded-lg bg-indigo-100/60 dark:bg-indigo-900/30 px-3 py-2">
          <Sparkles className="w-4 h-4 text-indigo-500 mt-0.5 flex-shrink-0" />
          <p className="text-sm text-indigo-900 dark:text-indigo-100">{data.narrative}</p>
        </div>
      )}

      {actError && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 px-3 py-2">
          <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
          <p className="text-sm text-red-700 dark:text-red-300">{actError}</p>
        </div>
      )}

      <div className="space-y-1.5">
        {data.steps.map((s) => {
          const isNext = !!next && s.key === next.key
          const warn = !s.done && s.required
          return (
            <div key={s.key}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 ${
                isNext ? 'bg-white dark:bg-gray-800 ring-1 ring-indigo-200 dark:ring-indigo-800'
                : warn ? 'bg-amber-50/60 dark:bg-amber-900/10' : ''}`}>
              {s.done
                ? <CheckCircle2 className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                : warn
                  ? <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0" />
                  : <Circle className="w-5 h-5 flex-shrink-0 text-gray-300 dark:text-gray-600" />}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className={`text-sm font-medium ${s.done ? 'text-gray-500 dark:text-gray-400' : 'text-gray-900 dark:text-white'}`}>{s.title}</span>
                  {!s.required && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400">optional</span>}
                </div>
                <div className={`text-xs truncate ${warn ? 'text-amber-600 dark:text-amber-400' : 'text-gray-500 dark:text-gray-400'}`}>{s.detail}</div>
              </div>
              {!s.done && (
                <button onClick={() => act(s)} disabled={busyKey === s.key}
                  className="flex-shrink-0 inline-flex items-center gap-1 rounded-md border border-indigo-300 dark:border-indigo-700 px-2.5 py-1 text-xs font-medium text-indigo-700 dark:text-indigo-300 hover:bg-indigo-50 dark:hover:bg-indigo-900/30 disabled:opacity-60 disabled:cursor-not-allowed">
                  {busyKey === s.key ? (
                    <><Loader2 className="w-3 h-3 animate-spin" /> Starting…</>
                  ) : s.key === 'protection' ? (
                    <>Start now</>
                  ) : (
                    <>{isNext ? 'Do this' : 'Open'} <ArrowRight className="w-3 h-3" /></>
                  )}
                </button>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
