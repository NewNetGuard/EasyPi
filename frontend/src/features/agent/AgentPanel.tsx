import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import {
  AlertCircle,
  Bot,
  ChevronDown,
  ChevronUp,
  Loader2,
  Send,
  Sparkles,
  Wand2,
  X,
} from 'lucide-react'
import Button from '../../components/common/Button'
import Card from '../../components/common/Card'
import type { DiagnosticAction, DiagnosticExplainResponse } from './types'
import FactList from './FactList'
import ReasonChain from './ReasonChain'
import Recommendations from './Recommendations'
import { useAgent } from './useAgent'

const confidenceClasses: Record<'high' | 'medium' | 'low', string> = {
  high: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  medium: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
  low: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
}

function ResponseCard({
  response,
  onRunAction,
  executingActionId,
  confirmingActionId,
  onConfirmAction,
  onCancelAction,
}: {
  response: DiagnosticExplainResponse
  onRunAction: (action: DiagnosticAction) => void
  executingActionId: string | null
  confirmingActionId: string | null
  onConfirmAction: (action: DiagnosticAction) => void
  onCancelAction: () => void
}) {
  const [showAllActions, setShowAllActions] = useState(false)

  const sortedActions = useMemo(() => {
    const styleWeight: Record<DiagnosticAction['style'], number> = {
      primary: 0,
      secondary: 1,
      danger: 2,
    }

    return [...response.actions].sort((left, right) => {
      const styleDiff = styleWeight[left.style] - styleWeight[right.style]
      if (styleDiff !== 0) {
        return styleDiff
      }
      if (left.requires_confirmation !== right.requires_confirmation) {
        return left.requires_confirmation ? 1 : -1
      }
      return left.label.localeCompare(right.label)
    })
  }, [response.actions])

  const immediateActions = useMemo(() => {
    const visible: DiagnosticAction[] = []

    for (const action of sortedActions) {
      if (action.style === 'danger') {
        continue
      }
      visible.push(action)
      if (visible.length === 3) {
        break
      }
    }

    if (visible.length === 0 && sortedActions.length > 0) {
      visible.push(sortedActions[0])
    }

    return visible
  }, [sortedActions])

  const overflowActions = useMemo(
    () => sortedActions.filter((action) => !immediateActions.some((visible) => visible.action_id === action.action_id)),
    [immediateActions, sortedActions]
  )

  return (
    <Card className="border border-slate-200 bg-white/95 shadow-sm dark:border-dark-700 dark:bg-dark-900/95" noPadding>
      <div className="space-y-4 p-4">
        <div className="flex flex-wrap items-start gap-2">
          <div className="inline-flex h-9 w-9 items-center justify-center rounded-2xl bg-gradient-to-br from-sky-500 to-cyan-500 text-white shadow-sm">
            <Bot className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                {response.title}
              </h3>
              <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${confidenceClasses[response.confidence]}`}>
                {response.confidence}
              </span>
            </div>
            <p className="mt-2 text-sm leading-6 text-slate-700 dark:text-slate-200">
              {response.summary}
            </p>
            {(response.section || response.module) && (
            <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-slate-500 dark:text-slate-400">
              {response.target && <span>Target: {response.target}</span>}
              {response.section && <span>Section: {response.section}</span>}
              {response.subsection && <span>Subsection: {response.subsection}</span>}
              {response.module && <span>Module: {response.module}</span>}
            </div>
          )}
          </div>
        </div>

        <div className="space-y-4">
          <ReasonChain steps={response.reason_chain} />
          <FactList facts={response.facts} />
          {response.checks_run.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                Checks run
              </h4>
              <div className="flex flex-wrap gap-2">
                {response.checks_run.map((check) => (
                  <span
                    key={check}
                    className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-600 dark:border-dark-700 dark:bg-dark-950 dark:text-slate-300"
                  >
                    {check}
                  </span>
                ))}
              </div>
            </div>
          )}
          <Recommendations items={response.recommendations} />
        </div>

        {sortedActions.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
              Available actions
            </h4>
            <div className="flex flex-wrap gap-2">
              {immediateActions.map((action) => {
                const variant =
                  action.style === 'danger'
                    ? 'danger'
                    : action.style === 'primary'
                      ? 'primary'
                      : 'outline'

                return (
                  <Button
                    key={action.action_id}
                    variant={variant}
                    size="sm"
                    loading={executingActionId === action.action_id}
                    onClick={() => onRunAction(action)}
                    icon={<Wand2 className="h-4 w-4" />}
                  >
                    {action.label}
                  </Button>
                )
              })}
            </div>

            {overflowActions.length > 0 && (
              <div className="space-y-3 pt-1">
                <button
                  type="button"
                  onClick={() => setShowAllActions((value) => !value)}
                  className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-500 transition-colors hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
                >
                  {showAllActions ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  {showAllActions ? 'Hide extra actions' : `More actions (${overflowActions.length})`}
                </button>

                {showAllActions && (
                  <div className="grid gap-3">
                    {overflowActions.map((action) => {
                      const variant =
                        action.style === 'danger'
                          ? 'danger'
                          : action.style === 'primary'
                            ? 'primary'
                            : 'outline'

                      return (
                        <div
                          key={action.action_id}
                          className={`rounded-2xl border p-3 ${
                            action.style === 'danger'
                              ? 'border-rose-200 bg-rose-50 dark:border-rose-900/40 dark:bg-rose-900/20'
                              : 'border-slate-200 bg-slate-50 dark:border-dark-700 dark:bg-dark-950'
                          }`}
                        >
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div className="min-w-0 flex-1">
                              <div className="text-sm font-semibold text-slate-900 dark:text-white">
                                {action.label}
                              </div>
                              <div className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                                {action.description}
                              </div>
                              {action.style === 'danger' && (
                                <div className="mt-2 text-xs font-semibold uppercase tracking-[0.16em] text-rose-700 dark:text-rose-300">
                                  Risky action
                                </div>
                              )}
                            </div>
                            <Button
                              variant={variant}
                              size="sm"
                              loading={executingActionId === action.action_id}
                              onClick={() => onRunAction(action)}
                              icon={<Wand2 className="h-4 w-4" />}
                              className="shrink-0"
                            >
                              Run
                            </Button>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )}

            {confirmingActionId && (
              <div className="rounded-2xl border border-amber-200 bg-amber-50 p-3 dark:border-amber-900/40 dark:bg-amber-900/20">
                <div className="flex items-start gap-3">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-300" />
                  <div className="min-w-0 flex-1 space-y-3">
                    <div>
                      <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
                        Confirm action
                      </p>
                      <p className="mt-1 text-sm text-amber-800 dark:text-amber-300">
                        {
                          response.actions.find((action) => action.action_id === confirmingActionId)?.confirmation_text ||
                          'This action changes the current EasyPi state.'
                        }
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {response.actions
                        .filter((action) => action.action_id === confirmingActionId)
                        .map((action) => (
                          <Button
                            key={action.action_id}
                            variant={action.style === 'danger' ? 'danger' : 'primary'}
                            size="sm"
                            loading={executingActionId === action.action_id}
                            onClick={() => onConfirmAction(action)}
                            icon={<Wand2 className="h-4 w-4" />}
                          >
                            Confirm {action.label}
                          </Button>
                        ))}
                      <Button variant="outline" size="sm" onClick={onCancelAction}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  )
}

export default function AgentPanel() {
  const {
    isOpen,
    setIsOpen,
    draft,
    setDraft,
    section,
    entries,
    submitQuestion,
    askSuggestion,
    clearThread,
    runAction,
    executingActionId,
  } = useAgent()

  const scrollRef = useRef<HTMLDivElement | null>(null)
  const latestEntryRef = useRef<HTMLDivElement | null>(null)
  const [confirmingAction, setConfirmingAction] = useState<{
    entryId: string
    action: DiagnosticAction
  } | null>(null)
  const primarySuggestions = useMemo(() => section.suggestions.slice(0, 4), [section.suggestions])

  useLayoutEffect(() => {
    if (!isOpen || !scrollRef.current || !latestEntryRef.current) {
      return
    }
    const container = scrollRef.current
    const latestEntry = latestEntryRef.current
    const nextTop = Math.max(0, latestEntry.offsetTop - 8)
    const frame = window.requestAnimationFrame(() => {
      container.scrollTo({ top: nextTop, behavior: 'smooth' })
    })
    return () => window.cancelAnimationFrame(frame)
  }, [entries, isOpen])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && isOpen) {
        setIsOpen(false)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [isOpen, setIsOpen])

  const handleSubmit = async () => {
    await submitQuestion(draft)
  }

  const handleActionExecute = async (entryId: string, action: DiagnosticAction) => {
    const entry = entries.find((item) => item.id === entryId)
    if (!entry) {
      return
    }
    setConfirmingAction(null)
    await runAction(entry, action)
  }

  const handleActionRequest = async (entryId: string, action: DiagnosticAction) => {
    if (action.requires_confirmation) {
      setConfirmingAction({ entryId, action })
      return
    }
    await handleActionExecute(entryId, action)
  }

  return (
    <>
      {isOpen && (
        <>
          <div
            className="fixed inset-0 z-40 bg-slate-950/45 backdrop-blur-sm"
            onClick={() => setIsOpen(false)}
          />

          <aside className="fixed inset-y-0 right-0 z-50 flex w-full max-w-[30rem] flex-col border-l border-slate-200 bg-slate-50 shadow-2xl dark:border-dark-700 dark:bg-dark-950">
            <div className="border-b border-slate-200 bg-white px-5 py-4 dark:border-dark-700 dark:bg-dark-900">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="inline-flex items-center gap-2 rounded-full bg-sky-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-sky-700 dark:bg-sky-900/20 dark:text-sky-300">
                    <Sparkles className="h-3.5 w-3.5" />
                    {section.title.replace(/\s+Agent$/i, '')} Assistant
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {entries.length > 0 && (
                    <button
                      type="button"
                      onClick={clearThread}
                      className="rounded-xl border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-600 transition-colors hover:bg-slate-100 dark:border-dark-700 dark:text-slate-300 dark:hover:bg-dark-800"
                    >
                      Clear
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setIsOpen(false)}
                    className="rounded-xl border border-slate-200 p-2 text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-700 dark:border-dark-700 dark:text-slate-400 dark:hover:bg-dark-800 dark:hover:text-slate-200"
                    aria-label="Close agent panel"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>

            <div className="border-b border-slate-200 bg-gradient-to-b from-white to-slate-50 px-5 py-4 dark:border-dark-700 dark:from-dark-900 dark:to-dark-950">
              <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500 dark:text-slate-400">
                Suggested questions
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {primarySuggestions.map((suggestion) => (
                  <button
                    key={suggestion.id}
                    type="button"
                    onClick={() => askSuggestion(suggestion)}
                    className="rounded-full border border-slate-200 bg-white px-3 py-2 text-left text-xs font-medium text-slate-700 transition-colors hover:border-sky-300 hover:bg-sky-50 hover:text-sky-700 dark:border-dark-700 dark:bg-dark-900 dark:text-slate-200 dark:hover:border-sky-800 dark:hover:bg-sky-900/20 dark:hover:text-sky-300"
                  >
                    {suggestion.label}
                  </button>
                ))}
              </div>
            </div>

            <div ref={scrollRef} className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
              {entries.length === 0 ? (
                <div className="flex h-full items-center justify-center text-sm text-slate-400 dark:text-slate-500">
                  Ask a question below.
                </div>
              ) : (
                entries.map((entry) => (
                  <div
                    key={entry.id}
                    ref={entry.id === entries[entries.length - 1]?.id ? latestEntryRef : null}
                    className="space-y-3"
                  >
                    <div className="flex justify-end">
                      <div className="max-w-[85%] rounded-3xl bg-slate-900 px-4 py-3 text-sm text-white shadow-sm dark:bg-slate-100 dark:text-slate-900">
                        {entry.question}
                      </div>
                    </div>

                    {entry.status === 'pending' && (
                      <Card className="border border-slate-200 bg-white dark:border-dark-700 dark:bg-dark-900">
                        <div className="space-y-4">
                          <div className="flex items-center gap-3 text-sm font-medium text-slate-700 dark:text-slate-200">
                            <Loader2 className="h-4 w-4 animate-spin text-sky-500" />
                            Agent is collecting local facts for this section...
                          </div>
                          <div className="space-y-2">
                            <div className="h-3 w-32 animate-pulse rounded-full bg-slate-200 dark:bg-dark-700" />
                            <div className="h-3 w-full animate-pulse rounded-full bg-slate-200 dark:bg-dark-700" />
                            <div className="h-3 w-5/6 animate-pulse rounded-full bg-slate-200 dark:bg-dark-700" />
                          </div>
                        </div>
                      </Card>
                    )}

                    {entry.status === 'error' && (
                      <Card className="border border-rose-200 bg-rose-50 dark:border-rose-900/40 dark:bg-rose-900/20">
                        <div className="flex items-start gap-3 text-sm text-rose-800 dark:text-rose-300">
                          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                          <div>{entry.error || 'The agent request failed.'}</div>
                        </div>
                      </Card>
                    )}

                    {entry.response && (
                      <ResponseCard
                        response={entry.response}
                        executingActionId={executingActionId}
                        confirmingActionId={
                          confirmingAction?.entryId === entry.id ? confirmingAction.action.action_id : null
                        }
                        onRunAction={(action) => void handleActionRequest(entry.id, action)}
                        onConfirmAction={(action) => void handleActionExecute(entry.id, action)}
                        onCancelAction={() => setConfirmingAction(null)}
                      />
                    )}

                    {entry.actionRuns.length > 0 && (
                      <div className="space-y-3">
                        {entry.actionRuns.map((actionRun) => (
                          <Card
                            key={actionRun.id}
                            className={`border ${
                              actionRun.result.success
                                ? 'border-emerald-200 bg-emerald-50 dark:border-emerald-900/40 dark:bg-emerald-900/20'
                                : 'border-rose-200 bg-rose-50 dark:border-rose-900/40 dark:bg-rose-900/20'
                            }`}
                          >
                            <div className="space-y-3">
                              <div className="text-sm font-semibold text-slate-900 dark:text-white">
                                {actionRun.label}
                              </div>
                              <div
                                className={`text-sm ${
                                  actionRun.result.success
                                    ? 'text-emerald-800 dark:text-emerald-300'
                                    : 'text-rose-800 dark:text-rose-300'
                                }`}
                              >
                                {actionRun.result.message}
                              </div>
                              {actionRun.result.follow_up && (
                                <ResponseCard
                                  response={actionRun.result.follow_up as DiagnosticExplainResponse}
                                  executingActionId={executingActionId}
                                  confirmingActionId={
                                    confirmingAction?.entryId === entry.id ? confirmingAction.action.action_id : null
                                  }
                                  onRunAction={(action) => void handleActionRequest(entry.id, action)}
                                  onConfirmAction={(action) => void handleActionExecute(entry.id, action)}
                                  onCancelAction={() => setConfirmingAction(null)}
                                />
                              )}
                            </div>
                          </Card>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="border-t border-slate-200 bg-white px-5 py-4 dark:border-dark-700 dark:bg-dark-900">
              <div className="space-y-2">
                <div className="flex gap-3">
                  <textarea
                    value={draft}
                    onChange={(event) => setDraft(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' && !event.shiftKey) {
                        event.preventDefault()
                        void handleSubmit()
                      }
                    }}
                    rows={2}
                    maxLength={500}
                    placeholder={section.placeholder}
                    className="min-h-[3.25rem] flex-1 resize-none rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition-colors focus:border-sky-400 focus:bg-white dark:border-dark-700 dark:bg-dark-950 dark:text-white dark:focus:border-sky-700 dark:focus:bg-dark-900"
                  />
                  <Button
                    variant="primary"
                    size="md"
                    onClick={() => void handleSubmit()}
                    disabled={!draft.trim()}
                    icon={<Send className="h-4 w-4" />}
                    className="self-end rounded-2xl bg-gradient-to-r from-sky-500 to-cyan-500 px-4 py-3 hover:from-sky-600 hover:to-cyan-600"
                  >
                    Ask
                  </Button>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400">
                  <span>Press Enter to ask. Use Shift + Enter for a new line.</span>
                  <span>{draft.length}/500 characters. Answers are based on local EasyPi facts and current section context.</span>
                </div>
              </div>
            </div>
          </aside>
        </>
      )}
    </>
  )
}
