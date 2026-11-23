import { useCallback, useEffect, useMemo, useState } from 'react'
import { useLocation } from 'react-router-dom'
import toast from 'react-hot-toast'
import {
  executeAgentAction,
  explainAgent,
  getAgentSectionConfig,
  getAgentTabFromLocation,
} from './api'
import { useAgentPanelStore } from '../../stores/agentPanelStore'
import type {
  AgentActionRun,
  AgentConversationEntry,
  AgentSectionConfig,
  AgentSuggestion,
  DiagnosticAction,
  DiagnosticExplainRequest,
} from './types'

const buildId = () =>
  typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `agent_${Date.now()}_${Math.random().toString(16).slice(2)}`

const buildEntry = (question: string, request: DiagnosticExplainRequest): AgentConversationEntry => ({
  id: buildId(),
  question,
  request,
  status: 'pending',
  createdAt: new Date().toISOString(),
  actionRuns: [],
})

export const useAgent = () => {
  const location = useLocation()
  const section = useMemo<AgentSectionConfig>(
    () => getAgentSectionConfig(location.pathname),
    [location.pathname]
  )
  const tab = useMemo(
    () => getAgentTabFromLocation(location.search, location.hash, location.pathname),
    [location.hash, location.pathname, location.search]
  )
  const threadKey = section.route

  const isOpen = useAgentPanelStore((state) => state.isOpen)
  const setIsOpen = useAgentPanelStore((state) => (value: boolean) => (value ? state.open() : state.close()))
  const draft = useAgentPanelStore((state) => state.draft)
  const setDraft = useAgentPanelStore((state) => state.setDraft)
  const queuedQuestion = useAgentPanelStore((state) => state.queuedQuestion)
  const clearQueuedQuestion = useAgentPanelStore((state) => state.clearQueuedQuestion)
  const [showAllSuggestions, setShowAllSuggestions] = useState(false)
  const [threads, setThreads] = useState<Record<string, AgentConversationEntry[]>>({})
  const [executingActionId, setExecutingActionId] = useState<string | null>(null)

  const entries = threads[threadKey] ?? []
  const pendingCount = entries.filter((entry) => entry.status === 'pending').length

  useEffect(() => {
    setDraft('')
    setShowAllSuggestions(false)
  }, [setDraft, threadKey])

  const updateEntry = useCallback((
    activeThreadKey: string,
    entryId: string,
    updater: (entry: AgentConversationEntry) => AgentConversationEntry
  ) => {
    setThreads((current) => ({
      ...current,
      [activeThreadKey]: (current[activeThreadKey] ?? []).map((entry) => (
        entry.id === entryId ? updater(entry) : entry
      )),
    }))
  }, [])

  const submitQuestion = useCallback(async (
    rawQuestion: string,
    extras: Partial<DiagnosticExplainRequest> = {}
  ) => {
    // eslint-disable-next-line no-control-regex -- Reject non-printing prompt bytes before API submission.
    const question = rawQuestion.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ').trim().slice(0, 500)
    if (!question) {
      return
    }

    const request: DiagnosticExplainRequest = {
      question,
      route: section.route,
      tab: extras.tab ?? tab,
      target_type: extras.target_type,
      target: extras.target,
      entity_type: extras.entity_type,
      entity_id: extras.entity_id,
    }
    const activeThreadKey = threadKey
    const entry = buildEntry(question, request)

    setThreads((current) => ({
      ...current,
      [activeThreadKey]: [...(current[activeThreadKey] ?? []), entry],
    }))
    setDraft('')

    try {
      const response = await explainAgent(request)
      updateEntry(activeThreadKey, entry.id, (current) => ({
        ...current,
        status: 'done',
        response,
      }))
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to ask the agent.'
      updateEntry(activeThreadKey, entry.id, (current) => ({
        ...current,
        status: 'error',
        error: message,
      }))
      toast.error(message)
    }
  }, [section.route, setDraft, tab, threadKey, updateEntry])

  useEffect(() => {
    if (!queuedQuestion) {
      return
    }
    clearQueuedQuestion()
    void submitQuestion(queuedQuestion.question, queuedQuestion.extras)
  }, [queuedQuestion, clearQueuedQuestion, submitQuestion])

  const askSuggestion = async (suggestion: AgentSuggestion) => {
    await submitQuestion(suggestion.question, {
      target: suggestion.target,
      target_type: suggestion.target_type,
      tab: suggestion.tab,
      entity_type: suggestion.entity_type,
      entity_id: suggestion.entity_id,
    })
  }

  const runAction = async (entry: AgentConversationEntry, action: DiagnosticAction) => {
    const activeThreadKey = threadKey
    const executionKey = `${entry.id}:${action.action_id}`
    setExecutingActionId(executionKey)

    try {
      const result = await executeAgentAction({
        action_id: action.action_id,
        parameters: action.parameters,
        confirmation_token: action.confirmation_token || '',
        question: entry.request.question,
        route: entry.request.route,
        tab: entry.request.tab,
        target_type: entry.request.target_type,
        target: entry.request.target,
        entity_type: entry.request.entity_type,
        entity_id: entry.request.entity_id,
      })

      const actionRun: AgentActionRun = {
        id: buildId(),
        label: action.label,
        result,
        createdAt: new Date().toISOString(),
      }

      updateEntry(activeThreadKey, entry.id, (current) => ({
        ...current,
        actionRuns: [...current.actionRuns, actionRun],
      }))

      if (result.success) {
        toast.success(result.message)
      } else {
        toast.error(result.message)
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to execute the agent action.'
      const actionRun: AgentActionRun = {
        id: buildId(),
        label: action.label,
        result: {
          action_id: action.action_id,
          success: false,
          message,
          data: {},
          follow_up: null,
        },
        createdAt: new Date().toISOString(),
      }

      updateEntry(activeThreadKey, entry.id, (current) => ({
        ...current,
        actionRuns: [...current.actionRuns, actionRun],
      }))
      toast.error(message)
    } finally {
      setExecutingActionId(null)
    }
  }

  const clearThread = () => {
    setThreads((current) => ({
      ...current,
      [threadKey]: [],
    }))
  }

  return {
    isOpen,
    setIsOpen,
    draft,
    setDraft,
    section,
    entries,
    pendingCount,
    showAllSuggestions,
    setShowAllSuggestions,
    submitQuestion,
    askSuggestion,
    clearThread,
    runAction,
    executingActionId,
  }
}
