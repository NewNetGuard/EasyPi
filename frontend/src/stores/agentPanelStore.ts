import { create } from 'zustand'
import type { DiagnosticExplainRequest } from '../features/agent/types'

interface QueuedAgentQuestion {
  question: string
  extras?: Partial<DiagnosticExplainRequest>
}

interface AgentPanelState {
  isOpen: boolean
  draft: string
  queuedQuestion: QueuedAgentQuestion | null
  open: () => void
  close: () => void
  setDraft: (draft: string) => void
  queueQuestion: (question: string, extras?: Partial<DiagnosticExplainRequest>) => void
  clearQueuedQuestion: () => void
}

export const useAgentPanelStore = create<AgentPanelState>((set) => ({
  isOpen: false,
  draft: '',
  queuedQuestion: null,
  open: () => set({ isOpen: true }),
  close: () => set({ isOpen: false }),
  setDraft: (draft) => set({ draft }),
  queueQuestion: (question, extras) =>
    set({
      isOpen: true,
      draft: '',
      queuedQuestion: { question, extras },
    }),
  clearQueuedQuestion: () => set({ queuedQuestion: null }),
}))
