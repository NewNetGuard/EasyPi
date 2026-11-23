import { create } from 'zustand'

const MAX_SEARCH_LENGTH = 96

// Older releases persisted raw search and error text. Remove that legacy state;
// help diagnostics are intentionally memory-only now.
try {
  window.localStorage.removeItem('easypi-help-metrics')
} catch {
  // Storage may be unavailable in hardened browser profiles.
}

interface HelpMetricsState {
  recentSearches: string[]
  guideViews: Record<string, number>
  faqFeedback: Record<string, { up: number; down: number }>
  logSearch: (query: string) => void
  logGuideView: (guideId: string) => void
  voteFaq: (faqId: string, type: 'up' | 'down') => void
}

export const useHelpStore = create<HelpMetricsState>()(
  (set) => ({
      recentSearches: [],
      guideViews: {},
      faqFeedback: {},
      logSearch: (query) => {
        const cleaned = query.trim().slice(0, MAX_SEARCH_LENGTH)
        if (!cleaned) return
        set((state) => {
          const updated = [cleaned, ...state.recentSearches.filter((q) => q !== cleaned)].slice(0, 8)
          return { recentSearches: updated }
        })
      },
      logGuideView: (guideId) => {
        set((state) => ({
          guideViews: {
            ...state.guideViews,
            [guideId]: (state.guideViews[guideId] || 0) + 1
          }
        }))
      },
      voteFaq: (faqId, type) => {
        set((state) => {
          const current = state.faqFeedback[faqId] || { up: 0, down: 0 }
          const updated = {
            ...state.faqFeedback,
            [faqId]: {
              up: type === 'up' ? current.up + 1 : current.up,
              down: type === 'down' ? current.down + 1 : current.down
            }
          }
          return { faqFeedback: updated }
        })
      }
  })
)
