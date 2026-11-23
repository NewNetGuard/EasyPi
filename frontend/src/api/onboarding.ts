import api from './client'

export interface OnboardingStep {
  key: string
  title: string
  done: boolean
  required: boolean
  detail: string
  hint: string
  link: string
}
export interface OnboardingStatus {
  steps: OnboardingStep[]
  completedCount: number
  totalCount: number
  requiredDone: boolean
  allDone: boolean
  nextStep: string | null
  piIp: string | null
  narrative: string
}

export const getOnboarding = async (): Promise<OnboardingStatus> => {
  const { data } = await api.get('/netprotection/onboarding')
  return data
}

// Start the NetProtection DNS filter (used by the "Protection is on" step so the
// button actually turns it on, instead of just navigating). Normalises the
// endpoint's 500-on-failure into a result the card can show.
export const startProtection = async (): Promise<{ success: boolean; error?: string }> => {
  try {
    await api.post('/netprotection/start')
    return { success: true }
  } catch (e: unknown) {
    const err = e as { response?: { data?: { detail?: string } }; message?: string }
    const detail = err?.response?.data?.detail
    const msg = (typeof detail === 'string' && detail) || err?.message || 'Could not start the DNS filter.'
    return { success: false, error: msg }
  }
}
