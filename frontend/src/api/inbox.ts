import apiClient from './client'

export type InboxSource = 'jobs' | 'security' | 'push' | 'watchdog'
export type InboxSeverity = 'critical' | 'warning' | 'success' | 'info'

export interface InboxSummary {
  total: number
  action_required: number
  critical: number
  warning: number
  success: number
  info: number
  jobs: number
  security: number
  push: number
  watchdog: number
}

export interface InboxItem {
  event_id: string
  source: InboxSource
  severity: InboxSeverity
  title: string
  message: string
  timestamp?: string | null
  route?: string | null
  source_label?: string | null
}

export interface InboxResponse {
  generated_at: string
  summary: InboxSummary
  items: InboxItem[]
}

export const listInbox = async (limit = 60): Promise<InboxResponse> => {
  const response = await apiClient.get('/inbox', { params: { limit } })
  return response.data
}
