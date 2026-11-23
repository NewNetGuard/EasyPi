import api from './client'

export interface NrdStatus {
  enabled: boolean
  max_age_days: number
  feed_domains: number
  feed_updated_at?: string | null
}

export const getNrdStatus = async (): Promise<NrdStatus> => {
  const { data } = await api.get('/dns/heuristics/nrd')
  return data
}

export const setNrdConfig = async (body: { enabled?: boolean; max_age_days?: number }) => {
  const { data } = await api.post('/dns/heuristics/nrd', body)
  return data
}

export const refreshNrdFeed = async () => {
  const { data } = await api.post('/dns/heuristics/nrd/refresh')
  return data
}

export interface NrdBlockedDomain {
  domain: string
  time?: string | null
  client?: string | null
  evidence?: string | null
}

export const getNrdBlocked = async (limit = 60): Promise<{ count: number; domains: NrdBlockedDomain[] }> => {
  const { data } = await api.get('/dns/heuristics/nrd/blocked', { params: { limit } })
  return data || { count: 0, domains: [] }
}
