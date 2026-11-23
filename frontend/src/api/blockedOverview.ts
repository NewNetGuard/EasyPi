import api from './client'

export type BlockedPeriod = '24h' | '7d'

/** Why an entry sits in its section: the engine's reason, the name, or timing. */
export type ClassificationBasis = 'reason' | 'name' | 'behavior'

export interface BlockedDomain {
  domain: string
  count: number
  last_seen: string
  devices: string[]
  source_key: string
  source_label: string
  basis: ClassificationBasis
}

export interface AllowedDomain {
  domain: string
  added_at: string
  hits: number
  comment: string
  source: string
  source_label: string
}

export interface BlockedOverview {
  period: BlockedPeriod
  client_id: string | null
  sites: BlockedDomain[]
  trackers: BlockedDomain[]
  allowed: AllowedDomain[]
  scanned_rows: number
  truncated: boolean
}

export const getBlockedOverview = async (
  period: BlockedPeriod,
  clientId?: string,
): Promise<BlockedOverview> => {
  const { data } = await api.get('/netprotection/blocked-overview', {
    params: { period, ...(clientId ? { client_id: clientId } : {}) },
  })
  return data
}

/** The user's latest decision for one host: allow (unblock) or block again. */
export const setDomainDecision = async (domain: string, decision: 'allow' | 'block') => {
  const { data } = await api.post('/netprotection/domain-decision', { domain, decision })
  return data
}
