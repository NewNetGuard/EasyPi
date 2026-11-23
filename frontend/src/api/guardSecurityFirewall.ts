import { securityApi } from './client'
import type { FirewallRule } from '../types/security'

export const getFirewallRules = async (): Promise<FirewallRule[]> => {
  try {
    const { data } = await securityApi.get('/firewall/rules')
    return data || []
  } catch {
    return []
  }
}

export const addFirewallRule = async (rule: Omit<FirewallRule, 'id' | 'createdAt' | 'hits'>) => {
  const { data } = await securityApi.post('/firewall/rule', rule)
  return data
}

export const toggleFirewall = async (enabled: boolean) => {
  const { data } = await securityApi.post('/firewall/toggle', { enabled })
  return data
}

export const deleteFirewallRule = async (id: string) => {
  const { data } = await securityApi.delete(`/firewall/rule/${id}`)
  return data
}
