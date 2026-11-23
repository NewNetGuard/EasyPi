import axios from 'axios'

import apiClient from './client'

export type ActionPreviewId =
  | 'backup.restore'
  | 'backup.delete'
  | 'backup.cancel'
  | 'rollback.restore'
  | 'rollback.delete'
  | 'security.fix_firewall'
  | 'security.fix_ssh_root_login'
  | 'security.fix_password_auth'
  | 'security.fix_filesystem_readonly'
  | 'security.fix_outdated_packages'
  | 'dns.deploy'
  | 'wireguard.install'
  | 'wireguard.reset'
  | 'wireguard.uninstall'
  | 'remote-access.install'
  | 'remote-access.uninstall'

export type ActionPreviewRisk = 'low' | 'medium' | 'high' | 'critical'

export interface ActionPreviewResponse {
  action_id: ActionPreviewId
  title: string
  target_label?: string | null
  summary: string
  risk_level: ActionPreviewRisk
  destructive: boolean
  requires_confirmation: boolean
  affects: string[]
  service_impact: string[]
  rollback_available: boolean
  rollback_hint?: string | null
  recommended_checks: string[]
}

const handleError = (error: unknown) => {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (detail) {
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    }
  }
  throw error
}

export const getActionPreview = async (
  actionId: ActionPreviewId,
  targetId: string | number
): Promise<ActionPreviewResponse> => {
  try {
    const response = await apiClient.post<ActionPreviewResponse>('/action-preview', {
      action_id: actionId,
      target_id: String(targetId),
    })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}
