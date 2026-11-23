import type {
  DiagnosticAction,
  DiagnosticActionRequest,
  DiagnosticActionResponse,
  DiagnosticExplainRequest,
  DiagnosticExplainResponse,
} from '../../api/ai'

export type AgentSectionId =
  | 'dashboard'
  | 'monitoring'
  | 'guard-security'
  | 'personal-dns'
  | 'file-manager'
  | 'help'
  | 'ip-cameras'
  | 'network-activity'
  | 'network-toolkit'
  | 'remote-access'
  | 'security'
  | 'settings'
  | 'setup'
  | 'system-backup'
  | 'jobs'
  | 'notifications-center'
  | 'rollback-center'
  | 'terminal'
  | 'users'
  | 'vpn'
  | 'internet-encryption'
  | 'stealth'
  | 'marketplace'
  | 'cloud'
  | 'ai'
  | 'generic'

export interface AgentSuggestion {
  id: string
  label: string
  question: string
  target?: string
  target_type?: DiagnosticExplainRequest['target_type']
  tab?: string
  entity_type?: string
  entity_id?: string
}

export interface AgentSectionConfig {
  id: AgentSectionId
  route: string
  title: string
  subtitle: string
  intro: string
  placeholder: string
  suggestions: AgentSuggestion[]
}

export interface AgentActionRun {
  id: string
  label: string
  result: DiagnosticActionResponse
  createdAt: string
}

export interface AgentConversationEntry {
  id: string
  question: string
  request: DiagnosticExplainRequest
  status: 'pending' | 'done' | 'error'
  response?: DiagnosticExplainResponse
  error?: string
  createdAt: string
  actionRuns: AgentActionRun[]
}

export type {
  DiagnosticAction,
  DiagnosticActionRequest,
  DiagnosticActionResponse,
  DiagnosticExplainRequest,
  DiagnosticExplainResponse,
}
