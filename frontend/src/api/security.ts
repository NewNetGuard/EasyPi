/**
 * Security API Client
 */

import apiClient from './client';

export interface SecurityIssue {
  id: string;
  message: string;
  status: 'critical' | 'warning' | 'passed';
  details?: string;
  fixable: boolean;
}

export interface SecurityScanResponse {
  last_scan: string;
  critical: SecurityIssue[];
  warnings: SecurityIssue[];
  passed: SecurityIssue[];
}

export interface FixResponse {
  status: 'success' | 'error';
  message: string;
}

export interface FixJobStartResponse {
  status: 'success' | 'error';
  message: string;
  job_id?: string;
}

export interface FixJobStatusResponse {
  status: 'running' | 'success' | 'error' | 'idle';
  message?: string;
  progress?: number;
  job_id?: string;
}

export interface PasswordChangeRequest {
  username: string;
  new_password: string;
}

export interface FirewallRule {
  id: number;
  port: number;
  protocol: string;
  source: string;
  action: string;
  created_at: string;
}

export interface FirewallRuleCreate {
  port: number;
  protocol: 'tcp' | 'udp';
  source: string;
}

// Scan
export const runSecurityScan = async (): Promise<SecurityScanResponse> => {
  const response = await apiClient.get('/security/scan');
  return response.data;
};

// Fix endpoints
export const fixDefaultPassword = async (data: PasswordChangeRequest): Promise<FixResponse> => {
  const response = await apiClient.post('/security/fix/default-password', data);
  return response.data;
};

export const fixSshRootLogin = async (): Promise<FixResponse> => {
  const response = await apiClient.post('/security/fix/ssh-root-login');
  return response.data;
};

export const fixOutdatedPackages = async (): Promise<FixResponse> => {
  const response = await apiClient.post('/security/fix/outdated-packages', {}, {
    timeout: 600000 // 10 minutes for package updates
  });
  return response.data;
};

export const startOutdatedPackagesFix = async (): Promise<FixJobStartResponse> => {
  const response = await apiClient.post('/security/fix/outdated-packages/start');
  return response.data;
};

export const getOutdatedPackagesFixStatus = async (jobId?: string): Promise<FixJobStatusResponse> => {
  const response = await apiClient.get('/security/fix/outdated-packages/status', {
    params: jobId ? { job_id: jobId } : undefined
  });
  return response.data;
};

export const fixFirewall = async (): Promise<FixResponse> => {
  const response = await apiClient.post('/security/fix/firewall');
  return response.data;
};

export const fixPasswordAuth = async (): Promise<FixResponse> => {
  const response = await apiClient.post('/security/fix/password-auth');
  return response.data;
};

export const fixFilesystemReadonly = async (): Promise<FixResponse> => {
  const response = await apiClient.post('/security/fix/filesystem-readonly');
  return response.data;
};

export const cancelFix = async (fixType: string): Promise<{ status: string; message: string }> => {
  const response = await apiClient.post(`/security/cancel/${fixType}`);
  return response.data;
};

// Firewall rules
export const getFirewallRules = async (): Promise<FirewallRule[]> => {
  const response = await apiClient.get('/security/firewall/rules');
  return response.data;
};

export const addFirewallRule = async (rule: FirewallRuleCreate): Promise<FirewallRule> => {
  const response = await apiClient.post('/security/firewall/add', rule);
  return response.data;
};

export const deleteFirewallRule = async (ruleId: number): Promise<void> => {
  await apiClient.delete(`/security/firewall/remove/${ruleId}`);
};

// Audit logs
export interface AuditLogEntry {
  timestamp: string;
  type: 'success' | 'warning' | 'info' | 'error';
  title: string;
  details: string;
  source: string;
}

export interface AuditLogsResponse {
  logs: AuditLogEntry[];
  total: number;
}

export const getAuditLogs = async (limit: number = 50): Promise<AuditLogsResponse> => {
  const response = await apiClient.get(`/security/audit-logs?limit=${limit}`);
  return response.data;
};
