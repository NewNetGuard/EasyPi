export const netProtectionKeys = {
  all: ['netprotection'] as const,
  status: () => [...netProtectionKeys.all, 'status'] as const,
  statusFull: () => [...netProtectionKeys.all, 'status', 'full'] as const,
  config: () => [...netProtectionKeys.all, 'config'] as const,
  dashboard: () => [...netProtectionKeys.all, 'dashboard'] as const,
  stats: (period: string) => [...netProtectionKeys.all, 'stats', period] as const,
  verdicts: (params?: object) => [...netProtectionKeys.all, 'verdicts', params] as const,
  verdict: (flowId: string) => [...netProtectionKeys.all, 'verdict', flowId] as const,
  matchers: () => [...netProtectionKeys.all, 'matchers'] as const,
  whitelist: () => [...netProtectionKeys.all, 'whitelist'] as const,
  blacklist: () => [...netProtectionKeys.all, 'blacklist'] as const,
  shields: () => [...netProtectionKeys.all, 'shields'] as const,
  devices: () => [...netProtectionKeys.all, 'devices'] as const,
  threatStats: () => [...netProtectionKeys.all, 'threat-stats'] as const,
  blocklist: () => [...netProtectionKeys.all, 'blocklist'] as const,
  metrics: () => [...netProtectionKeys.all, 'metrics'] as const,
};

export const blocklistKeys = {
  all: ['blocklists'] as const,
  status: () => [...blocklistKeys.all, 'status'] as const,
  verified: () => [...blocklistKeys.all, 'verified'] as const,
  custom: () => [...blocklistKeys.all, 'custom'] as const,
  progress: () => [...blocklistKeys.all, 'progress'] as const,
};
