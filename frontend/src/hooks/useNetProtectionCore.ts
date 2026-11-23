import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as netProtectionApi from '../api/netProtectionApi';
import type {
  Matcher,
  NetProtectionConfig,
  ShieldProfileId,
  ThreatStats,
  VerdictType,
  Device,
} from '../api/netProtectionApi';
import { netProtectionKeys } from './netProtectionHookKeys';

export { netProtectionKeys } from './netProtectionHookKeys';

export function useNetProtectionStatus() {
  return useQuery({
    queryKey: netProtectionKeys.status(),
    queryFn: netProtectionApi.getNetProtectionStatus,
    staleTime: 30000,
  });
}

export function useNetProtectionFullStatus() {
  return useQuery({
    queryKey: netProtectionKeys.statusFull(),
    queryFn: netProtectionApi.getNetProtectionFullStatus,
    staleTime: 30000,
  });
}

export function useNetProtectionConfig() {
  return useQuery({
    queryKey: netProtectionKeys.config(),
    queryFn: netProtectionApi.getNetProtectionConfig,
    staleTime: 60000,
  });
}

export function useUpdateNetProtectionConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (config: Partial<NetProtectionConfig>) => netProtectionApi.updateNetProtectionConfig(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.config() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.dashboard() });
    },
  });
}

export function useEnableProtection() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.enableProtection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.status() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.config() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.dashboard() });
    },
  });
}

export function useDisableProtection() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.disableProtection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.status() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.config() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.dashboard() });
    },
  });
}

export function useNetProtectionDashboard() {
  return useQuery({
    queryKey: netProtectionKeys.dashboard(),
    queryFn: netProtectionApi.getNetProtectionDashboard,
    staleTime: 10000,
    refetchInterval: 30000,
  });
}

export function useNetProtectionStats(period: '24h' | '7d' = '24h') {
  return useQuery({
    queryKey: netProtectionKeys.stats(period),
    queryFn: () => netProtectionApi.getNetProtectionStats(period),
    staleTime: 30000,
  });
}

export function useVerdicts(params?: {
  offset?: number;
  limit?: number;
  search?: string;
  verdict_type?: VerdictType;
  include_system?: boolean;
}) {
  return useQuery({
    queryKey: netProtectionKeys.verdicts(params),
    queryFn: () => netProtectionApi.getVerdicts(params),
    staleTime: 5000,
    refetchInterval: 10000,
  });
}

export function useQueryLogStats() {
  return useQuery({
    queryKey: ['netprotection', 'querylog', 'stats'],
    queryFn: netProtectionApi.getQueryLogStats,
    staleTime: 10000,
    refetchInterval: 30000,
  });
}

export function useClearQueryLog() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (olderThanDays: number = 0) => netProtectionApi.clearQueryLog(olderThanDays),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.verdicts() });
      queryClient.invalidateQueries({ queryKey: ['netprotection', 'querylog', 'stats'] });
    },
  });
}

export function useVerdictDetail(flowId: string) {
  return useQuery({
    queryKey: netProtectionKeys.verdict(flowId),
    queryFn: () => netProtectionApi.getVerdictDetail(flowId),
    enabled: !!flowId,
  });
}

export function useMatchers() {
  return useQuery({
    queryKey: netProtectionKeys.matchers(),
    queryFn: netProtectionApi.getMatchers,
    staleTime: 60000,
  });
}

export function useCreateMatcher() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.createMatcher,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.matchers() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.dashboard() });
    },
  });
}

export function useUpdateMatcher() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ matcherId, updates }: { matcherId: string; updates: Partial<Matcher> }) =>
      netProtectionApi.updateMatcher(matcherId, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.matchers() });
    },
  });
}

export function useDeleteMatcher() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.deleteMatcher,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.matchers() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.dashboard() });
    },
  });
}

export function useWhitelist() {
  return useQuery({
    queryKey: netProtectionKeys.whitelist(),
    queryFn: netProtectionApi.getWhitelist,
    staleTime: 60000,
  });
}

export function useAddToWhitelist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (domain: string) => netProtectionApi.addToWhitelist(domain),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.whitelist() });
    },
  });
}

export function useRemoveFromWhitelist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.removeFromWhitelist,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.whitelist() });
    },
  });
}

export function useBlacklist() {
  return useQuery({
    queryKey: netProtectionKeys.blacklist(),
    queryFn: netProtectionApi.getBlacklist,
    staleTime: 60000,
  });
}

export function useAddToBlacklist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (domain: string) => netProtectionApi.addToBlacklist(domain),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.blacklist() });
    },
  });
}

export function useRemoveFromBlacklist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.removeFromBlacklist,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.blacklist() });
    },
  });
}

export function useShieldProfiles() {
  return useQuery({
    queryKey: netProtectionKeys.shields(),
    queryFn: netProtectionApi.getShieldProfiles,
    staleTime: 300000,
  });
}

export function useSetShieldProfile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.setShieldProfile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.shields() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.config() });
    },
  });
}

export function useDevices() {
  return useQuery({
    queryKey: netProtectionKeys.devices(),
    queryFn: netProtectionApi.getDevices,
    staleTime: 30000,
  });
}

export function useUpdateDevice() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ deviceId, updates }: { deviceId: string; updates: Partial<Device> }) =>
      netProtectionApi.updateDevice(deviceId, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.devices() });
    },
  });
}

export function useSetDeviceShieldProfile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ deviceId, profileId }: { deviceId: string; profileId: ShieldProfileId }) =>
      netProtectionApi.setDeviceShieldProfile(deviceId, profileId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.devices() });
    },
  });
}

export function useThreatStats() {
  return useQuery({
    queryKey: netProtectionKeys.threatStats(),
    queryFn: netProtectionApi.getThreatStats,
    staleTime: 60000,
  });
}

export function useBlocklistInfo() {
  return useQuery({
    queryKey: netProtectionKeys.blocklist(),
    queryFn: netProtectionApi.getBlocklistInfo,
    staleTime: 60000,
  });
}

export function useGenerateBlocklist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.generateBlocklist,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.blocklist() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.threatStats() });
    },
  });
}

export function useCleanupExpiredThreats() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.cleanupExpiredThreats,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.blocklist() });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.threatStats() });
    },
  });
}

export function useNetProtectionMetrics() {
  return useQuery({
    queryKey: netProtectionKeys.metrics(),
    queryFn: netProtectionApi.getNetProtectionMetrics,
    staleTime: 10000,
    refetchInterval: 30000,
  });
}
