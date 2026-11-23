import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as netProtectionApi from '../api/netProtectionApi';
import { blocklistKeys, netProtectionKeys } from './netProtectionHookKeys';

export { blocklistKeys } from './netProtectionHookKeys';

export function useBlocklistStatus() {
  return useQuery({
    queryKey: blocklistKeys.status(),
    queryFn: netProtectionApi.getBlocklistStatus,
    staleTime: 30000,
  });
}

export function useVerifiedSources() {
  return useQuery({
    queryKey: blocklistKeys.verified(),
    queryFn: netProtectionApi.getVerifiedSources,
    staleTime: 60000,
  });
}

export function useSetVerifiedSourceEnabled() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ sourceId, enabled }: { sourceId: string; enabled: boolean }) =>
      netProtectionApi.setVerifiedSourceEnabled(sourceId, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: blocklistKeys.all });
    },
  });
}

export function useCustomSources() {
  return useQuery({
    queryKey: blocklistKeys.custom(),
    queryFn: netProtectionApi.getCustomSources,
    staleTime: 30000,
  });
}

export function useGenerateBlocklists() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.generateBlocklists,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: blocklistKeys.all });
      queryClient.invalidateQueries({ queryKey: netProtectionKeys.dashboard() });
    },
  });
}

export function useGenerationProgress() {
  return useQuery({
    queryKey: blocklistKeys.progress(),
    queryFn: netProtectionApi.getGenerationProgress,
    refetchInterval: 1000,
  });
}

export function useAddCustomSource() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.addCustomSource,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: blocklistKeys.custom() });
      queryClient.invalidateQueries({ queryKey: blocklistKeys.status() });
    },
  });
}

export function useUploadCustomBlocklistFile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ file, name, format, user_confirmed_risks }: {
      file: File;
      name: string;
      format: 'hosts' | 'domains' | 'adblock' | 'auto';
      user_confirmed_risks: boolean;
    }) => netProtectionApi.uploadCustomBlocklistFile(file, name, format, user_confirmed_risks),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: blocklistKeys.custom() });
      queryClient.invalidateQueries({ queryKey: blocklistKeys.status() });
    },
  });
}

export function useRemoveCustomSource() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: netProtectionApi.removeCustomSource,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: blocklistKeys.custom() });
      queryClient.invalidateQueries({ queryKey: blocklistKeys.status() });
    },
  });
}

export function useSetCustomSourceEnabled() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ sourceId, enabled }: { sourceId: string; enabled: boolean }) =>
      netProtectionApi.setCustomSourceEnabled(sourceId, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: blocklistKeys.custom() });
      queryClient.invalidateQueries({ queryKey: blocklistKeys.status() });
    },
  });
}

export function useGetUseCustomBlocklist() {
  return useQuery({
    queryKey: ['blocklist', 'use-custom'],
    queryFn: netProtectionApi.getUseCustomBlocklist,
  });
}

export function useSetUseCustomBlocklist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (enabled: boolean) => netProtectionApi.setUseCustomBlocklist(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blocklist', 'use-custom'] });
      queryClient.invalidateQueries({ queryKey: blocklistKeys.status() });
    },
  });
}
