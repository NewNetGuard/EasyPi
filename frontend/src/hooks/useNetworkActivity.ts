/**
 * Network Activity Hooks
 * 
 * React Query hooks for network monitoring and device traffic analysis
 */

import { useQuery } from '@tanstack/react-query';
import api from '../api/client';
import type {
  NetworkDevice,
  DeviceTraffic,
  NetworkActivityStats,
  NetProtectionStatus,
  DNSQuery,
  PrismActivityResponse
} from '../types/network';

// Get NetProtection status
export function useNetProtectionStatus() {
  return useQuery({
    queryKey: ['NetProtection', 'status'],
    queryFn: async (): Promise<NetProtectionStatus> => {
      const { data } = await api.get('/network-activity/status');
      return data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

// Get all network devices
export function useNetworkDevices(activeOnly = false) {
  return useQuery({
    queryKey: ['network', 'devices', activeOnly],
    queryFn: async (): Promise<NetworkDevice[]> => {
      const { data } = await api.get('/network-activity/devices', {
        params: { active_only: activeOnly }
      });
      return data.devices;
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });
}

// Get traffic details for a specific device
export function useDeviceTraffic(deviceIp: string | null, limit = 100) {
  return useQuery({
    queryKey: ['network', 'device-traffic', deviceIp, limit],
    queryFn: async (): Promise<DeviceTraffic> => {
      if (!deviceIp) throw new Error('Device IP is required');
      const { data } = await api.get(
        `/network-activity/devices/${deviceIp}/traffic`,
        { params: { limit } }
      );
      return data;
    },
    enabled: !!deviceIp,
    refetchInterval: 5000, // Refresh every 5 seconds for live view
  });
}

// Get overall network statistics
export function useNetworkStats() {
  return useQuery({
    queryKey: ['network', 'stats'],
    queryFn: async (): Promise<NetworkActivityStats> => {
      const { data } = await api.get('/network-activity/stats');
      return data;
    },
    refetchInterval: 15000, // Refresh every 15 seconds
  });
}

// Get live DNS queries across all devices
export function useLiveQueries(limit = 20) {
  return useQuery({
    queryKey: ['network', 'live-queries', limit],
    queryFn: async (): Promise<DNSQuery[]> => {
      const { data } = await api.get('/network-activity/queries/live', {
        params: { limit }
      });
      return data.queries;
    },
    refetchInterval: 3000, // Refresh every 3 seconds for real-time feel
  });
}

// Get bounded TLS/QUIC observations from Prisma for the technical Query Log.
export function usePrismActivity(limit = 200, enabled = true) {
  return useQuery({
    queryKey: ['network', 'prism-activity', limit],
    queryFn: async (): Promise<PrismActivityResponse> => {
      const { data } = await api.get('/network-activity/queries/prism', {
        params: { limit }
      });
      return data;
    },
    enabled,
    refetchInterval: 5000,
  });
}

