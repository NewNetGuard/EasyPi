import api from './client';
import type {
  BlocklistInfo,
  DashboardStats,
  Device,
  NetProtectionConfig,
  NetProtectionStatus,
  ShieldProfileId,
  ShieldProfilesResponse,
  ThreatStats,
} from './netProtectionTypes';

const getApiBase = () => '/netprotection';

export async function getNetProtectionStatus(): Promise<{ configured: boolean; available: boolean }> {
  const response = await api.get(`${getApiBase()}/status`);
  return response.data;
}

export async function getNetProtectionFullStatus(): Promise<NetProtectionStatus> {
  const response = await api.get(`${getApiBase()}/status/full`);
  return response.data;
}

export async function getNetProtectionConfig(): Promise<NetProtectionConfig> {
  const response = await api.get(`${getApiBase()}/config`);
  return response.data;
}

export async function updateNetProtectionConfig(config: Partial<NetProtectionConfig>): Promise<NetProtectionConfig> {
  const response = await api.put(`${getApiBase()}/config`, config);
  return response.data;
}

export async function enableProtection(): Promise<{ success: boolean; message: string }> {
  const response = await api.post(`${getApiBase()}/protection/enable`);
  return response.data;
}

export async function disableProtection(): Promise<{ success: boolean; message: string }> {
  const response = await api.post(`${getApiBase()}/protection/disable`);
  return response.data;
}

export async function getNetProtectionDashboard(): Promise<DashboardStats> {
  const response = await api.get(`${getApiBase()}/dashboard`);
  return response.data;
}

export async function getNetProtectionStats(period: '24h' | '7d' = '24h'): Promise<{
  totalQueries: number;
  blocked: number;
  blockRate: number;
  queryTrend: Array<{ time: string; queries: number; blocked: number; allowed: number }>;
  blockTrend: Array<{ time: string; blocked: number; allowed: number }>;
  topBlocked: Array<{ domain: string; hits: number }>;
  topClients: Array<{ client: string; queries: number }>;
  topQueried: Array<{ domain: string; queries: number }>;
  avgResponseTime: number | null;
}> {
  const response = await api.get(`${getApiBase()}/stats`, { params: { period } });
  return response.data;
}

export async function getShieldProfiles(): Promise<ShieldProfilesResponse> {
  const response = await api.get(`${getApiBase()}/shields`);
  return response.data;
}

export async function setShieldProfile(profileId: ShieldProfileId): Promise<{ success: boolean; profile: string }> {
  const response = await api.post(`${getApiBase()}/shields/set`, { profile_id: profileId });
  return response.data;
}

export async function getDevices(): Promise<Device[]> {
  const response = await api.get(`${getApiBase()}/devices`);
  return response.data;
}

export async function updateDevice(deviceId: string, updates: Partial<Device>): Promise<Device> {
  const response = await api.put(`${getApiBase()}/devices/${deviceId}`, updates);
  return response.data;
}

export async function setDeviceShieldProfile(deviceId: string, profileId: ShieldProfileId): Promise<Device> {
  const response = await api.put(`${getApiBase()}/devices/${deviceId}/shield`, { profile_id: profileId });
  return response.data;
}

export async function getThreatStats(): Promise<ThreatStats> {
  const response = await api.get(`${getApiBase()}/threat-intel/stats`);
  return response.data;
}

export async function getBlocklistInfo(): Promise<BlocklistInfo> {
  const response = await api.get(`${getApiBase()}/threat-intel/blocklist`);
  return response.data;
}

export async function generateBlocklist(): Promise<{ success: boolean; domain_count: number; path: string }> {
  const response = await api.post(`${getApiBase()}/threat-intel/blocklist/generate`);
  return response.data;
}

export async function cleanupExpiredThreats(): Promise<{ removed: number; remaining: number }> {
  const response = await api.post(`${getApiBase()}/threat-intel/cleanup`);
  return response.data;
}

export async function getNetProtectionMetrics(): Promise<{
  queries_total: number;
  blocked_total: number;
  cache_hits: number;
  avg_latency_ms: number;
  uptime_seconds: number;
}> {
  const response = await api.get(`${getApiBase()}/metrics`);
  return response.data;
}
