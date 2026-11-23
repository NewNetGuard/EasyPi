import api from './client';
import type { QueryLogStats, Verdict, VerdictListResponse, VerdictType } from './netProtectionTypes';

const getApiBase = () => '/netprotection';

export async function getVerdicts(params?: {
  offset?: number;
  limit?: number;
  search?: string;
  verdict_type?: VerdictType;
  include_system?: boolean;
}): Promise<VerdictListResponse> {
  const response = await api.get(`${getApiBase()}/verdicts`, { params });
  return response.data;
}

export async function getQueryLogStats(): Promise<QueryLogStats> {
  const response = await api.get(`${getApiBase()}/verdicts/stats`);
  return response.data;
}

export async function clearQueryLog(olderThanDays: number = 0): Promise<{ cleared: number; message: string }> {
  const response = await api.delete(`${getApiBase()}/verdicts`, {
    params: { older_than_days: olderThanDays }
  });
  return response.data;
}

export async function getVerdictDetail(flowId: string): Promise<Verdict> {
  const response = await api.get(`${getApiBase()}/verdicts/${flowId}`);
  return response.data;
}
