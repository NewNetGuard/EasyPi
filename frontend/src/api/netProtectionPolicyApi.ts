import api from './client';
import type { Matcher } from './netProtectionTypes';

const getApiBase = () => '/netprotection';

export async function getMatchers(): Promise<Matcher[]> {
  const response = await api.get(`${getApiBase()}/matchers`);
  return response.data;
}

export async function createMatcher(matcher: Omit<Matcher, 'id' | 'rules_count' | 'last_updated' | 'created_at'>): Promise<Matcher> {
  const response = await api.post(`${getApiBase()}/matchers`, matcher);
  return response.data;
}

export async function updateMatcher(matcherId: string, updates: Partial<Matcher>): Promise<Matcher> {
  const response = await api.put(`${getApiBase()}/matchers/${matcherId}`, updates);
  return response.data;
}

export async function deleteMatcher(matcherId: string): Promise<{ success: boolean }> {
  const response = await api.delete(`${getApiBase()}/matchers/${matcherId}`);
  return response.data;
}

export async function getWhitelist(): Promise<{ domains: string[] }> {
  const response = await api.get(`${getApiBase()}/whitelist`);
  return response.data;
}

export async function addToWhitelist(domain: string, comment?: string, type: string = 'exact'): Promise<{ success: boolean; domain: string }> {
  const response = await api.post(`${getApiBase()}/whitelist`, { domain, type, comment: comment ?? '' });
  return response.data;
}

export async function removeFromWhitelist(domain: string): Promise<{ success: boolean; domain: string }> {
  const response = await api.delete(`${getApiBase()}/whitelist/${encodeURIComponent(domain)}`);
  return response.data;
}

export async function getBlacklist(): Promise<{ domains: string[] }> {
  const response = await api.get(`${getApiBase()}/blacklist`);
  return response.data;
}

export async function addToBlacklist(domain: string, comment?: string, type: string = 'exact'): Promise<{ success: boolean; domain: string }> {
  const response = await api.post(`${getApiBase()}/blacklist`, { domain, type, comment: comment ?? '' });
  return response.data;
}

export async function removeFromBlacklist(domain: string): Promise<{ success: boolean; domain: string }> {
  const response = await api.delete(`${getApiBase()}/blacklist/${encodeURIComponent(domain)}`);
  return response.data;
}
