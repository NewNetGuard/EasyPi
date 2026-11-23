import api from './client'

const getApiBase = () => '/netprotection'

export interface BlocklistSource {
  id: string;
  name: string;
  url: string;
  license: string;
  format: string;
  description?: string;
  enabled: boolean;
  requires_consent?: boolean;  // GPL / NonCommercial / unknown → must show license + opt-in tick
  info_url?: string;  // project / license page for the consent dialog (NOT the raw multi-MB list)
  added_at?: string;
  last_error?: string | null;
  domain_count?: number;
}

export interface LayerStatus {
  name: string;
  success: boolean;
  domain_count: number;
  sources_count: number;
  sources_ok: string[];
  sources_failed: string[];
  generated_at: string | null;
  error?: string | null;
}

export interface EffectiveStatus {
  total_domains: number;
  verified_domains: number;
  custom_domains: number;
  sources: string[];
  licenses: string[];
  generated_at: string;
  mode: 'verified_only' | 'verified+custom';
}

export interface BlocklistStatus {
  verified: LayerStatus | null;
  custom: LayerStatus | null;
  effective: EffectiveStatus | null;
  verified_sources: BlocklistSource[];
  custom_sources: BlocklistSource[];
}

export interface GenerationProgress {
  phase: 'cleaning' | 'downloading' | 'parsing' | 'writing' | 'done' | 'error';
  current_source: string;
  sources_done: number;
  sources_total: number;
  domains_collected: number;
  progress_percent: number;
  message: string;
}

export interface GenerationResult {
  verified: LayerStatus;
  custom: LayerStatus | null;
  effective: EffectiveStatus;
  error?: string;
}

export async function getBlocklistStatus(): Promise<BlocklistStatus> {
  const response = await api.get(`${getApiBase()}/blocklists/status`);
  return response.data;
}

export async function getVerifiedSources(): Promise<BlocklistSource[]> {
  const response = await api.get(`${getApiBase()}/blocklists/verified/sources`);
  return response.data;
}

export async function setVerifiedSourceEnabled(
  sourceId: string,
  enabled: boolean,
  userConfirmedRisks: boolean = false
): Promise<{ success: boolean }> {
  const response = await api.put(
    `${getApiBase()}/blocklists/verified/sources/${sourceId}`,
    null,
    { params: { enabled, user_confirmed_risks: userConfirmedRisks } }
  );
  return response.data;
}

export async function generateBlocklists(): Promise<GenerationResult> {
  const response = await api.post(`${getApiBase()}/blocklists/generate`);
  return response.data;
}

export async function getGenerationProgress(): Promise<GenerationProgress | null> {
  const response = await api.get(`${getApiBase()}/blocklists/progress`);
  return response.data;
}

export async function getCustomSources(): Promise<BlocklistSource[]> {
  const response = await api.get(`${getApiBase()}/blocklists/custom/sources`);
  return response.data;
}

export async function addCustomSource(data: {
  url: string;
  name: string;
  format: 'hosts' | 'domains' | 'adblock';
  user_confirmed_risks: boolean;
}): Promise<{ success: boolean; source: BlocklistSource }> {
  const response = await api.post(`${getApiBase()}/blocklists/custom/add`, data);
  return response.data;
}

export async function uploadCustomBlocklistFile(
  file: File,
  name: string,
  format: 'hosts' | 'domains' | 'adblock' | 'auto',
  user_confirmed_risks: boolean
): Promise<{ success: boolean; source: BlocklistSource; entries_count: number }> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('name', name);
  formData.append('format', format);
  formData.append('user_confirmed_risks', String(user_confirmed_risks));

  const response = await api.post(`${getApiBase()}/blocklists/custom/upload`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
}

export async function removeCustomSource(sourceId: string): Promise<{ success: boolean }> {
  const response = await api.delete(`${getApiBase()}/blocklists/custom/${sourceId}`);
  return response.data;
}

export async function setCustomSourceEnabled(
  sourceId: string,
  enabled: boolean
): Promise<{ success: boolean }> {
  const response = await api.put(
    `${getApiBase()}/blocklists/custom/${sourceId}`,
    null,
    { params: { enabled } }
  );
  return response.data;
}

export interface UseCustomStatus {
  use_custom: boolean;
  custom_available: boolean;
  current_file: 'verified' | 'custom';
}

export async function getUseCustomBlocklist(): Promise<UseCustomStatus> {
  const response = await api.get(`${getApiBase()}/blocklists/use-custom`);
  return response.data;
}

export interface SetUseCustomResult {
  success: boolean;
  use_custom: boolean;
  current_file: 'verified' | 'custom';
  domains_loaded: number;
}

export async function setUseCustomBlocklist(enabled: boolean): Promise<SetUseCustomResult> {
  const response = await api.post(`${getApiBase()}/blocklists/use-custom`, null, {
    params: { enabled }
  });
  return response.data;
}
