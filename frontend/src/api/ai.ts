import api from './client';
import { getCsrfHeaders } from '../utils/csrf';

// API URL is relative since client.ts already has baseURL = '/api/v1'
const API_URL = '/ai';

// Helper to get auth headers for fetch requests (using cookies)
const getAuthHeaders = (): HeadersInit => {
  return {
    'Content-Type': 'application/json',
  };
};

// Helper for streaming fetch with auth
const getApiBaseForFetch = (): string => {
  return '/api/v1/ai';
};

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp?: string;
}

export interface ChatSession {
  session_id: string;
  title: string;
  message_count: number;
  created_at: string | null;
  last_message_at: string | null;
  model?: string | null;
}

export interface ChatRequest {
  message: string;
  session_id?: string;
  temperature?: number;
}

export interface ChatResponse {
  response: string;
  session_id: string;
}

export type DiagnosticCategory = 'device' | 'domain' | 'service' | 'unknown';

export interface DiagnosticFact {
  label: string;
  value: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface DiagnosticAction {
  action_id: string;
  label: string;
  description: string;
  style: 'primary' | 'secondary' | 'danger';
  requires_confirmation: boolean;
  confirmation_text?: string | null;
  confirmation_token?: string | null;
  parameters: Record<string, unknown>;
}

export interface DiagnosticExplainRequest {
  question: string;
  target_type?: 'auto' | 'device' | 'domain' | 'service';
  target?: string;
  route?: string;
  tab?: string;
  entity_type?: string;
  entity_id?: string;
}

export interface DiagnosticExplainResponse {
  category: DiagnosticCategory;
  target: string;
  matched: boolean;
  title: string;
  summary: string;
  confidence: 'high' | 'medium' | 'low';
  section?: string | null;
  subsection?: string | null;
  module?: string | null;
  source_status: 'ok' | 'partial' | 'unavailable' | 'stale' | 'conflict';
  source_errors: string[];
  checks_run: string[];
  facts: DiagnosticFact[];
  recommendations: string[];
  reason_chain: string[];
  actions: DiagnosticAction[];
}

export interface DiagnosticActionRequest {
  action_id: string;
  parameters?: Record<string, unknown>;
  confirmation_token: string;
  question?: string;
  target_type?: 'auto' | 'device' | 'domain' | 'service';
  target?: string;
  route?: string;
  tab?: string;
  entity_type?: string;
  entity_id?: string;
}

export interface DiagnosticActionResponse {
  action_id: string;
  success: boolean;
  message: string;
  data: Record<string, unknown>;
  follow_up?: DiagnosticExplainResponse | null;
}

export interface DiagnosticProbeResponse {
  probe_id: string;
  success: boolean;
  source_status: 'ok' | 'partial' | 'unavailable' | 'stale' | 'conflict';
  message: string;
  [key: string]: unknown;
}

export interface AIInstallStatus {
  is_installed: boolean;
  status: string;
  model_name?: string;
  model_path?: string;
  ollama_url?: string;
  installed_at?: string;
  last_health_check?: string;
  temperature?: number;
  system_prompt?: string;
}

export interface OllamaStatus {
  installed: boolean;
  service_active: boolean;
  service_status: string;
  healthy: boolean;
}

export interface OllamaActionResult extends OllamaStatus {
  success: boolean;
  error?: string;
}

export interface InstallOptions {
  model_name?: string;
  temperature?: number;
  system_prompt?: string;
}

export interface AIModelInfo {
  name: string;
  display_name: string;
  description: string;
  size_gb: number;
  tags: string[];
  recommended: boolean;
  notes?: string;
  installed?: boolean;
}

export interface AISettingsPayload {
  model_name?: string;
  temperature?: number;
  system_prompt?: string;
}

export const aiApi = {
  // Get installation status
  getStatus: async (): Promise<AIInstallStatus> => {
    const { data } = await api.get(`${API_URL}/status`);
    return data;
  },

  // Check health
  checkHealth: async (): Promise<{ status: string; message: string }> => {
    const { data } = await api.get(`${API_URL}/health`);
    return data;
  },

  getOllamaStatus: async (): Promise<OllamaStatus> => {
    const { data } = await api.get(`${API_URL}/ollama/status`);
    return data;
  },

  ensureOllama: async (
    onMessage: (message: string) => void,
    onProgress: (percent: number, message: string) => void,
    onComplete: () => void,
    onError: (error: string) => void
  ): Promise<void> => {
    const percentFromLine = (text: string): number | null => {
      const match = text.match(/(\d+(?:\.\d+)?)%/);
      if (!match) return null;
      const value = Number.parseFloat(match[1]);
      if (Number.isNaN(value)) return null;
      return Math.max(0, Math.min(100, value));
    };

    try {
      const csrfHeaders = await getCsrfHeaders();
      const response = await fetch(`${getApiBaseForFetch()}/ollama/ensure`, {
        method: 'POST',
        headers: { ...getAuthHeaders(), ...csrfHeaders },
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) {
        throw new Error('Response body is null');
      }

      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          const tail = buffer.trim();
          if (tail) {
            try {
              const data = JSON.parse(tail);
              if (data.type === 'error') {
                onError(data.message || 'Unknown error');
                return;
              }
              if (data.type === 'progress') {
                onProgress(typeof data.percent === 'number' ? data.percent : 0, data.message || '');
              } else if (data.type === 'log') {
                const pct = percentFromLine(data.message || '');
                if (pct !== null) {
                  onProgress(pct, '');
                }
                onMessage(data.message || '');
              } else if (data.message) {
                onMessage(data.message);
              }
            } catch {
              const pct = percentFromLine(tail);
              if (pct !== null) {
                onProgress(pct, '');
              }
              onMessage(tail);
            }
          }
          onComplete();
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const raw of lines) {
          const line = raw.trim();
          if (!line) continue;
          try {
            const data = JSON.parse(line);
            if (data.type === 'error') {
              onError(data.message || 'Unknown error');
              return;
            }
            if (data.type === 'progress') {
              onProgress(typeof data.percent === 'number' ? data.percent : 0, data.message || '');
            } else if (data.type === 'log') {
              const pct = percentFromLine(data.message || '');
              if (pct !== null) {
                onProgress(pct, '');
              }
              onMessage(data.message || '');
            } else if (data.message) {
              onMessage(data.message);
            }
          } catch {
            const pct = percentFromLine(line);
            if (pct !== null) {
              onProgress(pct, '');
            }
            onMessage(line);
          }
        }
      }
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unknown error');
    }
  },

  startOllama: async (): Promise<OllamaActionResult> => {
    const { data } = await api.post(`${API_URL}/ollama/start`);
    return data;
  },

  stopOllama: async (): Promise<OllamaActionResult> => {
    const { data } = await api.post(`${API_URL}/ollama/stop`);
    return data;
  },

  // Install AI (streaming)
  install: async (
    onProgress: (percent: number, message: string, stage?: string) => void,
    onModelProgress: (percent: number, downloaded: string, total: string, speed: string) => void,
    onOllamaProgress: (percent: number, message: string) => void,
    onComplete: () => void,
    onError: (error: string) => void,
    options?: InstallOptions
  ): Promise<void> => {
    try {
      const csrfHeaders = await getCsrfHeaders();
      const response = await fetch(`${getApiBaseForFetch()}/install`, {
        method: 'POST',
        headers: { ...getAuthHeaders(), ...csrfHeaders },
        credentials: 'include',
        body: JSON.stringify(options ?? {}),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) {
        throw new Error('Response body is null');
      }

      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          const tail = buffer.trim();
          if (tail) {
            try {
              const data = JSON.parse(tail);
              if (data.type === 'progress') {
                onProgress(data.percent || 0, data.message || '', data.stage);
                if (data.stage === 'model' && typeof data.percent === 'number') {
                  onModelProgress(data.percent, data.message || '', '', '');
                }
              } else if (data.type === 'model_progress') {
                onModelProgress(data.percent || 0, data.downloaded || '', data.total || '', data.speed || '');
              } else if (data.type === 'ollama_progress') {
                onOllamaProgress(data.percent || 0, data.message || '');
              } else if (data.type === 'log') {
                onProgress(-1, data.message || '');
              } else if (data.type === 'error') {
                onError(data.message || 'Unknown error');
                return;
              }
            } catch (e) {
              if (tail.includes('✓') || tail.includes('✅')) {
                onProgress(-1, tail);
              }
            }
          }
          onComplete();
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const raw of lines) {
          const line = raw.trim();
          if (!line) continue;
          try {
            const data = JSON.parse(line);

            if (data.type === 'progress') {
              onProgress(data.percent || 0, data.message || '', data.stage);
              // Fallback: if stage=model but no dedicated model_progress is emitted
              if (data.stage === 'model' && typeof data.percent === 'number') {
                onModelProgress(data.percent, data.message || '', '', '');
              }
            } else if (data.type === 'model_progress') {
              onModelProgress(
                data.percent || 0, 
                data.downloaded || '', 
                data.total || '', 
                data.speed || ''
              );
            } else if (data.type === 'ollama_progress') {
              onOllamaProgress(data.percent || 0, data.message || '');
            } else if (data.type === 'log') {
              onProgress(-1, data.message || ''); // -1 means no progress update
            } else if (data.type === 'error') {
              onError(data.message || 'Unknown error');
              return;
            }

            // Check for completion
            if (data.percent === 100 && data.stage === 'complete') {
              onComplete();
              return;
            }
          } catch (e) {
            // Not JSON, treat as plain log
            if (line.includes('✓') || line.includes('✅')) {
              onProgress(-1, line);
            }
          }
        }
      }
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unknown error');
    }
  },

  // Uninstall AI (streaming)
  uninstall: async (
    onMessage: (message: string) => void,
    onComplete: () => void,
    onError: (error: string) => void
  ): Promise<void> => {
    try {
      const csrfHeaders = await getCsrfHeaders();
      const response = await fetch(`${getApiBaseForFetch()}/uninstall`, {
        method: 'DELETE',
        headers: { ...getAuthHeaders(), ...csrfHeaders },
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) {
        throw new Error('Response body is null');
      }

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          onComplete();
          break;
        }

        const chunk = decoder.decode(value, { stream: true });
        onMessage(chunk);
      }
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unknown error');
    }
  },

  // Send message (non-streaming)
  sendMessage: async (request: ChatRequest): Promise<ChatResponse> => {
    const { data } = await api.post(`${API_URL}/ask`, request);
    return data;
  },

  explainDiagnostic: async (
    request: DiagnosticExplainRequest
  ): Promise<DiagnosticExplainResponse> => {
    const { data } = await api.post(`${API_URL}/diagnostics/explain`, request);
    return data;
  },

  executeDiagnosticAction: async (
    request: DiagnosticActionRequest
  ): Promise<DiagnosticActionResponse> => {
    const { data } = await api.post(`${API_URL}/diagnostics/action`, request);
    return data;
  },

  runDiagnosticProbe: async (
    probe_id: string,
    parameters: Record<string, unknown> = {}
  ): Promise<DiagnosticProbeResponse> => {
    const { data } = await api.post(`${API_URL}/diagnostics/probe`, { probe_id, parameters });
    return data;
  },

  // Send message (streaming)
  streamMessage: async (
    request: ChatRequest,
    onChunk: (chunk: string) => void,
    onComplete: () => void,
    onError: (error: string) => void,
    signal?: AbortSignal
  ): Promise<void> => {
    const keepaliveToken = '[[KEEPALIVE]]';
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

    try {
      const csrfHeaders = await getCsrfHeaders();
      const response = await fetch(`${getApiBaseForFetch()}/chat/stream`, {
        method: 'POST',
        headers: { ...getAuthHeaders(), ...csrfHeaders },
        credentials: 'include',
        body: JSON.stringify(request),
        signal,
      });

      if (!response.ok) {
        // Try to get error message from response body
        let errorMessage = `HTTP ${response.status}`;
        try {
          const errorText = await response.text();
          if (errorText) {
            // Try to parse JSON error
            try {
              const errorJson = JSON.parse(errorText);
              errorMessage = errorJson.detail || errorJson.message || errorMessage;
            } catch {
              // Not JSON, use text as is
              errorMessage = errorText.substring(0, 200); // Limit error length
            }
          }
        } catch {
          // Could not read body
        }
        throw new Error(errorMessage);
      }

      reader = response.body?.getReader() ?? null;
      const decoder = new TextDecoder();

      if (!reader) {
        throw new Error('Response body is null');
      }

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          onComplete();
          break;
        }

        let chunk = decoder.decode(value, { stream: true });
        if (!chunk) {
          continue;
        }

        // Remove keepalive tokens
        if (chunk.includes(keepaliveToken)) {
          chunk = chunk.split(keepaliveToken).join('');
          if (!chunk) {
            continue;
          }
        }

        // Check for error markers
        if (chunk.includes('[Error:')) {
          await reader.cancel();
          onError(chunk);
          return;
        }
        
        onChunk(chunk);
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        // User cancelled - clean up gracefully
        if (reader) {
          try {
            await reader.cancel();
          } catch {}
        }
        onComplete();
        return;
      }
      if (reader) {
        try {
          await reader.cancel();
        } catch {}
      }
      
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('Chat stream error:', errorMessage);
      onError(errorMessage);
    } finally {
      if (reader) {
        try {
          reader.releaseLock();
        } catch {}
      }
    }
  },

  // Get conversation history
  getHistory: async (sessionId: string): Promise<ChatMessage[]> => {
    const { data } = await api.get(`${API_URL}/history/${sessionId}`);
    return data;
  },

  // Clear conversation history for a session
  clearHistory: async (sessionId: string): Promise<{ deleted: number }> => {
    const { data } = await api.delete(`${API_URL}/history/${sessionId}`);
    return data;
  },

  // Clear all conversation history
  clearAllHistory: async (): Promise<{ deleted: number }> => {
    const { data } = await api.delete(`${API_URL}/history`);
    return data;
  },

  // Get all chat sessions
  getSessions: async (): Promise<ChatSession[]> => {
    const { data } = await api.get(`${API_URL}/sessions`);
    return data;
  },

  // Get curated models
  getModels: async (): Promise<AIModelInfo[]> => {
    const { data } = await api.get(`${API_URL}/models`);
    return data;
  },

  // Get list of installed models from Ollama
  getInstalledModels: async (): Promise<string[]> => {
    try {
      const { data } = await api.get(`${API_URL}/models/installed`);
      return data.models || [];
    } catch {
      return [];
    }
  },

  // Update AI config (model/settings)
  updateConfig: async (payload: AISettingsPayload): Promise<AIInstallStatus> => {
    const { data } = await api.put(`${API_URL}/config`, payload);
    return data;
  },

  // Delete model only (keep Ollama installed)
  deleteModel: async (
    onMessage: (message: string) => void,
    onComplete: () => void,
    onError: (error: string) => void
  ): Promise<void> => {
    try {
      const csrfHeaders = await getCsrfHeaders();
      const response = await fetch(`${getApiBaseForFetch()}/model`, {
        method: 'DELETE',
        headers: { ...getAuthHeaders(), ...csrfHeaders },
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) {
        throw new Error('Response body is null');
      }

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          onComplete();
          break;
        }

        const chunk = decoder.decode(value, { stream: true });
        onMessage(chunk);
      }
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unknown error');
    }
  },

  // Cancel ongoing installation
  cancelInstall: async (): Promise<{ success: boolean; message: string }> => {
    const { data } = await api.post(`${API_URL}/install/cancel`);
    return data;
  },
};
