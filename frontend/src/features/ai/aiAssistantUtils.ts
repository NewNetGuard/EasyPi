import type { AIModelInfo } from '../../api/ai';

export const DEFAULT_SYSTEM_PROMPT = "You are EasyPi's local assistant. Be accurate, concise, and helpful.";

export const FALLBACK_MODELS: AIModelInfo[] = [
  {
    name: 'qwen2.5:3b',
    display_name: 'Qwen 2.5 3B',
    description: 'Fast local model balanced for Raspberry Pi.',
    size_gb: 1.9,
    tags: ['raspberry-pi', 'balanced'],
    recommended: true,
    notes: 'Recommended EasyPi default for responsive local chat.',
  },
  {
    name: 'llama3.1:8b',
    display_name: 'Llama 3.1 8B',
    description: 'Meta Llama with high speed and quality.',
    size_gb: 4.3,
    tags: ['speed'],
    recommended: true,
    notes: 'Faster than Qwen, good for diagnostics.',
  },
  {
    name: 'qwen2.5:14b',
    display_name: 'Qwen 2.5 14B',
    description: 'Higher quality but requires more memory.',
    size_gb: 8.6,
    tags: ['quality'],
    recommended: false,
    notes: 'Requires 24+ GB RAM or swap file.',
  },
  {
    name: 'deepseek-r1:14b',
    display_name: 'DeepSeek-R1 14B',
    description: 'Model focused on reasoning and step-by-step execution.',
    size_gb: 9.2,
    tags: ['reasoning'],
    recommended: false,
    notes: 'Detailed responses, useful for diagnostics.',
  },
];

export const sanitizeModelName = (modelName: string) =>
  modelName.replace(/[^a-z0-9]+/gi, '_').toLowerCase();

export const sessionStorageKey = (modelName: string) => `ai_current_session:${modelName}`;

export const buildSessionId = (modelName: string) => `session_${sanitizeModelName(modelName)}_${Date.now()}`;

export const OLLAMA_POLL_INTERVAL = 3000;
export const OLLAMA_POLL_DURATION = 60000;

export const formatEta = (seconds: number) => {
  if (!Number.isFinite(seconds) || seconds <= 0) return 'a few seconds';
  const total = Math.round(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
};
