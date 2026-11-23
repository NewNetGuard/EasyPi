import { useCallback, useEffect, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { aiApi, type AIModelInfo, type OllamaStatus } from '../../api/ai';
import { DEFAULT_SYSTEM_PROMPT, FALLBACK_MODELS } from './aiAssistantUtils';

interface UseAIAssistantStatusParams {
  selectedModel: string;
  setSelectedModel: Dispatch<SetStateAction<string>>;
}

interface UseAIAssistantStatusResult {
  error: string | null;
  setError: Dispatch<SetStateAction<string | null>>;
  isHealthy: boolean;
  setIsHealthy: Dispatch<SetStateAction<boolean>>;
  isInstalled: boolean;
  setIsInstalled: Dispatch<SetStateAction<boolean>>;
  installedModels: string[];
  setInstalledModels: Dispatch<SetStateAction<string[]>>;
  models: AIModelInfo[];
  modelPath: string | null;
  setModelPath: Dispatch<SetStateAction<string | null>>;
  systemPrompt: string;
  setSystemPrompt: Dispatch<SetStateAction<string>>;
  temperatureValue: number;
  setTemperatureValue: Dispatch<SetStateAction<number>>;
  checkStatus: () => Promise<void>;
  isModelInstalled: (modelName: string) => boolean;
}

export function useAIAssistantStatus({
  selectedModel,
  setSelectedModel,
}: UseAIAssistantStatusParams): UseAIAssistantStatusResult {
  const [error, setError] = useState<string | null>(null);
  const [isHealthy, setIsHealthy] = useState(false);
  const [isInstalled, setIsInstalled] = useState(false);
  const [modelPath, setModelPath] = useState<string | null>(null);
  const [models, setModels] = useState<AIModelInfo[]>(FALLBACK_MODELS);
  const [installedModels, setInstalledModels] = useState<string[]>([]);
  const [temperatureValue, setTemperatureValue] = useState(0.1);
  const [systemPrompt, setSystemPrompt] = useState(DEFAULT_SYSTEM_PROMPT);
  const [, setModelsLoading] = useState(true);

  const checkStatus = useCallback(async () => {
    try {
      const [status, installed, ollama] = await Promise.all([
        aiApi.getStatus(),
        aiApi.getInstalledModels(),
        aiApi.getOllamaStatus().catch(() => null),
      ]);
      const ollamaStatusValue = ollama as OllamaStatus | null;
      const selected = status.model_name || selectedModel;
      const selectedInstalled = installed.some(
        (model) => model === selected || model === `${selected}:latest`,
      );
      const hasModels = installed.length > 0;
      const healthy =
        (status.status === 'ready' && selectedInstalled) || Boolean(ollamaStatusValue?.healthy);

      setSelectedModel(selected);
      setInstalledModels(installed);
      setIsInstalled(selectedInstalled);
      setIsHealthy(healthy);
      setTemperatureValue(typeof status.temperature === 'number' ? status.temperature : 0.1);
      setSystemPrompt(status.system_prompt || DEFAULT_SYSTEM_PROMPT);
      setModelPath(status.model_path || null);

      if (hasModels && !healthy) {
        setError('Service installed but not responding');
      } else {
        setError(null);
      }
    } catch (err) {
      console.error('Failed to check AI status:', err);
    }
  }, [selectedModel, setSelectedModel]);

  const isModelInstalled = useCallback((modelName: string) => {
    return installedModels.some((model) => model === modelName || model === `${modelName}:latest`);
  }, [installedModels]);

  useEffect(() => {
    void checkStatus();
  }, [checkStatus]);

  useEffect(() => {
    const fetchModels = async () => {
      try {
        const [data, installed] = await Promise.all([
          aiApi.getModels(),
          aiApi.getInstalledModels(),
        ]);
        setModels(data);
        setInstalledModels(installed);
        setSelectedModel((previous) => (
          data.some((model) => model.name === previous) ? previous : data[0]?.name || previous
        ));
      } catch {
        setModels(FALLBACK_MODELS);
      } finally {
        setModelsLoading(false);
      }
    };

    void fetchModels();
  }, [setSelectedModel]);

  return {
    error,
    setError,
    isHealthy,
    setIsHealthy,
    isInstalled,
    setIsInstalled,
    installedModels,
    setInstalledModels,
    models,
    modelPath,
    setModelPath,
    systemPrompt,
    setSystemPrompt,
    temperatureValue,
    setTemperatureValue,
    checkStatus,
    isModelInstalled,
  };
}
