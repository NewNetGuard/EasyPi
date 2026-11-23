import { useCallback } from 'react';
import toast from 'react-hot-toast';
import { aiApi, type AIModelInfo, type OllamaStatus } from '../../api/ai';

interface UseAIAssistantModelSelectionParams {
  models: AIModelInfo[];
  selectedModel: string;
  setSelectedModel: (value: string) => void;
  installedModels: string[];
  isModelInstalled: (modelName: string) => boolean;
  ollamaStatus: OllamaStatus | null;
  ollamaWorking: boolean;
  installing: boolean;
  uninstalling: boolean;
  temperatureValue: number;
  systemPrompt: string;
  checkStatus: () => Promise<void>;
  abortActiveStream: () => void;
  onSwitchToChat: () => void;
}

interface UseAIAssistantModelSelectionResult {
  currentModelInfo: AIModelInfo;
  hasInstalledModels: boolean;
  selectedModelInstalled: boolean;
  ollamaInstalled: boolean;
  ollamaRunning: boolean;
  ollamaHealthy: boolean;
  ollamaStatusReady: boolean;
  blockOllamaUninstall: boolean;
  handleModelSelection: (model: AIModelInfo, installed: boolean) => Promise<void>;
}

export function useAIAssistantModelSelection({
  models,
  selectedModel,
  setSelectedModel,
  installedModels,
  isModelInstalled,
  ollamaStatus,
  ollamaWorking,
  installing,
  uninstalling,
  temperatureValue,
  systemPrompt,
  checkStatus,
  abortActiveStream,
  onSwitchToChat,
}: UseAIAssistantModelSelectionParams): UseAIAssistantModelSelectionResult {
  const currentModelInfo = models.find((model) => model.name === selectedModel) || models[0];
  const hasInstalledModels = installedModels.length > 0;
  const selectedModelInstalled = isModelInstalled(selectedModel);
  const ollamaInstalled = Boolean(ollamaStatus?.installed);
  const ollamaRunning = Boolean(ollamaStatus?.service_active);
  const ollamaHealthy = Boolean(ollamaStatus?.healthy);
  const ollamaStatusReady = ollamaStatus !== null;
  const blockOllamaUninstall = ollamaWorking || installing || uninstalling;

  const handleModelSelection = useCallback(async (model: AIModelInfo, installed: boolean) => {
    abortActiveStream();

    if (installed) {
      try {
        await aiApi.updateConfig({
          model_name: model.name,
          temperature: temperatureValue,
          system_prompt: systemPrompt,
        });

        setSelectedModel(model.name);
        await checkStatus();
        onSwitchToChat();
        toast.success(`Selected model: ${model.display_name}`);
      } catch {
        toast.error('Failed to switch model');
      }
      return;
    }

    setSelectedModel(model.name);
  }, [
    abortActiveStream,
    checkStatus,
    onSwitchToChat,
    setSelectedModel,
    systemPrompt,
    temperatureValue,
  ]);

  return {
    currentModelInfo,
    hasInstalledModels,
    selectedModelInstalled,
    ollamaInstalled,
    ollamaRunning,
    ollamaHealthy,
    ollamaStatusReady,
    blockOllamaUninstall,
    handleModelSelection,
  };
}
