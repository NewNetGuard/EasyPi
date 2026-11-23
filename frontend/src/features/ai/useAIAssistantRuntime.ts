import { useCallback, useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { aiApi, type OllamaStatus } from '../../api/ai';
import { formatEta, OLLAMA_POLL_DURATION, OLLAMA_POLL_INTERVAL, DEFAULT_SYSTEM_PROMPT } from './aiAssistantUtils';

interface UseAIAssistantRuntimeParams {
  selectedModel: string;
  temperatureValue: number;
  systemPrompt: string;
  installedModels: string[];
  abortActiveStream: () => void;
  checkStatus: () => Promise<void>;
  setError: (value: string | null) => void;
  setIsInstalled: (value: boolean) => void;
  setIsHealthy: (value: boolean) => void;
  setInstalledModels: (value: string[]) => void;
  setModelPath: (value: string | null) => void;
  setTemperatureValue: (value: number) => void;
  setSystemPrompt: (value: string) => void;
  onInstallComplete: () => void;
}

interface UseAIAssistantRuntimeResult {
  ollamaStatus: OllamaStatus | null;
  ollamaWorking: boolean;
  showOllamaModal: boolean;
  setShowOllamaModal: (value: boolean) => void;
  ollamaLogs: string[];
  ollamaProgress: number;
  ollamaEta: string | null;
  ollamaFinalizing: boolean;
  showInstallModal: boolean;
  setShowInstallModal: (value: boolean) => void;
  installLogs: string[];
  installing: boolean;
  installProgress: number;
  installStage: string;
  modelDownloadProgress: number;
  modelDownloadInfo: { downloaded: string; total: string; speed: string };
  showUninstallModal: boolean;
  setShowUninstallModal: (value: boolean) => void;
  uninstallLogs: string[];
  uninstalling: boolean;
  showDeleteModelModal: boolean;
  setShowDeleteModelModal: (value: boolean) => void;
  deleteModelLogs: string[];
  deletingModel: boolean;
  savingSettings: boolean;
  setSavingSettings: (value: boolean) => void;
  refreshOllamaStatus: () => Promise<void>;
  handleDeleteModel: () => Promise<void>;
  handleInstall: () => Promise<void>;
  handleCancelInstall: () => Promise<void>;
  handleSaveSettings: (options: {
    setSelectedModel: (value: string) => void;
    closeSettings: () => void;
  }) => Promise<void>;
  handleUninstall: () => Promise<void>;
  handleEnsureOllama: () => Promise<void>;
  handleToggleOllama: () => Promise<void>;
}

export function useAIAssistantRuntime({
  selectedModel,
  temperatureValue,
  systemPrompt,
  installedModels,
  abortActiveStream,
  checkStatus,
  setError,
  setIsInstalled,
  setIsHealthy,
  setInstalledModels,
  setModelPath,
  setTemperatureValue,
  setSystemPrompt,
  onInstallComplete,
}: UseAIAssistantRuntimeParams): UseAIAssistantRuntimeResult {
  const [ollamaStatus, setOllamaStatus] = useState<OllamaStatus | null>(null);
  const [ollamaWorking, setOllamaWorking] = useState(false);
  const [showOllamaModal, setShowOllamaModal] = useState(false);
  const [ollamaLogs, setOllamaLogs] = useState<string[]>([]);
  const [ollamaProgress, setOllamaProgress] = useState(0);
  const [ollamaEta, setOllamaEta] = useState<string | null>(null);
  const [ollamaFinalizing, setOllamaFinalizing] = useState(false);

  const [showInstallModal, setShowInstallModal] = useState(false);
  const [installLogs, setInstallLogs] = useState<string[]>([]);
  const [installing, setInstalling] = useState(false);
  const [installProgress, setInstallProgress] = useState(0);
  const [installStage, setInstallStage] = useState('init');
  const [modelDownloadProgress, setModelDownloadProgress] = useState(0);
  const [modelDownloadInfo, setModelDownloadInfo] = useState({ downloaded: '', total: '', speed: '' });

  const [showUninstallModal, setShowUninstallModal] = useState(false);
  const [uninstallLogs, setUninstallLogs] = useState<string[]>([]);
  const [uninstalling, setUninstalling] = useState(false);

  const [showDeleteModelModal, setShowDeleteModelModal] = useState(false);
  const [deleteModelLogs, setDeleteModelLogs] = useState<string[]>([]);
  const [deletingModel, setDeletingModel] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);

  const ollamaPollRef = useRef<number | null>(null);
  const ollamaPollStartedAtRef = useRef(0);
  const ollamaStartRef = useRef<number | null>(null);
  const ollamaLastProgressRef = useRef(0);
  const ollamaLastProgressAtRef = useRef<number | null>(null);
  const ollamaRateRef = useRef<number | null>(null);
  const ollamaFinalizingRef = useRef(false);

  const updateOllamaEta = useCallback((percent: number) => {
    if (percent <= 0 || percent >= 100) {
      setOllamaEta(null);
      return;
    }

    const now = Date.now();
    if (!ollamaStartRef.current || percent < ollamaLastProgressRef.current) {
      ollamaStartRef.current = now;
      ollamaLastProgressRef.current = percent;
      ollamaLastProgressAtRef.current = now;
      ollamaRateRef.current = null;
      setOllamaEta(null);
      return;
    }

    if (percent === ollamaLastProgressRef.current) {
      return;
    }

    const lastAt = ollamaLastProgressAtRef.current ?? now;
    const deltaT = (now - lastAt) / 1000;
    const deltaP = percent - ollamaLastProgressRef.current;
    if (deltaT <= 0 || deltaP <= 0) {
      return;
    }

    const instantRate = deltaP / deltaT;
    const prevRate = ollamaRateRef.current;
    const smoothedRate = prevRate ? (prevRate * 0.7 + instantRate * 0.3) : instantRate;
    ollamaRateRef.current = smoothedRate;

    if (percent < 3 || smoothedRate <= 0) {
      setOllamaEta(null);
    } else {
      const remaining = Math.max(0, 100 - percent);
      setOllamaEta(formatEta(remaining / smoothedRate));
    }

    ollamaLastProgressRef.current = percent;
    ollamaLastProgressAtRef.current = now;
  }, []);

  const refreshOllamaStatus = useCallback(async () => {
    try {
      const status = await aiApi.getOllamaStatus();
      setOllamaStatus(status);
    } catch (err) {
      console.error('Failed to fetch Ollama status:', err);
      setOllamaStatus(null);
    }
  }, []);

  const stopOllamaPoll = useCallback(() => {
    if (ollamaPollRef.current) {
      clearInterval(ollamaPollRef.current);
      ollamaPollRef.current = null;
    }
  }, []);

  const startOllamaPoll = useCallback(() => {
    stopOllamaPoll();
    ollamaPollStartedAtRef.current = Date.now();
    void refreshOllamaStatus();
    void checkStatus();

    ollamaPollRef.current = window.setInterval(() => {
      void refreshOllamaStatus();
      void checkStatus();
      if (Date.now() - ollamaPollStartedAtRef.current > OLLAMA_POLL_DURATION) {
        stopOllamaPoll();
      }
    }, OLLAMA_POLL_INTERVAL);
  }, [checkStatus, refreshOllamaStatus, stopOllamaPoll]);

  useEffect(() => {
    return () => stopOllamaPoll();
  }, [stopOllamaPoll]);

  useEffect(() => {
    void refreshOllamaStatus();
  }, [refreshOllamaStatus]);

  useEffect(() => {
    if (!ollamaWorking || !ollamaStatus || !ollamaStatus.installed) {
      return;
    }

    setOllamaWorking(false);
    setOllamaFinalizing(false);
    setOllamaProgress(100);
    setOllamaEta(null);
    ollamaFinalizingRef.current = false;

    if (showOllamaModal) {
      setShowOllamaModal(false);
    }

    if (ollamaStatus.service_active || ollamaStatus.healthy) {
      setOllamaLogs((prev) => [...prev, 'Ollama is ready']);
      toast.success('Ollama ready');
    } else {
      setOllamaLogs((prev) => [...prev, 'Ollama installed (service inactive)']);
      toast.success('Ollama installed');
    }
  }, [ollamaStatus, ollamaWorking, showOllamaModal]);

  const handleDeleteModel = useCallback(async () => {
    setShowDeleteModelModal(true);
    setDeletingModel(true);
    setDeleteModelLogs([]);
    setError(null);

    await aiApi.deleteModel(
      (message) => setDeleteModelLogs((prev) => [...prev, message]),
      () => {
        setDeletingModel(false);
        setIsInstalled(false);
        setIsHealthy(false);
        setModelPath(null);
        setDeleteModelLogs((prev) => [...prev, 'Deletion complete']);
        toast.success('Model deleted');
        setTimeout(() => {
          setShowDeleteModelModal(false);
          void checkStatus();
        }, 2000);
      },
      (err) => {
        setDeletingModel(false);
        setError(err);
        setDeleteModelLogs((prev) => [...prev, err]);
        toast.error('Deletion error');
      },
    );
  }, [checkStatus, setError, setIsHealthy, setIsInstalled, setModelPath]);

  const handleInstall = useCallback(async () => {
    setShowInstallModal(true);
    setInstalling(true);
    setInstallLogs([]);
    setInstallProgress(0);
    setInstallStage('init');
    setModelDownloadProgress(0);
    setModelDownloadInfo({ downloaded: '', total: '', speed: '' });
    setOllamaProgress(0);
    setError(null);

    await aiApi.install(
      (percent, message, stage) => {
        if (percent >= 0) {
          setInstallProgress(percent);
        }
        if (message && !message.includes('%')) {
          setInstallLogs((prev) => [...prev.slice(-50), message]);
        }
        if (stage) {
          setInstallStage(stage);
        }
      },
      (modelPercent, downloaded, total, speed) => {
        setModelDownloadProgress(modelPercent);
        setModelDownloadInfo({ downloaded, total, speed });
      },
      (ollamaPercent) => setOllamaProgress(ollamaPercent),
      () => {
        setInstalling(false);
        setIsInstalled(true);
        setIsHealthy(true);
        setInstallProgress(100);
        setInstallStage('complete');
        setModelDownloadProgress(100);
        toast.success('AI Chat installed');
        aiApi.getInstalledModels().then(setInstalledModels).catch(() => {});
        setTimeout(() => {
          setShowInstallModal(false);
          onInstallComplete();
        }, 2000);
      },
      (err) => {
        setInstalling(false);
        setError(err);
        setInstallLogs((prev) => [...prev, err]);
        toast.error('Installation error');
      },
      { model_name: selectedModel, temperature: temperatureValue, system_prompt: systemPrompt },
    );
  }, [
    onInstallComplete,
    selectedModel,
    setError,
    setInstalledModels,
    setIsHealthy,
    setIsInstalled,
    systemPrompt,
    temperatureValue,
  ]);

  const handleCancelInstall = useCallback(async () => {
    if (!confirm('Cancel installation? All downloaded files will be deleted.')) {
      return;
    }

    try {
      setInstallLogs((prev) => [...prev, 'Cancelling installation...']);
      const result = await aiApi.cancelInstall();

      if (result.success) {
        setInstalling(false);
        setInstallProgress(0);
        setInstallStage('init');
        setModelDownloadProgress(0);
        setShowInstallModal(false);
        toast.success('Installation cancelled');
        const installed = await aiApi.getInstalledModels();
        setInstalledModels(installed);
      } else {
        toast.error(result.message || 'Failed to cancel');
      }
    } catch (err) {
      toast.error('Failed to cancel installation');
      console.error(err);
    }
  }, [setInstalledModels]);

  const handleSaveSettings = useCallback(async ({
    setSelectedModel,
    closeSettings,
  }: {
    setSelectedModel: (value: string) => void;
    closeSettings: () => void;
  }) => {
    setSavingSettings(true);
    abortActiveStream();
    try {
      const updated = await aiApi.updateConfig({
        model_name: selectedModel,
        temperature: temperatureValue,
        system_prompt: systemPrompt,
      });
      const nextModel = updated.model_name || selectedModel;
      const installed = await aiApi.getInstalledModels().catch(() => installedModels);
      const selectedInstalled = installed.some(
        (model) => model === nextModel || model === `${nextModel}:latest`,
      );
      setInstalledModels(installed);
      setIsInstalled(selectedInstalled);
      setIsHealthy(updated.status === 'ready' && selectedInstalled);
      setSelectedModel(nextModel);
      setTemperatureValue(typeof updated.temperature === 'number' ? updated.temperature : temperatureValue);
      setSystemPrompt(updated.system_prompt || DEFAULT_SYSTEM_PROMPT);
      toast.success('Settings saved');
      closeSettings();
    } catch {
      toast.error('Failed to save settings');
    } finally {
      setSavingSettings(false);
    }
  }, [
    abortActiveStream,
    installedModels,
    selectedModel,
    setInstalledModels,
    setIsHealthy,
    setIsInstalled,
    setSystemPrompt,
    setTemperatureValue,
    systemPrompt,
    temperatureValue,
  ]);

  const handleUninstall = useCallback(async () => {
    setShowUninstallModal(true);
    setUninstalling(true);
    setUninstallLogs([]);
    setError(null);

    await aiApi.uninstall(
      (message) => setUninstallLogs((prev) => [...prev, message]),
      () => {
        setUninstalling(false);
        setIsInstalled(false);
        setIsHealthy(false);
        setUninstallLogs((prev) => [...prev, 'Ollama uninstall complete']);
        toast.success('Ollama uninstalled');
        setTimeout(() => {
          setShowUninstallModal(false);
          void checkStatus();
        }, 2000);
      },
      (err) => {
        setUninstalling(false);
        setError(err);
        setUninstallLogs((prev) => [...prev, `Error: ${err}`]);
        toast.error('Uninstall error');
      },
    );
  }, [checkStatus, setError, setIsHealthy, setIsInstalled]);

  const handleEnsureOllama = useCallback(async () => {
    setShowOllamaModal(true);
    setOllamaWorking(true);
    setOllamaLogs([]);
    setOllamaProgress(0);
    setOllamaEta(null);
    setOllamaFinalizing(false);
    ollamaStartRef.current = Date.now();
    ollamaLastProgressRef.current = 0;
    ollamaLastProgressAtRef.current = null;
    ollamaRateRef.current = null;
    ollamaFinalizingRef.current = false;
    setError(null);
    startOllamaPoll();

    await aiApi.ensureOllama(
      (message) => setOllamaLogs((prev) => [...prev, message]),
      (percent, message) => {
        if (typeof percent === 'number') {
          const clampedRaw = Math.max(0, Math.min(100, percent));
          if (clampedRaw >= 100 && !ollamaFinalizingRef.current) {
            ollamaFinalizingRef.current = true;
            setOllamaFinalizing(true);
            setOllamaLogs((prev) => [...prev, 'Download complete. Finalizing installation...']);
          }
          const displayPercent = ollamaWorking && clampedRaw >= 100 ? 99 : clampedRaw;
          setOllamaProgress(displayPercent);
          if (displayPercent >= 99) {
            setOllamaEta(null);
          } else {
            updateOllamaEta(displayPercent);
          }
        }
        if (message) {
          setOllamaLogs((prev) => [...prev, message]);
        }
      },
      async () => {
        setOllamaWorking(false);
        setOllamaProgress(100);
        setOllamaEta(null);
        setOllamaFinalizing(false);
        ollamaFinalizingRef.current = false;
        await refreshOllamaStatus();
        await checkStatus();
        startOllamaPoll();
        setOllamaLogs((prev) => [...prev, 'Ollama is ready']);
        toast.success('Ollama ready');
      },
      (err) => {
        const errText = String(err ?? '');
        const errLower = errText.toLowerCase();
        const isNetwork = ['network', 'fetch', 'timeout', 'connection'].some((term) => errLower.includes(term));

        setOllamaWorking(false);
        setOllamaEta(null);
        setOllamaFinalizing(false);
        ollamaFinalizingRef.current = false;

        if (isNetwork) {
          setError(null);
          setOllamaLogs((prev) => [...prev, 'Connection lost. Install may continue in background...']);
          toast('Installation still running. Checking status...', { icon: 'i' });
          void (async () => {
            try {
              const status = await aiApi.getOllamaStatus();
              setOllamaStatus(status);
              if (status?.installed) {
                setOllamaProgress(100);
                setOllamaLogs((prev) => [...prev, 'Ollama installed']);
                toast.success('Ollama installed');
              }
            } catch {
            } finally {
              startOllamaPoll();
            }
          })();
          return;
        }

        setError(errText);
        setOllamaLogs((prev) => [...prev, errText]);
        toast.error('Ollama install failed');
      },
    );
  }, [checkStatus, ollamaWorking, refreshOllamaStatus, setError, startOllamaPoll, updateOllamaEta]);

  const handleToggleOllama = useCallback(async () => {
    if (!ollamaStatus?.installed) {
      toast.error('Ollama is not installed');
      return;
    }

    setOllamaWorking(true);
    setError(null);
    try {
      if (ollamaStatus.service_active) {
        const result = await aiApi.stopOllama();
        if (!result.success && result.error) {
          throw new Error(result.error);
        }
        toast.success('Ollama stopped');
      } else {
        const result = await aiApi.startOllama();
        if (!result.success && result.error) {
          throw new Error(result.error);
        }
        toast.success('Ollama started');
      }

      await refreshOllamaStatus();
      await checkStatus();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to manage Ollama';
      setError(message);
      toast.error(message);
    } finally {
      setOllamaWorking(false);
    }
  }, [checkStatus, ollamaStatus, refreshOllamaStatus, setError]);

  return {
    ollamaStatus,
    ollamaWorking,
    showOllamaModal,
    setShowOllamaModal,
    ollamaLogs,
    ollamaProgress,
    ollamaEta,
    ollamaFinalizing,
    showInstallModal,
    setShowInstallModal,
    installLogs,
    installing,
    installProgress,
    installStage,
    modelDownloadProgress,
    modelDownloadInfo,
    showUninstallModal,
    setShowUninstallModal,
    uninstallLogs,
    uninstalling,
    showDeleteModelModal,
    setShowDeleteModelModal,
    deleteModelLogs,
    deletingModel,
    savingSettings,
    setSavingSettings,
    refreshOllamaStatus,
    handleDeleteModel,
    handleInstall,
    handleCancelInstall,
    handleSaveSettings,
    handleUninstall,
    handleEnsureOllama,
    handleToggleOllama,
  };
}
