import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { CSSProperties, KeyboardEvent } from 'react'
import { AIAssistantBanners } from '../features/ai/AIAssistantBanners'
import { AIAssistantHeader } from '../features/ai/AIAssistantHeader'
import { AIAssistantComposer } from '../features/ai/AIAssistantComposer'
import { AIAssistantDeleteModelModal } from '../features/ai/AIAssistantDeleteModelModal'
import { AIAssistantMessages } from '../features/ai/AIAssistantMessages'
import { AIAssistantModelSelection } from '../features/ai/AIAssistantModelSelection'
import { AIAssistantSettingsDrawer } from '../features/ai/AIAssistantSettingsDrawer'
import { AIAssistantSessionsPanel } from '../features/ai/AIAssistantSessionsPanel'
import { AIAssistantUninstallModal } from '../features/ai/AIAssistantUninstallModal'
import { useAIAssistantChat } from '../features/ai/useAIAssistantChat'
import { useAIAssistantDarkMode } from '../features/ai/useAIAssistantDarkMode'
import { useAIAssistantModelSelection } from '../features/ai/useAIAssistantModelSelection'
import { useAIAssistantRuntime } from '../features/ai/useAIAssistantRuntime'
import { useAIAssistantSessions } from '../features/ai/useAIAssistantSessions'
import { useAIAssistantStatus } from '../features/ai/useAIAssistantStatus'
import {
  DEFAULT_SYSTEM_PROMPT,
} from '../features/ai/aiAssistantUtils'
import toast from 'react-hot-toast'

export default function AIAssistant() {
  const [searchParams, setSearchParams] = useSearchParams()
  const initialModel = localStorage.getItem('ai_last_model') || 'qwen2.5:3b'
  const [selectedModel, setSelectedModel] = useState(initialModel)

  // View mode: 'chat' or 'models' (install page)
  const viewMode: 'chat' | 'models' = searchParams.get('tab') === 'chat' ? 'chat' : 'models'
  const setViewMode = (nextView: 'chat' | 'models') => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', nextView)
    setSearchParams(next, { replace: true })
  }
  const [showSettings, setShowSettings] = useState(false)
  const streamAbortRef = useRef<AbortController | null>(null)

  const abortActiveStream = () => {
    if (streamAbortRef.current) {
      streamAbortRef.current.abort()
      streamAbortRef.current = null
    }
  }

  const handleModelSelect = (modelName: string) => {
    abortActiveStream()
    setSelectedModel(modelName)
  }

  const switchToChatView = () => {
    setViewMode('chat')
  }

  const switchToModelsView = () => {
    abortActiveStream()
    setViewMode('models')
  }

  const closeSettings = () => {
    setShowSettings(false)
  }

  const closeInstallModal = () => {
    setShowInstallModal(false)
  }

  const openOllamaModal = () => {
    setShowOllamaModal(true)
  }

  const closeOllamaModal = () => {
    setShowOllamaModal(false)
    if (ollamaWorking) {
      toast('Installation continues in background')
    }
  }

  const resetSettings = () => {
    setSelectedModel(models[0]?.name || 'qwen2.5:3b')
    setTemperatureValue(0.1)
    setSystemPrompt(DEFAULT_SYSTEM_PROMPT)
  }

  const saveSettings = () => handleSaveSettings({
    setSelectedModel,
    closeSettings,
  })

  const confirmDeleteModel = () => {
    if (confirm('Delete model? Ollama will remain installed.')) {
      closeSettings()
      void handleDeleteModel()
    }
  }

  const confirmUninstallFromSettings = () => {
    if (confirm('Completely remove Ollama and all models?')) {
      closeSettings()
      void handleUninstall()
    }
  }

  const confirmUninstallFromModels = () => {
    if (confirm('Completely remove Ollama and all models?')) {
      void handleUninstall()
    }
  }

  const toggleSessions = () => {
    setShowSessions((prev) => !prev)
  }

  const closeSessions = () => {
    setShowSessions(false)
  }

  const openSettings = () => {
    setShowSettings(true)
  }

  const clearError = () => {
    setError(null)
  }

  const handleSendMessage = () => {
    void sendMessage()
  }

  const handleComposerKeyPress = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    handleKeyPress(event, handleSendMessage)
  }

  const closeUninstallModal = () => {
    setShowUninstallModal(false)
  }

  const closeDeleteModelModal = () => {
    setShowDeleteModelModal(false)
  }

  const isDarkMode = useAIAssistantDarkMode()

  const aiThemeStyles = {
    '--ai-surface': isDarkMode ? '#0f172a' : '#ffffff',
    '--ai-surface-2': isDarkMode ? '#1e293b' : '#f3f4f6',
    '--ai-border': isDarkMode ? '#334155' : '#e5e7eb',
    '--ai-text': isDarkMode ? '#f1f5f9' : '#1f2937',
    '--ai-text-muted': isDarkMode ? '#cbd5e1' : '#6b7280',
    '--ai-text-subtle': isDarkMode ? '#94a3b8' : '#9ca3af',
  } as CSSProperties

  const {
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
  } = useAIAssistantStatus({
    selectedModel,
    setSelectedModel,
  })

  const {
    messages,
    setMessages,
    sessionId,
    showSessions,
    setShowSessions,
    sessions,
    loadingHistory,
    messagesEndRef,
    handleNewChat,
    handleSwitchSession,
    handleClearChat,
    handleDeleteSession,
    handleKeyPress,
  } = useAIAssistantSessions({
    selectedModel,
    setSelectedModel,
    temperatureValue,
    systemPrompt,
    isInstalled,
    abortActiveStream,
    onSwitchToChat: switchToChatView,
  })

  const {
    input,
    setInput,
    loading,
    sendMessage,
  } = useAIAssistantChat({
    selectedModel,
    temperatureValue,
    installedModels,
    isModelInstalled,
    sessionId,
    setMessages,
    setError,
    abortActiveStream,
    setStreamController: (controller) => {
      streamAbortRef.current = controller
    },
    onRequireModelInstall: switchToModelsView,
  })

  const {
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
    handleDeleteModel,
    handleInstall,
    handleCancelInstall,
    handleSaveSettings,
    handleUninstall,
    handleEnsureOllama,
    handleToggleOllama,
  } = useAIAssistantRuntime({
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
    onInstallComplete: switchToChatView,
  })

  useEffect(() => {
    return () => {
      if (streamAbortRef.current) {
        streamAbortRef.current.abort()
        streamAbortRef.current = null
      }
    }
  }, [])
  const {
    currentModelInfo,
    hasInstalledModels,
    selectedModelInstalled,
    ollamaInstalled,
    ollamaRunning,
    ollamaHealthy,
    ollamaStatusReady,
    blockOllamaUninstall,
    handleModelSelection,
  } = useAIAssistantModelSelection({
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
    onSwitchToChat: switchToChatView,
  })

  // ==================== СТРАНИЦА УСТАНОВКИ МОДЕЛЕЙ ====================
  if (!hasInstalledModels || !selectedModelInstalled || viewMode === 'models') {
    return (
      <AIAssistantModelSelection
        aiThemeStyles={aiThemeStyles}
        models={models}
        selectedModel={selectedModel}
        currentModelInfo={currentModelInfo}
        temperatureValue={temperatureValue}
        setTemperatureValue={setTemperatureValue}
        isModelInstalled={isModelInstalled}
        onSelectModel={handleModelSelection}
        onInstall={handleInstall}
        onEnsureOllama={handleEnsureOllama}
        onToggleOllama={handleToggleOllama}
        onUninstallOllama={confirmUninstallFromModels}
        ollamaStatusReady={ollamaStatusReady}
        ollamaInstalled={ollamaInstalled}
        ollamaRunning={ollamaRunning}
        ollamaHealthy={ollamaHealthy}
        ollamaWorking={ollamaWorking}
        ollamaFinalizing={ollamaFinalizing}
        ollamaProgress={ollamaProgress}
        ollamaEta={ollamaEta}
        ollamaStatus={ollamaStatus}
        blockOllamaUninstall={blockOllamaUninstall}
        showInstallModal={showInstallModal}
        installing={installing}
        installStage={installStage}
        modelDownloadProgress={modelDownloadProgress}
        installProgress={installProgress}
        modelDownloadInfo={modelDownloadInfo}
        installLogs={installLogs}
        error={error}
        onCloseInstallModal={closeInstallModal}
        onCancelInstall={handleCancelInstall}
        showOllamaModal={showOllamaModal}
        ollamaLogs={ollamaLogs}
        onShowOllamaModal={openOllamaModal}
        onCloseOllamaModal={closeOllamaModal}
      />
    )
  }
  return (
    <div
      className="h-[calc(100vh-4rem)] flex flex-col bg-gray-50 dark:bg-dark-950"
      style={aiThemeStyles}
    >
      {/* Хедер */}
      <AIAssistantHeader
        isHealthy={isHealthy}
        currentModelLabel={currentModelInfo?.display_name || selectedModel}
        temperatureValue={temperatureValue}
        showSessions={showSessions}
        sessionsCount={sessions.length}
        hasMessages={messages.length > 0}
        onOpenModels={switchToModelsView}
        onNewChat={handleNewChat}
        onToggleSessions={toggleSessions}
        onClearChat={handleClearChat}
        onOpenSettings={openSettings}
      />

      <AIAssistantSessionsPanel
        show={showSessions}
        sessions={sessions}
        sessionId={sessionId}
        onClose={closeSessions}
        onSwitchSession={handleSwitchSession}
        onDeleteSession={handleDeleteSession}
      />
      <AIAssistantBanners
        selectedModelInstalled={selectedModelInstalled}
        error={error}
        onOpenModels={switchToModelsView}
        onClearError={clearError}
      />

      <AIAssistantMessages
        loadingHistory={loadingHistory}
        messages={messages}
        messagesEndRef={messagesEndRef}
      />

      {/* Ввод */}
      <AIAssistantComposer
        input={input}
        loading={loading}
        isHealthy={isHealthy}
        selectedModelInstalled={selectedModelInstalled}
        onInputChange={setInput}
        onSend={handleSendMessage}
        onKeyPress={handleComposerKeyPress}
      />

      {/* Настройки */}
      <AIAssistantSettingsDrawer
        show={showSettings}
        models={models}
        selectedModel={selectedModel}
        temperatureValue={temperatureValue}
        systemPrompt={systemPrompt}
        modelPath={modelPath}
        savingSettings={savingSettings}
        isModelInstalled={isModelInstalled}
        onClose={closeSettings}
        onModelSelect={handleModelSelect}
        onTemperatureChange={setTemperatureValue}
        onSystemPromptChange={setSystemPrompt}
        onReset={resetSettings}
        onSave={saveSettings}
        onDeleteModel={confirmDeleteModel}
        onUninstall={confirmUninstallFromSettings}
      />

      <AIAssistantUninstallModal
        show={showUninstallModal}
        uninstalling={uninstalling}
        uninstallLogs={uninstallLogs}
        error={error}
        onClose={closeUninstallModal}
      />

      <AIAssistantDeleteModelModal
        show={showDeleteModelModal}
        deletingModel={deletingModel}
        selectedModel={selectedModel}
        modelPath={modelPath}
        deleteModelLogs={deleteModelLogs}
        error={error}
        onClose={closeDeleteModelModal}
      />

    </div>
  )
}

