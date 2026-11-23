import type { CSSProperties } from 'react'
import { AlertCircle, Brain, ChevronDown, Download, Shield, Sparkles, Zap } from 'lucide-react'
import type { AIModelInfo } from '../../api/ai'
import { AIAssistantInstallModal } from './AIAssistantInstallModal'
import { AIAssistantOllamaModal } from './AIAssistantOllamaModal'

interface OllamaStatusShape {
  service_active?: boolean
  healthy?: boolean
  service_status?: string
}

interface ModelDownloadInfo {
  downloaded: string
  total: string
  speed: string
}

interface AIAssistantModelSelectionProps {
  aiThemeStyles: CSSProperties
  models: AIModelInfo[]
  selectedModel: string
  currentModelInfo?: AIModelInfo
  temperatureValue: number
  setTemperatureValue: (value: number) => void
  isModelInstalled: (modelName: string) => boolean
  onSelectModel: (model: AIModelInfo, installed: boolean) => void | Promise<void>
  onInstall: () => void
  onEnsureOllama: () => void
  onToggleOllama: () => void
  onUninstallOllama: () => void
  ollamaStatusReady: boolean
  ollamaInstalled: boolean
  ollamaRunning: boolean
  ollamaHealthy: boolean
  ollamaWorking: boolean
  ollamaFinalizing: boolean
  ollamaProgress: number
  ollamaEta: string | null
  ollamaStatus: OllamaStatusShape | null
  blockOllamaUninstall: boolean
  showInstallModal: boolean
  installing: boolean
  installStage: string
  modelDownloadProgress: number
  installProgress: number
  modelDownloadInfo: ModelDownloadInfo
  installLogs: string[]
  error: string | null
  onCloseInstallModal: () => void
  onCancelInstall: () => void
  showOllamaModal: boolean
  ollamaLogs: string[]
  onShowOllamaModal: () => void
  onCloseOllamaModal: () => void
}

export function AIAssistantModelSelection({
  aiThemeStyles,
  models,
  selectedModel,
  currentModelInfo,
  temperatureValue,
  setTemperatureValue,
  isModelInstalled,
  onSelectModel,
  onInstall,
  onEnsureOllama,
  onToggleOllama,
  onUninstallOllama,
  ollamaStatusReady,
  ollamaInstalled,
  ollamaRunning,
  ollamaHealthy,
  ollamaWorking,
  ollamaFinalizing,
  ollamaProgress,
  ollamaEta,
  ollamaStatus,
  blockOllamaUninstall,
  showInstallModal,
  installing,
  installStage,
  modelDownloadProgress,
  installProgress,
  modelDownloadInfo,
  installLogs,
  error,
  onCloseInstallModal,
  onCancelInstall,
  showOllamaModal,
  ollamaLogs,
  onShowOllamaModal,
  onCloseOllamaModal,
}: AIAssistantModelSelectionProps) {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-dark-950" style={aiThemeStyles}>
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="text-center mb-10">
          <div className="inline-flex p-5 rounded-3xl mb-6" style={{ background: 'linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)' }}>
            <Sparkles className="w-16 h-16" style={{ color: '#ffffff' }} />
          </div>
          <h1 className="text-2xl font-bold mb-4" style={{ color: 'var(--ai-text)' }}>AI Chat</h1>
          <p className="text-base max-w-2xl mx-auto" style={{ color: 'var(--ai-text-muted)' }}>
            Local AI assistant for server administration. Works completely offline using Ollama.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-4" style={{ marginTop: '20px', marginBottom: '20px' }}>
          {[
            { icon: Brain, title: 'Smart Answers', desc: 'Help with Linux, services, and more', color: '#10b981' },
            { icon: Shield, title: 'Privacy', desc: 'Data stays on your server', color: '#3b82f6' },
            { icon: Zap, title: 'Quick Start', desc: 'One-click installation', color: '#f59e0b' },
          ].map((feature) => (
            <div
              key={feature.title}
              className="rounded-2xl p-5 text-center flex flex-col items-center justify-center"
              style={{ background: 'var(--ai-surface)', border: '1px solid var(--ai-border)', minHeight: '180px' }}
            >
              <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-3" style={{ background: feature.color }}>
                <feature.icon className="w-6 h-6" style={{ color: '#ffffff' }} />
              </div>
              <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--ai-text)' }}>{feature.title}</h3>
              <p style={{ color: 'var(--ai-text-muted)' }}>{feature.desc}</p>
            </div>
          ))}
        </div>

        <div className="rounded-2xl p-6 mb-6" style={{ background: 'var(--ai-surface)', border: '1px solid var(--ai-border)' }}>
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-base font-bold mb-1" style={{ color: 'var(--ai-text)' }}>Ollama Runtime</h2>
              <p className="text-sm" style={{ color: 'var(--ai-text-muted)' }}>
                Install and control the local Ollama service used for AI models.
              </p>
            </div>
            <div
              className="px-3 py-1 rounded-full text-xs font-semibold"
              style={{
                background: !ollamaStatusReady
                  ? 'var(--ai-surface-2)'
                  : (!ollamaInstalled
                    ? 'var(--ai-surface-2)'
                    : (!ollamaRunning
                      ? '#fef3c7'
                      : (ollamaHealthy ? '#dcfce7' : '#fef2f2'))),
                color: !ollamaStatusReady
                  ? 'var(--ai-text-muted)'
                  : (!ollamaInstalled
                    ? 'var(--ai-text-muted)'
                    : (!ollamaRunning
                      ? '#92400e'
                      : (ollamaHealthy ? '#166534' : '#dc2626'))),
              }}
            >
              {!ollamaStatusReady
                ? 'Checking...'
                : (!ollamaInstalled
                  ? 'Not installed'
                  : (!ollamaRunning
                    ? 'Inactive'
                    : (ollamaHealthy ? 'Running' : 'Not responding')))}
            </div>
          </div>

          <div className="mt-4 flex flex-wrap gap-3">
            {!ollamaInstalled && (
              <button
                onClick={onEnsureOllama}
                disabled={!ollamaStatusReady || ollamaWorking}
                className="px-4 py-2 rounded-xl font-semibold disabled:opacity-50 bg-violet-500 dark:bg-violet-600 text-white"
              >
                Install Ollama
              </button>
            )}

            {ollamaInstalled && (
              <>
                <button
                  onClick={onToggleOllama}
                  disabled={!ollamaStatusReady || ollamaWorking}
                  className={`px-4 py-2 rounded-xl font-semibold disabled:opacity-50 ${ollamaRunning
                    ? 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400'
                    : 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400'
                    }`}
                >
                  {ollamaRunning ? 'Stop Ollama' : 'Start Ollama'}
                </button>
                <button
                  onClick={onUninstallOllama}
                  disabled={!ollamaStatusReady || blockOllamaUninstall}
                  className="px-4 py-2 rounded-xl font-semibold disabled:opacity-50 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400"
                >
                  Uninstall Ollama
                </button>
              </>
            )}
          </div>

          {ollamaWorking && (
            <div className="mt-4 rounded-xl p-3" style={{ background: 'var(--ai-surface-2)' }}>
              <div className="flex items-center justify-between text-xs mb-2" style={{ color: 'var(--ai-text-muted)' }}>
                <span>{ollamaFinalizing ? 'Finalizing...' : `Installing... ${ollamaProgress}%`}</span>
                <span>{ollamaFinalizing ? 'Please wait...' : `ETA: ${ollamaEta ?? 'calculating...'}`}</span>
              </div>
              <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--ai-border)' }}>
                <div className="h-full" style={{ width: `${Math.max(2, ollamaProgress)}%`, background: '#8b5cf6' }} />
              </div>
              <button
                onClick={onShowOllamaModal}
                className="mt-3 text-xs font-semibold underline"
                style={{ color: 'var(--ai-text-muted)' }}
              >
                Show details
              </button>
            </div>
          )}

          {ollamaStatusReady && (
            <p className="text-xs mt-3" style={{ color: 'var(--ai-text-subtle)' }}>
              Service status: {ollamaStatus?.service_status || 'unknown'} · Health: {!ollamaRunning ? 'Offline' : (ollamaHealthy ? 'OK' : 'Not responding')}
            </p>
          )}
        </div>

        <div className="rounded-2xl p-4 sm:p-8 shadow-2xl dark:shadow-none" style={{ background: 'var(--ai-surface)' }}>
          <h2 className="text-base sm:text-lg font-bold mb-4 sm:mb-6" style={{ color: 'var(--ai-text)' }}>Select Model</h2>

          <div className="mb-6">
            <div className="space-y-3">
              {models.map((model) => {
                const installed = isModelInstalled(model.name)
                const isSelected = selectedModel === model.name

                return (
                  <div
                    key={model.name}
                    onClick={() => onSelectModel(model, installed)}
                    className={`rounded-xl p-3 sm:p-4 cursor-pointer transition-all border-2 ${installed
                      ? (isSelected
                        ? 'border-emerald-500 bg-emerald-50 dark:bg-dark-900'
                        : 'border-emerald-400 bg-emerald-50/70 dark:bg-dark-900')
                      : (isSelected
                        ? 'border-violet-500 bg-violet-50 dark:bg-dark-900'
                        : 'border-gray-200 dark:border-dark-700 bg-gray-50 dark:bg-dark-900')
                      }`}
                    style={{ transform: isSelected ? 'scale(1.01)' : 'scale(1)' }}
                  >
                    <div className="flex items-start sm:items-center justify-between gap-2">
                      <div className="flex items-start sm:items-center gap-2 sm:gap-3 flex-1 min-w-0">
                        <div
                          className="w-8 h-8 sm:w-10 sm:h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                          style={{ background: installed ? '#10b981' : 'var(--ai-border)' }}
                        >
                          {installed ? (
                            <span className="text-sm sm:text-base" style={{ color: '#ffffff' }}>OK</span>
                          ) : (
                            <Download className="w-4 h-4 sm:w-5 sm:h-5" style={{ color: '#9ca3af' }} />
                          )}
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-1 sm:gap-2">
                            <span className="text-xs sm:text-sm font-semibold" style={{ color: 'var(--ai-text)' }}>
                              {model.display_name}
                            </span>
                            <span className="text-xs" style={{ color: 'var(--ai-text-muted)' }}>
                              ({model.size_gb.toFixed(1)} GB)
                            </span>
                            {installed && (
                              <span className="px-1.5 sm:px-2 py-0.5 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">
                                Ready
                              </span>
                            )}
                            {model.recommended && !installed && (
                              <span className="px-1.5 sm:px-2 py-0.5 text-xs font-medium rounded-full bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400">
                                Recommended
                              </span>
                            )}
                          </div>
                          <p className="text-xs mt-0.5" style={{ color: 'var(--ai-text-muted)' }}>
                            {model.description}
                          </p>
                        </div>
                      </div>

                      {installed && (
                        <div className="flex-shrink-0" style={{ color: '#10b981' }}>
                          <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5 -rotate-90" />
                        </div>
                      )}
                    </div>

                    {isSelected && !installed && (
                      <div className="mt-3 px-3 py-2 rounded-lg text-xs flex items-center gap-2 bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400">
                        <AlertCircle className="w-4 h-4" />
                        <span>This model will be downloaded (~{model.size_gb.toFixed(1)} GB)</span>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {currentModelInfo?.notes && (
              <p className="mt-3 text-sm" style={{ color: 'var(--ai-text-muted)' }}>
                {currentModelInfo.notes}
              </p>
            )}
          </div>

          {!isModelInstalled(selectedModel) && (
            <>
              <div className="mb-6">
                <div className="flex justify-between mb-2">
                  <label className="text-xs font-semibold" style={{ color: 'var(--ai-text)' }}>Temperature</label>
                  <span className="text-xs font-bold px-3 py-1 rounded-full bg-violet-500 dark:bg-violet-600 text-white">
                    {temperatureValue.toFixed(2)}
                  </span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={1.5}
                  step={0.05}
                  value={temperatureValue}
                  onChange={(event) => setTemperatureValue(Number(event.target.value))}
                  className="w-full h-3 rounded-full appearance-none cursor-pointer"
                  style={{ background: 'linear-gradient(90deg, #3b82f6 0%, #8b5cf6 50%, #ec4899 100%)' }}
                />
                <div className="flex justify-between text-xs mt-1" style={{ color: 'var(--ai-text-subtle)' }}>
                  <span>Precise</span>
                  <span>Creative</span>
                </div>
              </div>

              <div className="rounded-xl p-3 sm:p-4 mb-4 sm:mb-6 flex gap-2 sm:gap-4" style={{ background: 'linear-gradient(135deg, #fef3c7 0%, #fde68a 100%)', border: '1px solid #fbbf24' }}>
                <Sparkles className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" style={{ color: '#d97706' }} />
                <div>
                  <p className="text-xs sm:text-sm font-semibold" style={{ color: '#92400e' }}>
                    Download size: ~{currentModelInfo?.size_gb.toFixed(1)} GB
                  </p>
                  <p className="text-xs" style={{ color: '#a16207' }}>
                    {currentModelInfo?.notes || 'Stable internet connection required.'}
                  </p>
                </div>
              </div>

              <button
                onClick={onInstall}
                className="w-full flex items-center justify-center gap-2 sm:gap-3 font-bold py-3 sm:py-4 px-4 sm:px-6 rounded-xl text-xs sm:text-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
                style={{
                  background: 'linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)',
                  color: '#ffffff',
                  boxShadow: '0 10px 40px -10px rgba(139, 92, 246, 0.5)'
                }}
              >
                <Download className="w-5 h-5 sm:w-6 sm:h-6" />
                <span className="truncate">Install {currentModelInfo?.display_name}</span>
              </button>
            </>
          )}
        </div>

        <AIAssistantInstallModal
          show={showInstallModal}
          installing={installing}
          installStage={installStage}
          modelDownloadProgress={modelDownloadProgress}
          installProgress={installProgress}
          modelDownloadInfo={modelDownloadInfo}
          installLogs={installLogs}
          selectedModel={selectedModel}
          currentModelInfo={currentModelInfo}
          error={error}
          onClose={onCloseInstallModal}
          onCancel={onCancelInstall}
        />

        <AIAssistantOllamaModal
          show={showOllamaModal}
          ollamaWorking={ollamaWorking}
          ollamaProgress={ollamaProgress}
          ollamaFinalizing={ollamaFinalizing}
          ollamaEta={ollamaEta}
          ollamaLogs={ollamaLogs}
          error={error}
          onClose={onCloseOllamaModal}
        />
      </div>
    </div>
  )
}
