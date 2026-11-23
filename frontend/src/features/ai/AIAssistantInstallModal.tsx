import { AlertCircle, Loader2, X } from 'lucide-react'
import type { AIModelInfo } from '../../api/ai'

interface ModelDownloadInfo {
  downloaded: string
  total: string
  speed: string
}

interface AIAssistantInstallModalProps {
  show: boolean
  installing: boolean
  installStage: string
  modelDownloadProgress: number
  installProgress: number
  modelDownloadInfo: ModelDownloadInfo
  installLogs: string[]
  selectedModel: string
  currentModelInfo?: AIModelInfo
  error: string | null
  onClose: () => void
  onCancel: () => void
}

export function AIAssistantInstallModal({
  show,
  installing,
  installStage,
  modelDownloadProgress,
  installProgress,
  modelDownloadInfo,
  installLogs,
  selectedModel,
  currentModelInfo,
  error,
  onClose,
  onCancel,
}: AIAssistantInstallModalProps) {
  if (!show) {
    return null
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="rounded-2xl w-full max-w-lg p-6" style={{ background: 'var(--ai-surface)' }}>
        <h3 className="text-base font-bold mb-4" style={{ color: 'var(--ai-text)' }}>Installing AI Chat</h3>

        {installing && (
          <div className="font-mono text-sm flex items-center gap-2 px-4 py-3 rounded-xl mb-4 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200">
            {(() => {
              const isDownloadingModel = installStage === 'model' || modelDownloadProgress > 0
              const percent = isDownloadingModel
                ? Math.max(modelDownloadProgress, 0)
                : Math.max(installProgress, 0)

              const barWidth = 18
              const filled = Math.min(barWidth, Math.max(0, Math.round((percent / 100) * barWidth)))
              const empty = Math.max(0, barWidth - filled)
              const bar = `|${'#'.repeat(filled)}${' '.repeat(empty)}|`

              let volume = ''
              if (modelDownloadInfo.downloaded && modelDownloadInfo.total) {
                volume = `${modelDownloadInfo.downloaded}/${modelDownloadInfo.total}`
                if (modelDownloadInfo.speed) {
                  volume += ` ${modelDownloadInfo.speed}`
                }
              } else if (isDownloadingModel && percent > 5) {
                const modelSize = currentModelInfo?.size_gb || 4.7
                const downloadedSize = (percent / 100) * modelSize
                volume = `${downloadedSize.toFixed(1)} GB/${modelSize.toFixed(1)} GB`
              }

              return (
                <>
                  <span className="font-bold min-w-[3ch] text-right" style={{ color: '#10b981' }}>
                    {percent}%
                  </span>
                  <span className="whitespace-pre" style={{ color: '#60a5fa' }}>{bar}</span>
                  {volume && (
                    <span style={{ color: 'var(--ai-text-subtle)' }}>{volume}</span>
                  )}
                </>
              )
            })()}
          </div>
        )}

        <div className="rounded-xl p-3 max-h-32 overflow-auto font-mono text-xs mb-4 scroll-smooth bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-300">
          {installLogs.length === 0 ? (
            <span style={{ color: 'var(--ai-text-muted)' }}>Waiting...</span>
          ) : (
            installLogs.slice(-20).map((log, index) => (
              <div key={index} className="py-0.5">{log}</div>
            ))
          )}
        </div>

        {error && (
          <div className="rounded-xl p-3 mb-4 flex items-center gap-2 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400">
            <AlertCircle className="w-5 h-5" />
            <span className="text-sm">{error}</span>
          </div>
        )}

        {installProgress === 100 && !installing && (
          <div className="rounded-xl p-4 mb-4 bg-green-50 dark:bg-green-900/20 border border-green-300 dark:border-green-700">
            <div className="flex items-start gap-3">
              <span className="text-lg">OK</span>
              <div className="flex-1">
                <p className="font-semibold mb-1" style={{ color: '#166534' }}>Model installed</p>
                <p className="text-sm font-mono break-all" style={{ color: '#15803d' }}>
                  ~/.ollama/models/{selectedModel.replace(':', '/')}
                </p>
                <p className="text-xs mt-2" style={{ color: '#16a34a' }}>
                  You can delete the model later in settings to free up space.
                </p>
              </div>
            </div>
          </div>
        )}

        {!installing && (
          <button
            onClick={onClose}
            className="w-full font-semibold py-3 rounded-xl transition-all hover:opacity-90"
            style={{
              background: installProgress === 100 ? '#10b981' : '#8b5cf6',
              color: '#ffffff'
            }}
          >
            {installProgress === 100 ? 'Start Chat' : 'Close'}
          </button>
        )}

        {installing && (
          <div className="space-y-3">
            <div className="flex items-center justify-center gap-2 py-2" style={{ color: 'var(--ai-text-muted)' }}>
              <Loader2 className="w-5 h-5 animate-spin" style={{ color: '#8b5cf6' }} />
              <span>Installation in progress...</span>
            </div>
            <button
              onClick={onCancel}
              className="w-full font-semibold py-3 rounded-xl transition-all hover:opacity-90 flex items-center justify-center gap-2"
              style={{
                background: '#fef2f2',
                color: '#dc2626',
                border: '2px solid #fecaca'
              }}
            >
              <X className="w-5 h-5" />
              Cancel Installation
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
