interface AIAssistantOllamaModalProps {
  show: boolean
  ollamaWorking: boolean
  ollamaProgress: number
  ollamaFinalizing: boolean
  ollamaEta: string | null
  ollamaLogs: string[]
  error: string | null
  onClose: () => void
}

export function AIAssistantOllamaModal({
  show,
  ollamaWorking,
  ollamaProgress,
  ollamaFinalizing,
  ollamaEta,
  ollamaLogs,
  error,
  onClose,
}: AIAssistantOllamaModalProps) {
  if (!show) {
    return null
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="rounded-2xl w-full max-w-lg p-6" style={{ background: 'var(--ai-surface)' }}>
        <h3 className="text-base font-bold mb-4" style={{ color: 'var(--ai-text)' }}>Ollama Setup</h3>

        {ollamaWorking && (
          <div className="h-2 rounded-full overflow-hidden mb-4" style={{ background: 'var(--ai-border)' }}>
            <div className="h-full" style={{ width: `${Math.max(2, ollamaProgress)}%`, background: '#8b5cf6' }} />
          </div>
        )}

        <p className="text-xs mb-3" style={{ color: 'var(--ai-text-muted)' }}>
          {ollamaFinalizing
            ? 'Finalizing... (download complete)'
            : `Progress: ${ollamaProgress}%${ollamaWorking && ollamaProgress > 0 && ollamaProgress < 100 ? ` · ETA: ${ollamaEta ?? 'calculating...'}` : ''}`}
        </p>

        <div className="rounded-xl p-3 max-h-48 overflow-auto font-mono text-xs mb-4 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-300">
          {ollamaLogs.length === 0 ? (
            <span style={{ color: 'var(--ai-text-muted)' }}>Waiting...</span>
          ) : (
            ollamaLogs.map((log, index) => <div key={index}>{log}</div>)
          )}
        </div>

        {error && <div className="rounded-xl p-3 mb-4 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400">{error}</div>}

        <button
          onClick={onClose}
          className="w-full py-3 rounded-xl"
          style={{ background: 'var(--ai-surface-2)', color: 'var(--ai-text)' }}
        >
          {ollamaWorking ? 'Hide (continue in background)' : 'Close'}
        </button>
      </div>
    </div>
  )
}
