interface AIAssistantUninstallModalProps {
  show: boolean
  uninstalling: boolean
  uninstallLogs: string[]
  error: string | null
  onClose: () => void
}

export function AIAssistantUninstallModal({
  show,
  uninstalling,
  uninstallLogs,
  error,
  onClose,
}: AIAssistantUninstallModalProps) {
  if (!show) {
    return null
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="rounded-2xl w-full max-w-lg p-6" style={{ background: 'var(--ai-surface)' }}>
        <h3 className="text-base font-bold mb-4" style={{ color: 'var(--ai-text)' }}>Removing Ollama</h3>

        {uninstalling && (
          <div className="h-2 rounded-full overflow-hidden mb-4" style={{ background: 'var(--ai-border)' }}>
            <div className="h-full w-full animate-pulse bg-red-500" />
          </div>
        )}

        <div className="rounded-xl p-3 max-h-40 overflow-auto font-mono text-xs mb-4 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-300">
          {uninstallLogs.map((log, index) => <div key={index}>{log}</div>)}
        </div>

        {error && <div className="rounded-xl p-3 mb-4 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400">{error}</div>}

        {!uninstalling && (
          <button
            onClick={onClose}
            className="w-full py-3 rounded-xl"
            style={{ background: 'var(--ai-surface-2)', color: 'var(--ai-text)' }}
          >
            Close
          </button>
        )}
      </div>
    </div>
  )
}
