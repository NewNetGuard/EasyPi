import { AlertCircle, X } from 'lucide-react'

interface AIAssistantBannersProps {
  selectedModelInstalled: boolean
  error: string | null
  onOpenModels: () => void
  onClearError: () => void
}

export function AIAssistantBanners({
  selectedModelInstalled,
  error,
  onOpenModels,
  onClearError,
}: AIAssistantBannersProps) {
  return (
    <>
      {!selectedModelInstalled && (
        <div className="px-6 pt-3">
          <div className="max-w-4xl mx-auto rounded-lg p-3 flex items-center gap-2 bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400">
            <AlertCircle className="w-4 h-4" />
            <span className="text-sm flex-1">Selected model is not installed. Install a model to start chatting.</span>
            <button
              onClick={onOpenModels}
              className="px-2 py-1 text-xs rounded bg-yellow-100 dark:bg-yellow-900/40"
            >
              Open models
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="px-6">
          <div className="max-w-4xl mx-auto rounded-lg p-3 flex items-center gap-2 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400">
            <AlertCircle className="w-4 h-4" />
            <span className="text-sm flex-1">{error}</span>
            <button onClick={onClearError}><X className="w-4 h-4" /></button>
          </div>
        </div>
      )}
    </>
  )
}
