import { Loader2, Send } from 'lucide-react'

interface AIAssistantComposerProps {
  input: string
  loading: boolean
  isHealthy: boolean
  selectedModelInstalled: boolean
  onInputChange: (value: string) => void
  onSend: () => void
  onKeyPress: (event: React.KeyboardEvent<HTMLTextAreaElement>) => void
}

export function AIAssistantComposer({
  input,
  loading,
  isHealthy,
  selectedModelInstalled,
  onInputChange,
  onSend,
  onKeyPress,
}: AIAssistantComposerProps) {
  return (
    <div className="bg-white dark:bg-dark-900 border-t border-gray-200 dark:border-dark-800 px-6 py-4">
      <div className="max-w-4xl mx-auto flex gap-3">
        <textarea
          className="flex-1 rounded-xl px-4 py-3 focus:outline-none focus:ring-4 resize-none"
          style={{ background: 'var(--ai-surface-2)', border: '2px solid var(--ai-border)', color: 'var(--ai-text)' }}
          rows={1}
          placeholder={selectedModelInstalled ? 'Type a message...' : 'Install a model to start chatting...'}
          value={input}
          onChange={(event) => onInputChange(event.target.value)}
          onKeyPress={onKeyPress}
          disabled={loading || !isHealthy || !selectedModelInstalled}
        />
        <button
          onClick={onSend}
          disabled={!input.trim() || loading || !isHealthy || !selectedModelInstalled}
          className="px-5 py-3 rounded-xl transition-all disabled:opacity-50"
          style={{ background: 'linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)', color: '#ffffff' }}
        >
          {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
        </button>
      </div>
    </div>
  )
}
