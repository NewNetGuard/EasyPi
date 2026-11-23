import { MessageSquare, Trash2, X } from 'lucide-react';
import type { ChatSession } from '../../api/ai';

interface AIAssistantSessionsPanelProps {
  show: boolean;
  sessions: ChatSession[];
  sessionId: string;
  onClose: () => void;
  onSwitchSession: (session: ChatSession) => void;
  onDeleteSession: (sessionId: string, event: React.MouseEvent) => void;
}

export function AIAssistantSessionsPanel({
  show,
  sessions,
  sessionId,
  onClose,
  onSwitchSession,
  onDeleteSession,
}: AIAssistantSessionsPanelProps) {
  if (!show) {
    return null;
  }

  return (
    <div className="max-w-4xl mx-auto mt-3">
      <div
        className="rounded-xl overflow-hidden"
        style={{ background: 'var(--ai-surface)', boxShadow: '0 10px 40px rgba(0,0,0,0.2)' }}
      >
        <div className="p-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--ai-border)' }}>
          <span className="font-semibold text-sm" style={{ color: 'var(--ai-text)' }}>
            Chat History ({sessions.length})
          </span>
          <button onClick={onClose} className="p-1 rounded" style={{ color: 'var(--ai-text-muted)' }}>
            <X className="w-4 h-4" />
          </button>
        </div>

        {sessions.length === 0 ? (
          <div className="p-4 text-center" style={{ color: 'var(--ai-text-subtle)' }}>
            <MessageSquare className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No chat history yet</p>
          </div>
        ) : (
          <div className="max-h-64 overflow-y-auto">
            {sessions.map((session) => (
              <div
                key={session.session_id}
                onClick={() => onSwitchSession(session)}
                className="p-3 cursor-pointer transition-colors flex items-center gap-3 group"
                style={{
                  background: session.session_id === sessionId ? 'var(--ai-surface-2)' : 'transparent',
                  borderBottom: '1px solid var(--ai-border)'
                }}
              >
                <MessageSquare
                  className="w-5 h-5 flex-shrink-0"
                  style={{ color: session.session_id === sessionId ? '#8b5cf6' : 'var(--ai-text-subtle)' }}
                />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate" style={{ color: 'var(--ai-text)' }}>
                    {session.title}
                  </p>
                  <p className="text-xs" style={{ color: 'var(--ai-text-subtle)' }}>
                    {session.message_count} messages • {session.last_message_at ? new Date(session.last_message_at).toLocaleDateString() : ''}
                  </p>
                </div>
                {session.session_id === sessionId && (
                  <span className="px-2 py-0.5 text-xs rounded-full bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-400">
                    Active
                  </span>
                )}
                <button
                  onClick={(event) => onDeleteSession(session.session_id, event)}
                  className="p-1 rounded opacity-0 group-hover:opacity-100 transition-opacity text-red-500 dark:text-red-400"
                  title="Delete chat"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
