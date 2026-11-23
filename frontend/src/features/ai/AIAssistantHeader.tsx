import { Bot, History, Package, Plus, Settings, Trash2 } from 'lucide-react';

interface AIAssistantHeaderProps {
  isHealthy: boolean;
  currentModelLabel: string;
  temperatureValue: number;
  showSessions: boolean;
  sessionsCount: number;
  hasMessages: boolean;
  onOpenModels: () => void;
  onNewChat: () => void;
  onToggleSessions: () => void;
  onClearChat: () => void;
  onOpenSettings: () => void;
}

export function AIAssistantHeader({
  isHealthy,
  currentModelLabel,
  temperatureValue,
  showSessions,
  sessionsCount,
  hasMessages,
  onOpenModels,
  onNewChat,
  onToggleSessions,
  onClearChat,
  onOpenSettings,
}: AIAssistantHeaderProps) {
  return (
    <div style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }} className="px-3 sm:px-6 py-3 sm:py-4">
      <div className="max-w-4xl mx-auto flex flex-wrap sm:flex-nowrap items-center justify-between gap-2 sm:gap-0">
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="p-1.5 sm:p-2 rounded-xl" style={{ background: 'rgba(255,255,255,0.2)' }}>
            <Bot className="w-5 h-5 sm:w-6 sm:h-6" style={{ color: '#ffffff' }} />
          </div>
          <div>
            <h1 className="text-xs sm:text-sm font-semibold flex flex-wrap items-center gap-1 sm:gap-2" style={{ color: '#ffffff' }}>
              <span>AI Chat</span>
              {isHealthy ? (
                <span className="inline-flex items-center gap-1 px-1.5 sm:px-2 py-0.5 text-xs rounded-full bg-green-900/30 dark:bg-green-900/30 text-green-300 dark:text-green-300">
                  <span className="w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full bg-green-500" />
                  <span className="hidden sm:inline">Online</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-1.5 sm:px-2 py-0.5 text-xs rounded-full bg-yellow-900/30 dark:bg-yellow-900/30 text-yellow-300 dark:text-yellow-300">
                  <span className="hidden sm:inline">Not responding</span>
                </span>
              )}
            </h1>
            <p className="text-xs truncate max-w-[150px] sm:max-w-none" style={{ color: 'rgba(255,255,255,0.7)' }}>
              {currentModelLabel} • T={temperatureValue.toFixed(2)}
            </p>
          </div>
        </div>

        <div className="flex items-center justify-between w-full sm:w-auto gap-2 sm:gap-3">
          <button
            onClick={onOpenModels}
            className="p-2 sm:p-2.5 rounded-lg transition-colors"
            style={{ background: 'rgba(255,255,255,0.1)', color: '#ffffff' }}
            title="Manage models"
          >
            <Package className="w-5 h-5 sm:w-6 sm:h-6" />
          </button>

          <button
            onClick={onNewChat}
            className="p-2 sm:p-2.5 rounded-lg transition-colors"
            style={{ background: 'rgba(255,255,255,0.1)', color: '#ffffff' }}
            title="New chat"
          >
            <Plus className="w-5 h-5 sm:w-6 sm:h-6" />
          </button>

          <button
            onClick={onToggleSessions}
            className="p-2 sm:p-2.5 rounded-lg transition-colors relative"
            style={{ background: showSessions ? 'rgba(255,255,255,0.3)' : 'rgba(255,255,255,0.1)', color: '#ffffff' }}
            title="Chat history"
          >
            <History className="w-5 h-5 sm:w-6 sm:h-6" />
            {sessionsCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 sm:w-5 sm:h-5 text-xs flex items-center justify-center rounded-full bg-green-500 text-white">
                {sessionsCount}
              </span>
            )}
          </button>

          {hasMessages && (
            <button
              onClick={onClearChat}
              className="p-2 sm:p-2.5 rounded-lg transition-colors"
              style={{ background: 'rgba(239,68,68,0.2)', color: '#fca5a5' }}
              title="Clear chat"
            >
              <Trash2 className="w-5 h-5 sm:w-6 sm:h-6" />
            </button>
          )}

          <button
            onClick={onOpenSettings}
            className="p-2 sm:p-2.5 rounded-lg transition-colors"
            style={{ background: 'rgba(255,255,255,0.1)', color: '#ffffff' }}
          >
            <Settings className="w-5 h-5 sm:w-6 sm:h-6" />
          </button>
        </div>
      </div>
    </div>
  );
}
